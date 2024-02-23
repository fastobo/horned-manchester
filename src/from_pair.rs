use std::collections::BTreeSet;

use curie::Curie;
use curie::PrefixMapping;
use horned_owl::model::*;
use horned_owl::ontology::set::SetOntology;
use pest::iterators::Pair;

use crate::error::Error;
use crate::error::Result;
use crate::parser::Rule;
use crate::frames::ClassFrame;
use crate::Context;

// ---------------------------------------------------------------------------

/// A trait for OWL elements that can be obtained from OWL Manchester tokens.
///
/// `Pair<Rule>` values can be obtained from the `OwlManchesterParser` struct
/// after parsing a document.
pub trait FromPair<A: ForIRI>: Sized {
    /// The valid production rule for the implementor.
    const RULE: Rule;

    /// Create a new instance from a `Pair`.
    #[inline]
    fn from_pair(pair: Pair<Rule>, context: &Context<'_, A>) -> Result<Self> {
        if cfg!(debug_assertions) && &pair.as_rule() != &Self::RULE {
            return Err(Error::from(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::ParsingError {
                    positives: vec![pair.as_rule()],
                    negatives: vec![Self::RULE],
                },
                pair.as_span(),
            )));
        }
        Self::from_pair_unchecked(pair, context)
    }

    /// Create a new instance from a `Pair` without checking the PEG rule.
    fn from_pair_unchecked(pair: Pair<Rule>, context: &Context<'_, A>) -> Result<Self>;
}

// ---------------------------------------------------------------------------

macro_rules! impl_wrapper {
    ($ty:ident, $rule:path) => {
        impl<A: ForIRI> FromPair<A> for $ty<A> {
            const RULE: Rule = $rule;
            fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
                FromPair::<A>::from_pair(pair.into_inner().next().unwrap(), ctx).map($ty)
            }
        }
    };
}

impl_wrapper!(Class, Rule::ClassIRI);
impl_wrapper!(Import, Rule::ImportIRI);
impl_wrapper!(NamedIndividual, Rule::IndividualIRI);
impl_wrapper!(ObjectProperty, Rule::ObjectPropertyIRI);
impl_wrapper!(DataProperty, Rule::DataPropertyIRI);
impl_wrapper!(AnnotationProperty, Rule::AnnotationPropertyIRI);

macro_rules! impl_vector {
    ($A:ident, $ty:ty, $rule:path) => {
        impl<$A: ForIRI> FromPair<$A> for $ty {
            const RULE: Rule = $rule;
            fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, $A>) -> Result<Self> {
                pair.into_inner()
                    .map(|pair| FromPair::from_pair(pair, ctx))
                    .collect()
            }
        }
    };
}

impl_vector!(A, Vec<Literal<A>>, Rule::LiteralList);
impl_vector!(A, Vec<Individual<A>>, Rule::IndividualList);

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for Annotation<A> {
    const RULE: Rule = Rule::Annotation;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut inner = pair.into_inner();
        let ap = FromPair::<A>::from_pair(inner.next().unwrap(), ctx)?;
        let av = FromPair::<A>::from_pair(inner.next().unwrap(), ctx)?;
        Ok(Annotation { ap, av })
    }
}

impl<A: ForIRI> FromPair<A> for AnnotationValue<A> {
    const RULE: Rule = Rule::AnnotationTarget;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::NodeID => {
                unimplemented!("AnnotationValue does not support NodeID yet")
            }
            Rule::IRI => {
                let iri = FromPair::<A>::from_pair(inner, ctx)?;
                Ok(AnnotationValue::IRI(iri))
            }
            Rule::Literal => {
                let literal = FromPair::<A>::from_pair(inner, ctx)?;
                Ok(AnnotationValue::Literal(literal))
            }
            rule => unreachable!("unexpected rule in AnnotationValue::from_pair: {:?}", rule),
        }
    }
}

impl<A: ForIRI> FromPair<A> for BTreeSet<Annotation<A>> {
    const RULE: Rule = Rule::AnnotationAnnotatedList;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut inner = pair.into_inner();
        let mut annotations = BTreeSet::new();

        for pair in inner {
            match pair.as_rule() {
                Rule::Annotation => {
                    let annotation = Annotation::<A>::from_pair(pair, ctx)?;
                    annotations.insert(annotation);
                }
                Rule::Annotations => {
                    unimplemented!("nested annotation lists not supported")
                }
                rule => unreachable!("unexpected rule in BTreeSet<Annotation>::from_pair: {:?}", rule),
            }
        }

        Ok(annotations)
    }
}

// ---------------------------------------------------------------------------

fn from_restriction_pair<A: ForIRI>(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Restriction);
    unimplemented!("Restriction")
}

fn from_atomic_pair<A: ForIRI>(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Atomic);

    let mut inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::Description => FromPair::from_pair(inner, ctx),
        Rule::ClassIRI => FromPair::from_pair(inner, ctx).map(ClassExpression::Class),
        Rule::IndividualList => FromPair::from_pair(inner, ctx).map(ClassExpression::ObjectOneOf),
        rule => unreachable!("unexpected rule in ClassExpression::from_pair: {:?}", rule),
    }
}

fn from_primary_pair<A: ForIRI>(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Primary);

    let mut inner = pair.into_inner();
    let mut pair = inner.next().unwrap();

    let mut is_complement = false;

    if pair.as_rule() == Rule::LIT_NOT {
        is_complement = true;
        pair = inner.next().unwrap();
    }
    
    let ce = match pair.as_rule() {
        Rule::Restriction => from_restriction_pair(pair, ctx),
        Rule::Atomic => from_atomic_pair(pair, ctx),
        rule => unreachable!("unexpected rule in ClassExpression::from_pair: {:?}", rule),
    };

    if is_complement {
        ce.map(Box::new).map(ClassExpression::ObjectComplementOf)
    } else {
        ce
    }
}

fn from_conjuction_pair<A: ForIRI>(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Conjuction);
    
    let mut inner = pair.into_inner().peekable();
    match inner.peek().unwrap().as_rule() {
        Rule::ClassIRI => {
            let class = Class::from_pair(inner.next().unwrap(), ctx)?;
            let mut intersection = vec![ ClassExpression::Class(class) ];
            while let Some(pair) = inner.next() {
                let cexp = if pair.as_rule() == Rule::LIT_NOT {
                    ClassExpression::ObjectComplementOf(Box::new(from_restriction_pair(inner.next().unwrap(), ctx)?))
                } else {
                    from_restriction_pair(pair, ctx)?
                };
                intersection.push(cexp)
            };
            Ok(ClassExpression::ObjectIntersectionOf(intersection))
        },
        Rule::Primary => {
            let mut primaries = inner
                .map(|pair| from_primary_pair(pair, ctx))
                .collect::<Result<Vec<_>>>()?;
            if primaries.len() == 1 {
                Ok(primaries.pop().unwrap())
            } else {
                Ok(ClassExpression::ObjectIntersectionOf(primaries))
            }
        }
        rule => unreachable!("unexpected rule in ClassExpression::from_pair: {:?}", rule),
    }
}

impl<A: ForIRI> FromPair<A> for ClassExpression<A> {
    const RULE: Rule = Rule::Description;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut inner = pair.into_inner();

        if inner.len() == 1 {
            from_conjuction_pair(inner.next().unwrap(), ctx)
        } else {
            Ok(ClassExpression::ObjectUnionOf(
                inner
                    .map(|pair| from_conjuction_pair(pair, ctx))
                    .collect::<Result<_>>()?
            ))
        }

    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for Datatype<A> {
    const RULE: Rule = Rule::Datatype;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        match pair.as_str() {
            "integer" => { unimplemented!() }
            "decimal" => { unimplemented!() }
            "float" => { unimplemented!() }
            "string" => { unimplemented!() }
            _ => {
                let mut inner = pair.into_inner();
                unimplemented!()
            }
        }
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for Individual<A> {
    const RULE: Rule = Rule::Individual;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::IndividualIRI => {
                FromPair::from_pair(inner, ctx).map(Individual::Named)
            }
            Rule::NodeID => {
                FromPair::from_pair(inner, ctx).map(Individual::Anonymous)
            }
            rule => unreachable!("unexpected rule in Individual::from_pair: {:?}", rule),
        }
    }
}

impl<A: ForIRI> FromPair<A> for AnonymousIndividual<A> {
    const RULE: Rule = Rule::NodeID;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        Ok(AnonymousIndividual(pair.as_str().to_string().into()))
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for Literal<A> {
    const RULE: Rule = Rule::Literal;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let pair = pair.into_inner().next().unwrap();
        match pair.as_rule() {

            Rule::TypedLiteral => {
                let mut inner = pair.into_inner();
                let literal = String::from_pair(inner.next().unwrap(), ctx)?;
                let dty = Datatype::from_pair(inner.next().unwrap(), ctx)?;
                Ok(Literal::Datatype {
                    literal,
                    datatype_iri: dty.0,
                })
            }

            Rule::StringLiteralWithLanguage => {
                let mut inner = pair.into_inner();
                let literal = String::from_pair(inner.next().unwrap(), ctx)?;
                let lang = inner.next().unwrap().as_str()[1..].trim().to_string();
                Ok(Literal::Language { literal, lang })
            }

            Rule::StringLiteralNoLanguage => {
                let mut inner = pair.into_inner();
                let literal = String::from_pair(inner.next().unwrap(), ctx)?;
                Ok(Literal::Simple { literal })
            }

            Rule::IntegerLiteral => {
                unimplemented!()
            }

            Rule::DecimalLiteral => {
                unimplemented!()
            }

            Rule::FloatingPointLiteral => {
                unimplemented!()
            }

            // Rule::Literal => Self::from_pair(pair.into_inner().next().unwrap(), ctx),
            // Rule::TypedLiteral => {
            //     let mut inner = pair.into_inner();
            //     let literal = String::from_pair(inner.next().unwrap(), ctx)?;
            //     let dty = Datatype::from_pair(inner.next().unwrap(), ctx)?;
            //     Ok(Literal::Datatype {
            //         literal,
            //         datatype_iri: dty.0,
            //     })
            // }
            // Rule::StringLiteralWithLanguage => {
            //     let mut inner = pair.into_inner();
            //     let literal = String::from_pair(inner.next().unwrap(), ctx)?;
            //     let lang = inner.next().unwrap().as_str()[1..].trim().to_string();
            //     Ok(Literal::Language { literal, lang })
            // }
            // Rule::StringLiteralNoLanguage => {
            //     let mut inner = pair.into_inner();
            //     let literal = String::from_pair(inner.next().unwrap(), ctx)?;
            //     Ok(Literal::Simple { literal })
            // }
            rule => unreachable!("unexpected rule in Literal::from_pair: {:?}", rule),
        }
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for OntologyID<A> {
    const RULE: Rule = Rule::OntologyID;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let iri = Some(FromPair::<A>::from_pair(pairs.next().unwrap(), ctx)?);
        let viri = match pairs.next() {
            Some(pair) => Some(FromPair::<A>::from_pair(pair, ctx)?),
            None => None,
        };
        
        Ok(OntologyID { iri, viri })
    }
} 

impl<A: ForIRI> FromPair<A> for SetOntology<A> {
    const RULE: Rule = Rule::Ontology;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner().peekable();

        let mut ontology = SetOntology::default();
        let mut ontology_id = ontology.mut_id();

        // Parse ontology IRI and version IRI if any
        if pairs.peek().map(|p| p.as_rule() == Rule::OntologyIRI).unwrap_or(false) {
            let pair = pairs.next().unwrap();
            *ontology_id = FromPair::<A>::from_pair(pair, ctx)?;
        }

        // Process imports
        while pairs.peek().map(|p| p.as_rule() == Rule::Import).unwrap_or(false) {
            let pair = pairs.next().unwrap();
            ontology.insert(Import::from_pair(pair, ctx)?);
        }

        // Process ontology annotations
        while pairs.peek().map(|p| p.as_rule() == Rule::Annotations).unwrap_or(false) {
            let pair = pairs.next().unwrap();
            // ontology.insert(OntologyAnnotation::from_pair(pair, ctx)?);
            unimplemented!()
        }
        
        // Process frames
        for pair in pairs {
            unimplemented!()
        }

        Ok(ontology)
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for ClassFrame<A> {
    const RULE: Rule = Rule::ClassFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();
        
        let class = Class::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = ClassFrame::new(class);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::ClassClause);

            let mut inner = pair.into_inner();
            let tag = inner.next().unwrap();

            match tag.as_rule() {

                Rule::LIT_ANNOTATIONS => {
                    let mut value = inner.next().unwrap().into_inner().peekable();
                    while value.peek().is_some() {
                        let mut pair = value.next().unwrap();
                        let mut annotations = BTreeSet::new();
                        
                        if pair.as_rule() == Rule::Annotations {
                            annotations = FromPair::from_pair(pair, ctx)?;
                            pair = value.next().unwrap();
                        } 

                        let ann = FromPair::from_pair(pair, ctx)?;
                        let subject = AnnotationSubject::IRI(frame.class.0.clone());

                        let assertion = AnnotationAssertion { subject, ann };
                        frame.axioms.push(
                            AnnotatedAxiom { 
                                axiom: Axiom::AnnotationAssertion(assertion), 
                                ann: annotations 
                            }
                        );
                    }

                }
                Rule::LIT_SUB_CLASS_OF => {
                    let mut value = inner.next().unwrap().into_inner().peekable();
                    while value.peek().is_some() {
                        let mut pair = value.next().unwrap();
                        let mut annotations = BTreeSet::new();

                        if pair.as_rule() == Rule::Annotations {
                            annotations = FromPair::from_pair(pair, ctx)?;
                            pair = value.next().unwrap();
                        }

                        let sub_class_of = SubClassOf {
                            sup: ClassExpression::Class(frame.class.clone()),
                            sub: ClassExpression::from_pair(pair, ctx)?,
                        };
                        frame.axioms.push(
                            AnnotatedAxiom {
                                axiom: Axiom::SubClassOf(sub_class_of),
                                ann: annotations,
                            }
                        );
                    }
                }
                Rule::LIT_EQUIVALENT_TO => {
                    panic!("{:?}", tag);
                }
                Rule::LIT_DISJOINT_WITH => {
                    panic!("{:?}", tag);
                }
                Rule::LIT_DISJOINT_UNION_OF => {
                    panic!("{:?}", tag);
                }
                Rule::LIT_HAS_KEY => {
                    panic!("{:?}", tag);
                }

                rule => unreachable!("unexpected rule in ClassFrame::from_pair: {:?}", rule),
            }
        }

        Ok(frame)
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for IRI<A> {
    const RULE: Rule = Rule::IRI;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::SimpleIRI => {
                let local = inner.into_inner().next().unwrap();
                let iri = format!(":{}", local.as_str());
                Ok(ctx.iri(iri))
            }
            Rule::AbbreviatedIRI => {
                let mut pname = inner.into_inner().next().unwrap().into_inner();
                let prefix = pname.next().unwrap().into_inner().next();
                let local = pname.next().unwrap();
                let curie = Curie::new(prefix.map(|p| p.as_str()), local.as_str());
                if let Some(prefixes) = ctx.prefixes {
                    prefixes
                        .expand_curie(&curie)
                        .map_err(Error::from)
                        .map(|s| ctx.iri(s))
                } else {
                    Err(Error::from(curie::ExpansionError::Invalid))
                }
            }
            Rule::FullIRI => {
                let iri = inner.into_inner().next().unwrap();
                Ok(ctx.iri(iri.as_str()))
            }
            rule => unreachable!("unexpected rule in IRI::from_pair: {:?}", rule),
        }
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for String {
    const RULE: Rule = Rule::QuotedString;
    fn from_pair_unchecked(pair: Pair<Rule>, _ctx: &Context<'_, A>) -> Result<Self> {
        let l = pair.as_str().len();
        let s = &pair.as_str()[1..l - 1];
        Ok(s.replace(r"\\", r"\").replace(r#"\""#, r#"""#))
    }
}


// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use super::*;
    use crate::parser::OwlManchesterParser;

    macro_rules! assert_parse_into {
        ($ty:ty, $rule:path, $build:ident, $prefixes:ident, $doc:expr, $expected:expr) => {
            let doc = $doc.trim();
            let ctx = Context::<'_, String>::new(&$build, &$prefixes);
            match OwlManchesterParser::parse($rule, doc) {
                Ok(mut pairs) => {
                    let res = <$ty as FromPair<String>>::from_pair(pairs.next().unwrap(), &ctx);
                    assert_eq!(res.unwrap(), $expected);
                }
                Err(e) => panic!(
                    "parsing using {:?}:\n{}\nfailed with: {}",
                    $rule,
                    doc.trim(),
                    e
                ),
            }
        };
    }
    
    #[test]
    fn class_frame() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#").unwrap();

        assert_parse_into!(
            ClassFrame<String>,
            Rule::ClassFrame,
            build,
            prefixes,
            r#"
            Class: <http://purl.obolibrary.org/obo/APO_0000098>
            
                Annotations: 
                    rdfs:label "utilization of carbon source"
                
                SubClassOf: 
                    <http://purl.obolibrary.org/obo/APO_0000096>
            "#,
            ClassFrame::with_axioms(
                build.class("http://purl.obolibrary.org/obo/APO_0000098"),
                vec![
                    AnnotatedAxiom {
                        ann: BTreeSet::new(),
                        axiom: Axiom::AnnotationAssertion(
                            AnnotationAssertion {
                                subject: AnnotationSubject::IRI(build.iri("http://purl.obolibrary.org/obo/APO_0000098")),
                                ann: Annotation {
                                    ap: build.annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                                    av: AnnotationValue::Literal(Literal::Simple {
                                        literal: String::from("utilization of carbon source")
                                    })
                                }
                            }
                        )
                    },
                    AnnotatedAxiom {
                        ann: BTreeSet::new(),
                        axiom: Axiom::SubClassOf(SubClassOf {
                            sup: ClassExpression::Class(
                                build.class("http://purl.obolibrary.org/obo/APO_0000098")
                            ),
                            sub: ClassExpression::Class(
                                build.class("http://purl.obolibrary.org/obo/APO_0000096"),
                            )
                        })
                    }
                ]
            )
        );
    }

    #[test]
    fn iri() {
        let build = Build::new();
        let prefixes = PrefixMapping::default();

        assert_parse_into!(
            IRI<String>,
            Rule::IRI,
            build,
            prefixes,
            r#"<http://example.com/owl/families>"#,
            build.iri("http://example.com/owl/families")
        );
        assert_parse_into!(
            IRI<String>,
            Rule::IRI,
            build,
            prefixes,
            r#"John"#,
            build.iri(":John")
        );
    }

    #[test]
    fn quoted_string() {
        let build = Build::new();
        let prefixes = PrefixMapping::default();

        assert_parse_into!(
            String,
            Rule::QuotedString,
            build,
            prefixes,
            r#""\"Hello, there\", he said""#,
            String::from(r#""Hello, there", he said"#)
        );
    }

}
