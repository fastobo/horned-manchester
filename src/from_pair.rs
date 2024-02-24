use std::collections::BTreeSet;

use curie::Curie;
use curie::PrefixMapping;
use horned_owl::model::*;
use horned_owl::ontology::iri_mapped::IRIMappedOntology;
use horned_owl::ontology::axiom_mapped::AxiomMappedOntology;
use horned_owl::io::rdf::reader::RDFOntology;
use horned_owl::ontology::set::SetOntology;
use horned_owl::ontology::indexed::OneIndexedOntology;
use horned_owl::ontology::indexed::TwoIndexedOntology;
use horned_owl::ontology::indexed::ThreeIndexedOntology;
use horned_owl::ontology::indexed::FourIndexedOntology;
use horned_owl::ontology::indexed::OntologyIndex;
use horned_owl::ontology::indexed::ForIndex;
use pest::iterators::Pair;
use pest::iterators::Pairs;

use crate::error::Error;
use crate::error::Result;
use crate::parser::Rule;
use crate::frames::Frame;
use crate::frames::ClassFrame;
use crate::frames::DatatypeFrame;
use crate::frames::DataPropertyFrame;
use crate::frames::ObjectPropertyFrame;
use crate::frames::AnnotationPropertyFrame;
use crate::frames::IndividualFrame;
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

/// Parse optional `Annotations` into a `BTreeSet` to use with `AnnotatedAxioms`.
fn axiom_annotations<'a, A: ForIRI>(pair: &mut Pair<'a, Rule>, pairs: &mut Pairs<'a, Rule>, ctx: &Context<'_, A>) -> Result<BTreeSet<Annotation<A>>> {
    if pair.as_rule() == Rule::Annotations {
        let p = std::mem::replace(pair, pairs.next().unwrap());
        let anns = BTreeSet::from_pair(p.into_inner().next().unwrap(), ctx)?;
        Ok(anns)
    } else {
        Ok(BTreeSet::new())
    }
}

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

    if pair.as_rule() == Rule::KEYWORD_NOT {
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
                let cexp = if pair.as_rule() == Rule::KEYWORD_NOT {
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

        let mut ontology = SetOntology::new();
        let mut ontology_id = ontology.mut_id();

        // Parse ontology IRI and version IRI if any
        if pairs.peek().map(|p| p.as_rule() == Rule::OntologyID).unwrap_or(false) {
            let pair = pairs.next().unwrap();
            *ontology_id = FromPair::<A>::from_pair(pair, ctx)?;
        }

        // Process imports
        while pairs.peek().map(|p| p.as_rule() == Rule::Import).unwrap_or(false) {
            let pair = pairs.next().unwrap();
            ontology.insert(Import::from_pair(pair.into_inner().next().unwrap(), ctx)?);
        }

        // Process ontology annotations
        while pairs.peek().map(|p| p.as_rule() == Rule::Annotations).unwrap_or(false) {
            let mut annotations = pairs.next().unwrap().into_inner();
            let mut annotated_list = annotations.next().unwrap().into_inner();
            while let Some(mut pair) = annotated_list.next() {
                let anns = axiom_annotations(&mut pair, &mut annotated_list, ctx)?;
                let annotation = Annotation::from_pair(pair, ctx)?;
                ontology.insert(
                    AnnotatedAxiom {
                        axiom: Axiom::OntologyAnnotation(OntologyAnnotation(annotation)),
                        ann: anns,
                    }
                );
            }
        }

        // Process frames
        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::Frame);
            let inner = pair.into_inner().next().unwrap();
            let axioms = match inner.as_rule() {
                Rule::DatatypeFrame => DatatypeFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::ClassFrame => ClassFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::ObjectPropertyFrame => ObjectPropertyFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::DataPropertyFrame => DataPropertyFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::AnnotationPropertyFrame => AnnotationPropertyFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::IndividualFrame => IndividualFrame::from_pair(inner, ctx)?.into_axioms(),
                rule => unreachable!("unexpected rule in ClassFrame::from_pair: {:?}", rule),
            };
            for axiom in axioms {
                ontology.insert(axiom);
            }
        }

        Ok(ontology)
    }
}

impl<A, O> FromPair<A> for (O, PrefixMapping)
where
    A: ForIRI, 
    O: Ontology<A> + MutableOntology<A> + FromPair<A>
{
    const RULE: Rule = Rule::OntologyDocument;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        // Build the prefix mapping and use it to build the ontology
        let mut prefixes = PrefixMapping::default();
        let mut inner = pairs.next().unwrap();
        while inner.as_rule() == Rule::PrefixDeclaration {
            let mut decl = inner.into_inner();
            let mut pname = decl.next().unwrap().into_inner();
            let iri = decl.next().unwrap().into_inner().next().unwrap();

            if let Some(prefix) = pname.next().unwrap().into_inner().next() {
                prefixes
                    .add_prefix(prefix.as_str(), iri.as_str())
                    .expect("grammar does not allow invalid prefixes");
            } else {
                prefixes.set_default(iri.as_str());
            }

            inner = pairs.next().unwrap();
        }

        let context = Context::new(ctx.build, &prefixes);
        O::from_pair(inner, &context).map(|ont| (ont, prefixes))
    }
}

// ---------------------------------------------------------------------------

// impl<A: ForIRI> FromPair<A> for Frame<A> {
//     const RULE: Rule = Rule::Frame;
//     fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
//         let inner = pair.into_inner().next().unwrap();
//         match inner.as_rule() {
//             Rule::DatatypeFrame => FromPair::from_pair(inner, ctx).map(Frame::Datatype),
//             Rule::ClassFrame => FromPair::from_pair(inner, ctx).map(Frame::Class),
//             Rule::ObjectPropertyFrame => FromPair::from_pair(inner, ctx).map(Frame::ObjectProperty),
//             Rule::DataPropertyFrame => FromPair::from_pair(inner, ctx).map(Frame::DataProperty),
//             Rule::AnnotationPropertyFrame => FromPair::from_pair(inner, ctx).map(Frame::AnnotationProperty),
//             Rule::IndividualFrame => FromPair::from_pair(inner, ctx).map(Frame::Individual),
//             Rule::Misc => unimplemented!(),
//             rule => unreachable!("unexpected rule in Frame::from_pair: {:?}", rule),
//         }
//     }
// }

impl<A: ForIRI> FromPair<A> for DatatypeFrame<A> {
    const RULE: Rule = Rule::DatatypeFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        unimplemented!()
    }
}

impl<A: ForIRI> FromPair<A> for ClassFrame<A> {
    const RULE: Rule = Rule::ClassFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let class = Class::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = ClassFrame::from(class);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::ClassClause);
            let mut inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::ClassAnnotationsClause => {
                    let mut annotated_list = inner.into_inner().next().unwrap().into_inner();
                    while let Some(mut pair) = annotated_list.next() {
                        let annotations = axiom_annotations(&mut pair, &mut annotated_list, ctx)?;
                        let ann = FromPair::from_pair(pair, ctx)?;
                        let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                        let assertion = AnnotationAssertion { subject, ann };
                        frame.axioms.push(
                            AnnotatedAxiom {
                                axiom: Axiom::AnnotationAssertion(assertion),
                                ann: annotations
                            }
                        );
                    }
                }
                Rule::ClassSubClassOfClause => {
                    let mut value = inner.into_inner().next().unwrap().into_inner();
                    while let Some(mut pair) = value.next() {
                        let annotations = axiom_annotations(&mut pair, &mut value, ctx)?;
                        let sub_class_of = SubClassOf {
                            sup: ClassExpression::Class(frame.entity.clone()),
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
                Rule::ClassEquivalentToClause => {
                    let mut value = inner.into_inner().next().unwrap().into_inner();
                    while let Some(mut pair) = value.next() {
                        let ann = axiom_annotations(&mut pair, &mut value, ctx)?;
                        let axiom = EquivalentClasses(vec![
                            ClassExpression::Class(frame.entity.clone()),
                            ClassExpression::from_pair(pair, ctx)?,
                        ]).into();
                        frame.axioms.push(AnnotatedAxiom { axiom, ann });
                    }
                }
                Rule::ClassDisjointWithClause => {
                    let mut value = inner.into_inner().next().unwrap().into_inner();
                    while let Some(mut pair) = value.next() {
                        let ann = axiom_annotations(&mut pair, &mut value, ctx)?;
                        let axiom = DisjointClasses(vec![
                            ClassExpression::Class(frame.entity.clone()),
                            ClassExpression::from_pair(pair, ctx)?,
                        ]).into();
                        frame.axioms.push(AnnotatedAxiom { axiom, ann });
                    }
                }
                Rule::ClassDisjointUnionOfClause => {
                    let mut value = inner.into_inner();
                    let mut pair = value.next().unwrap();
                    let ann = axiom_annotations(&mut pair, &mut value, ctx)?;
                    let descriptions = pair.into_inner()
                        .map(|pair| ClassExpression::from_pair(pair, ctx))
                        .collect::<Result<Vec<_>>>()?;
                    let axiom = DisjointUnion(frame.entity.clone(), descriptions).into();
                    frame.axioms.push(AnnotatedAxiom { axiom, ann })
                }
                Rule::ClassHasKeyClause => {
                    // let mut value = inner.next().unwrap().into_inner();
                    // let mut pair = value.next().unwrap();

                    // let annotations;
                    // if pair.as_rule() == Rule::Annotations {
                    //     annotations = FromPair::from_pair(pair, ctx)?;
                    //     pair = value.next().unwrap();
                    // } else {
                    //     annotations = BTreeSet::new();
                    // }
                        // let has_key = HasKey {
                        //     ce: ClassExpression::Class(frame.class.clone()),
                        //     vpe: ClassExpression::from_pair(pair, ctx)?,
                        // ]);
                        // frame.axioms.push(
                        //     AnnotatedAxiom {
                        //         axiom: Axiom::DisjointClasses(disjoint_classes),
                        //         ann: annotations,
                        //     }
                        // );
                    unimplemented!()
                }
                rule => unreachable!("unexpected rule in ClassFrame::from_pair: {:?}", rule),
            }
        }

        Ok(frame)
    }
}

impl<A: ForIRI> FromPair<A> for ObjectPropertyFrame<A> {
    const RULE: Rule = Rule::ObjectPropertyFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let op = ObjectProperty::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = ObjectPropertyFrame::from(op);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::ObjectPropertyClause);
            let mut inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::ObjectPropertyAnnotationsClause => {
                    let mut annotated_list = inner.into_inner().next().unwrap().into_inner();
                    while let Some(mut pair) = annotated_list.next() {
                        let annotations = axiom_annotations(&mut pair, &mut annotated_list, ctx)?;
                        let ann = FromPair::from_pair(pair, ctx)?;
                        let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                        let assertion = AnnotationAssertion { subject, ann };
                        frame.axioms.push(
                            AnnotatedAxiom {
                                axiom: Axiom::AnnotationAssertion(assertion),
                                ann: annotations
                            }
                        );
                    }
                }

                rule => unreachable!("unexpected rule in ClassFrame::from_pair: {:?}", rule),
            }
        }

        Ok(frame)
    }
}

impl<A: ForIRI> FromPair<A> for DataPropertyFrame<A> {
    const RULE: Rule = Rule::DataPropertyFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        unimplemented!()
    }
}

impl<A: ForIRI> FromPair<A> for AnnotationPropertyFrame<A> {
    const RULE: Rule = Rule::AnnotationPropertyFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let ap = AnnotationProperty::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = AnnotationPropertyFrame::from(ap);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::AnnotationPropertyClause);
            let mut inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::AnnotationPropertyAnnotationsClause => {
                    let mut annotated_list = inner.into_inner().next().unwrap().into_inner();
                    while let Some(mut pair) = annotated_list.next() {
                        let mut annotations = BTreeSet::new();
                        if pair.as_rule() == Rule::Annotations {
                            annotations = FromPair::from_pair(pair, ctx)?;
                            pair = annotated_list.next().unwrap();
                        } else {
                            annotations = BTreeSet::new();
                        }

                        let ann = FromPair::from_pair(pair, ctx)?;
                        let subject = AnnotationSubject::IRI(frame.entity.0.clone());

                        let assertion = AnnotationAssertion { subject, ann };
                        frame.axioms.push(
                            AnnotatedAxiom {
                                axiom: Axiom::AnnotationAssertion(assertion),
                                ann: annotations
                            }
                        );
                    }
                }
                Rule::AnnotationPropertyDomainClause => {
                    // let mut value = inner.next().unwrap().into_inner().peekable();
                    // while value.peek().is_some() {
                    //     let mut pair = value.next().unwrap();
                    //     let mut annotations = BTreeSet::new();

                    //     if pair.as_rule() == Rule::Annotations {
                    //         annotations = FromPair::from_pair(pair, ctx)?;
                    //         pair = value.next().unwrap();
                    //     }

                    //     let ap = frame.ap.clone();
                    //     let iri = FromPair::from_pair(pair, ctx)?;

                    //     let apd = AnnotationPropertyDomain { ap, iri };
                    //     frame.axioms.push(
                    //         AnnotatedAxiom {
                    //             axiom: Axiom::AnnotationPropertyDomain(apd),
                    //             ann: annotations
                    //         }
                    //     );
                    // }
                    unimplemented!()
                }
                Rule::AnnotationPropertyRangeClause => {
                    // let mut value = inner.next().unwrap().into_inner().peekable();
                    // while value.peek().is_some() {
                    //     let mut pair = value.next().unwrap();
                    //     let mut annotations = BTreeSet::new();

                    //     if pair.as_rule() == Rule::Annotations {
                    //         annotations = FromPair::from_pair(pair, ctx)?;
                    //         pair = value.next().unwrap();
                    //     }

                    //     let ap = frame.ap.clone();
                    //     let iri = FromPair::from_pair(pair, ctx)?;

                    //     let apr = AnnotationPropertyRange { ap, iri };
                    //     frame.axioms.push(
                    //         AnnotatedAxiom {
                    //             axiom: Axiom::AnnotationPropertyRange(apr),
                    //             ann: annotations
                    //         }
                    //     );
                    // }
                    unimplemented!()
                }
                Rule::AnnotationPropertySubPropertyOfClause => {
                    unimplemented!();
                }
                rule => unreachable!("unexpected rule in ClassFrame::from_pair: {:?}", rule),
            }
        }

        Ok(frame)
    }
}

impl<A: ForIRI> FromPair<A> for IndividualFrame<A> {
    const RULE: Rule = Rule::IndividualFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for PropertyExpression<A> {
    const RULE: Rule = Rule::PropertyExpression;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::ObjectPropertyExpression => {
                FromPair::from_pair(inner, ctx).map(PropertyExpression::ObjectPropertyExpression)
            }
            Rule::DataPropertyExpression => {
                let pair = inner.into_inner().next().unwrap();
                FromPair::from_pair(pair, ctx).map(PropertyExpression::DataProperty)
            }
            rule => unreachable!("unexpected rule in PropertyExpression::from_pair: {:?}", rule),
        }
    }
}

impl<A: ForIRI> FromPair<A> for ObjectPropertyExpression<A> {
    const RULE: Rule = Rule::ObjectPropertyExpression;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::ObjectPropertyIRI => {
                FromPair::from_pair(inner, ctx)
                    .map(ObjectPropertyExpression::ObjectProperty)
            }
            Rule::InverseObjectProperty => {
                let pair = inner.into_inner().last().unwrap();
                FromPair::from_pair(pair, ctx)
                    .map(ObjectPropertyExpression::InverseObjectProperty)
            }
            rule => unreachable!("unexpected rule in ObjectPropertyExpression::from_pair: {:?}", rule),
        }
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
                let curie = Curie::new(None, local.as_str());
                let iri = format!("{}", local.as_str());
                if let Some(prefixes) = ctx.prefixes {
                    prefixes
                        .expand_curie(&curie)
                        .map_err(Error::from)
                        .map(|s| ctx.iri(s))
                } else {
                    Err(Error::from(curie::ExpansionError::Invalid))
                }
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
                    match res {
                        Err(e) => panic!("parsing failed:\n{}", e),
                        Ok(x) => assert_eq!(x, $expected),
                    }
                }
                Err(e) => panic!(
                    "lexing using {:?}:\n{}\nfailed with: {}",
                    $rule,
                    doc.trim(),
                    e
                ),
            }
        };
    }

    #[test]
    fn annotation_property_frame() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");
        prefixes.add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#").unwrap();

        assert_parse_into!(
            AnnotationPropertyFrame<String>,
            Rule::AnnotationPropertyFrame,
            build,
            prefixes,
            r#"
            AnnotationProperty: <http://purl.obolibrary.org/obo/IAO_0000115>
            "#,
            AnnotationPropertyFrame::with_axioms(
                build.annotation_property("http://purl.obolibrary.org/obo/IAO_0000115"),
                vec![
                    DeclareAnnotationProperty(
                        build.annotation_property("http://purl.obolibrary.org/obo/IAO_0000115")
                    ).into()
                ]
            )
        );

        assert_parse_into!(
            AnnotationPropertyFrame<String>,
            Rule::AnnotationPropertyFrame,
            build,
            prefixes,
            r#"
            AnnotationProperty: <http://purl.obolibrary.org/obo/IAO_0000115>

                Annotations:
                    rdfs:label "definition"
            "#,
            AnnotationPropertyFrame::with_axioms(
                build.annotation_property("http://purl.obolibrary.org/obo/IAO_0000115"),
                vec![
                    DeclareAnnotationProperty(
                        build.annotation_property("http://purl.obolibrary.org/obo/IAO_0000115")
                    ).into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(build.iri("http://purl.obolibrary.org/obo/IAO_0000115")),
                        ann: Annotation {
                            ap: build.annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("definition")
                            })
                        }
                    }.into()
                ]
            )
        );
    }

    #[test]
    fn class_frame() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");
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
                    DeclareClass(
                        build.class("http://purl.obolibrary.org/obo/APO_0000098"),
                    ).into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(build.iri("http://purl.obolibrary.org/obo/APO_0000098")),
                        ann: Annotation {
                            ap: build.annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("utilization of carbon source")
                            })
                        }
                    }.into(),
                    SubClassOf {
                        sup: ClassExpression::Class(
                            build.class("http://purl.obolibrary.org/obo/APO_0000098")
                        ),
                        sub: ClassExpression::Class(
                            build.class("http://purl.obolibrary.org/obo/APO_0000096"),
                        )
                    }.into(),
                ]
            )
        );

        assert_parse_into!(
            ClassFrame<String>,
            Rule::ClassFrame,
            build,
            prefixes,
            r#"
            Class: <http://purl.obolibrary.org/obo/BFO_0000002>

            DisjointWith:
                <http://purl.obolibrary.org/obo/BFO_0000003>
            "#,
            ClassFrame::with_axioms(
                build.class("http://purl.obolibrary.org/obo/BFO_0000002"),
                vec![
                    DeclareClass(
                        build.class("http://purl.obolibrary.org/obo/BFO_0000002"),
                    ).into(),
                    DisjointClasses(
                        vec![
                            ClassExpression::Class(build.class("http://purl.obolibrary.org/obo/BFO_0000002")),
                            ClassExpression::Class(build.class("http://purl.obolibrary.org/obo/BFO_0000003")),
                        ]
                    ).into(),
                ]
            )
        );
    }

    #[test]
    fn iri() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");

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
            build.iri("http://example.com/owl/families#John")
        );
        assert_parse_into!(
            IRI<String>,
            Rule::IRI,
            build,
            prefixes,
            r#"<http://purl.obolibrary.org/obo/ms.owl>"#,
            build.iri("http://purl.obolibrary.org/obo/ms.owl")
        );
    }

    #[test]
    fn object_property_expression() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");
        prefixes.add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#").unwrap();

        assert_parse_into!(
            ObjectPropertyExpression<String>,
            Rule::ObjectPropertyExpression,
            build,
            prefixes,
            r#"inverse hasSpouse"#,
            ObjectPropertyExpression::InverseObjectProperty(
                build.object_property("http://example.com/owl/families#hasSpouse")
            )
        );
    }

    #[test]
    fn object_property_frame() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#").unwrap();

        assert_parse_into!(
            ObjectPropertyFrame<String>,
            Rule::ObjectPropertyFrame,
            build,
            prefixes,
            r#"
            ObjectProperty: <http://purl.obolibrary.org/obo/RO_0000052>

            Annotations:
                <http://www.geneontology.org/formats/oboInOwl#hasDbXref> "RO:0000052",
                rdfs:label "inheres in"

            "#,
            ObjectPropertyFrame::with_axioms(
                build.object_property("http://purl.obolibrary.org/obo/RO_0000052"),
                vec![
                    DeclareObjectProperty(
                        build.object_property("http://purl.obolibrary.org/obo/RO_0000052")
                    ).into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(build.iri("http://purl.obolibrary.org/obo/RO_0000052")),
                        ann: Annotation {
                            ap: build.annotation_property("http://www.geneontology.org/formats/oboInOwl#hasDbXref"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("RO:0000052")
                            })
                        }
                    }.into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(build.iri("http://purl.obolibrary.org/obo/RO_0000052")),
                        ann: Annotation {
                            ap: build.annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("inheres in")
                            })
                        }
                    }.into(),
                ]
            )
        );
    }

    #[test]
    fn ontology() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://www.example.com/owl/families#");
        prefixes.add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#").unwrap();

        assert_parse_into!(
            SetOntology<String>,
            Rule::Ontology,
            build,
            prefixes,
            r#"
            Ontology:
            "#,
            SetOntology::new()
        );

        let mut ont = SetOntology::new();
        ont.mut_id().iri = Some(build.iri("http://purl.obolibrary.org/obo/ms.owl"));
        ont.mut_id().viri = Some(build.iri("http://purl.obolibrary.org/obo/ms/4.1.29/ms.owl"));
        assert_parse_into!(
            SetOntology<String>,
            Rule::Ontology,
            build,
            prefixes,
            r#"Ontology: <http://purl.obolibrary.org/obo/ms.owl>
                <http://purl.obolibrary.org/obo/ms/4.1.29/ms.owl>
            "#,
            ont
        );

        let mut ont = SetOntology::new();
        ont.insert( AnnotatedAxiom {
            ann: BTreeSet::from_iter(vec![
                Annotation {
                    ap: build.annotation_property("http://www.example.com/owl/families#creator"),
                    av: AnnotationValue::IRI(build.iri("http://www.example.com/owl/families#John")),
                }
            ]),
            axiom: Axiom::OntologyAnnotation(OntologyAnnotation(Annotation {
                ap: build.annotation_property("http://www.geneontology.org/formats/oboInOwl#hasOBOFormatVersion"),
                av: AnnotationValue::Literal(Literal::Simple { literal: String::from("1.2") })
            })),
        });
        ont.insert( AnnotatedAxiom {
            ann: BTreeSet::new(),
            axiom: Axiom::OntologyAnnotation(OntologyAnnotation(Annotation {
                ap: build.annotation_property("http://www.geneontology.org/formats/oboInOwl#saved-by"),
                av: AnnotationValue::Literal(Literal::Simple { literal: String::from("cooperl") })
            })),
        });
        assert_parse_into!(
            SetOntology<String>,
            Rule::Ontology,
            build,
            prefixes,
            r#"Ontology:

            Annotations:
                Annotations:
                    creator John
                <http://www.geneontology.org/formats/oboInOwl#hasOBOFormatVersion> "1.2",
                <http://www.geneontology.org/formats/oboInOwl#saved-by> "cooperl"
            "#,
            ont
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
