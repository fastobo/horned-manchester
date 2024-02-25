use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::str::FromStr;

use curie::Curie;
use curie::PrefixMapping;
use horned_owl::model::*;
use horned_owl::ontology::set::SetOntology;
use pest::iterators::Pair;
use pest::iterators::Pairs;

use crate::error::Error;
use crate::error::Result;
use crate::frames::AnnotationPropertyFrame;
use crate::frames::ClassFrame;
use crate::frames::DataPropertyFrame;
use crate::frames::DatatypeFrame;
use crate::frames::MiscClause;

use crate::frames::IndividualFrame;
use crate::frames::ObjectPropertyFrame;
use crate::parser::Rule;
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
        if cfg!(debug_assertions) && pair.as_rule() != Self::RULE {
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

// --- Helpers ---------------------------------------------------------------

/// Mark some rules as unreachable when performing rule matching.
macro_rules! unexpected_rule {
    ($type:ident, $rule:expr) => {
        unreachable!(
            "unexpected rule in {}::from_pair: {:?}",
            stringify!($type),
            $rule
        )
    };
}

/// Descend one layer of depth into a pair which rule contains a single rule.
fn descend(pair: Pair<Rule>) -> Pair<Rule> {
    pair.into_inner().next().unwrap()
}

/// Parse optional `Annotations` into a `BTreeSet` to use with `AnnotatedAxioms`.
fn axiom_annotations<'a, A: ForIRI>(
    pair: &mut Pair<'a, Rule>,
    pairs: &mut Pairs<'a, Rule>,
    ctx: &Context<'_, A>,
) -> Result<BTreeSet<Annotation<A>>> {
    if pair.as_rule() == Rule::Annotations {
        let p = std::mem::replace(pair, pairs.next().unwrap());
        let anns = BTreeSet::from_pair(descend(p), ctx)?;
        Ok(anns)
    } else {
        Ok(BTreeSet::new())
    }
}

// --- IRI Wrappers ----------------------------------------------------------

macro_rules! impl_wrapper {
    ($ty:ident, $rule:path) => {
        impl<A: ForIRI> FromPair<A> for $ty<A> {
            const RULE: Rule = $rule;
            fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
                FromPair::<A>::from_pair(descend(pair), ctx).map($ty)
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

// --- Raw Item Lists --------------------------------------------------------

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

// --- Annotation ------------------------------------------------------------

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
        let inner = descend(pair);
        match inner.as_rule() {
            Rule::NodeID => {
                // FIXME: currently unsupported in `horned-owl`
                Err(Error::custom(
                    "anonymous annotation targets are not supported",
                    inner.as_span(),
                ))
            }
            Rule::IRI => {
                let iri = FromPair::<A>::from_pair(inner, ctx)?;
                Ok(AnnotationValue::IRI(iri))
            }
            Rule::Literal => {
                let literal = FromPair::<A>::from_pair(inner, ctx)?;
                Ok(AnnotationValue::Literal(literal))
            }
            rule => unexpected_rule!(AnnotationValue, rule),
        }
    }
}

impl<A: ForIRI> FromPair<A> for BTreeSet<Annotation<A>> {
    const RULE: Rule = Rule::AnnotationAnnotatedList;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = pair.into_inner();
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
                rule => unexpected_rule!(BTreeSet, rule),
            }
        }

        Ok(annotations)
    }
}

// --- ClassExpression -------------------------------------------------------

// Class expressions have several production rules in the Manchester syntax
// because they may be more restrictive in some cases; we parse all these
// different rules into a ClassExpression anyway, but we still need to
// support the different rules.

fn from_restriction_pair<A: ForIRI>(
    pair: Pair<Rule>,
    ctx: &Context<'_, A>,
) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Restriction);

    macro_rules! data_cardinality {
        ($inner:ident, $ctx:ident, ClassExpression:: $variant:ident) => {{
            let span = $inner.as_span();
            let mut pairs = $inner.into_inner();

            let dp = DataProperty::from_pair(descend(pairs.next().unwrap()), $ctx)?;
            let n = u32::from_pair(pairs.next().unwrap(), $ctx)?;

            let dr = if let Some(pair) = pairs.next() {
                DataRange::from_pair(pair, $ctx)?
            } else {
                // FIXME: currently unsupported in `horned-owl`
                return Err(Error::custom(
                    concat!(
                        stringify!($variant),
                        " without data range are not supported"
                    ),
                    span,
                ));
            };

            Ok(ClassExpression::$variant { n, dp, dr })
        }};
    }

    macro_rules! object_cardinality {
        ($inner:ident, $ctx:ident, ClassExpression:: $variant:ident) => {{
            let span = $inner.as_span();
            let mut pairs = $inner.into_inner();

            let ope = ObjectPropertyExpression::from_pair(pairs.next().unwrap(), $ctx)?;
            let n = u32::from_pair(pairs.next().unwrap(), $ctx)?;

            let bce = if let Some(pair) = pairs.next() {
                from_primary_pair(pair, $ctx).map(Box::new)?
            } else {
                // FIXME: currently unsupported in `horned-owl`
                return Err(Error::custom(
                    concat!(
                        stringify!($variant),
                        " without class expression are not supported"
                    ),
                    span,
                ));
            };

            Ok(ClassExpression::$variant { n, ope, bce })
        }};
    }

    let inner = descend(pair);
    match inner.as_rule() {
        Rule::DataSomeValuesFromRestriction => {
            let mut pairs = inner.into_inner();
            let dp = FromPair::from_pair(descend(pairs.next().unwrap()), ctx)?;
            let dr = FromPair::from_pair(pairs.next().unwrap(), ctx)?;
            Ok(ClassExpression::DataSomeValuesFrom { dp, dr })
        }
        Rule::DataAllValuesFromRestriction => {
            let mut pairs = inner.into_inner();
            let dp = FromPair::from_pair(pairs.next().unwrap().into_inner().next().unwrap(), ctx)?;
            let dr = FromPair::from_pair(pairs.next().unwrap(), ctx)?;
            Ok(ClassExpression::DataAllValuesFrom { dp, dr })
        }
        Rule::DataHasValueRestriction => {
            let mut pairs = inner.into_inner();
            let dp = FromPair::from_pair(descend(pairs.next().unwrap()), ctx)?;
            let l = FromPair::from_pair(pairs.next().unwrap(), ctx)?;
            Ok(ClassExpression::DataHasValue { dp, l })
        }
        Rule::DataMinCardinalityRestriction => {
            data_cardinality!(inner, ctx, ClassExpression::DataMinCardinality)
        }
        Rule::DataMaxCardinalityRestriction => {
            data_cardinality!(inner, ctx, ClassExpression::DataMaxCardinality)
        }
        Rule::DataExactCardinalityRestriction => {
            data_cardinality!(inner, ctx, ClassExpression::DataExactCardinality)
        }
        Rule::ObjectSomeValuesFromRestriction => {
            let mut pairs = inner.into_inner();
            let ope = FromPair::from_pair(pairs.next().unwrap(), ctx)?;
            let bce = from_primary_pair(pairs.next().unwrap(), ctx).map(Box::new)?;
            Ok(ClassExpression::ObjectSomeValuesFrom { ope, bce })
        }
        Rule::ObjectAllValuesFromRestriction => {
            let mut pairs = inner.into_inner();
            let ope = FromPair::from_pair(pairs.next().unwrap(), ctx)?;
            let bce = from_primary_pair(pairs.next().unwrap(), ctx).map(Box::new)?;
            Ok(ClassExpression::ObjectAllValuesFrom { ope, bce })
        }
        Rule::ObjectHasValueRestriction => {
            unimplemented!()
        }
        Rule::ObjectHasSelfRestriction => {
            let mut pairs = inner.into_inner();
            let ope = FromPair::from_pair(pairs.next().unwrap(), ctx)?;
            Ok(ClassExpression::ObjectHasSelf(ope))
        }
        Rule::ObjectMinCardinalityRestriction => {
            object_cardinality!(inner, ctx, ClassExpression::ObjectMinCardinality)
        }
        Rule::ObjectMaxCardinalityRestriction => {
            object_cardinality!(inner, ctx, ClassExpression::ObjectMaxCardinality)
        }
        Rule::ObjectExactCardinalityRestriction => {
            object_cardinality!(inner, ctx, ClassExpression::ObjectExactCardinality)
        }
        rule => unexpected_rule!(ClassExpression, rule),
    }
}

fn from_atomic_pair<A: ForIRI>(
    pair: Pair<Rule>,
    ctx: &Context<'_, A>,
) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Atomic);

    let inner = descend(pair);
    match inner.as_rule() {
        Rule::Description => FromPair::from_pair(inner, ctx),
        Rule::ClassIRI => FromPair::from_pair(inner, ctx).map(ClassExpression::Class),
        Rule::IndividualList => FromPair::from_pair(inner, ctx).map(ClassExpression::ObjectOneOf),
        rule => unexpected_rule!(ClassExpression, rule),
    }
}

fn from_primary_pair<A: ForIRI>(
    pair: Pair<Rule>,
    ctx: &Context<'_, A>,
) -> Result<ClassExpression<A>> {
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
        rule => unexpected_rule!(ClassExpression, rule),
    };

    if is_complement {
        ce.map(Box::new).map(ClassExpression::ObjectComplementOf)
    } else {
        ce
    }
}

fn from_conjuction_pair<A: ForIRI>(
    pair: Pair<Rule>,
    ctx: &Context<'_, A>,
) -> Result<ClassExpression<A>> {
    debug_assert!(pair.as_rule() == Rule::Conjuction);

    let mut inner = pair.into_inner().peekable();
    match inner.peek().unwrap().as_rule() {
        Rule::ClassIRI => {
            let class = Class::from_pair(inner.next().unwrap(), ctx)?;
            let mut intersection = vec![ClassExpression::Class(class)];
            while let Some(pair) = inner.next() {
                let cexp = if pair.as_rule() == Rule::KEYWORD_NOT {
                    ClassExpression::ObjectComplementOf(Box::new(from_restriction_pair(
                        inner.next().unwrap(),
                        ctx,
                    )?))
                } else {
                    from_restriction_pair(pair, ctx)?
                };
                intersection.push(cexp)
            }
            Ok(ClassExpression::ObjectIntersectionOf(intersection))
        }
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
        rule => unexpected_rule!(ClassExpression, rule),
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
                    .collect::<Result<_>>()?,
            ))
        }
    }
}

// --- DataRange -------------------------------------------------------------

// Similarly to class expressions, data ranges can be parsed from several
// production rules.

fn from_data_conjunction_pair<A: ForIRI>(
    pair: Pair<Rule>,
    ctx: &Context<'_, A>,
) -> Result<DataRange<A>> {
    debug_assert!(pair.as_rule() == Rule::DataConjunction);

    let mut ranges = pair
        .into_inner()
        .map(|pair| DataRange::from_pair(pair, ctx))
        .collect::<Result<Vec<_>>>()?;
    if ranges.len() == 1 {
        Ok(ranges.pop().unwrap())
    } else {
        Ok(DataRange::DataIntersectionOf(ranges))
    }
}

fn from_data_range_pair<A: ForIRI>(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<DataRange<A>> {
    debug_assert!(pair.as_rule() == Rule::DataRange);

    let mut ranges = pair
        .into_inner()
        .map(|pair| from_data_conjunction_pair(pair, ctx))
        .collect::<Result<Vec<_>>>()?;
    if ranges.len() == 1 {
        Ok(ranges.pop().unwrap())
    } else {
        Ok(DataRange::DataUnionOf(ranges))
    }
}

fn from_data_atomic_pair<A: ForIRI>(
    pair: Pair<Rule>,
    ctx: &Context<'_, A>,
) -> Result<DataRange<A>> {
    debug_assert!(pair.as_rule() == Rule::DataAtomic);

    let inner = descend(pair);
    match inner.as_rule() {
        Rule::DataRange => from_data_range_pair(inner, ctx),
        Rule::DatatypeRestriction => unimplemented!(),
        Rule::Datatype => {
            let datatype = Datatype::from_pair(inner, ctx)?;
            Ok(DataRange::Datatype(datatype))
        }
        Rule::LiteralList => {
            let literals = FromPair::from_pair(descend(inner), ctx)?;
            Ok(DataRange::DataOneOf(literals))
        }
        rule => unexpected_rule!(DataRange, rule),
    }
}

impl<A: ForIRI> FromPair<A> for DataRange<A> {
    const RULE: Rule = Rule::DataPrimary;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = descend(pair);
        match inner.as_rule() {
            Rule::DataAtomic => from_data_atomic_pair(inner, ctx),
            Rule::DataAtomicComplement => {
                let pair = descend(inner);
                from_data_atomic_pair(pair, ctx)
                    .map(Box::new)
                    .map(DataRange::DataComplementOf)
            }
            rule => unexpected_rule!(DataRange, rule),
        }
    }
}

// --- Datatype --------------------------------------------------------------

// The Manchester syntax has builtin support for the `float`, `integer`,
// `decimal` and `string` datatypes, which are translated into their `xsd`
// equivalent. The `xsd` prefix should always be available as mandated by
// the specification, so CURIE expansion should always work, but as a backend
// we can use hardcoded IRIs.
// (see https://www.w3.org/TR/owl2-manchester-syntax/#Ontologies_and_Annotations)

impl<A: ForIRI> FromPair<A> for Datatype<A> {
    const RULE: Rule = Rule::Datatype;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        macro_rules! xsd_datatype {
            ($ctx:ident, xsd: $datatype:expr) => {{
                let iri = $ctx
                    .prefixes
                    .as_ref()
                    .and_then(|prefixes| {
                        let curie = Curie::new(Some("xsd"), stringify!($datatype));
                        prefixes.expand_curie(&curie).ok().map(|x| $ctx.iri(x))
                    })
                    .unwrap_or_else(|| {
                        $ctx.iri(concat!(
                            "http://www.w3.org/2001/XMLSchema#",
                            stringify!($datatype)
                        ))
                    });
                Ok(Datatype(iri))
            }};
        }

        let inner = descend(pair);
        match inner.as_rule() {
            Rule::IntegerDatatype => xsd_datatype!(ctx, xsd:integer),
            Rule::DecimalDatatype => xsd_datatype!(ctx, xsd:decimal),
            Rule::FloatDatatype => xsd_datatype!(ctx, xsd:float),
            Rule::StringDatatype => xsd_datatype!(ctx, xsd:string),
            Rule::DatatypeIRI => FromPair::from_pair(descend(inner), ctx).map(Datatype),
            rule => unexpected_rule!(ClassFrame, rule),
        }
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for Individual<A> {
    const RULE: Rule = Rule::Individual;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = descend(pair);
        match inner.as_rule() {
            Rule::IndividualIRI => FromPair::from_pair(inner, ctx).map(Individual::Named),
            Rule::NodeID => FromPair::from_pair(inner, ctx).map(Individual::Anonymous),
            rule => unexpected_rule!(Individual, rule),
        }
    }
}

impl<A: ForIRI> FromPair<A> for AnonymousIndividual<A> {
    const RULE: Rule = Rule::NodeID;
    fn from_pair_unchecked(pair: Pair<Rule>, _ctx: &Context<'_, A>) -> Result<Self> {
        Ok(AnonymousIndividual(pair.as_str().to_string().into()))
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for Literal<A> {
    const RULE: Rule = Rule::Literal;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        macro_rules! xsd_literal {
            ($pair:ident, $ctx:ident, xsd: $datatype:expr) => {{
                let literal = $pair.as_str().to_string();
                let curie = Curie::new(Some("xsd"), stringify!($datatype));
                let datatype_iri = if let Some(prefixes) = $ctx.prefixes {
                    prefixes
                        .expand_curie(&curie)
                        .map_err(Error::from)
                        .map(|s| $ctx.iri(s))?
                } else {
                    return Err(Error::from(curie::ExpansionError::Invalid));
                };
                Ok(Literal::Datatype {
                    literal,
                    datatype_iri,
                })
            }};
        }

        let pair = descend(pair);
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
            Rule::IntegerLiteral => xsd_literal!(pair, ctx, xsd:integer),
            Rule::DecimalLiteral => xsd_literal!(pair, ctx, xsd:decimal),
            Rule::FloatingPointLiteral => xsd_literal!(pair, ctx, xsd:float),
            Rule::BooleanLiteral => xsd_literal!(pair, ctx, xsd:boolean),
            rule => unexpected_rule!(Literal, rule),
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
        let ontology_id = ontology.mut_id();

        // Parse ontology IRI and version IRI if any
        if pairs
            .peek()
            .map(|p| p.as_rule() == Rule::OntologyID)
            .unwrap_or(false)
        {
            let pair = pairs.next().unwrap();
            *ontology_id = FromPair::<A>::from_pair(pair, ctx)?;
        }

        // Process imports
        while pairs
            .peek()
            .map(|p| p.as_rule() == Rule::Import)
            .unwrap_or(false)
        {
            let pair = pairs.next().unwrap();
            ontology.insert(Import::from_pair(descend(pair), ctx)?);
        }

        // Process ontology annotations
        while pairs
            .peek()
            .map(|p| p.as_rule() == Rule::Annotations)
            .unwrap_or(false)
        {
            let mut annotations = pairs.next().unwrap().into_inner();
            let mut annotated_list = annotations.next().unwrap().into_inner();
            while let Some(mut pair) = annotated_list.next() {
                let anns = axiom_annotations(&mut pair, &mut annotated_list, ctx)?;
                let annotation = Annotation::from_pair(pair, ctx)?;
                ontology.insert(AnnotatedAxiom {
                    axiom: Axiom::OntologyAnnotation(OntologyAnnotation(annotation)),
                    ann: anns,
                });
            }
        }

        // Process frames
        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::Frame);
            let inner = descend(pair);
            let axioms = match inner.as_rule() {
                Rule::DatatypeFrame => DatatypeFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::ClassFrame => ClassFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::ObjectPropertyFrame => {
                    ObjectPropertyFrame::from_pair(inner, ctx)?.into_axioms()
                }
                Rule::DataPropertyFrame => DataPropertyFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::AnnotationPropertyFrame => {
                    AnnotationPropertyFrame::from_pair(inner, ctx)?.into_axioms()
                }
                Rule::IndividualFrame => IndividualFrame::from_pair(inner, ctx)?.into_axioms(),
                Rule::MiscClause => {
                    let clause = MiscClause::from_pair(inner, ctx)?;
                    vec![clause.into()]
                }
                rule => unexpected_rule!(Frame, rule),
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
    O: Ontology<A> + MutableOntology<A> + FromPair<A>,
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
            let iri = descend(decl.next().unwrap());

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

macro_rules! annotated_axiom {
    ($pair:ident, $inner:ident, $ctx:ident, $frame:ident, axiom = $axiom:expr) => {{
        let mut annotated_list = descend($inner).into_inner();
        while let Some(mut $pair) = annotated_list.next() {
            let ann = axiom_annotations(&mut $pair, &mut annotated_list, $ctx)?;
            let axiom = $axiom;
            $frame.axioms.push(AnnotatedAxiom { axiom, ann });
        }
    }};
}

impl<A: ForIRI> FromPair<A> for DatatypeFrame<A> {
    const RULE: Rule = Rule::DatatypeFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let datatype = Datatype::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = DatatypeFrame::from(datatype);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::DatatypeClause);
            let inner = descend(pair);
            match inner.as_rule() {
                Rule::DatatypeAnnotationsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ann = FromPair::from_pair(pair, ctx)?;
                            let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                            AnnotationAssertion { subject, ann }.into()
                        }
                    )
                }
                Rule::DatatypeEquivalentToClause => {
                    let mut pairs = inner.into_inner();
                    let mut pair = pairs.next().unwrap();
                    let ann = axiom_annotations(&mut pair, &mut pairs, ctx)?;

                    let range = from_data_range_pair(pair, ctx)?;
                    let kind = frame.entity.clone();

                    let axiom = DatatypeDefinition { kind, range }.into();
                    frame.axioms.push(AnnotatedAxiom { ann, axiom });
                }
                rule => unexpected_rule!(ClassFrame, rule),
            }
        }

        Ok(frame)
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
            let inner = descend(pair);
            match inner.as_rule() {
                Rule::ClassAnnotationsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ann = FromPair::from_pair(pair, ctx)?;
                            let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                            AnnotationAssertion { subject, ann }.into()
                        }
                    )
                }
                Rule::ClassSubClassOfClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            SubClassOf {
                                sup: ClassExpression::from_pair(pair, ctx)?,
                                sub: ClassExpression::Class(frame.entity.clone()),
                            }
                            .into()
                        }
                    )
                }
                Rule::ClassEquivalentToClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            EquivalentClasses(vec![
                                ClassExpression::Class(frame.entity.clone()),
                                ClassExpression::from_pair(pair, ctx)?,
                            ])
                            .into()
                        }
                    )
                }
                Rule::ClassDisjointWithClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            DisjointClasses(vec![
                                ClassExpression::Class(frame.entity.clone()),
                                ClassExpression::from_pair(pair, ctx)?,
                            ])
                            .into()
                        }
                    )
                }
                Rule::ClassDisjointUnionOfClause => {
                    let mut value = inner.into_inner();
                    let mut pair = value.next().unwrap();
                    let ann = axiom_annotations(&mut pair, &mut value, ctx)?;
                    let descriptions = pair
                        .into_inner()
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
                rule => unexpected_rule!(ClassFrame, rule),
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
            let inner = descend(pair);
            match inner.as_rule() {
                Rule::ObjectPropertyAnnotationsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ann = FromPair::from_pair(pair, ctx)?;
                            let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                            AnnotationAssertion { subject, ann }.into()
                        }
                    )
                }
                Rule::ObjectPropertyDomainClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ce = FromPair::from_pair(pair, ctx)?;
                            let ope = frame.entity.clone().into();
                            ObjectPropertyDomain { ope, ce }.into()
                        }
                    )
                }
                Rule::ObjectPropertyRangeClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ce = FromPair::from_pair(pair, ctx)?;
                            let ope = frame.entity.clone().into();
                            ObjectPropertyRange { ope, ce }.into()
                        }
                    )
                }
                Rule::ObjectPropertyCharacteristicsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let op = ObjectPropertyExpression::ObjectProperty(frame.entity.clone());
                            match descend(pair).as_rule() {
                                Rule::FunctionalCharacteristic => {
                                    FunctionalObjectProperty(op).into()
                                }
                                Rule::InverseFunctionalCharacteristic => {
                                    InverseFunctionalObjectProperty(op).into()
                                }
                                Rule::ReflexiveCharacteristic => ReflexiveObjectProperty(op).into(),
                                Rule::IrreflexiveCharacteristic => {
                                    IrreflexiveObjectProperty(op).into()
                                }
                                Rule::SymmetricCharacteristic => SymmetricObjectProperty(op).into(),
                                Rule::AsymmetricCharacteristic => {
                                    AsymmetricObjectProperty(op).into()
                                }
                                Rule::TransitiveCharacteristic => {
                                    TransitiveObjectProperty(op).into()
                                }
                                rule => unexpected_rule!(ObjectPropertyFrame, rule),
                            }
                        }
                    )
                }
                Rule::ObjectPropertySubPropertyOfClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            SubObjectPropertyOf {
                                sup: ObjectPropertyExpression::from_pair(pair, ctx)?,
                                sub: SubObjectPropertyExpression::ObjectPropertyExpression(
                                    frame.entity.clone().into(),
                                ),
                            }
                            .into()
                        }
                    )
                }
                Rule::ObjectPropertyEquivalentToClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            EquivalentObjectProperties(vec![
                                ObjectPropertyExpression::ObjectProperty(frame.entity.clone()),
                                ObjectPropertyExpression::from_pair(pair, ctx)?,
                            ])
                            .into()
                        }
                    )
                }
                Rule::ObjectPropertyDisjointWithClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            DisjointObjectProperties(vec![
                                ObjectPropertyExpression::ObjectProperty(frame.entity.clone()),
                                ObjectPropertyExpression::from_pair(pair, ctx)?,
                            ])
                            .into()
                        }
                    )
                }
                Rule::ObjectPropertyInverseOfClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let pair = descend(pair);
                            let op = match pair.as_rule() {
                                Rule::ObjectPropertyIRI => FromPair::from_pair(pair, ctx)?,
                                Rule::InverseObjectProperty => {
                                    // FIXME: currently unsupported in `horned-owl`
                                    return Err(Error::custom(
                                        "InverseOf cannot contain inverse object property expression",
                                        pair.as_span()
                                    ));
                                }
                                rule => unexpected_rule!(ObjectPropertyExpression, rule),
                            };
                            InverseObjectProperties(op, frame.entity.clone()).into()
                        }
                    )
                }
                Rule::ObjectPropertySubPropertyChainClause => {
                    let mut chainlist = inner.into_inner();
                    let mut pair = chainlist.next().unwrap();
                    let ann = axiom_annotations(&mut pair, &mut chainlist, ctx)?;
                    let chain = chainlist
                        .map(|pair| FromPair::from_pair(pair, ctx))
                        .collect::<Result<Vec<_>>>()?;
                    let axiom = SubObjectPropertyOf {
                        sup: frame.entity.clone().into(),
                        sub: SubObjectPropertyExpression::ObjectPropertyChain(chain),
                    }
                    .into();
                    frame.axioms.push(AnnotatedAxiom { ann, axiom });
                }
                rule => unexpected_rule!(ObjectPropertyFrame, rule),
            }
        }

        Ok(frame)
    }
}

impl<A: ForIRI> FromPair<A> for DataPropertyFrame<A> {
    const RULE: Rule = Rule::DataPropertyFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let dt = DataProperty::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = DataPropertyFrame::from(dt);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::DataPropertyClause);
            let inner = descend(pair);
            match inner.as_rule() {
                Rule::DataPropertyAnnotationsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ann = FromPair::from_pair(pair, ctx)?;
                            let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                            AnnotationAssertion { subject, ann }.into()
                        }
                    )
                }
                Rule::DataPropertyDomainClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let dp = frame.entity.clone();
                            let ce = FromPair::from_pair(pair, ctx)?;
                            DataPropertyDomain { dp, ce }.into()
                        }
                    )
                }
                Rule::DataPropertyRangeClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let dp = frame.entity.clone();
                            let dr = from_data_range_pair(pair, ctx)?;
                            DataPropertyRange { dp, dr }.into()
                        }
                    )
                }
                Rule::DataPropertyCharacteristicsClause => unimplemented!(),
                Rule::DataPropertySubPropertyOfClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let inner = descend(pair);
                            SubDataPropertyOf {
                                sup: DataProperty::from_pair(inner, ctx)?,
                                sub: frame.entity.clone(),
                            }
                            .into()
                        }
                    )
                }
                Rule::DataPropertyEquivalentToClause => unimplemented!(),
                Rule::DataPropertyDisjointWithClause => unimplemented!(),
                rule => unexpected_rule!(DataPropertyFrame, rule),
            }
        }

        Ok(frame)
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
            let inner = descend(pair);
            match inner.as_rule() {
                Rule::AnnotationPropertyAnnotationsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ann = FromPair::from_pair(pair, ctx)?;
                            let subject = AnnotationSubject::IRI(frame.entity.0.clone());
                            AnnotationAssertion { subject, ann }.into()
                        }
                    )
                }
                Rule::AnnotationPropertyDomainClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let iri = FromPair::from_pair(pair, ctx)?;
                            let ap = frame.entity.clone();
                            AnnotationPropertyDomain { ap, iri }.into()
                        }
                    )
                }
                Rule::AnnotationPropertyRangeClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let iri = FromPair::from_pair(pair, ctx)?;
                            let ap = frame.entity.clone();
                            AnnotationPropertyRange { ap, iri }.into()
                        }
                    )
                }
                Rule::AnnotationPropertySubPropertyOfClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            SubAnnotationPropertyOf {
                                sup: AnnotationProperty::from_pair(pair, ctx)?,
                                sub: frame.entity.clone(),
                            }
                            .into()
                        }
                    )
                }
                rule => unexpected_rule!(AnnotationPropertyFrame, rule),
            }
        }

        Ok(frame)
    }
}

impl<A: ForIRI> FromPair<A> for IndividualFrame<A> {
    const RULE: Rule = Rule::IndividualFrame;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let mut pairs = pair.into_inner();

        let individual = Individual::from_pair(pairs.next().unwrap(), ctx)?;
        let mut frame = IndividualFrame::from(individual);

        for pair in pairs {
            debug_assert!(pair.as_rule() == Rule::IndividualClause);
            let inner = descend(pair);
            match inner.as_rule() {
                Rule::IndividualAnnotationsClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let ann = FromPair::from_pair(pair, ctx)?;
                            let subject = match &frame.entity {
                                Individual::Anonymous(anon) => {
                                    AnnotationSubject::AnonymousIndividual(anon.clone())
                                }
                                Individual::Named(anon) => AnnotationSubject::IRI(anon.0.clone()),
                            };
                            AnnotationAssertion { subject, ann }.into()
                        }
                    )
                }
                Rule::IndividualTypesClause => {
                    annotated_axiom!(
                        pair,
                        inner,
                        ctx,
                        frame,
                        axiom = {
                            let i = frame.entity.clone();
                            let ce = ClassExpression::from_pair(pair, ctx)?;
                            ClassAssertion { ce, i }.into()
                        }
                    )
                }
                Rule::IndividualFactsClause => unimplemented!(),
                Rule::IndividualSameAsClause => unimplemented!(),
                Rule::IndividualDifferentFromClause => unimplemented!(),
                rule => unexpected_rule!(AnnotationPropertyFrame, rule),
            }
        }

        Ok(frame)
    }
}

impl<A: ForIRI> FromPair<A> for MiscClause<A> {
    const RULE: Rule = Rule::MiscClause;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        macro_rules! entity_list {
            ($inner:ident, $ctx:ident, $clause:ident) => {{
                entity_list!($inner, $ctx, $clause, |pair| FromPair::from_pair(
                    pair, $ctx
                ))
            }};
            ($inner:ident, $ctx:ident, $clause:ident, $closure:expr) => {{
                let mut pairs = $inner.into_inner();
                let mut pair = pairs.next().unwrap();
                let ann = axiom_annotations(&mut pair, &mut pairs, $ctx)?;
                let entities = pair.into_inner().map($closure).collect::<Result<_>>()?;
                let axiom = $clause(entities).into();
                Ok(MiscClause::new(AnnotatedAxiom { ann, axiom }))
            }};
        }

        let inner = descend(pair);
        match inner.as_rule() {
            Rule::MiscEquivalentClassesClause => {
                entity_list!(inner, ctx, EquivalentClasses)
            }
            Rule::MiscDisjointClassesClause => {
                entity_list!(inner, ctx, DisjointClasses)
            }
            Rule::MiscEquivalentObjectPropertiesClause => {
                entity_list!(inner, ctx, EquivalentObjectProperties)
            }
            Rule::MiscDisjointObjectPropertiesClause => {
                entity_list!(inner, ctx, DisjointObjectProperties)
            }
            Rule::MiscEquivalentDataPropertiesClause => {
                entity_list!(inner, ctx, EquivalentDataProperties, |pair| {
                    FromPair::from_pair(descend(pair), ctx)
                })
            }
            Rule::MiscDisjointDataPropertiesClause => {
                entity_list!(inner, ctx, DisjointDataProperties, |pair| {
                    FromPair::from_pair(descend(pair), ctx)
                })
            }
            Rule::MiscSameIndividualClause => {
                entity_list!(inner, ctx, SameIndividual)
            }
            Rule::MiscDifferentIndividualsClause => {
                entity_list!(inner, ctx, DifferentIndividuals)
            }
            Rule::MiscHasKeyClause => unimplemented!(),
            rule => unexpected_rule!(MiscClause, rule),
        }
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for PropertyExpression<A> {
    const RULE: Rule = Rule::PropertyExpression;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = descend(pair);
        match inner.as_rule() {
            Rule::ObjectPropertyExpression => {
                FromPair::from_pair(inner, ctx).map(PropertyExpression::ObjectPropertyExpression)
            }
            Rule::DataPropertyExpression => {
                let pair = descend(inner);
                FromPair::from_pair(pair, ctx).map(PropertyExpression::DataProperty)
            }
            rule => unexpected_rule!(PropertyExpression, rule),
        }
    }
}

impl<A: ForIRI> FromPair<A> for ObjectPropertyExpression<A> {
    const RULE: Rule = Rule::ObjectPropertyExpression;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = descend(pair);
        match inner.as_rule() {
            Rule::ObjectPropertyIRI => {
                FromPair::from_pair(inner, ctx).map(ObjectPropertyExpression::ObjectProperty)
            }
            Rule::InverseObjectProperty => {
                let pair = inner.into_inner().last().unwrap();
                FromPair::from_pair(pair, ctx).map(ObjectPropertyExpression::InverseObjectProperty)
            }
            rule => unexpected_rule!(ObjectPropertyExpression, rule),
        }
    }
}

// ---------------------------------------------------------------------------

impl<A: ForIRI> FromPair<A> for IRI<A> {
    const RULE: Rule = Rule::IRI;
    fn from_pair_unchecked(pair: Pair<Rule>, ctx: &Context<'_, A>) -> Result<Self> {
        let inner = descend(pair);
        match inner.as_rule() {
            Rule::SimpleIRI => {
                let local = descend(inner);
                let curie = Curie::new(None, local.as_str());
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
                let mut pname = descend(inner).into_inner();
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
                let iri = descend(inner);
                Ok(ctx.iri(iri.as_str()))
            }
            rule => unexpected_rule!(IRI, rule),
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

impl<A: ForIRI> FromPair<A> for u32 {
    const RULE: Rule = Rule::NonNegativeInteger;
    fn from_pair_unchecked(pair: Pair<Rule>, _ctx: &Context<'_, A>) -> Result<Self> {
        Ok(Self::from_str(pair.as_str()).expect("cannot fail with the right rule"))
    }
}

impl<A: ForIRI> FromPair<A> for NonZeroU32 {
    const RULE: Rule = Rule::PositiveInteger;
    fn from_pair_unchecked(pair: Pair<Rule>, _ctx: &Context<'_, A>) -> Result<Self> {
        let n = u32::from_str(pair.as_str()).expect("cannot fail with the right rule");
        Ok(Self::new(n).expect("cannot be zero with the right rule"))
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

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
    fn annotation() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");
        prefixes
            .add_prefix("owl", "http://www.w3.org/2002/07/owl#")
            .unwrap();
        prefixes
            .add_prefix("xsd", "http://www.w3.org/2001/XMLSchema#")
            .unwrap();

        assert_parse_into!(
            Annotation<String>,
            Rule::Annotation,
            build,
            prefixes,
            r#"owl:deprecated true"#,
            Annotation {
                ap: build.annotation_property("http://www.w3.org/2002/07/owl#deprecated"),
                av: AnnotationValue::Literal(Literal::Datatype {
                    literal: "true".into(),
                    datatype_iri: build.iri("http://www.w3.org/2001/XMLSchema#boolean"),
                }),
            }
        );
    }

    #[test]
    fn annotation_property_frame() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");
        prefixes
            .add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#")
            .unwrap();

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
                vec![DeclareAnnotationProperty(
                    build.annotation_property("http://purl.obolibrary.org/obo/IAO_0000115")
                )
                .into()]
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
                    )
                    .into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(
                            build.iri("http://purl.obolibrary.org/obo/IAO_0000115")
                        ),
                        ann: Annotation {
                            ap: build
                                .annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("definition")
                            })
                        }
                    }
                    .into()
                ]
            )
        );
    }

    #[test]
    fn class_frame() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://example.com/owl/families#");
        prefixes
            .add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#")
            .unwrap();

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
                    DeclareClass(build.class("http://purl.obolibrary.org/obo/APO_0000098"),).into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(
                            build.iri("http://purl.obolibrary.org/obo/APO_0000098")
                        ),
                        ann: Annotation {
                            ap: build
                                .annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("utilization of carbon source")
                            })
                        }
                    }
                    .into(),
                    SubClassOf {
                        sub: ClassExpression::Class(
                            build.class("http://purl.obolibrary.org/obo/APO_0000098")
                        ),
                        sup: ClassExpression::Class(
                            build.class("http://purl.obolibrary.org/obo/APO_0000096"),
                        )
                    }
                    .into(),
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
                    DeclareClass(build.class("http://purl.obolibrary.org/obo/BFO_0000002"),).into(),
                    DisjointClasses(vec![
                        ClassExpression::Class(
                            build.class("http://purl.obolibrary.org/obo/BFO_0000002")
                        ),
                        ClassExpression::Class(
                            build.class("http://purl.obolibrary.org/obo/BFO_0000003")
                        ),
                    ])
                    .into(),
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
        prefixes
            .add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#")
            .unwrap();

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
        prefixes
            .add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#")
            .unwrap();

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
                    )
                    .into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(
                            build.iri("http://purl.obolibrary.org/obo/RO_0000052")
                        ),
                        ann: Annotation {
                            ap: build.annotation_property(
                                "http://www.geneontology.org/formats/oboInOwl#hasDbXref"
                            ),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("RO:0000052")
                            })
                        }
                    }
                    .into(),
                    AnnotationAssertion {
                        subject: AnnotationSubject::IRI(
                            build.iri("http://purl.obolibrary.org/obo/RO_0000052")
                        ),
                        ann: Annotation {
                            ap: build
                                .annotation_property("http://www.w3.org/2000/01/rdf-schema#label"),
                            av: AnnotationValue::Literal(Literal::Simple {
                                literal: String::from("inheres in")
                            })
                        }
                    }
                    .into(),
                ]
            )
        );
    }

    #[test]
    fn ontology() {
        let build = Build::new();
        let mut prefixes = PrefixMapping::default();
        prefixes.set_default("http://www.example.com/owl/families#");
        prefixes
            .add_prefix("rdfs", "http://www.w3.org/2000/01/rdf-schema#")
            .unwrap();

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
        ont.insert(AnnotatedAxiom {
            ann: BTreeSet::from_iter(vec![Annotation {
                ap: build.annotation_property("http://www.example.com/owl/families#creator"),
                av: AnnotationValue::IRI(build.iri("http://www.example.com/owl/families#John")),
            }]),
            axiom: Axiom::OntologyAnnotation(OntologyAnnotation(Annotation {
                ap: build.annotation_property(
                    "http://www.geneontology.org/formats/oboInOwl#hasOBOFormatVersion",
                ),
                av: AnnotationValue::Literal(Literal::Simple {
                    literal: String::from("1.2"),
                }),
            })),
        });
        ont.insert(AnnotatedAxiom {
            ann: BTreeSet::new(),
            axiom: Axiom::OntologyAnnotation(OntologyAnnotation(Annotation {
                ap: build
                    .annotation_property("http://www.geneontology.org/formats/oboInOwl#saved-by"),
                av: AnnotationValue::Literal(Literal::Simple {
                    literal: String::from("cooperl"),
                }),
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
