use std::collections::BTreeSet;

use curie::PrefixMapping;
use horned_owl::model::*;
use horned_owl::ontology::axiom_mapped::AxiomMappedOntology;
use horned_owl::ontology::set::SetOntology;

use crate::error::Error;
use crate::error::Result;
use crate::from_pair::FromPair;
use crate::parser::OwlManchesterParser;
use crate::Context;

/// A trait for OWL elements that can be deserialized from OWL Manchester syntax.
///
/// The deserialization will fail if the entirety of the input string cannot
/// be deserialized into the declared type.
pub trait FromManchester<A: ForIRI>: Sized + FromPair<A> {
    /// Deserialize a string containing an OWL element in Manchester syntax.
    #[inline]
    fn from_omn(s: &str) -> Result<Self> {
        Self::from_omn_ctx(s, &Context::default())
    }

    fn from_omn_ctx(s: &str, context: &Context<'_, A>) -> Result<Self>;
}

impl<A, O> FromManchester<A> for (O, PrefixMapping)
where
    A: ForIRI,
    O: Ontology<A> + MutableOntology<A> + FromPair<A>,
{
    fn from_omn_ctx(s: &str, context: &Context<'_, A>) -> Result<Self> {
        let mut pairs = OwlManchesterParser::parse(Self::RULE, s)?;
        if pairs.as_str().len() == s.len() {
            Self::from_pair(pairs.next().unwrap(), context)
        } else {
            Err(Error::from(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError {
                    message: "remaining input".to_string(),
                },
                pest::Span::new(s, pairs.as_str().len(), s.len()).unwrap(),
            )))
        }
    }
}

// We use a macro instead of a blanket impl to have all types displayed in
// the documentation.
macro_rules! implement {
    ($($ty:ident),+) => {
        $(impl<A: ForIRI> FromManchester<A> for $ty<A> {
            fn from_omn_ctx(s: &str, context: &Context<'_, A>) -> Result<Self> {
                let mut pairs = OwlManchesterParser::parse(Self::RULE, s)?;
                if pairs.as_str().len() == s.len() {
                     Self::from_pair(pairs.next().unwrap(), context)
                } else {
                    Err(
                        Error::from(
                            pest::error::Error::new_from_span(
                                pest::error::ErrorVariant::CustomError {
                                    message: "remaining input".to_string(),
                                },
                                pest::Span::new(s, pairs.as_str().len(), s.len()).unwrap()
                            )
                        )
                    )
                }
            }
        })*
    }
}

implement!(
    // AnnotationProperty,
    // AnnotatedAxiom,
    // Annotation,
    // AnnotationValue,
    // AnonymousIndividual,
    // Axiom,
    // AxiomMappedOntology,
    // BTreeSet<Annotation>,
    // Class,
    // ClassExpression,
    // DataProperty,
    // DataRange,
    // Datatype,
    // DeclareClass,
    // DeclareDatatype,
    // DeclareObjectProperty,
    // DeclareDataProperty,
    // DeclareAnnotationProperty,
    // DeclareNamedIndividual,
    // Facet,
    // FacetRestriction,
    // Import,
    // Individual,
    // IRI,
    // NamedIndividual,
    Literal,
    // ObjectPropertyExpression,
    // ObjectProperty,
    SetOntology // OntologyAnnotation,
                // String,
                // SubObjectPropertyExpression
);

#[cfg(test)]
mod tests {

    use super::*;
    use horned_owl::model::DeclareClass;

    // #[test]
    // fn test_remaining_input() {
    //     match DeclareClass::from_omn("Class(<http://example.com/a>) Class(<http://example.com/b>)")
    //     {
    //         Ok(ok) => panic!("unexpected success: {:?}", ok),
    //         Err(Error::Pest(e)) => {
    //             assert_eq!(
    //                 e.variant,
    //                 pest::error::ErrorVariant::CustomError {
    //                     message: "remaining input".to_string(),
    //                 }
    //             )
    //         }
    //         Err(other) => panic!("unexpected error: {:?}", other),
    //     }
    // }
}
