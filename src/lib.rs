
#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate pest_derive;

extern crate curie;
extern crate horned_owl;
extern crate pest;

mod error;
pub mod parser;
mod frames;
mod from_pair;

use std::borrow::Borrow;

use curie::PrefixMapping;
use horned_owl::model::IRI;
use horned_owl::model::ForIRI;
use horned_owl::model::Build;
use horned_owl::model::Ontology;

pub use self::error::Error;
pub use self::error::Result;

/// A context to pass around while parsing and writing OWL Manchester documents.
#[derive(Default, Debug)]
pub struct Context<'a, A: ForIRI> {
    build: Option<&'a Build<A>>,
    prefixes: Option<&'a PrefixMapping>,
}

impl<'a, A: ForIRI> Context<'a, A> {
    /// Create a new context with the given IRI builder and prefix mapping.
    pub fn new<B, P>(build: B, prefixes: P) -> Self
    where
        B: Into<Option<&'a Build<A>>>,
        P: Into<Option<&'a PrefixMapping>>,
    {
        Self {
            build: build.into(),
            prefixes: prefixes.into(),
        }
    }

    /// Obtain an IRI for the given string, using the internal builder if any.
    pub fn iri<S>(&self, s: S) -> IRI<A>
    where
        S: Borrow<str>,
    {
        match self.build {
            Some(b) => b.iri(s),
            None => Build::new().iri(s),
        }
    }
}
