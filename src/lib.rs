#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate pest_derive;

extern crate curie;
extern crate horned_owl;
extern crate pest;

mod error;
mod frames;
mod from_omn;
mod from_pair;
pub mod parser;

use std::borrow::Borrow;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use curie::PrefixMapping;
use horned_owl::model::Build;
use horned_owl::model::ForIRI;
use horned_owl::model::MutableOntology;
use horned_owl::model::Ontology;
use horned_owl::model::IRI;

pub use self::error::Error;
pub use self::error::Result;
pub use self::from_omn::FromManchester;
pub use self::from_pair::FromPair;

/// A context to pass around while parsing and writing OWL Manchester documents.
#[derive(Debug)]
pub struct Context<'a, A: ForIRI> {
    build: Option<&'a Build<A>>,
    prefixes: Option<&'a PrefixMapping>,
    strict: bool,
}

impl<'a, A: ForIRI> Default for Context<'a, A> {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl<'a, A: ForIRI> From<&'a Build<A>> for Context<'a, A> {
    fn from(build: &'a Build<A>) -> Self {
        Self::new(build, None)
    }
}

impl<'a, A: ForIRI> From<&'a PrefixMapping> for Context<'a, A> {
    fn from(prefixes: &'a PrefixMapping) -> Self {
        Self::new(None, prefixes)
    }
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
            strict: false,
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

/// Parse an entire OWL document from a string.
#[inline]
pub fn from_str<A, O, S>(src: S) -> Result<(O, PrefixMapping)>
where
    A: ForIRI,
    O: Ontology<A> + MutableOntology<A> + FromManchester<A>,
    S: AsRef<str>,
{
    FromManchester::from_omn(src.as_ref())
}

/// Parse an entire OWL document from a `Read` implementor.
#[inline]
pub fn from_reader<A, O, R>(mut r: R) -> Result<(O, PrefixMapping)>
where
    A: ForIRI,
    O: Ontology<A> + MutableOntology<A> + FromManchester<A>,
    R: Read,
{
    let mut s = String::new();
    r.read_to_string(&mut s)?;
    from_str(s)
}

/// Parse an entire OWL document from a file on the local filesystem.
#[inline]
pub fn from_file<A, O, P>(path: P) -> Result<(O, PrefixMapping)>
where
    A: ForIRI,
    O: Ontology<A> + MutableOntology<A> + FromManchester<A>,
    P: AsRef<Path>,
{
    let f = File::open(path)?;
    #[cfg(not(feature = "memmap"))]
    return from_reader(f);

    #[cfg(feature = "memmap")]
    unsafe {
        let map = memmap::Mmap::map(&f)?;
        match std::str::from_utf8(&map) {
            Ok(text) => from_str(text),
            Err(error) => Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error,
            ))),
        }
    }
}
