use curie::Curie;
use curie::PrefixMapping;
use horned_owl::model::*;
use pest::iterators::Pair;

#[derive(Debug, PartialEq)]
pub struct ClassFrame<A: ForIRI> {
    pub class: Class<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>
}

impl<A: ForIRI> ClassFrame<A> {
    pub fn new(class: Class<A>) -> Self {
        Self::with_axioms(class, Vec::new())
    }

    pub fn with_axioms(class: Class<A>, axioms: Vec<AnnotatedAxiom<A>>) -> Self {
        ClassFrame { class, axioms }
    }
}