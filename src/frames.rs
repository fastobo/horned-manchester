use curie::Curie;
use curie::PrefixMapping;
use horned_owl::model::*;
use pest::iterators::Pair;

// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Frame<A: ForIRI> {
    Datatype(DatatypeFrame<A>),
    Class(ClassFrame<A>),
    ObjectProperty(ObjectPropertyFrame<A>),
    DataProperty(DataPropertyFrame<A>),
    AnnotationProperty(AnnotationPropertyFrame<A>),
    Individual(IndividualFrame<A>),
    Misc(AnnotatedAxiom<A>),
}

// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct DatatypeFrame<A: ForIRI> {
    pub datatype: Datatype<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>
}

impl<A: ForIRI> DatatypeFrame<A> {
    pub fn new(datatype: Datatype<A>) -> Self {
        Self::with_axioms(datatype, Vec::new())
    }

    pub fn with_axioms(datatype: Datatype<A>, axioms: Vec<AnnotatedAxiom<A>>) -> Self {
        DatatypeFrame { datatype, axioms }
    }
}

// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct ObjectPropertyFrame<A: ForIRI> {
    pub op: ObjectProperty<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>
}

impl<A: ForIRI> ObjectPropertyFrame<A> {
    pub fn new(op: ObjectProperty<A>) -> Self {
        Self::with_axioms(op, Vec::new())
    }

    pub fn with_axioms(op: ObjectProperty<A>, axioms: Vec<AnnotatedAxiom<A>>) -> Self {
        ObjectPropertyFrame { op, axioms }
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct DataPropertyFrame<A: ForIRI> {
    pub op: DataProperty<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>
}


// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct AnnotationPropertyFrame<A: ForIRI> {
    pub ap: AnnotationProperty<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>
}

impl<A: ForIRI> AnnotationPropertyFrame<A> {
    pub fn new(ap: AnnotationProperty<A>) -> Self {
        Self::with_axioms(ap, Vec::new())
    }

    pub fn with_axioms(ap: AnnotationProperty<A>, axioms: Vec<AnnotatedAxiom<A>>) -> Self {
        AnnotationPropertyFrame { ap, axioms }
    }
}


// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct IndividualFrame<A: ForIRI> {
    pub individual: Individual<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>
}

