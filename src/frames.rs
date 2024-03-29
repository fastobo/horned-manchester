use horned_owl::model::*;

// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct Frame<A: ForIRI, T> {
    pub entity: T,
    pub axioms: Vec<AnnotatedAxiom<A>>,
}

impl<A: ForIRI, T> Frame<A, T> {
    #[allow(unused)]
    pub fn with_axioms(entity: T, axioms: Vec<AnnotatedAxiom<A>>) -> Self {
        Self { entity, axioms }
    }

    #[allow(unused)]
    pub fn into_axioms(self) -> Vec<AnnotatedAxiom<A>> {
        self.axioms
    }
}

// ---------------------------------------------------------------------------

macro_rules! impl_from {
    ($ty:ident, $entity:ident, $declare:ident) => {
        impl<A: ForIRI> From<$entity<A>> for $ty<A> {
            fn from(entity: $entity<A>) -> Self {
                let axioms = vec![$declare(entity.clone()).into()];
                Self { entity, axioms }
            }
        }
    };
}

// ---------------------------------------------------------------------------

pub type DatatypeFrame<A> = Frame<A, Datatype<A>>;

impl_from!(DatatypeFrame, Datatype, DeclareDatatype);

// ---------------------------------------------------------------------------

pub type ClassFrame<A> = Frame<A, Class<A>>;

impl_from!(ClassFrame, Class, DeclareClass);

// ---------------------------------------------------------------------------

pub type ObjectPropertyFrame<A> = Frame<A, ObjectProperty<A>>;

impl_from!(ObjectPropertyFrame, ObjectProperty, DeclareObjectProperty);

// ---------------------------------------------------------------------------

pub type DataPropertyFrame<A> = Frame<A, DataProperty<A>>;

impl_from!(DataPropertyFrame, DataProperty, DeclareDataProperty);

// ---------------------------------------------------------------------------

pub type AnnotationPropertyFrame<A> = Frame<A, AnnotationProperty<A>>;

impl_from!(
    AnnotationPropertyFrame,
    AnnotationProperty,
    DeclareAnnotationProperty
);

// ---------------------------------------------------------------------------

pub type IndividualFrame<A> = Frame<A, Individual<A>>;

// Need manual implementation because anonymous individuals must not be declared.
impl<A: ForIRI> From<Individual<A>> for IndividualFrame<A> {
    fn from(entity: Individual<A>) -> Self {
        let axioms = match &entity {
            Individual::Anonymous(_) => Vec::new(),
            Individual::Named(ni) => vec![DeclareNamedIndividual(ni.clone()).into()],
        };
        Self { entity, axioms }
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MiscClause<A: ForIRI>(pub Option<AnnotatedAxiom<A>>);

impl<A: ForIRI> MiscClause<A> {
    pub fn new(axiom: AnnotatedAxiom<A>) -> Self {
        MiscClause(Some(axiom))
    }

    pub fn empty() -> Self {
        MiscClause(None)
    }
}

impl<A: ForIRI> From<AnnotatedAxiom<A>> for MiscClause<A> {
    fn from(axiom: AnnotatedAxiom<A>) -> Self {
        MiscClause::new(axiom)
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InverseObjectPropertyFrame<A: ForIRI> {
    pub entity: ObjectPropertyExpression<A>,
    pub axioms: Vec<AnnotatedAxiom<A>>,
}

impl<A: ForIRI> InverseObjectPropertyFrame<A> {
    pub fn new(entity: ObjectPropertyExpression<A>) -> Self {
        let axioms = Vec::new();
        Self { entity, axioms }
    }

    pub fn into_axioms(self) -> Vec<AnnotatedAxiom<A>> {
        self.axioms
    }
}

impl<A: ForIRI> From<ObjectPropertyExpression<A>> for InverseObjectPropertyFrame<A> {
    fn from(ope: ObjectPropertyExpression<A>) -> Self {
        Self::new(ope)
    }
}
