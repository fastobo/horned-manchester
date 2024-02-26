use super::error::Result;
use pest::iterators::Pairs;

/// The OWL2 Manchester Syntax parser.
///
/// You shouldn't have to use this type directly: instead, use the top level
/// `parse` function to parse an ontology document.
#[derive(Debug, Parser)]
#[grammar = "omn.pest"]
#[grammar = "rfc3987.pest"]
#[grammar = "sparql.pest"]
#[grammar = "bcp47.pest"]
pub struct OwlManchesterParser;

impl OwlManchesterParser {
    /// Parse an input string using the given production rule.
    ///
    /// This is basically a specialized version of [`pest::Parser::parse`]
    /// that only accepts [`Rule`], and does not need the `Parser` trait to
    /// be in scope.
    ///
    /// [`Rule`]: ./enum.Rule.html
    /// [`pest::Parser::parse`]: https://docs.rs/pest/latest/pest/trait.Parser.html
    pub fn parse(rule: Rule, input: &str) -> Result<Pairs<Rule>> {
        <Self as pest::Parser<Rule>>::parse(rule, input).map_err(From::from)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    macro_rules! assert_parse {
        ($rule:path, $doc:expr) => {
            let doc = $doc.trim();
            match OwlManchesterParser::parse($rule, doc) {
                Ok(mut p) => assert_eq!(p.next().unwrap().as_span().end(), doc.len()),
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
    fn annotation() {
        assert_parse!(Rule::Annotation, r#"creator John"#);
        assert_parse!(Rule::Annotation, r#"creationYear 2008"#);
        assert_parse!(Rule::Annotation, r#"mainClass Person"#);
    }

    #[test]
    fn annotation_target() {
        assert_parse!(Rule::AnnotationTarget, r#"Person"#);
    }

    #[test]
    fn annotation_annotated_list() {
        assert_parse!(
            Rule::AnnotationAnnotatedList,
            r#"creator John , creationYear 2008"#
        );
        assert_parse!(
            Rule::AnnotationAnnotatedList,
            r#"creator John , creationYear 2008 , creator John"#
        );
        assert_parse!(
            Rule::AnnotationAnnotatedList,
            r#"creator John, creationYear 2008, mainClass Person"#
        );
        assert_parse!(
            Rule::AnnotationAnnotatedList,
            r#"creator John, creationYear 2008, mainClass Person"#
        );
    }

    #[test]
    fn annotation_property_frame() {
        assert_parse!(
            Rule::AnnotationPropertyFrame,
            r#"
            AnnotationProperty: creator
                Domain: Entity
                Range: Person
                SubPropertyOf: initialCreator
            "#
        );
        assert_parse!(
            Rule::AnnotationPropertyFrame,
            r#"
            AnnotationProperty: <http://purl.obolibrary.org/obo/IAO_0000115>

                Annotations:
                    rdfs:label "definition"
            "#
        );
    }

    #[test]
    fn annotation_property_uri() {
        assert_parse!(Rule::AnnotationPropertyIRI, r#"creator"#);
    }

    #[test]
    fn annotations() {
        assert_parse!(
            Rule::Annotations,
            r#"Annotations: creator John, creationYear 2008, mainClass Person"#
        );
        assert_parse!(
            Rule::Annotations,
            r#"Annotations: creator John , Annotations: rdfs:comment "Creation Year" creationYear 2008 , mainClass Person"#
        );
        assert_parse!(
            Rule::Annotations,
            r#"Annotations: creator John , Annotations: rdfs:comment "Creation Year" creationYear 2008 , mainClass Person"#
        );
    }

    #[test]
    fn class_clause() {
        assert_parse!(
            Rule::ClassClause,
            r#"SubClassOf: owl:Thing that hasFirstName exactly 1"#
        );
        assert_parse!(
            Rule::ClassClause,
            r#"SubClassOf: owl:Thing that hasFirstName only string[minLength 1]"#
        );
        assert_parse!(
            Rule::ClassClause,
            r#"SubClassOf: owl:Thing that hasFirstName exactly 1 and hasFirstName only string[minLength 1]"#
        );
        assert_parse!(
            Rule::ClassClause,
            r#"SubClassOf: hasAge exactly 1 and hasAge only not NegInt"#
        );
        assert_parse!(
            Rule::ClassClause,
            r#"SubClassOf: hasGender exactly 1 and hasGender only {female , male}"#
        );
        assert_parse!(
            Rule::ClassClause,
            r#"SubClassOf: hasSSN max 1, hasSSN min 1"#
        );
        assert_parse!(Rule::ClassClause, r#"SubClassOf: not hates Self"#);
        assert_parse!(Rule::ClassClause, r#"EquivalentTo: g:People"#);
        assert_parse!(Rule::ClassClause, r#"DisjointWith: g:Rock , g:Mineral"#);
        assert_parse!(
            Rule::ClassClause,
            r#"DisjointUnionOf: Annotations: description "either child or adult" Child, Adult"#
        );
        assert_parse!(
            Rule::ClassClause,
            r#"HasKey: Annotations: description "has social security number" hasSSN"#
        );
    }

    #[test]
    fn class_frame() {
        assert_parse!(
            Rule::ClassFrame,
            r#"
            Class: Person
                SubClassOf: owl:Thing that hasFirstName exactly 1 and hasFirstName only string[minLength 1]
                SubClassOf: hasAge exactly 1 and hasAge only not NegInt
                SubClassOf: hasGender exactly 1 and hasGender only {female , male}
                SubClassOf: hasSSN max 1, hasSSN min 1
                SubClassOf: not hates Self
                EquivalentTo: g:People
                DisjointWith: g:Rock , g:Mineral
                DisjointUnionOf: Annotations: description "either child or adult" Child, Adult
                HasKey: Annotations: description "has social security number" hasSSN
            "#
        );
        assert_parse!(
            Rule::ClassFrame,
            r#"
            Class: <http://purl.obolibrary.org/obo/APO_0000098>

                Annotations:

                        Annotations: <http://www.geneontology.org/formats/oboInOwl#hasDbXref> "SGD:curators"
                    <http://purl.obolibrary.org/obo/IAO_0000115> "The ability to utilize the specified compound as a carbon source.",
                    <http://www.geneontology.org/formats/oboInOwl#hasAlternativeId> "YPO:0000098",
                    <http://www.geneontology.org/formats/oboInOwl#hasOBONamespace> "observable",
                    <http://www.geneontology.org/formats/oboInOwl#id> "APO:0000098",
                    <http://www.geneontology.org/formats/oboInOwl#inSubset> <http://purl.obolibrary.org/obo/apo#AspGD>,
                    <http://www.geneontology.org/formats/oboInOwl#inSubset> <http://purl.obolibrary.org/obo/apo#CGD>,
                    <http://www.geneontology.org/formats/oboInOwl#inSubset> <http://purl.obolibrary.org/obo/apo#CryptoGD>,
                    <http://www.geneontology.org/formats/oboInOwl#inSubset> <http://purl.obolibrary.org/obo/apo#SGD>,
                    rdfs:label "utilization of carbon source"

                SubClassOf:
                    <http://purl.obolibrary.org/obo/APO_0000096>
            "#
        );
        assert_parse!(
            Rule::ClassFrame,
            r#"
            Class: <http://purl.obolibrary.org/obo/APO_0000098>

                Annotations:
                    rdfs:label "utilization of carbon source"

                SubClassOf:
                    <http://purl.obolibrary.org/obo/APO_0000096>
            "#
        );
    }

    #[test]
    fn conjuction() {
        assert_parse!(
            Rule::Conjuction,
            r#"owl:Thing that hasFirstName exactly 1 and hasFirstName only string[minLength 1]"#
        );
    }

    #[test]
    fn data_primary() {
        assert_parse!(Rule::DataPrimary, r#"string[minLength 1]"#);
    }

    #[test]
    fn data_property_frame() {
        assert_parse!(
            Rule::DataPropertyFrame,
            r#"
            DataProperty: hasAge
                Characteristics: Annotations: description "functional" Functional
                Domain: Person
                Range: integer
                SubPropertyOf: hasVerifiedAge
                EquivalentTo: hasAgeInYears
                DisjointWith: hasSSN
            "#
        );
    }

    #[test]
    fn data_property_expression() {
        assert_parse!(Rule::DataPropertyExpression, r#"hasFirstName"#);
    }

    #[test]
    fn data_range() {
        assert_parse!(Rule::DataRange, r#"integer[< 0]"#);
    }

    #[test]
    fn datatype_frame() {
        assert_parse!(
            Rule::DatatypeFrame,
            r#"
            Datatype: NegInt
                Annotations: createdBy Martin, creationYear 2024
                EquivalentTo: integer[< 0]
            "#
        );
    }

    #[test]
    fn datatype_restriction() {
        assert_parse!(Rule::DatatypeRestriction, r#"integer[< 0]"#);
    }

    #[test]
    fn description() {
        assert_parse!(Rule::Description, r#"hasSSN max 1"#);
        assert_parse!(Rule::Description, r#"not hates Self"#);
    }

    #[test]
    fn floating_point_literal() {
        assert_parse!(Rule::FloatingPointLiteral, r#"1.0f"#);
        assert_parse!(Rule::FloatingPointLiteral, r#"+3.14e0F"#);
        assert_parse!(Rule::FloatingPointLiteral, r#".025f"#);
        assert_parse!(Rule::FloatingPointLiteral, r#"-.01f"#);
    }

    #[test]
    fn import() {
        assert_parse!(Rule::Import, r#"Import: <http://ex.com/owl2/families.owl>"#);
    }

    #[test]
    fn individual_clause() {
        assert_parse!(
            Rule::IndividualClause,
            r#"Types: Person , hasFirstName value "John" or hasFirstName value "Jack"^^xsd:string"#
        );
        assert_parse!(
            Rule::IndividualClause,
            r#"Facts: hasWife Mary, not hasChild Susan, hasAge 33, hasChild _:child1"#
        );
    }

    #[test]
    fn individual() {
        assert_parse!(Rule::Individual, r#"Susan"#);
        assert_parse!(Rule::Individual, r#"_:child1"#);
    }

    #[test]
    fn individual_frame() {
        assert_parse!(
            Rule::IndividualFrame,
            r#"
            Individual: John
                Types: Person , hasFirstName value "John" or hasFirstName value "Jack"^^xsd:string
                Facts: hasWife Mary, not hasChild Susan, hasAge 33, hasChild _:child1
                SameAs: Jack
                DifferentFrom: Susan
            "#
        );
        assert_parse!(
            Rule::IndividualFrame,
            r#"
            Individual: _:child1
                Types: Person
                Facts: hasChild Susan
            "#
        );
    }

    #[test]
    fn integer_literal() {
        assert_parse!(Rule::IntegerLiteral, r#"2008"#);
    }

    #[test]
    fn iri() {
        assert_parse!(Rule::IRI, r#"owl:deprecated"#);
        assert_parse!(Rule::IRI, r#"John"#);
        assert_parse!(Rule::IRI, r#"<https://en.wiktionary.org/wiki/Ῥόδος>"#);
    }

    #[test]
    fn literal() {
        assert_parse!(Rule::Literal, r#"2008"#);
        assert_parse!(Rule::Literal, r#"true"#);
        assert_parse!(Rule::Literal, r#"1.0f"#);
    }

    #[test]
    fn misc() {
        assert_parse!(
            Rule::MiscClause,
            r#"DisjointClasses: Annotations: creator Jonh g:Rock, g:Scissor, g:Paper"#
        );
    }

    #[test]
    fn object_property_clause() {
        assert_parse!(Rule::ObjectPropertyClause, "Range: Person, Woman");
        assert_parse!(
            Rule::ObjectPropertyClause,
            "SubPropertyOf: hasSpouse, loves"
        );
        assert_parse!(Rule::ObjectPropertyClause, "EquivalentTo: isMarriedTo");
        assert_parse!(Rule::ObjectPropertyClause, "DisjointWith: hates");
        assert_parse!(
            Rule::ObjectPropertyClause,
            "InverseOf: hasSpouse, inverse hasSpouse"
        );
        assert_parse!(Rule::ObjectPropertyClause, "Characteristics: Transitive");
        assert_parse!(Rule::ObjectPropertyClause, "SubPropertyChain: <http://purl.obolibrary.org/obo/BFO_0000050> o <http://purl.obolibrary.org/obo/BFO_0000062>");
        assert_parse!(
            Rule::ObjectPropertyClause,
            "Domain: <http://purl.obolibrary.org/obo/BFO_0000003>"
        );
        assert_parse!(
            Rule::ObjectPropertyClause,
            "Range: <http://purl.obolibrary.org/obo/BFO_0000003>"
        );
        assert_parse!(
            Rule::ObjectPropertyClause,
            "InverseOf: <http://purl.obolibrary.org/obo/BFO_0000063>"
        );
    }

    #[test]
    fn object_property_expression() {
        assert_parse!(Rule::ObjectPropertyExpression, "hasSpouse");
        assert_parse!(Rule::ObjectPropertyExpression, "inverse hasSpouse");
        assert_parse!(Rule::ObjectPropertyExpression, "hasSSN");
    }

    #[test]
    fn object_property_fact() {
        assert_parse!(Rule::ObjectPropertyFact, r#"hasChild _:child1"#);
    }

    #[test]
    fn object_property_frame() {
        assert_parse!(
            Rule::ObjectPropertyFrame,
            r#"
            ObjectProperty: hasWife
                Characteristics: Functional, InverseFunctional, Reflexive, Irreflexive, Asymmetric, Transitive
                Domain: Annotations: rdfs:comment "General domain",
                                    creator John
                        Person,
                        Annotations: rdfs:comment "More specific domain"
                        Man
                Range: Person, Woman
                SubPropertyOf: hasSpouse, loves
                EquivalentTo: isMarriedTo
                DisjointWith: hates
                InverseOf: hasSpouse, inverse hasSpouse
            "#
        );
        assert_parse!(
            Rule::ObjectPropertyFrame,
            r#"
            ObjectProperty: <http://purl.obolibrary.org/obo/BFO_0000062>

                Annotations:
                    <http://purl.obolibrary.org/obo/IAO_0000111> "preceded by",
                    <http://purl.obolibrary.org/obo/IAO_0000115> "x is preceded by y if and only if the time point at which y ends is before or equivalent to the time point at which x starts. Formally: x preceded by y iff ω(y) <= α(x), where α is a function that maps a process to a start point, and ω is a function that maps a process to an end point.",
                    <http://purl.obolibrary.org/obo/IAO_0000116> "An example is: translation preceded_by transcription; aging preceded_by development (not however death preceded_by aging). Where derives_from links classes of continuants, preceded_by links classes of processes. Clearly, however, these two relations are not independent of each other. Thus if cells of type C1 derive_from cells of type C, then any cell division involving an instance of C1 in a given lineage is preceded_by cellular processes involving an instance of C.    The assertion P preceded_by P1 tells us something about Ps in general: that is, it tells us something about what happened earlier, given what we know about what happened later. Thus it does not provide information pointing in the opposite direction, concerning instances of P1 in general; that is, that each is such as to be succeeded by some instance of P. Note that an assertion to the effect that P preceded_by P1 is rather weak; it tells us little about the relations between the underlying instances in virtue of which the preceded_by relation obtains. Typically we will be interested in stronger relations, for example in the relation immediately_preceded_by, or in relations which combine preceded_by with a condition to the effect that the corresponding instances of P and P1 share participants, or that their participants are connected by relations of derivation, or (as a first step along the road to a treatment of causality) that the one process in some way affects (for example, initiates or regulates) the other.",
                    <http://purl.obolibrary.org/obo/IAO_0000118> "is preceded by",
                    <http://purl.obolibrary.org/obo/IAO_0000118> "preceded_by",
                    <http://purl.org/dc/elements/1.1/source> "http://www.obofoundry.org/ro/#OBO_REL:preceded_by",
                    <http://www.geneontology.org/formats/oboInOwl#hasOBONamespace> "Planarian_Anatomy",
                    <http://www.geneontology.org/formats/oboInOwl#id> "BFO:0000062",
                    <http://www.geneontology.org/formats/oboInOwl#inSubset> <http://purl.obolibrary.org/obo/plana#ro-eco>,
                    rdfs:label "preceded by"

                SubPropertyOf:
                    <http://purl.obolibrary.org/obo/RO_0002086>

                SubPropertyChain:
                    <http://purl.obolibrary.org/obo/BFO_0000050> o <http://purl.obolibrary.org/obo/BFO_0000062>

                Characteristics:
                    Transitive

                Domain:
                    <http://purl.obolibrary.org/obo/BFO_0000003>

                Range:
                    <http://purl.obolibrary.org/obo/BFO_0000003>

                InverseOf:
                    <http://purl.obolibrary.org/obo/BFO_0000063>
            "#
        );
        assert_parse!(
            Rule::ObjectPropertyFrame,
            r#"
            ObjectProperty: <http://purl.obolibrary.org/obo/RO_0004032>

                Annotations:
                    <http://purl.obolibrary.org/obo/RO_0004049> <http://purl.obolibrary.org/obo/RO_0002264>,
                    <http://purl.obolibrary.org/obo/plana#seeAlso> <http://wiki.geneontology.org/index.php/Acts_upstream_of_or_within,_positive_effect>,
                    <http://www.geneontology.org/formats/oboInOwl#created_by> "cjm",
                    <http://www.geneontology.org/formats/oboInOwl#creation_date> "2018-01-26T23:49:30Z",
                    <http://www.geneontology.org/formats/oboInOwl#hasOBONamespace> "Planarian_Anatomy",
                    <http://www.geneontology.org/formats/oboInOwl#id> "RO:0004032",
                    rdfs:label "acts upstream of or within, positive effect"

                SubPropertyOf:
                    <http://purl.obolibrary.org/obo/RO_0002264>

                SubPropertyChain:
                    <http://purl.obolibrary.org/obo/RO_0002327> o <http://purl.obolibrary.org/obo/RO_0004047>

            "#
        );
    }

    #[test]
    fn object_property_iri() {
        assert_parse!(Rule::ObjectPropertyIRI, r#"hasChild"#);
    }

    #[test]
    fn ontology() {
        assert_parse!(
            Rule::Ontology,
            r#"
            Ontology: <http://purl.obolibrary.org/obo/ms.owl>
                <http://purl.obolibrary.org/obo/ms/4.1.29/ms.owl>
                Import: <http://ontologies.berkeleybop.org/pato.obo>
                Import: <http://ontologies.berkeleybop.org/uo.obo>
            "#
        );
        assert_parse!(
            Rule::Ontology,
            r#"
            Ontology: <http://purl.obolibrary.org/obo/ms.owl>
                <http://purl.obolibrary.org/obo/ms/4.1.29/ms.owl>
                Import: <http://ontologies.berkeleybop.org/pato.obo>
                Import: <http://ontologies.berkeleybop.org/uo.obo>

            AnnotationProperty: <http://www.geneontology.org/formats/oboInOwl#auto-generated-by>

            AnnotationProperty: <http://www.geneontology.org/formats/oboInOwl#date>

            AnnotationProperty: <http://www.geneontology.org/formats/oboInOwl#default-namespace>
            "#
        );
        assert_parse!(
            Rule::Ontology,
            r#"
            Ontology: <http://purl.obolibrary.org/obo/bspo.owl>
                <http://purl.obolibrary.org/obo/bspo/releases/2023-05-27/bspo.owl>

            Annotations: 
                obo:IAO_0000700 <http://purl.obolibrary.org/obo/CARO_0000000>

            DifferentIndividuals: 
                obo:IAO_0000226,obo:IAO_0000227,obo:IAO_0000228,obo:IAO_0000229
            "#
        );
    }

    #[test]
    fn prefix() {
        assert_parse!(
            Rule::PrefixDeclaration,
            r#"Prefix: : <http://ex.com/owl/families#>"#
        );
        assert_parse!(
            Rule::PrefixDeclaration,
            r#"Prefix: g: <http://ex.com/owl2/families#>"#
        );
    }

    #[test]
    fn quoted_string() {
        assert_parse!(Rule::QuotedString, r#""gene_ontology""#);
    }

    #[test]
    fn restriction() {
        assert_parse!(Rule::Restriction, r#"hasFirstName exactly 1"#);
        assert_parse!(
            Rule::Restriction,
            r#"hasFirstName only string[minLength 1]"#
        );
    }

    #[test]
    fn string_literal_with_language() {
        assert_parse!(Rule::StringLiteralWithLanguage, r#""Agronomy Ontology"@en"#);
    }
}
