use super::error::Result;
use pest::iterators::Pairs;

/// The OWL2 Manchester Syntax parser.
///
/// You shouldn't have to use this type directly: instead, use the top level
/// `parse` function to parse an ontology document.
#[derive(Debug, Parser)]
#[grammar = "sparql.pest"]
#[grammar = "bcp47.pest"]
#[grammar = "rfc3987.pest"]
#[grammar = "owl.pest"]
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
        assert_parse!(Rule::AnnotationAnnotatedList, r#"creator John , creationYear 2008"#);
        assert_parse!(Rule::AnnotationAnnotatedList, r#"creator John , creationYear 2008 , creator John"#);
        assert_parse!(Rule::AnnotationAnnotatedList, r#"creator John, creationYear 2008, mainClass Person"#);
        assert_parse!(Rule::AnnotationAnnotatedList, r#"creator John, creationYear 2008, mainClass Person"#);
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
    fn import() {
        assert_parse!(Rule::Import, r#"Import: <http://ex.com/owl2/families.owl>"#);
    }

    #[test]
    fn individual_clause() {
        assert_parse!(Rule::IndividualClause, r#"Types: Person , hasFirstName value "John" or hasFirstName value "Jack"^^xsd:string"#);
        assert_parse!(Rule::IndividualClause, r#"Facts: hasWife Mary, not hasChild Susan, hasAge 33, hasChild _:child1"#);
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
    }

    #[test]
    fn integer_literal() {
        assert_parse!(Rule::IntegerLiteral, r#"2008"#);
    }

    #[test]
    fn literal() {
        assert_parse!(Rule::Literal, r#"2008"#);
    }

    #[test]
    fn misc() {
        assert_parse!(Rule::Misc, r#"DisjointClasses: Annotations: creator Jonh g:Rock, g:Scissor, g:Paper"#);
    }

    #[test]
    fn prefix() {
        assert_parse!(Rule::PrefixDeclaration, r#"Prefix: : <http://ex.com/owl/families#>"#);
        assert_parse!(Rule::PrefixDeclaration, r#"Prefix: g: <http://ex.com/owl2/families#>"#);
    }

    #[test]
    fn object_property_clause() {
        assert_parse!(Rule::ObjectPropertyClause, "Range: Person, Woman");
        assert_parse!(Rule::ObjectPropertyClause, "SubPropertyOf: hasSpouse, loves");
        assert_parse!(Rule::ObjectPropertyClause, "EquivalentTo: isMarriedTo");
        assert_parse!(Rule::ObjectPropertyClause, "DisjointWith: hates");
        assert_parse!(Rule::ObjectPropertyClause, "InverseOf: hasSpouse, inverse hasSpouse");
    }

    #[test]
    fn object_property_expression() {
        assert_parse!(Rule::ObjectPropertyExpression, "hasSpouse");
        assert_parse!(Rule::ObjectPropertyExpression, "inverse hasSpouse");
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
    }

    #[test]
    fn object_property_iri() {
        assert_parse!(Rule::ObjectPropertyIRI, r#"hasChild"#);
    }

    #[test]
    fn quoted_string() {
        assert_parse!(Rule::QuotedString, r#""gene_ontology""#);
    }


}
