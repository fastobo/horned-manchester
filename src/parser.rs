use super::error::Result;
use pest::iterators::Pairs;

/// The OWL2 Manchester Syntax parser.
///
/// You shouldn't have to use this type directly: instead, use the top level
/// `parse` function to parse an ontology document.
#[derive(Debug, Parser)]
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
    fn namespace() {
        assert_parse!(Rule::Namespace, r#"Namespace: <http://ex.com/owl/families#>"#);
    }

    #[test]
    fn import() {
        assert_parse!(Rule::Import, r#"Import: <http://ex.com/owl2/families.owl>"#);
    }

    #[test]
    fn literal() {
        assert_parse!(Rule::Literal, r#"2008"#);
    }

    #[test]
    fn integer_literal() {
        assert_parse!(Rule::IntegerLiteral, r#"2008"#);
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
        assert_parse!(Rule::AnnotationPropertyURI, r#"creator"#);
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
    }

    #[test]
    fn quoted_string() {
        assert_parse!(Rule::QuotedString, r#""gene_ontology""#);
    }

    #[test]
    fn misc() {
        assert_parse!(Rule::Misc, r#"DisjointClasses: g:Rock, g:Scissor, g:Paper"#);
    }
}
