use std::fmt::Write;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens, TokenStreamExt};

/// A helper for generating code blocks for documentation.
///
/// We frequently want to be able to generate code blocks like:
/// ````markdown
/// # Example
/// ```
/// # an_ignored_rust_line();
/// assert!(true);
/// ```
/// ````
///
/// `CodeBlock` lets you generate these examples. Once the fields are filled out, it can be
/// interpolated directly into quoted code, where it will turn into a `#[doc = "..."]` attribute.
#[derive(Default)]
pub struct CodeBlock {
    /// What code should appear before the body?
    ///
    /// This code will be prefixed with a `#` so the user won't see it in the docs.
    pub hidden_prefix: TokenStream,
    /// What's the visible code that should be displayed?
    pub body: TokenStream,
    /// If `true`, then this code block will be marked as `ignore`, and won't be tested as a
    /// doctest.
    pub ignored: bool,
}
impl ToTokens for CodeBlock {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let mut doc = "```".to_string();
        if self.ignored {
            doc.push_str("ignore");
        }
        doc.push('\n');
        for line in self.hidden_prefix.to_string().lines() {
            writeln!(&mut doc, "# {line}").unwrap();
        }
        let body = &self.body;
        let pretty_body = prettyplease::unparse(
            &syn::parse2(quote! {
                fn hack() {
                    #body
                }
            })
            .unwrap(),
        );
        for line in pretty_body
            .trim()
            .strip_prefix("fn hack() {\n")
            .unwrap()
            .strip_suffix('}')
            .unwrap()
            .lines()
        {
            doc.push_str(line.strip_prefix("    ").unwrap_or(line));
            doc.push('\n');
        }
        doc.push_str("```\n");
        tokens.append_all(quote! {
            #[doc = #doc]
        });
    }
}
