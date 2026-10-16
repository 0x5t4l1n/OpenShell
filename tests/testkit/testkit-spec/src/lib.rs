// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The single definition of what a `#[testkit::test]` function declares.
//!
//! The `#[testkit::test]` macro and the test runner's catalog both parse
//! tests through this crate, so they cannot disagree about a test's ID,
//! description, or requirements.

use proc_macro2::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, ExprLit, Ident, Item, ItemFn, Lit, Meta, Token, bracketed};

/// What a test declares.
#[derive(Clone, Debug)]
pub struct TestSpec {
    /// The function name, which is the test ID.
    pub id: Ident,
    /// The doc comment, joined into one line.
    pub description: String,
    /// Capability names, as written in `requires = [...]`.
    pub requires: Vec<Ident>,
}

/// Arguments accepted by `#[testkit::test(...)]`.
#[derive(Default)]
struct Args {
    requires: Vec<Ident>,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut args = Self::default();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            if key != "requires" {
                return Err(syn::Error::new(
                    key.span(),
                    format!("unknown argument `{key}`; expected `requires = [...]`"),
                ));
            }
            input.parse::<Token![=]>()?;
            let content;
            bracketed!(content in input);
            args.requires
                .extend(Punctuated::<Ident, Token![,]>::parse_terminated(&content)?);
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(args)
    }
}

/// Parse a test from the attribute's arguments and the function it marks.
pub fn parse(args: TokenStream, item: &ItemFn) -> syn::Result<TestSpec> {
    let args: Args = syn::parse2(args)?;

    if item.sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            item.sig.fn_token,
            "testkit tests must be `async fn`",
        ));
    }
    if item.sig.inputs.len() != 1 {
        return Err(syn::Error::new_spanned(
            &item.sig.inputs,
            "testkit tests take exactly one argument: `cx: &mut testkit::Context`",
        ));
    }

    let description = doc_comment(&item.attrs);
    if description.is_empty() {
        return Err(syn::Error::new(
            item.sig.ident.span(),
            "testkit tests need a doc comment describing the behavior they verify",
        ));
    }

    Ok(TestSpec {
        id: item.sig.ident.clone(),
        description,
        requires: args.requires,
    })
}

/// Find every `#[testkit::test]` function in a source file.
pub fn scan(source: &str) -> syn::Result<Vec<TestSpec>> {
    let file = syn::parse_file(source)?;
    let mut tests = Vec::new();
    for item in &file.items {
        let Item::Fn(item) = item else {
            continue;
        };
        let Some(attr) = item.attrs.iter().find(|attr| is_testkit_test(attr)) else {
            continue;
        };
        let args = match &attr.meta {
            Meta::Path(_) => TokenStream::new(),
            Meta::List(list) => list.tokens.clone(),
            Meta::NameValue(meta) => {
                return Err(syn::Error::new_spanned(
                    meta,
                    "expected `#[testkit::test]` or `#[testkit::test(...)]`",
                ));
            }
        };
        tests.push(parse(args, item)?);
    }
    Ok(tests)
}

fn is_testkit_test(attr: &Attribute) -> bool {
    let segments: Vec<_> = attr.path().segments.iter().collect();
    segments.len() == 2 && segments[0].ident == "testkit" && segments[1].ident == "test"
}

/// The doc comment, joined into one line. Empty if there is none.
pub fn doc_comment(attrs: &[Attribute]) -> String {
    attrs
        .iter()
        .filter_map(|attr| match &attr.meta {
            Meta::NameValue(meta) if meta.path.is_ident("doc") => match &meta.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(line),
                    ..
                }) => Some(line.value().trim().to_string()),
                _ => None,
            },
            _ => None,
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &str, item: &str) -> syn::Result<TestSpec> {
        parse(args.parse().unwrap(), &syn::parse_str(item).unwrap())
    }

    #[test]
    fn parses_id_description_and_requirements() {
        let spec = parse_str(
            "requires = [service_exposure, gpu]",
            "/// First line\n/// second line.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap();
        assert_eq!(spec.id, "t");
        assert_eq!(spec.description, "First line second line.");
        assert_eq!(spec.requires, ["service_exposure", "gpu"]);
    }

    #[test]
    fn rejects_missing_doc_comment() {
        let err = parse_str(
            "",
            "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }

    #[test]
    fn rejects_sync_fn() {
        let err = parse_str(
            "",
            "/// Doc.\nfn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("async fn"), "{err}");
    }

    #[test]
    fn rejects_wrong_arity() {
        let err =
            parse_str("", "/// Doc.\nasync fn t() -> testkit::Result { Ok(()) }").unwrap_err();
        assert!(err.to_string().contains("exactly one argument"), "{err}");
    }

    #[test]
    fn rejects_unknown_argument() {
        let err = parse_str(
            "timeout = [x]",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown argument"), "{err}");
    }

    #[test]
    fn scans_only_testkit_tests() {
        let tests = scan(
            "
            use testkit::Context;

            /// Plain.
            #[testkit::test]
            async fn plain(cx: &mut Context) -> testkit::Result { Ok(()) }

            /// Needs exposure.
            #[testkit::test(requires = [service_exposure])]
            async fn exposed(cx: &mut Context) -> testkit::Result { Ok(()) }

            #[test]
            fn not_a_testkit_test() {}

            async fn helper(cx: &mut Context) {}
            ",
        )
        .unwrap();
        let ids: Vec<_> = tests.iter().map(|test| test.id.to_string()).collect();
        assert_eq!(ids, ["plain", "exposed"]);
        assert_eq!(tests[1].requires, ["service_exposure"]);
    }

    #[test]
    fn scan_reports_invalid_tests() {
        let err = scan("#[testkit::test]\nasync fn t(cx: &mut Context) {}").unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }
}
