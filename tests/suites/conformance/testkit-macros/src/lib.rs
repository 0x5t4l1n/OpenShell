// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `#[testkit::test]` attribute.
//!
//! A conformance test is an `async fn` taking `&mut testkit::Context` and
//! returning `testkit::Result`. Its doc comment is the test's description and
//! is required. The function name is the test ID. Requirements are named
//! after target capabilities:
//!
//! ```ignore
//! /// An exposed loopback HTTP service is reachable and goes away after delete.
//! #[testkit::test(requires = [service_exposure])]
//! async fn expose_service(cx: &mut Context) -> testkit::Result { /* ... */ }
//! ```
//!
//! The attribute expands to a `#[tokio::test]` wrapper with the same name, so
//! the nextest test name is the test ID. The original function is nested in
//! the wrapper and passed to `testkit::run`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Expr, ExprLit, Ident, ItemFn, Lit, LitStr, Meta, Token, bracketed};

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
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

fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let args: Args = syn::parse2(attr)?;
    let mut body: ItemFn = syn::parse2(item)?;

    if body.sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            body.sig.fn_token,
            "conformance tests must be `async fn`",
        ));
    }
    if body.sig.inputs.len() != 1 {
        return Err(syn::Error::new_spanned(
            &body.sig.inputs,
            "conformance tests take exactly one argument: `cx: &mut testkit::Context`",
        ));
    }

    let id = body.sig.ident.clone();
    let description = description(&body)?;
    let requires = args.requires.iter().map(|capability| {
        let variant = Ident::new(&to_camel_case(&capability.to_string()), capability.span());
        quote!(::testkit::Capability::#variant)
    });

    let vis = body.vis.clone();
    let wrapper_attrs: Vec<_> = body
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect();
    body.attrs.retain(|attr| !attr.path().is_ident("doc"));
    body.vis = syn::Visibility::Inherited;
    body.sig.ident = format_ident!("body");
    let id_str = LitStr::new(&id.to_string(), id.span());

    Ok(quote! {
        #(#wrapper_attrs)*
        #[::testkit::__private::tokio::test(crate = "::testkit::__private::tokio")]
        #vis async fn #id() {
            #body
            ::testkit::run(
                ::testkit::TestInfo {
                    id: #id_str,
                    description: #description,
                    requires: &[#(#requires),*],
                },
                body,
            )
            .await;
        }
    })
}

/// The test description: the doc comment, joined into one line.
fn description(item: &ItemFn) -> syn::Result<LitStr> {
    let lines: Vec<String> = item
        .attrs
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
        .collect();

    if lines.is_empty() {
        return Err(syn::Error::new(
            item.sig.ident.span(),
            "conformance tests need a doc comment describing the behavior they verify",
        ));
    }
    Ok(LitStr::new(&lines.join(" "), Span::call_site()))
}

fn to_camel_case(snake: &str) -> String {
    snake
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::expand;

    fn expand_str(attr: &str, item: &str) -> syn::Result<String> {
        expand(attr.parse().unwrap(), item.parse().unwrap()).map(|tokens| tokens.to_string())
    }

    #[test]
    fn expands_to_wrapper_with_same_name() {
        let out = expand_str(
            "",
            "/// Does a thing.\nasync fn does_a_thing(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap();
        assert!(out.contains("async fn does_a_thing ()"), "{out}");
        assert!(out.contains("async fn body (cx : & mut Context)"), "{out}");
        assert!(out.contains("id : \"does_a_thing\""), "{out}");
        assert!(out.contains("description : \"Does a thing.\""), "{out}");
    }

    #[test]
    fn joins_multi_line_doc_comments() {
        let out = expand_str(
            "",
            "/// First line\n/// second line.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap();
        assert!(out.contains("\"First line second line.\""), "{out}");
    }

    #[test]
    fn maps_requirements_to_capabilities() {
        let out = expand_str(
            "requires = [service_exposure, gpu]",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap();
        assert!(
            out.contains(
                "requires : & [:: testkit :: Capability :: ServiceExposure , :: testkit :: Capability :: Gpu]"
            ),
            "{out}"
        );
    }

    #[test]
    fn rejects_missing_doc_comment() {
        let err = expand_str(
            "",
            "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }

    #[test]
    fn rejects_sync_fn() {
        let err = expand_str(
            "",
            "/// Doc.\nfn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("async fn"), "{err}");
    }

    #[test]
    fn rejects_wrong_arity() {
        let err =
            expand_str("", "/// Doc.\nasync fn t() -> testkit::Result { Ok(()) }").unwrap_err();
        assert!(err.to_string().contains("exactly one argument"), "{err}");
    }

    #[test]
    fn rejects_unknown_argument() {
        let err = expand_str(
            "timeout = [x]",
            "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown argument"), "{err}");
    }
}
