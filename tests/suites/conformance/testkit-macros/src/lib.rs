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
//! the wrapper and passed to `testkit::run`. Parsing lives in `testkit-spec`,
//! which the test runner's catalog also uses.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Ident, ItemFn, LitStr};

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let mut body: ItemFn = syn::parse2(item)?;
    let spec = testkit_spec::parse(attr, &body)?;

    let id = spec.id;
    let id_str = LitStr::new(&id.to_string(), id.span());
    let description = LitStr::new(&spec.description, id.span());
    let requires = spec.requires.iter().map(|capability| {
        let variant = Ident::new(&to_camel_case(&capability.to_string()), capability.span());
        quote!(::testkit::Capability::#variant)
    });

    let vis = body.vis.clone();
    let doc_attrs: Vec<_> = body
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect();
    body.attrs.retain(|attr| !attr.path().is_ident("doc"));
    body.vis = syn::Visibility::Inherited;
    body.sig.ident = format_ident!("body");

    Ok(quote! {
        #(#doc_attrs)*
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
    fn reports_spec_errors() {
        let err = expand_str(
            "",
            "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }",
        )
        .unwrap_err();
        assert!(err.to_string().contains("doc comment"), "{err}");
    }
}
