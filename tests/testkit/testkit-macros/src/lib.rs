// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `#[testkit::test]` attribute.
//!
//! A test is an `async fn` taking `&mut testkit::Context` and returning
//! `testkit::Result`. Its doc comment is the test's description and is
//! required:
//!
//! ```ignore
//! /// An exposed loopback HTTP service is reachable and goes away after delete.
//! #[testkit::test]
//! async fn expose_service(cx: &mut Context) -> testkit::Result { /* ... */ }
//! ```
//!
//! Two arguments are optional:
//!
//! - `id = "t-0123abcd"` gives the test a stable identity that survives
//!   renames and moves, for tools such as waivers and result history.
//! - `requires = [service_exposure, gpu]` names the capabilities the
//!   environment must provide. The test runner leaves the test out of
//!   environments that lack them; a run that reaches the test anyway fails
//!   instead of passing without testing the behavior.
//!
//! The attribute expands to a `#[tokio::test]` wrapper with the same name, so
//! the nextest test name is the function name. The original function is nested
//! in the wrapper and passed to `testkit::run`. Parsing is done by
//! `testkit-spec`, which the test runner's catalog also uses. Other
//! attributes, such as `#[ignore]` or `#[cfg(...)]`, move to the wrapper.
//! `#[should_panic]` is rejected: a testkit test panics on any failure, so it
//! would pass for the wrong reason. Check the expected failure in the body
//! instead.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Attribute, ItemFn, LitStr};

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let mut body: ItemFn = syn::parse2(item)?;
    let spec = testkit_spec::parse(attr, &body)?;
    if let Some(attr) = body.attrs.iter().find(|attr| is_test_attr(attr)) {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[testkit::test]` already makes this a test; remove this attribute",
        ));
    }
    if let Some(attr) = body
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("should_panic"))
    {
        return Err(syn::Error::new_spanned(
            attr,
            "testkit tests panic on any failure, so `#[should_panic]` would pass for the \
             wrong reason; check the expected failure in the body, for example with \
             `CliOutput::failure` and `testkit::ensure!`",
        ));
    }

    let name = body.sig.ident.clone();
    let name_str = LitStr::new(&name.to_string(), name.span());
    let description = LitStr::new(&spec.description, name.span());
    let id = match &spec.id {
        Some(id) => {
            let id = LitStr::new(id, name.span());
            quote! { ::core::option::Option::Some(#id) }
        }
        None => quote! { ::core::option::Option::None },
    };
    let requires = spec
        .requires
        .iter()
        .map(|capability| format_ident!("{}", pascal_case(&capability.to_string())));

    let vis = body.vis.clone();
    let attrs = std::mem::take(&mut body.attrs);
    body.vis = syn::Visibility::Inherited;
    body.sig.ident = format_ident!("body");

    Ok(quote! {
        #(#attrs)*
        #[::testkit::__private::tokio::test(crate = "::testkit::__private::tokio")]
        #vis async fn #name() {
            #body
            ::testkit::run(
                ::testkit::TestInfo {
                    name: #name_str,
                    id: #id,
                    description: #description,
                    requires: &[#(::testkit::Capability::#requires),*],
                },
                body,
            )
            .await;
        }
    })
}

/// `#[test]`, `#[tokio::test]`, or another test attribute.
fn is_test_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
}

/// `service_exposure` as `ServiceExposure`, the name of the `Capability`
/// variant.
fn pascal_case(snake: &str) -> String {
    snake
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{expand, pascal_case};

    fn expand_str(attr: &str, item: &str) -> syn::Result<String> {
        expand(attr.parse().unwrap(), item.parse().unwrap()).map(|tokens| tokens.to_string())
    }

    const ITEM: &str = "/// Doc.\nasync fn t(cx: &mut Context) -> testkit::Result { Ok(()) }";

    #[test]
    fn carries_id_and_requirements() {
        let out = expand_str(
            "id = \"t-0123abcd\", requires = [service_exposure, gpu]",
            ITEM,
        )
        .unwrap();
        assert!(out.contains("Some (\"t-0123abcd\")"), "{out}");
        assert!(
            out.contains(
                "requires : & [:: testkit :: Capability :: ServiceExposure , :: testkit :: Capability :: Gpu]"
            ),
            "{out}"
        );
    }

    // A suite only compiles correct tests, so it never reaches these errors.
    #[test]
    fn rejects_misuse() {
        let ok_fn = "async fn t(cx: &mut Context) -> testkit::Result { Ok(()) }";
        for (attr, item, error) in [
            ("id = \"nope\"", ITEM.to_string(), "test IDs are"),
            (
                "requires = [teleport]",
                ITEM.to_string(),
                "unknown capability",
            ),
            ("speed = fast", ITEM.to_string(), "unknown argument"),
            ("", ok_fn.to_string(), "doc comment"),
            (
                "",
                "/// Doc.\nfn t(cx: &mut Context) -> testkit::Result { Ok(()) }".to_string(),
                "async fn",
            ),
            (
                "",
                "/// Doc.\nasync fn t() -> testkit::Result { Ok(()) }".to_string(),
                "exactly one argument",
            ),
            (
                "",
                format!("/// Doc.\n#[tokio::test]\n{ok_fn}"),
                "already makes this a test",
            ),
            (
                "",
                format!("/// Doc.\n#[should_panic]\n{ok_fn}"),
                "`#[should_panic]`",
            ),
        ] {
            let err = expand_str(attr, &item).unwrap_err();
            assert!(err.to_string().contains(error), "{item}: {err}");
        }
    }

    #[test]
    fn names_variants_in_pascal_case() {
        assert_eq!(pascal_case("gpu"), "Gpu");
        assert_eq!(pascal_case("persistent_workspace"), "PersistentWorkspace");
    }
}
