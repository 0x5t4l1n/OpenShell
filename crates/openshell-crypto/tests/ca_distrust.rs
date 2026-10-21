// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aws-lc")]

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

fn certificates(pem: &str) -> Vec<CertificateDer<'static>> {
    pem::parse_many(pem)
        .unwrap()
        .into_iter()
        .map(|block| {
            assert_eq!(block.tag(), "CERTIFICATE");
            CertificateDer::from(block.into_contents())
        })
        .collect()
}

#[test]
fn compromised_emudhra_keys_are_rejected_even_with_trusted_issuers() {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(include_str!("fixtures/emudhra/roots.bundle")) {
        roots.add(certificate).unwrap();
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        openshell_crypto::tls::configuration_provider(),
    )
    .build()
    .unwrap();
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_792_540_801));
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emudhra");
    let mut checked = 0;

    for entry in std::fs::read_dir(fixtures).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("chain") {
            continue;
        }
        let hostname = path.file_stem().unwrap().to_str().unwrap();
        let server_name = ServerName::try_from(hostname).unwrap();
        let chain = certificates(&std::fs::read_to_string(&path).unwrap());
        let error = verifier
            .verify_server_cert(&chain[0], &chain[1..], &server_name, &[], time)
            .expect_err("compromised intermediate keys must never authenticate a server");
        assert!(
            format!("{error:?}").contains("CertDistrusted"),
            "{hostname} must fail because its key is distrusted: {error:?}"
        );
        checked += 1;
    }

    assert_eq!(checked, 12);
}
