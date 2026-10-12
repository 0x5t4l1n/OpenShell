// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn route(host: &str, address: std::net::SocketAddr, ttl_ms: i64) -> DiscoveredServiceRoute {
    DiscoveredServiceRoute {
        workspace: "default".into(),
        sandbox: "sandbox".into(),
        name: host.into(),
        sandbox_id: "sandbox-id".into(),
        service_id: host.into(),
        hostname: host.into(),
        supervisor_instance_id: address.to_string(),
        runtime_generation: address.to_string(),
        supervisor_app_address: address.to_string(),
        service_revision: 1,
        expires_at: openshell_core::time::timestamp_from_millis(
            openshell_core::time::now_ms() + ttl_ms,
        )
        .ok(),
        ..Default::default()
    }
}

fn tls() -> (TlsAcceptor, TlsConnector) {
    let cert = rcgen::generate_simple_self_signed(vec!["*.svc.openshell.internal".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        TlsAcceptor::from(Arc::new(server)),
        TlsConnector::from(Arc::new(client)),
    )
}

#[tokio::test]
async fn real_tls_sni_selects_distinct_backends_and_withdrawal_closes_stream() {
    let (acceptor, connector) = tls();
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut cache, routes) = RouteCache::new();
    let host_a = "default--a--web.svc.openshell.internal";
    let host_b = "default--b--portal.svc.openshell.internal";
    cache
        .replace(
            "default",
            ServiceRouteSnapshot {
                routes: vec![
                    route(host_a, a.local_addr().unwrap(), 30_000),
                    route(host_b, b.local_addr().unwrap(), 30_000),
                ],
                ..Default::default()
            },
        )
        .unwrap();
    let mut backend_tasks = JoinSet::new();
    for (listener, reply) in [(a, b'A'), (b, b'B')] {
        let acceptor = acceptor.clone();
        backend_tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(socket).await.unwrap();
            stream.write_all(&[reply]).await.unwrap();
            let mut byte = [0];
            // Wait for proxy withdrawal or client close.
            let _ = stream.read(&mut byte).await;
        });
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(serve(listener, routes, 8));
    let mut clients = Vec::new();
    for (host, expected) in [(host_a, b'A'), (host_b, b'B')] {
        let mut client = connector
            .connect(
                ServerName::try_from(host.to_string()).unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        let mut reply = [0];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [expected]);
        clients.push(client);
    }
    cache.withdraw("default");
    for mut client in clients {
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    while backend_tasks.join_next().await.is_some() {}
    proxy.abort();
}

#[tokio::test]
async fn fragmented_client_hello_is_replayed_exactly_and_missing_sni_rejected() {
    let (_, connector) = tls();
    for sni in [true, false] {
        // Generate the real rustls ClientHello and fragment its transport arbitrarily.
        let mut config = connector.config().as_ref().clone();
        config.enable_sni = sni;
        let mut tls = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("default--a--web.svc.openshell.internal").unwrap(),
        )
        .unwrap();
        let mut original = Vec::new();
        tls.write_tls(&mut original).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut receiver, _) = listener.accept().await.unwrap();
        let bytes = original.clone();
        let sending = tokio::spawn(async move {
            for fragment in bytes.chunks(7) {
                sender.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let result = read_sni(&mut receiver).await;
        if sni {
            let (host, replay) = result.unwrap();
            assert_eq!(host, "default--a--web.svc.openshell.internal");
            assert_eq!(replay, original);
        } else {
            assert!(result.is_err());
        }
        sending.await.unwrap();
    }
}

#[tokio::test]
async fn unknown_sni_never_dials_and_expiry_rejects_cached_routes() {
    let (_, connector) = tls();
    let (mut cache, routes) = RouteCache::new();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    cache
        .replace(
            "default",
            ServiceRouteSnapshot {
                routes: vec![route(
                    "default--a--web.svc.openshell.internal",
                    backend.local_addr().unwrap(),
                    -1,
                )],
                ..Default::default()
            },
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(serve(listener, routes, 8));
    assert!(
        connector
            .connect(
                ServerName::try_from("default--a--web.svc.openshell.internal").unwrap(),
                TcpStream::connect(address).await.unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), backend.accept())
            .await
            .is_err()
    );
    proxy.abort();
}

#[tokio::test(start_paused = true)]
async fn cache_lease_renewal_preserves_backend_identity_but_changes_expiry() {
    let (mut cache, routes) = RouteCache::new();
    let host = "default--a--web.svc.openshell.internal";
    let mut declaration = route(host, "127.0.0.1:8443".parse().unwrap(), 30_000);
    cache
        .replace(
            "default",
            ServiceRouteSnapshot {
                routes: vec![declaration.clone()],
                ..Default::default()
            },
        )
        .unwrap();
    let first = selected(&routes, host).unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    declaration.advertisement_revision = 2;
    cache
        .replace(
            "default",
            ServiceRouteSnapshot {
                routes: vec![declaration.clone()],
                ..Default::default()
            },
        )
        .unwrap();
    let renewed = selected(&routes, host).unwrap();
    assert!(first.same_backend(&renewed));
    assert!(renewed.expires > first.expires);
    declaration.service_revision += 1;
    cache
        .replace(
            "default",
            ServiceRouteSnapshot {
                routes: vec![declaration],
                ..Default::default()
            },
        )
        .unwrap();
    assert!(!first.same_backend(&selected(&routes, host).unwrap()));
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(selected(&routes, host).is_err());
}

#[tokio::test]
async fn an_existing_tls_stream_closes_when_discovery_stops_refreshing() {
    let (acceptor, connector) = tls();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut cache, routes) = RouteCache::new();
    let host = "default--a--web.svc.openshell.internal";
    cache
        .replace(
            "default",
            ServiceRouteSnapshot {
                routes: vec![route(host, backend.local_addr().unwrap(), 500)],
                ..Default::default()
            },
        )
        .unwrap();
    let serving = tokio::spawn(async move {
        let (socket, _) = backend.accept().await.unwrap();
        let mut stream = acceptor.accept(socket).await.unwrap();
        stream.write_all(b"A").await.unwrap();
        let mut byte = [0];
        let _ = stream.read(&mut byte).await;
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(serve(listener, routes, 8));
    let mut client = connector
        .connect(
            ServerName::try_from(host).unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    let mut byte = [0];
    client.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, *b"A");
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    serving.await.unwrap();
    proxy.abort();
}
