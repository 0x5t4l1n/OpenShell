// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A sandbox's stable SPIFFE identity, delegated by SPIRE to a shared supervisor.
//!
//! A supervisor that hosts several sandboxes cannot use its own Workload API
//! identity for provider token grants: that identity names the supervisor,
//! not the sandbox. Instead, the SPIRE agent authorizes the supervisor as a
//! delegate on a private admin socket, and the supervisor asks that agent for
//! the JWT-SVID registered for one sandbox.
//!
//! The supervisor asks only for the sandbox its session is authorized as:
//!
//! 1. The session's current gateway JWT must verify against the gateway's
//!    session keys (algorithm, type, issuer, audience, lifetime) and name
//!    exactly the registered sandbox, runtime generation, and credential
//!    epoch. A revoked session has no JWT.
//! 2. Before issuance, an authenticated gateway call confirms that the
//!    gateway still accepts the session as the sandbox's current generation.
//! 3. The agent is asked for the single selector that names this gateway and
//!    sandbox. Exactly one JWT-SVID with the expected SPIFFE ID must come
//!    back; it is verified against the agent's JWT bundle for the expected
//!    trust domain, audience, and expiry. Nothing falls back to another
//!    identity.
//!
//! The SPIFFE ID is derived from the immutable sandbox ID, so it survives
//! restarts and runtime replacement, while each generation must earn its own
//! authorization. SVIDs and the agent socket never leave the supervisor.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use openshell_core::grpc_client::GatewayEndpoint;
use openshell_core::jwt::{CredentialEpoch, SandboxId, SessionJwtVerifier};
use openshell_core::sandbox_generation::SandboxGenerationId;
use openshell_core::spiffe::SandboxSpiffeIdPrefix;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};

/// SPIRE selector type of the registration entries for sandbox identities.
pub const SPIRE_SELECTOR_TYPE: &str = "openshell";

/// Bound on one exchange with the SPIRE agent.
const AGENT_CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on confirming the session's authorization with the gateway.
const GATEWAY_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);

/// Value of the one selector naming `sandbox_id` under `gateway_id`. Both IDs
/// are SPIFFE path segments, which cannot contain `:`.
#[must_use]
pub fn spire_selector_value(gateway_id: &str, sandbox_id: &str) -> String {
    format!("sandbox:{gateway_id}:{sandbox_id}")
}

/// Trusted inputs for one session's delegated sandbox identity.
pub struct DelegatedIdentityConfig {
    /// SPIRE agent admin socket that authorizes this supervisor as a delegate.
    pub admin_socket: PathBuf,
    pub spiffe_id_prefix: SandboxSpiffeIdPrefix,
    /// Gateway that issued the session's credentials; part of the SPIFFE ID.
    pub gateway_id: String,
    /// Verifies the session's gateway JWTs, from the gateway's launch keys.
    pub gateway_verifier: SessionJwtVerifier,
    pub sandbox_id: SandboxId,
    pub runtime_generation: SandboxGenerationId,
    pub auth_epoch: CredentialEpoch,
}

impl std::fmt::Debug for DelegatedIdentityConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedIdentityConfig")
            .field("admin_socket", &self.admin_socket)
            .field("spiffe_id_prefix", &self.spiffe_id_prefix)
            .field("gateway_id", &self.gateway_id)
            .field("sandbox_id", &self.sandbox_id)
            .field("runtime_generation", &self.runtime_generation)
            .field("auth_epoch", &self.auth_epoch)
            .finish_non_exhaustive()
    }
}

/// One session's delegated identity and the gateway access that authorizes it.
pub(crate) struct DelegatedSandboxIdentity {
    config: DelegatedIdentityConfig,
    gateway: GatewayEndpoint,
    sandbox_name: String,
    spiffe_id: String,
}

impl DelegatedSandboxIdentity {
    pub(crate) fn new(
        config: DelegatedIdentityConfig,
        gateway: GatewayEndpoint,
        sandbox_name: String,
    ) -> Result<Self, TokenGrantFailure> {
        let spiffe_id = config
            .spiffe_id_prefix
            .sandbox_spiffe_id(&config.gateway_id, config.sandbox_id.as_str())
            .map_err(|_| configuration_failure())?;
        if sandbox_name.is_empty() {
            return Err(configuration_failure());
        }
        Ok(Self {
            config,
            gateway,
            sandbox_name,
            spiffe_id,
        })
    }

    /// Verify that the session's current gateway JWT names this sandbox
    /// generation. A revoked, expired, non-expiring, or mismatched JWT fails.
    pub(crate) fn authorize(&self) -> Result<(), TokenGrantFailure> {
        let token = self
            .gateway
            .credentials()
            .current_gateway_token()
            .ok_or_else(identity_rejected)?;
        let session = self
            .config
            .gateway_verifier
            .verify(token.expose_secret())
            .map_err(|_| identity_rejected())?;
        if session.sandbox_id != self.config.sandbox_id
            || session.runtime_generation != self.config.runtime_generation
            || session.auth_epoch != self.config.auth_epoch
            || session.expires_at == 0
        {
            return Err(identity_rejected());
        }
        Ok(())
    }

    /// Obtain this sandbox's JWT-SVID for `audience`.
    ///
    /// The session is re-authorized after every wait, so a session removed
    /// meanwhile neither reaches the agent nor receives an SVID.
    pub(crate) async fn fetch_jwt_svid(&self, audience: &str) -> Result<String, TokenGrantFailure> {
        self.authorize()?;
        tokio::time::timeout(
            GATEWAY_CONFIRM_TIMEOUT,
            openshell_core::grpc_client::confirm_session_authorization(
                &self.gateway,
                &self.sandbox_name,
            ),
        )
        .await
        .map_err(|_| {
            TokenGrantFailure::new(TokenGrantFailureKind::Timeout, TokenGrantStage::GatewayRpc)
        })??;
        self.authorize()?;
        let selector = wire::Selector {
            r#type: SPIRE_SELECTOR_TYPE.to_string(),
            value: spire_selector_value(&self.config.gateway_id, self.config.sandbox_id.as_str()),
        };
        let mut agent = AdminClient::connect(&self.config.admin_socket).await?;
        self.authorize()?;
        let response = agent
            .fetch_jwt_svids(wire::FetchJwtSvidsRequest {
                audience: vec![audience.to_string()],
                selectors: vec![selector],
                pid: 0,
            })
            .await?;
        // One registration entry per sandbox; anything else is a
        // registration error, never a choice for the supervisor to make.
        let [svid] = response.svids.as_slice() else {
            return Err(identity_rejected());
        };
        let reported = svid
            .id
            .as_ref()
            .map(|id| format!("spiffe://{}{}", id.trust_domain, id.path));
        if reported.as_deref() != Some(self.spiffe_id.as_str()) {
            return Err(identity_rejected());
        }
        let bundles = agent.jwt_bundles(&self.config.spiffe_id_prefix).await?;
        let verified = spiffe::JwtSvid::parse_and_validate(&svid.token, &bundles, &[audience])
            .map_err(|_| identity_rejected())?;
        if verified.spiffe_id().to_string() != self.spiffe_id {
            return Err(identity_rejected());
        }
        self.authorize()?;
        Ok(svid.token.clone())
    }
}

fn configuration_failure() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Configuration,
    )
}

fn identity_rejected() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::WorkloadIdentityRejected,
        TokenGrantStage::WorkloadIdentity,
    )
}

fn agent_failure(kind: TokenGrantFailureKind) -> TokenGrantFailure {
    TokenGrantFailure::new(kind, TokenGrantStage::WorkloadIdentity)
}

fn status_failure(status: &tonic::Status) -> TokenGrantFailure {
    // Classify only by code; the agent's message is not retained.
    agent_failure(match status.code() {
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            TokenGrantFailureKind::WorkloadIdentityRejected
        }
        tonic::Code::DeadlineExceeded => TokenGrantFailureKind::Timeout,
        tonic::Code::Unavailable => TokenGrantFailureKind::Unavailable,
        tonic::Code::InvalidArgument | tonic::Code::Unimplemented => {
            TokenGrantFailureKind::Configuration
        }
        _ => TokenGrantFailureKind::Unclassified,
    })
}

/// Client for the SPIRE agent's Delegated Identity API.
struct AdminClient {
    grpc: tonic::client::Grpc<tonic::transport::Channel>,
}

impl AdminClient {
    async fn connect(socket: &std::path::Path) -> Result<Self, TokenGrantFailure> {
        // Delegation is authorized by the agent attesting this process over
        // a local socket; a TCP endpoint could not attest it.
        if !socket.is_absolute() {
            return Err(configuration_failure());
        }
        let endpoint =
            spiffe::transport::endpoint::Endpoint::parse(&format!("unix:{}", socket.display()))
                .map_err(|_| configuration_failure())?;
        let channel = tokio::time::timeout(
            AGENT_CALL_TIMEOUT,
            spiffe::transport::connector::connect(&endpoint),
        )
        .await
        .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))?
        .map_err(|_| agent_failure(TokenGrantFailureKind::Unavailable))?;
        Ok(Self {
            grpc: tonic::client::Grpc::new(channel),
        })
    }

    async fn fetch_jwt_svids(
        &mut self,
        request: wire::FetchJwtSvidsRequest,
    ) -> Result<wire::FetchJwtSvidsResponse, TokenGrantFailure> {
        tokio::time::timeout(AGENT_CALL_TIMEOUT, async {
            self.ready().await?;
            self.grpc
                .unary(
                    tonic::Request::new(request),
                    http::uri::PathAndQuery::from_static(wire::FETCH_JWT_SVIDS),
                    tonic_prost::ProstCodec::default(),
                )
                .await
                .map(tonic::Response::into_inner)
                .map_err(|status| status_failure(&status))
        })
        .await
        .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))?
    }

    /// The agent's current JWT bundle for the prefix's trust domain only.
    async fn jwt_bundles(
        &mut self,
        prefix: &SandboxSpiffeIdPrefix,
    ) -> Result<spiffe::JwtBundleSet, TokenGrantFailure> {
        let trust_domain = openshell_core::spiffe::trust_domain(prefix.as_str())
            .and_then(|name| spiffe::TrustDomain::new(name).ok())
            .ok_or_else(configuration_failure)?;
        let response: wire::SubscribeToJwtBundlesResponse =
            tokio::time::timeout(AGENT_CALL_TIMEOUT, async {
                self.ready().await?;
                let mut stream = self
                    .grpc
                    .server_streaming(
                        tonic::Request::new(wire::SubscribeToJwtBundlesRequest {}),
                        http::uri::PathAndQuery::from_static(wire::SUBSCRIBE_TO_JWT_BUNDLES),
                        tonic_prost::ProstCodec::default(),
                    )
                    .await
                    .map_err(|status| status_failure(&status))?
                    .into_inner();
                stream
                    .message()
                    .await
                    .map_err(|status| status_failure(&status))?
                    .ok_or_else(|| agent_failure(TokenGrantFailureKind::Unavailable))
            })
            .await
            .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))??;
        let jwks = response
            .bundles
            .get(&trust_domain.id_string())
            .ok_or_else(identity_rejected)?;
        let bundle = spiffe::JwtBundle::from_jwt_authorities(trust_domain, jwks)
            .map_err(|_| identity_rejected())?;
        let mut bundles = spiffe::JwtBundleSet::new();
        bundles.add_bundle(bundle);
        Ok(bundles)
    }

    async fn ready(&mut self) -> Result<(), TokenGrantFailure> {
        self.grpc
            .ready()
            .await
            .map_err(|_| agent_failure(TokenGrantFailureKind::Unavailable))
    }
}

/// Wire messages of the SPIRE agent Delegated Identity API.
///
/// Transcribed from `proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto`
/// and `proto/spire/api/types/{selector,jwtsvid,spiffeid}.proto` of
/// <https://github.com/spiffe/spire-api-sdk> at tag `v1.15.3` (commit
/// `adb81b3b0fb87a881693d1d42eaf8b2fa1223e42`), Copyright The SPIFFE Authors,
/// licensed under the Apache License, Version 2.0. Only the messages for
/// `FetchJWTSVIDs` and `SubscribeToJWTBundles` are reproduced; field numbers
/// and types are unchanged.
mod wire {
    use super::HashMap;

    pub(super) const FETCH_JWT_SVIDS: &str =
        "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/FetchJWTSVIDs";
    pub(super) const SUBSCRIBE_TO_JWT_BUNDLES: &str =
        "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles";

    /// `spire.api.types.Selector`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct Selector {
        #[prost(string, tag = "1")]
        pub r#type: String,
        #[prost(string, tag = "2")]
        pub value: String,
    }

    /// `spire.api.types.SPIFFEID`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct SpiffeId {
        #[prost(string, tag = "1")]
        pub trust_domain: String,
        #[prost(string, tag = "2")]
        pub path: String,
    }

    /// `spire.api.types.JWTSVID`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct JwtSvid {
        #[prost(string, tag = "1")]
        pub token: String,
        #[prost(message, optional, tag = "2")]
        pub id: Option<SpiffeId>,
        #[prost(int64, tag = "3")]
        pub expires_at: i64,
        #[prost(int64, tag = "4")]
        pub issued_at: i64,
        #[prost(string, tag = "5")]
        pub hint: String,
    }

    /// `spire.api.agent.delegatedidentity.v1.FetchJWTSVIDsRequest`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct FetchJwtSvidsRequest {
        #[prost(string, repeated, tag = "1")]
        pub audience: Vec<String>,
        #[prost(message, repeated, tag = "2")]
        pub selectors: Vec<Selector>,
        #[prost(int32, tag = "3")]
        pub pid: i32,
    }

    /// `spire.api.agent.delegatedidentity.v1.FetchJWTSVIDsResponse`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct FetchJwtSvidsResponse {
        #[prost(message, repeated, tag = "1")]
        pub svids: Vec<JwtSvid>,
    }

    /// `spire.api.agent.delegatedidentity.v1.SubscribeToJWTBundlesRequest`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct SubscribeToJwtBundlesRequest {}

    /// `spire.api.agent.delegatedidentity.v1.SubscribeToJWTBundlesResponse`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct SubscribeToJwtBundlesResponse {
        #[prost(map = "string, bytes", tag = "1")]
        pub bundles: HashMap<String, Vec<u8>>,
    }
}

#[cfg(test)]
mod spire_tests;
