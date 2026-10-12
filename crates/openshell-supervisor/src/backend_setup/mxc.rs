// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted Windows composition of the MXC isolation backend.

use super::{BackendServices, BackendSetup, BuiltBackend, LaunchIdentity, PreparedBackend};
use openshell_core::jwt::SessionBearerTokenSlot;
use openshell_isolation_interface::contract::BackendError;
use openshell_mxc_boundary::backend::{MxcReverseTcpConnector, MxcRuntimeBackend};
use openshell_mxc_boundary::launch::MxcLaunchDescriptor;
use openshell_supervisor_network::run::ProxyListenerConfig;
use std::sync::Arc;

pub(super) struct MxcBackendSetup;

impl BackendSetup for MxcBackendSetup {
    fn backend_name(&self) -> &str {
        openshell_mxc_boundary::BACKEND_NAME
    }

    fn decode(
        &self,
        payload: &[u8],
    ) -> Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        let descriptor = MxcLaunchDescriptor::decode(payload)?;
        let identity = LaunchIdentity {
            sandbox_id: descriptor.runtime.boundary_id.clone(),
            generation: descriptor.runtime.generation.clone(),
            session_id: descriptor.runtime.session_id,
            workload_identity: descriptor.runtime.workload_identity.clone(),
            vm_policy_identity: None,
        };
        Ok((
            identity,
            Box::new(MxcLaunch {
                descriptor,
                connector: Arc::new(MxcReverseTcpConnector::default()),
            }),
        ))
    }
}

struct MxcLaunch {
    descriptor: MxcLaunchDescriptor,
    // Retain the same listener across discovery, attachment, and reconnects.
    connector: Arc<MxcReverseTcpConnector>,
}

#[tonic::async_trait]
impl PreparedBackend for MxcLaunch {
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> Result<(Option<String>, bool), BackendError> {
        openshell_sandbox_backend::OpenShellRuntimeBackend::discover_policy_with_connector(
            self.descriptor.runtime.clone(),
            bearer,
            Some(self.connector.clone()),
        )
        .await
    }

    fn build(self: Box<Self>, services: BackendServices) -> Result<BuiltBackend, BackendError> {
        let payload = self.descriptor.runtime.backend_descriptor()?.payload;
        let proxy = self.descriptor.proxy;
        let identity_cache =
            Arc::new(openshell_supervisor_network::identity::BinaryIdentityCache::new());
        let identity_resolver = Arc::new(move |workload, listener| {
            use openshell_isolation_interface::contract::{
                BinaryIdentity, ExecutableIdentity, ResolveError,
            };
            let (path, pid) =
                openshell_mxc_boundary::socket_owner::resolve_connection_owner(workload, listener)
                    .map_err(ResolveError::Failed)?;
            let hash = identity_cache
                .verify_or_cache(&path)
                .map_err(|error| ResolveError::Failed(error.to_string()))?;
            let digest = hash.parse().map_err(|error| {
                ResolveError::Failed(format!("invalid executable digest: {error}"))
            })?;
            // The connection must still have the same owner after integrity hashing.
            if openshell_mxc_boundary::socket_owner::resolve_connection_owner(workload, listener)
                .map_err(ResolveError::Failed)?
                != (path.clone(), pid)
            {
                return Err(ResolveError::Failed(
                    "proxy socket owner changed during identity resolution".into(),
                ));
            }
            Ok(BinaryIdentity {
                executable: ExecutableIdentity {
                    path,
                    digest: Some(digest),
                },
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            })
        });
        Ok(BuiltBackend {
            payload,
            proxy_listener: Some(ProxyListenerConfig {
                bind_addr: proxy.bind_addr,
                authorization: proxy.authorization.into(),
                identity_resolver,
            }),
            backend: Arc::new(MxcRuntimeBackend::new(
                services.ca_file_paths,
                services.provider_credentials,
                services.sandbox_bearer,
                self.connector,
            )),
        })
    }
}
