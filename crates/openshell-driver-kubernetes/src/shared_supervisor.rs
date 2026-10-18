// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deployment bootstrap only: these replicas cannot host sandbox sessions yet.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Api;
use kube::api::{DeleteParams, Patch, PatchParams, Preconditions};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::config::SharedSupervisorScope;
use crate::{KubernetesComputeDriver, KubernetesDriverError};

const COMPONENT: &str = "shared-supervisor";
const FIELD_MANAGER: &str = "openshell-shared-supervisor";
const HEALTH_PORT: u16 = 5501;

fn identity(gateway: &str, workspace: Option<&str>) -> (String, BTreeMap<String, String>) {
    let scope = workspace.map_or("gateway", |_| "workspace");
    let digest = Sha256::digest(format!(
        "{gateway}\0{scope}\0{}",
        workspace.unwrap_or_default()
    ));
    let name = format!("os-shared-{digest:x}");
    let name = name[..42].to_string();
    let mut labels = BTreeMap::from([
        ("openshell.ai/managed-by".into(), "openshell".into()),
        ("openshell.ai/component".into(), COMPONENT.into()),
        ("openshell.ai/gateway-id".into(), gateway.into()),
        ("openshell.ai/supervisor-scope".into(), scope.into()),
        ("openshell.ai/supervisor-pool".into(), name.clone()),
    ]);
    if let Some(workspace) = workspace {
        labels.insert("openshell.ai/workspace".into(), workspace.into());
    }
    (name, labels)
}

impl KubernetesComputeDriver {
    fn shared_supervisor_namespace(
        &self,
        workspace: &str,
    ) -> Result<String, KubernetesDriverError> {
        self.validate_workspace_namespace(workspace)?;
        self.config
            .namespace_for_workspace(workspace, self.operator_allowlist())
            .map_err(KubernetesDriverError::Precondition)
    }

    pub(crate) async fn ensure_workspace_supervisor(
        &self,
        workspace: &str,
    ) -> Result<(), KubernetesDriverError> {
        if self.config.shared_supervisor.enabled
            && self.config.shared_supervisor.scope == SharedSupervisorScope::Workspace
        {
            let namespace = self.shared_supervisor_namespace(workspace)?;
            self.ensure_shared_supervisor(&namespace, Some(workspace))
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn ensure_shared_supervisor(
        &self,
        namespace: &str,
        workspace: Option<&str>,
    ) -> Result<(), KubernetesDriverError> {
        let (name, labels) = identity(&self.config.gateway_id, workspace);
        let api = Api::<Deployment>::namespaced(self.client.clone(), namespace);
        if let Some(existing) = api
            .get_opt(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            && !labels.iter().all(|(key, value)| {
                existing
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|actual| actual.get(key))
                    == Some(value)
            })
        {
            return Err(KubernetesDriverError::Precondition(format!(
                "shared supervisor Deployment {name} has a different owner"
            )));
        }
        let (uid, gid, _) = self.resolve_sandbox_identity_in_namespace(namespace).await;
        let mut args = vec![
            "shared".to_string(),
            "--gateway-id".into(),
            self.config.gateway_id.clone(),
            "--scope".into(),
            if workspace.is_some() {
                "workspace"
            } else {
                "gateway"
            }
            .into(),
        ];
        if let Some(workspace) = workspace {
            args.extend(["--workspace".into(), workspace.into()]);
        }
        let mut container = json!({
            "name": "supervisor", "image": self.config.supervisor_image, "args": args,
            "securityContext": { "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
                "capabilities": { "drop": ["ALL"] } },
            "ports": [{ "name": "health", "containerPort": HEALTH_PORT }],
            "readinessProbe": { "tcpSocket": { "port": "health" }, "periodSeconds": 2 },
            "livenessProbe": { "tcpSocket": { "port": "health" }, "periodSeconds": 10 },
            "resources": { "requests": { "cpu": "10m", "memory": "32Mi" }, "limits": { "memory": "128Mi" } }
        });
        if let Some(policy) = self.config.supervisor_image_pull_policy {
            container["imagePullPolicy"] = json!(policy.as_kubernetes_str());
        }
        let deployment = json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": { "name": name, "namespace": namespace, "labels": labels },
            "spec": { "replicas": 1, "selector": { "matchLabels": labels },
                "template": { "metadata": { "labels": labels }, "spec": {
                    "automountServiceAccountToken": false,
                    "securityContext": { "runAsNonRoot": true, "runAsUser": uid, "runAsGroup": gid,
                        "seccompProfile": { "type": "RuntimeDefault" } },
                    "imagePullSecrets": self.config.image_pull_secrets.iter().map(|name| json!({ "name": name })).collect::<Vec<_>>(),
                    "terminationGracePeriodSeconds": 10, "containers": [container]
                } }
            }
        });
        let deployment = api
            .patch(
                &name,
                &PatchParams::apply(FIELD_MANAGER),
                &Patch::Apply(&deployment),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let policy = json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": { "name": name, "namespace": namespace,
                "ownerReferences": [{ "apiVersion": "apps/v1", "kind": "Deployment", "name": name,
                    "uid": deployment.metadata.uid, "controller": true }] },
            "spec": { "podSelector": { "matchLabels": labels },
                "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": [] }
        });
        Api::<NetworkPolicy>::namespaced(self.client.clone(), namespace)
            .patch(
                &name,
                &PatchParams::apply(FIELD_MANAGER),
                &Patch::Apply(&policy),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        tracing::info!(%namespace, deployment = %name, ?workspace, "Ensured idle shared supervisor Deployment");
        Ok(())
    }

    pub(crate) async fn delete_workspace_supervisor(
        &self,
        workspace: &str,
    ) -> Result<(), KubernetesDriverError> {
        if !self.config.shared_supervisor.enabled
            || self.config.shared_supervisor.scope != SharedSupervisorScope::Workspace
        {
            return Ok(());
        }
        let namespace = self.shared_supervisor_namespace(workspace)?;
        let (name, labels) = identity(&self.config.gateway_id, Some(workspace));
        let api = Api::<Deployment>::namespaced(self.client.clone(), &namespace);
        if let Some(deployment) = api
            .get_opt(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
        {
            if !labels.iter().all(|(key, value)| {
                deployment
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|actual| actual.get(key))
                    == Some(value)
            }) {
                return Err(KubernetesDriverError::Precondition(format!(
                    "shared supervisor Deployment {name} has a different owner"
                )));
            }
            let params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: deployment.metadata.uid,
                    resource_version: deployment.metadata.resource_version,
                }),
                ..Default::default()
            };
            match api.delete(&name, &params).await {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
        }
        Ok(())
    }
}
