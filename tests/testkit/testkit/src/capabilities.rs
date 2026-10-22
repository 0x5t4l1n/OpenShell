// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What the environment under test provides.
//!
//! Capabilities are data about the environment, not about the gateway, so
//! they do not come from gateway resolution. The runner (or a developer)
//! lists them in `OPENSHELL_TEST_CAPABILITIES`:
//!
//! ```text
//! OPENSHELL_TEST_CAPABILITIES=compute_driver=docker,persistent_workspace,service_exposure
//! ```
//!
//! Entries are comma-separated. `name` provides a capability, `name=false`
//! does not, and `name=value` records a descriptive value such as
//! `compute_driver=docker` that tests can read with [`Capabilities::get`].
//!
//! Only a test that declares `#[testkit::test(requires = [...])]` reads
//! them. Such a test fails, rather than passing without testing anything,
//! when the environment does not provide what it requires. The runner leaves
//! those tests out of environments that lack the capability, so reaching one
//! there means the environment was misdescribed.
//!
//! Adapted from the capabilities of the target file in Evan Lezar's
//! NVIDIA/OpenShell#4629.

use std::collections::BTreeMap;

/// The variable listing the capabilities the environment provides.
pub const CAPABILITIES_ENV: &str = "OPENSHELL_TEST_CAPABILITIES";

/// A capability a test can require with `#[testkit::test(requires = [...])]`.
///
/// Variants are the snake-case requirement names in CamelCase, so an unknown
/// requirement fails to compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// A GPU is available to sandboxes.
    Gpu,
    /// Files in the sandbox workspace survive stop and start. The docs leave
    /// this to the compute driver.
    PersistentWorkspace,
    /// The compute driver runs without root privileges.
    Rootless,
    /// Exposed sandbox services are reachable from the test.
    ServiceExposure,
}

impl Capability {
    /// Every capability.
    pub const ALL: [Self; 4] = [
        Self::Gpu,
        Self::PersistentWorkspace,
        Self::Rootless,
        Self::ServiceExposure,
    ];

    /// The name used in `requires = [...]`, environment definitions and
    /// [`CAPABILITIES_ENV`].
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gpu => "gpu",
            Self::PersistentWorkspace => "persistent_workspace",
            Self::Rootless => "rootless",
            Self::ServiceExposure => "service_exposure",
        }
    }
}

/// The capabilities an environment provides, as listed in
/// [`CAPABILITIES_ENV`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    entries: BTreeMap<String, String>,
}

impl Capabilities {
    /// Read [`CAPABILITIES_ENV`]. `None` when it is not set.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        std::env::var(CAPABILITIES_ENV)
            .ok()
            .map(|value| Self::parse(&value))
    }

    /// Parse the comma-separated form described in the module docs.
    #[must_use]
    pub fn parse(list: &str) -> Self {
        let entries = list
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| match entry.split_once('=') {
                Some((name, value)) => (name.trim().to_string(), value.trim().to_string()),
                None => (entry.to_string(), "true".to_string()),
            })
            .collect();
        Self { entries }
    }

    /// Whether the environment provides `capability`.
    #[must_use]
    pub fn provides(&self, capability: Capability) -> bool {
        self.entries
            .get(capability.name())
            .is_some_and(|value| value != "false")
    }

    /// The value listed for a capability, such as `docker` for
    /// `compute_driver`. `true` for a capability listed without a value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(String::as_str)
    }
}

/// Check that the environment provides every capability in `requires`.
///
/// The caller reads the environment only for a test that has requirements, so
/// a test without them never depends on it. `None` means it was not set.
pub(crate) fn check_requirements(
    requires: &[Capability],
    provided: Option<&Capabilities>,
) -> Result<(), String> {
    if requires.is_empty() {
        return Ok(());
    }
    let names = requires
        .iter()
        .filter(|capability| !provided.is_some_and(|provided| provided.provides(**capability)))
        .map(|capability| capability.name())
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(());
    }
    let hint = if provided.is_none() {
        format!(" ({CAPABILITIES_ENV} is not set)")
    } else {
        String::new()
    };
    Err(format!(
        "requires {}, which the environment does not provide{hint}",
        names.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags_values_and_explicit_false() {
        let capabilities = Capabilities::parse(
            " compute_driver=docker, persistent_workspace ,gpu=false,,service_exposure=true",
        );
        assert_eq!(capabilities.get("compute_driver"), Some("docker"));
        assert!(capabilities.provides(Capability::PersistentWorkspace));
        assert!(capabilities.provides(Capability::ServiceExposure));
        assert!(!capabilities.provides(Capability::Gpu));
        assert!(!capabilities.provides(Capability::Rootless));
        assert_eq!(capabilities.get("arch"), None);
    }

    #[test]
    fn a_test_without_requirements_needs_nothing() {
        assert_eq!(check_requirements(&[], None), Ok(()));
    }

    #[test]
    fn reports_missing_requirements() {
        let provided = Capabilities::parse("gpu");
        let result = check_requirements(
            &[Capability::Gpu, Capability::ServiceExposure],
            Some(&provided),
        );
        assert_eq!(
            result,
            Err("requires service_exposure, which the environment does not provide".to_string())
        );
        assert_eq!(
            check_requirements(&[Capability::Gpu], Some(&provided)),
            Ok(())
        );
    }

    #[test]
    fn an_unset_environment_fails_a_test_that_requires_something() {
        let error = check_requirements(&[Capability::Gpu], None).unwrap_err();
        assert!(error.contains(CAPABILITIES_ENV), "{error}");
        assert!(error.contains("gpu"), "{error}");
    }

    #[test]
    fn variants_match_the_names_the_macro_accepts() {
        let names: Vec<_> = Capability::ALL
            .iter()
            .map(|capability| capability.name())
            .collect();
        assert_eq!(names, testkit_spec::CAPABILITIES);
    }
}
