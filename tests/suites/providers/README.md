# Provider suites

End-to-end suites for provider behavior, written on
[testkit](../../testkit/README.md). Each member crate is one suite. Tests run
against whichever gateway the environment registered.

| Suite | Covers |
|---|---|
| `refresh-keycloak` | OAuth refresh of a provider credential against Keycloak, including a revoked grant requiring reauthorization |

`refresh-keycloak` needs a Keycloak issuer and reads
`OPENSHELL_E2E_OIDC_ISSUER`, `OPENSHELL_E2E_OIDC_USERNAME`, and
`OPENSHELL_E2E_OIDC_PASSWORD`. Keycloak is only the provider token issuer; the
gateway itself can use mTLS. Linux only.

Providers and profiles created through the CLI are not cleaned up by testkit.
A test must delete them itself, including when it fails.
