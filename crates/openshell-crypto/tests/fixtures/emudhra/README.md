# eMudhra certificate fixtures

These public certificates come from [galadran/we-have-a-problem.com](https://github.com/galadran/we-have-a-problem.com/tree/bb7c2a87c5f9157ad83dd8ac32ae90a7e3205274), captured on October 20, 2026. They contain no private keys.

Each `.chain` file contains a server certificate followed by its intermediate certificates. The twelve chains cover the six compromised TLS intermediate keys through both the emSign and Sectigo cross-signing paths. `roots.bundle` contains their emSign ECC Root CA - G3 and AAA Certificate Services trust anchors from the source's `roots.json`.

The regression test deliberately trusts both roots. Removing a root from a bundled store must not be the only protection because an operating system or operator can add it again. The verifier must reject the compromised intermediate keys even when their issuers remain trusted.

Verification uses October 21, 2026 at 00:00:01 UTC, within the certificates' validity periods. A later certificate expiration must not make the test pass for the wrong reason.
