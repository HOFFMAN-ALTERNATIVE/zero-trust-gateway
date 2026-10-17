# 0001. Standard-library crypto instead of a JOSE library
Status: accepted
Date: 2026-10-17

## Context
The gateway must verify OIDC ID tokens and access tokens on every request. JWT verification is a well-known source of auth bypasses: `alg: none`, HS256 signed with the RSA public key, `jku`/`x5u` header fetching, algorithm confusion between key types.

## Options
1. A full JOSE library. Saves code. Brings JWE, header-driven key fetching and algorithm negotiation, all attack surface the gateway does not need, and its defaults change between versions.
2. A small verifier on `crypto/*`: fixed asymmetric allow-list (RS256, PS256, ES256, EdDSA), mandatory `kid`, key type pinned to `alg`, `crit` rejected, size cap.

## Decision
Option 2. About 250 lines whose only job is to refuse everything except the shapes we expect are easier to audit than a library's configuration surface.

## Consequences
- Every rejection path has a test (`TestVerifyRejections`), including invalid-curve points.
- New algorithms need code, not configuration. That is intended.
- The code must track spec errata itself; revisit if requirements grow to JWE or nested tokens.
