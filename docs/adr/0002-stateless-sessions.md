# 0002. Stateless signed sessions
Status: accepted
Date: 2026-10-17

## Context
Browser users log in once through the OIDC code flow; later requests need a session. The gateway should scale horizontally without a shared store.

## Options
1. Server-side sessions in Redis or a database. Instant revocation. Adds a stateful dependency on the request path that every replica needs, and its outage is an auth outage.
2. HMAC-SHA256 signed cookie carrying the identity, `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`, 15 minute TTL, multi-key rotation.

## Decision
Option 2. No shared state on the hot path, and the revocation gap is bounded by a short TTL.

## Consequences
- Revocation takes effect at the next login, at most 15 minutes by default. Policy is still re-evaluated on every request, so removing a route applies immediately.
- Key rotation: the first key signs, all configured keys verify; retire old keys after one TTL.
- Revisit if a deployment needs immediate logout across devices; a small revocation list keyed by session id would be the first step.
