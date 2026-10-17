# 0003. YAML allow/deny rules instead of Rego or CEL
Status: accepted
Date: 2026-10-17

## Context
Access rules decide who reaches which route. They are reviewed by security and platform people, not only developers, and a policy bug is an access-control bug.

## Options
1. Rego (OPA). Very expressive. A language to learn, evaluation-time errors, and a heavy dependency.
2. CEL expressions. Expressive and fast. Still code in YAML strings; reviewers must read expressions.
3. Declarative YAML: host plus segment-aware prefix routes, `deny` before `allow`, conditions on groups, subjects, emails, email domains, claims, methods and path prefixes. Strict parsing; rules without conditions are rejected.

## Decision
Option 3. It covers the BeyondCorp rules this gateway targets, has no evaluation-time failure modes, and a reviewer can read it without knowing a language.

## Consequences
- About 110 ns and zero allocations per decision.
- Hot reload on SIGHUP swaps the policy atomically and keeps the old one if the new file is invalid.
- Rules that need computation (time windows, risk scores) are not expressible. `policy.Evaluate` is the seam for a CEL backend if that need appears.
