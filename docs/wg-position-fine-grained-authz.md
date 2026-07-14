# Capability leases as prior art for fine-grained MCP authorization

> Position note for the MCP Fine-Grained Authorization WG (`#auth-wg-fine-grained-authz`). JJ / TomCruiseTorpedo, 2026-07. One page. Repos: [leasebroker](https://github.com/TomCruiseTorpedo/leasebroker) (broker + enforcement), [gatewarden](https://github.com/TomCruiseTorpedo/gatewarden) (gateway composition), [mcp-fit](https://github.com/TomCruiseTorpedo/mcp-fit) (server scoring — adjacent, not authz).

## Problem alignment

The WG charter targets authorization granularity beyond OAuth scope strings. Two artifacts already in the project's orbit describe the same need: issue #2852 (scoped execution receipts — gateway-issued, time-boxed, single-use, signed, bound to the exact call) and the RFC 9396 RAR direction named in the charter. We have been running an implementation of this shape since June 2026; the #2852 thread has since converged with it on the semantics (see the exchange there), and surfaced the design fork this WG is positioned to resolve: **provider-declared binding requirements vs gateway-side binding**. Our two protocol lanes demonstrate one model each — the A2A lane is provider-declared (agent card carries the lease extension at `capabilities.extensions[]`, `required: true`, protocol-level rejection of non-declaring clients), the MCP lane is gateway-bound (tool metadata has no declaration slot today — the gap SEP-1488/SEP-2385 circle). Same signed grant underneath: the models compose rather than fork.

## What is implemented (all open source, TypeScript, 313-test suite; `leasebroker@0.3.0` on npm)

| Semantic | Implementation | Status |
|---|---|---|
| Time-boxed grant | `Lease{issuedAt, expiresAt}`; expiry checked at every use, independent of signature validity | shipped, tested |
| Signed / offline-verifiable | PASETO v4.public (Ed25519), `kid` rotation; encoder validated against the official PASETO test vectors | shipped, tested |
| Scope bound to the concrete call | typed capabilities (`fs.read`/`fs.write` path globs, `http.call` endpoint allow-lists, `spend` caps) resolved per `tools/call` via a declarative tool→action mapping | shipped, tested |
| Mid-flight revocation | `RevocationList` consulted at every use — a cryptographically valid, unexpired lease still denies | shipped, tested |
| Budgeted use (generalizes single-use) | `SpendLedger`: atomic accrual against a cap in integer minor units; over-cap denies | shipped, tested |
| Human approval on high-risk grants | `veto-required` policy effect → pending state; no usable lease exists until approved; deny-until-approved, never block-in-path | shipped, tested |
| Audit binding | hash-chained append-only event log (request/decision/issuance/use/denial/revocation), verified against the hashes AS WRITTEN — never a re-chain | shipped, tested |
| Evidence survivability (external witness) | OpenTimestamps anchoring of the chain tip (`leasebroker anchor`): only the 32-byte tip digest leaves the machine; detached standard `.ots` proofs (verify with the reference `ots` client); local-only verification; verdicts split contradicted (fail-closed) vs damaged (degraded — bit rot is not an attack); a tampered chain refuses to anchor | shipped (v0.3.0), tested; Bitcoin-confirmed attestations verified cross-client |
| Observability composition | opt-in OTel exporter for the audit event stream (`OtelExportingAuditSink`) — governance events land in the OTel pipeline a deployment already runs, instead of a parallel observability surface | shipped (v0.3.0), tested |
| Session binding | lease token → MCP `sessionId` at `initialize` (SDK v1 `extra.sessionId`); no per-call token plumbing | shipped, tested |
| Cross-protocol carriage | the same lease carried over A2A v1.0.1 via a versioned `capabilities.extensions[]` profile (context-binding replaces session-binding; deny ladder; `auth-required` maps the approval pause) | shipped; full-stack live-HTTP test in gatewarden |

Enforcement point: an in-path proxy fronting unmodified downstream servers — the "enterprise gateway" role in #2852's terms. The spec roadmap's gateway/proxy-patterns work (Enterprise Readiness) is the natural home for standardizing what this component may see and assert.

## The boundary our implementation forces, which we think generalizes

**Static claims vs ledger state.** Signature, expiry, and scope are static claims — offline-verifiable by anyone holding the public key (a provider could verify the same token today, no broker round-trip). Revocation and spend are *ledger state* that only the enforcement point holds — which is why `single_use`-as-token-property struggles: consumption is inherently ledger state. This maps onto #2852's `signed_or_introspected` exactly: signed covers the static claims; introspection (or trusting the in-path gateway) covers the live ones. External anchoring extends the same boundary one level down: the *audit trail itself* becomes evidence that survives its own custodian — an operator can prove the log existed in its current form before a given Bitcoin block, with zero infrastructure and nothing but a 32-byte digest ever leaving the machine.

## What we would contribute to the WG

1. **A semantics checklist** any RAR-or-receipt design should cover, each item backed by a shipped implementation and its gotchas: expiry vs signature validity (separate checks), revocation (TTL alone leaves a live window), single-use vs budgeted use, scope-to-call binding for typed argument shapes, approval linkage as a first-class pending state, audit-chain binding (verify stored hashes, never re-chain — we shipped that bug and its fix), evidence survivability against the log's custodian, session/context binding without per-call token plumbing.
2. **Test vectors**: the static set (valid / expired / tampered / out-of-scope) as self-contained PASETO v4.public vectors. Revocation and spend-exhaustion vectors are necessarily **(token, ledger-state) pairs** — defining that two-part vector shape is, we think, a genuinely useful WG artifact. Anchored-evidence vectors (proof ↔ stored-chain agreement, contradicted vs damaged) can ride the same format.
3. **Cross-protocol prior art**: the A2A extension profile (deny ladder, task-state pins, context binding) as evidence the semantics generalize beyond MCP — and as the working example of provider-declared obligation advertisement.
4. **Failure-mode reports** from composing this with a real scorer/gateway (score-at-attach vs live enforcement state; unmapped-tool passthrough semantics; deny-by-default on malformed mappings; the evidence-laundering load bug class).

## What we are explicitly NOT pushing

- Not PASETO as the mandated format — the envelope is swappable behind a `Signer` interface; the semantics are the contribution.
- Not our broker as a required component — #2852's "do not require a specific receipt issuer" non-goal is right, and our own non-goals doc says the same.
- Not OpenTimestamps as the mandated witness — the anchor store is backend-shaped (RFC 3161 TSA addable); "the evidence should survive its custodian" is the requirement, not the mechanism.
- Not core-spec changes — extension/WG-guidance territory per the roadmap's own framing.
