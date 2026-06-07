# Architecture Decision Records — leasebroker

Single-doc ADR log for fleet run #2. Each ADR is load-bearing; consumers trace to these. Status legend: Accepted / Superseded. Decided 2026-06-07 with the operator; see `specs/lease-broker/spec.md` for the WHAT these realize.

---

## ADR-A — Lease signing / integrity: PASETO v4.public (Ed25519)

**Status:** Accepted.

**Context.** The spec requires leases to be tamper-evident and verifiable at the enforcement point with the least standing trust. The verifier should not be able to *forge* a lease (rules out shared-secret schemes), and verification should work offline from a public key.

**Decision.** Encode each issued lease as a **PASETO v4.public** token — Ed25519-signed, not encrypted (claims are integrity- and authenticity-protected, readable by the verifier). The broker holds the private signing key; enforcement points verify with the public key. The token's claims are the canonical `Lease` fields (id, agent, task, granted capabilities/scope, issuedAt, expiresAt) plus a `kid` for key rotation.

**Implementation (decided 2026-06-07 after dep audit):** build the minimal PASETO **v4.public** construction (PAE pre-authentication encoding + Ed25519 sign/verify + the `v4.public.` framing) **on `@noble/ed25519`** (v3, audited, actively maintained). The canonical `paseto` npm lib is **NOT** used — its last release was 2023-04 (~3 yr stale → no security patch path), unacceptable for a security product. We keep the standardized v4.public *token format* (interop-ready) while depending only on a fresh primitive.

**Alternatives considered.** Canonical `paseto` lib — rejected (stale, see above). `JWT` — rejected: `alg`-confusion and weak-default footguns. Raw `Ed25519` + canonical-JSON (no PASETO framing) — simpler, but we keep PASETO format for the cheap interop option since the cost is one well-tested encoder. `HMAC`/MAC — rejected: symmetric, so any verifier could forge leases.

**Consequences.** Enforcement verifies offline with the public key; no broker round-trip for authenticity. Key rotation via `kid`. The PASETO token IS the wire form of the lease. **Hand-built crypto encoding MUST be validated against the official PASETO v4.public test vectors** — this is a hard acceptance criterion on the signing bead, not optional. All of it sits behind the `Signer` interface, so a future swap (to a maintained lib, or to raw-Ed25519) is non-breaking. Revocation and expiry are checked *separately* (a signed token stays cryptographically valid past expiry/revocation — see ADR-B).

---

## ADR-B — Enforcement model: MCP middleware / proxy

**Status:** Accepted. (Most architecturally load-bearing.)

**Context.** Enforcement must be **guaranteed, not advisory** (spec: out-of-scope actions SHALL be denied). The product governs how agents use tools/MCP servers.

**Decision.** Implement enforcement as **MCP middleware** — a proxy MCP server that fronts one or more downstream MCP servers. It intercepts every `tools/call`, requires a valid lease (bound to the MCP session at handshake; see plan for binding mechanism), and on each call: verifies signature (ADR-A) → checks not-expired → checks not-revoked (`RevocationList`) → checks scope (path globs / allowed endpoints) → checks/accrues spend (`SpendLedger`) → forwards to the downstream server, or denies. Every call emits an audit event.

**Alternatives considered.** Generic call proxy (HTTP/exec) — broader but messier to scope-match and far less demonstrable. SDK/shim — lightest, but advisory (the agent must cooperate) → fails the guarantee requirement.

**Consequences.** In-path = guaranteed enforcement. Downstream MCP servers are unmodified. **Cumulative spend and revocation are mutable state at the enforcement point keyed by lease-id** — the signed lease stays immutable. Pairs with `mcp-fit` (it scores what a server exposes; this controls what an agent may do). The lease-to-session binding mechanism is a plan-level design point.

---

## ADR-C — Policy language: declarative allow-rules, with a Cedar ramp seam

**Status:** Accepted.

**Context.** Deny-by-default least-privilege (spec). For a security product, **auditability beats expressiveness** in v1, but we want a path to a richer policy language without a rewrite.

**Decision.** v1 policy = **declarative allow-rules as data**. Each rule matches on agent / capability-type / scope-constraints and yields an effect (`allow`, optionally `veto-required`); absence of a matching allow = `deny`. Evaluation sits behind a `PolicyEngine` interface (`evaluate(request) → Decision`). Leave a **plumbing seam** so a Cedar-backed engine can implement the same interface later with no consumer changes. Record the seam in `docs/canonical-patterns.md` at the stabilize phase.

**Alternatives considered.** Policy-as-code (TS functions) — introduces code execution into the trust path; rejected. Cedar now — heavier dependency, premature before the rule shapes are known.

**Consequences.** Simple, diffable, auditable rules now; no code-exec in the trust path. Consumers depend only on `PolicyEngine` (contract-first), so the Cedar drop-in is non-breaking. The rule-match primitive is canonical — `seam-map` entry, "do NOT re-implement rule matching inline."

---

## ADR-D — Veto / approval surface: CLI prompt + commands

**Status:** Accepted.

**Context.** Local-first, single operator. High-risk grants (spec: Human Veto requirement) need explicit human approval before a usable lease exists.

**Decision.** A `veto-required` decision writes a pending request to a `PendingStore` (no lease issued). The operator resolves via CLI: `leasebroker approve <reqId>` (→ issue under normal grant rules), `leasebroker deny <reqId>` (→ terminate, audit), `leasebroker pending` (→ list). `leasebroker revoke <leaseId>` adds to the `RevocationList`. The proxy, on a veto-required capability with no approval, denies. The surface is pluggable (web/notification) later.

**Alternatives considered.** Local web UI — heavier, premature for v1. Inline blocking TTY prompt in the proxy — couples enforcement to a terminal; rejected.

**Consequences.** Asynchronous approval model. `PendingStore` and `RevocationList` are state the broker/enforcement point consults. Clean separation: the proxy never blocks on a human; it denies until state says otherwise.

---

## ADR-E — Demo target: both filesystem and spend

**Status:** Accepted.

**Context.** The showcase must demonstrate red→green for **path-scope** and for **spend-cap** — the two hardest requirements.

**Decision.** Two fixtures behind the leasebroker proxy. **(1) Filesystem:** front the official `@modelcontextprotocol/server-filesystem`; a strawman agent leased to read `./data/**` attempts `./secrets/**` → denied (path-scope red→green). **(2) Spend/API:** a small deterministic mock API MCP server; a strawman leased with spend cap `$Y` and an allowed-endpoint set attempts an over-cap or off-list call → denied (spend-cap + endpoint-scope red→green). A `demo` script runs both and prints the red (unbrokered / over-privileged) vs green (brokered) outcomes.

**Alternatives considered.** fs-only — misses the spend story. Build-our-own server only — less credible than fronting a real MCP server.

**Consequences.** Two fixture lanes. Uses a real MCP server (fs) for credibility; the spend fixture is mocked to stay deterministic and offline (no real API keys / network in CI). Exercises every spec requirement, including spend accumulation and veto.
