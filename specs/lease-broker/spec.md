# Capability Lease Broker — Specification

> SDD source-of-truth spec (WHAT/WHY only). HOW lives in `plan.md` + ADRs.
> Fleet run #2. Name: `leasebroker` (decided 2026-06-07 — single token, valid npm + gt rig prefix).
> Status: **SHIPPED** (verified 2026-06-07). All requirements implemented and independently verified: one canonical contract, `tsc --noEmit` = 0, `vitest` green (9 files, 221 tests), `bun run build` clean, `node dist/cli/index.js --help` works, both red-to-green demo paths pass. ADRs A–E accepted in `docs/adrs.md`. Authored 2026-06-07.

## Purpose

AI agents and their tools/MCP servers today run with **standing, broad permissions** — a key, a token, a filesystem mount that stays live for the whole session regardless of what the agent is actually doing. The Capability Lease Broker replaces standing permissions with **time-bounded, narrowly-scoped capability leases**: an agent asks for exactly the capability a task needs ("read these paths / call this API / spend ≤ $Y, for task T, for N minutes"), a policy decides, and the broker issues a **signed, scoped, expiring lease** the agent must present to act. The broker enforces the scope, logs every event, can **revoke** mid-flight, and can require a **human veto** on high-risk grants.

It is least-privilege made operational for agentic systems: OAuth-scopes-meets-time-boxed-capabilities, with an audit trail and an approval gate. It is recursively relevant — it governs the exact class of autonomous-agent system that builds it — and complements `mcp-fit` (run #1): that scores what a server *exposes*; this controls what an agent may *do*.

## Non-Goals

- NOT an identity provider / not user authentication — it governs **capabilities** (what may be done), assuming agent identity is established upstream.
- NOT a general-purpose secrets manager — it brokers *use* of a capability, it does not aim to be the vault of record.
- NOT a network firewall or sandbox — enforcement is at the capability/request layer, not the kernel/network layer.
- NOT a multi-tenant cloud service in v1 — **local-first**, single-operator. Distribution is a later concern.

## Glossary

- **Capability** — a thing an agent may do, typed (e.g. `fs.read`, `http.call`, `spend`), with parameters that bound it.
- **Scope** — the concrete bounds on a capability for one lease (path globs, allowed hosts/endpoints, a spend cap, etc.).
- **Lease** — a signed, scoped, time-bounded grant of one or more capabilities to one agent for one task. The central contract.
- **Request** — an agent's ask for a lease (capability + scope + task id + requested duration).
- **Grant / Deny / Veto-required** — the three policy decisions.
- **Veto (approval gate)** — explicit human approval required before a high-risk lease is issued.
- **Revocation** — invalidating an active lease before its expiry.
- **Audit event** — an append-only record of any request, decision, issuance, use, denial, or revocation.

## Requirements

### Requirement: Lease Request
The broker SHALL accept a well-formed lease request (capability type, scope, task identifier, requested duration) and SHALL reject a malformed or under-specified one.

#### Scenario: Well-formed request accepted for evaluation
- GIVEN an agent with an established identity
- WHEN it submits a request naming a capability, a bounded scope, a task id, and a duration
- THEN the broker accepts the request and proceeds to policy evaluation

#### Scenario: Malformed request rejected
- GIVEN a request missing a required field (no scope, or no duration, or unknown capability type)
- WHEN it is submitted
- THEN the broker rejects it with a reason
- AND no lease is issued and no policy evaluation side effects occur

### Requirement: Least-Privilege Default
Absent a policy that explicitly allows a request, the broker's default decision SHALL be **deny**. There SHALL be no standing or implicit broad grant.

#### Scenario: No matching allow rule
- GIVEN a request for a capability that no policy rule permits
- WHEN policy is evaluated
- THEN the decision is deny
- AND the denial and its reason are recorded as an audit event

### Requirement: Policy Evaluation
The broker SHALL evaluate each accepted request against policy and produce exactly one decision: grant, deny, or veto-required.

#### Scenario: Allowed request granted
- GIVEN a request within an allow rule's bounds
- WHEN policy is evaluated
- THEN the decision is grant

#### Scenario: High-risk request requires veto
- GIVEN a request a policy marks high-risk (e.g. spend above a threshold, or a write capability)
- WHEN policy is evaluated
- THEN the decision is veto-required
- AND no usable lease exists until a human approves

### Requirement: Lease Issuance
On a grant, the broker SHALL issue a lease that is (a) scoped to no more than the request asked for, (b) time-bounded with an explicit expiry, and (c) tamper-evident, such that any modification to the lease is detectable on verification.

#### Scenario: Granted lease is scoped, expiring, and tamper-evident
- GIVEN a granted request for duration N
- WHEN the lease is issued
- THEN the lease carries the granted scope (no broader than requested), an expiry at issue-time + N, and an integrity guarantee
- AND a tampered copy of the lease fails verification

#### Scenario: Issued scope never exceeds requested scope
- GIVEN a request for scope S
- WHEN a lease is issued
- THEN the lease's scope is a subset of (or equal to) S
- AND never a superset

### Requirement: Lease Verification
Before any action is permitted, the broker (or its enforcement point) SHALL verify the presented lease's authenticity, that it is unexpired, and that it has not been revoked — and SHALL reject the action if any check fails.

#### Scenario: Valid lease permits the action
- GIVEN an authentic, unexpired, unrevoked lease whose scope covers the action
- WHEN the agent presents it to act
- THEN the action is permitted

#### Scenario: Forged or tampered lease rejected
- GIVEN a lease that fails its integrity check
- WHEN it is presented
- THEN the action is denied
- AND a denial audit event is recorded

### Requirement: Scope Enforcement
An action outside the presented lease's scope SHALL be denied, even when the lease itself is otherwise valid.

#### Scenario: Out-of-scope path denied
- GIVEN a valid lease scoped to read `./data/**`
- WHEN the agent attempts to read `./secrets/key.pem`
- THEN the action is denied
- AND a denial audit event records the attempted out-of-scope access

#### Scenario: Spend cap enforced
- GIVEN a valid lease with a spend cap of $Y
- WHEN an action would bring cumulative spend on the lease above $Y
- THEN the action is denied
- AND spend at or below $Y is permitted

### Requirement: Expiry (the time-box invariant)
A lease past its expiry SHALL be rejected, regardless of scope or authenticity. Expiry is not extendable in place; a new lease must be requested.

#### Scenario: Expired lease rejected
- GIVEN an otherwise-valid lease whose expiry has passed
- WHEN the agent presents it to act
- THEN the action is denied with an expiry reason
- AND the rejection is recorded

### Requirement: Revocation
The broker SHALL be able to revoke an active lease before its expiry, after which the lease SHALL be rejected on any use.

#### Scenario: Revoked lease rejected
- GIVEN an active, unexpired lease
- WHEN the operator revokes it
- THEN any subsequent presentation of that lease is denied
- AND the revocation is recorded as an audit event

### Requirement: Human Veto / Approval Gate
A request whose decision is veto-required SHALL NOT yield a usable lease until a human explicitly approves; a human denial SHALL terminate the request with no lease.

#### Scenario: Pending veto is not usable
- GIVEN a request that is veto-required
- WHEN the agent attempts to act before approval
- THEN there is no lease to present and the action cannot proceed

#### Scenario: Approved veto yields a lease
- GIVEN a veto-required request
- WHEN a human approves it
- THEN a lease is issued under the same scope/expiry rules as a direct grant

#### Scenario: Denied veto yields nothing
- GIVEN a veto-required request
- WHEN a human denies it
- THEN no lease is issued
- AND the denial is recorded

### Requirement: Audit Log
The broker SHALL record every request, decision, issuance, use, denial, and revocation as an append-only audit event sufficient to reconstruct who-asked-for-what, what-was-decided, and what-was-done.

#### Scenario: Full lifecycle is reconstructable
- GIVEN a lease that is requested, granted, used twice, and revoked
- WHEN the audit log is read back
- THEN it contains, in order, the request, the grant, both uses, and the revocation
- AND the log is append-only (no event can be silently altered or removed)

### Requirement: A2A Lease Extension

The system MUST provide the building blocks for enforcing capability leases
over A2A v1.0 agent-to-agent delegation, per the normative profile in
`docs/a2a-lease-extension-v1.md`: extension declaration, token carriage in
message metadata, context binding, and a deny-by-default gate reusing the
existing `Enforcer.check` pipeline unchanged. The helpers MUST NOT depend on
an A2A protocol client (the gateway consumer owns the wire).

#### Scenario: Extension-unaware client rejected at the protocol level

- GIVEN a request whose declared extensions do not include the lease extension URI
- WHEN the gate evaluates it
- THEN the decision is `ExtensionSupportRequiredError` (JSON-RPC `-32008`, HTTP 400, gRPC `FAILED_PRECONDITION`)
- AND no task-level processing occurs

#### Scenario: Missing or invalid lease rejects the task

- GIVEN a declaring client whose message carries no token (and whose context has none bound), or a token the enforcer rejects
- WHEN the gate evaluates it
- THEN the decision is task state `rejected` with the enforcement reason

#### Scenario: Context binding is sticky and conflict-safe

- GIVEN a context whose first message bound lease token T1
- WHEN a later message in the same context omits the token
- THEN the gate enforces against T1
- AND a later message presenting a DIFFERENT token T2 is rejected

#### Scenario: Pending veto pauses instead of denying

- GIVEN a declaring client with no token whose context has a pending human-approval request
- WHEN the gate evaluates it
- THEN the decision is task state `auth-required` (A2A §7.6), resumable out-of-band via `leasebroker approve`

## ADRs (HOW — explicitly NOT part of this spec)

Load-bearing design decisions. All 5 accepted 2026-06-07. Full text in `docs/adrs.md`.

- **(a) ADR-A — Lease signing / integrity: PASETO v4.public (Ed25519)** on `@noble/ed25519` (audited, fresh). The canonical `paseto` lib was rejected (3 yr stale). Token IS the wire form of the lease.
- **(b) ADR-B — Enforcement model: MCP middleware/proxy.** In-path between agent and downstream MCP servers — enforcement is guaranteed, not advisory.
- **(c) ADR-C — Policy language: declarative allow-rules (data)**, behind a `PolicyEngine` interface with a Cedar ramp seam. No code-exec in the trust path.
- **(d) ADR-D — Veto / approval surface: CLI commands** (`approve`/`deny`/`revoke`) for the local-first single-operator model. Pluggable later.
- **(e) ADR-E — Demo target: BOTH.** (1) Filesystem MCP server path-scope red→green. (2) Spend-cap + endpoint-scope red→green. Both implemented and verified.

## Product decisions (WHAT-level, all resolved)

1. ~~**Name**~~ — RESOLVED: `leasebroker`.
2. ~~**Capability taxonomy for v1**~~ — RESOLVED: v1 ships **`fs.read`, `fs.write`, `http.call`, `spend`** — all four implemented in `src/contract/types.ts` and the enforce scope checker. `fs.write` is included because it exercises the Human Veto requirement (high-risk write capability) and adds minimal enforcement surface beyond `fs.read`.
3. ~~**"Use" semantics**~~ — RESOLVED by ADR-B: enforcement is **in-path / mediated** via the MCP middleware — guaranteed, not advisory.

## Traceability note

Every requirement above must map to coverage in `plan.md` and to at least one bead in `BEADS.md`. The Lease (schema + verification behaviour) is the **shared contract** and MUST be landed/pinned before any consumer bead — run #1's lesson #1.
