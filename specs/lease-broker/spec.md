# Capability Lease Broker — Specification

> SDD source-of-truth spec (WHAT/WHY only). HOW lives in `plan.md` + ADRs.
> Fleet run #2. Name: `leasebroker` (decided 2026-06-07 — single token, valid npm + gt rig prefix).
> Status: DRAFT for review; the 5 HOW decisions are made (see Deferred section) and ready to become ADRs. Authored 2026-06-07.

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

## Deferred to plan.md / ADRs (HOW — explicitly NOT part of this spec)

Load-bearing design decisions. **All 5 decided 2026-06-07** (operator); each becomes an ADR in the plan phase. They do **not** change the WHAT above; they fix how it is realized.

- **(a) Lease signing / integrity mechanism** → **ADR-A. DEFAULT (operator to confirm): PASETO v4.public (Ed25519)** over a canonically-serialized lease — purpose-built capability-token format, avoids JWT footguns; alt = raw Ed25519 detached signature over canonical JSON. Tamper-evidence + offline verifiability.
- **(b) Enforcement model** → **ADR-B. DECIDED: MCP middleware/proxy.** Verification + scope enforcement sit **in-path** between the agent (MCP client) and MCP servers — enforcement is guaranteed, not advisory. Recursively relevant; pairs with `mcp-fit`.
- **(c) Policy language** → **ADR-C. DECIDED: declarative allow-rules (data), behind a policy-engine interface that leaves a plumbing seam to ramp up to the Cedar policy language later.** Auditable + no code-exec in the trust path now; expressiveness path preserved. Design the evaluator as an interface so a Cedar engine drops in without touching consumers (links `seam-map`).
- **(d) Veto / approval surface** → **ADR-D. DEFAULT (operator to confirm): CLI approval prompt + `approve`/`deny`/`revoke` commands** for the local-first single-operator model; pluggable surface later.
- **(e) Demo target** → **ADR-E. DECIDED: BOTH.** (1) Filesystem MCP server (`@modelcontextprotocol/server-filesystem`) — strawman agent reads outside leased path-scope → broker denies (path-scope red→green). (2) An API/HTTP MCP server — strawman exceeds the spend cap / hits a non-leased endpoint → broker denies (spend-cap + endpoint-scope red→green).

## Open product questions for the operator (WHAT-level)

1. ~~**Name**~~ — RESOLVED: `leasebroker`.
2. **Capability taxonomy for v1** — the "Both" demo (ADR-E) implies v1 covers **`fs.read`, `fs.write`, `http.call`, `spend`**. CONFIRM whether `fs.write` is in v1 scope (it is the highest-risk capability → exercises the Human Veto requirement well, but adds enforcement surface). Default: include `fs.write` precisely *because* it showcases the veto gate.
3. ~~**"Use" semantics**~~ — RESOLVED by ADR-B: enforcement is **in-path / mediated** via the MCP middleware, so enforcement is **guaranteed**, not advisory. (The self-attest-with-spot-checks alternative is dropped.)

## Traceability note

Every requirement above must map to coverage in `plan.md` and to at least one bead in `BEADS.md`. The Lease (schema + verification behaviour) is the **shared contract** and MUST be landed/pinned before any consumer bead — run #1's lesson #1.
