# Implementation Plan — leasebroker

The HOW for fleet run #2, committed against `specs/lease-broker/spec.md` and `docs/adrs.md`. This plan exists to make the build **contract-first** and the lanes **disjoint** so the fleet does not re-pay run #1's integration taxes. Doc style: single-doc, inline backticks, no fenced blocks.

## Stack

- **Language:** TypeScript (strict). **Runtime/dist:** Node, `npx`-distributable single CLI (`leasebroker`). **Dev/test:** `bun` + `vitest`, `tsc --noEmit` as the typecheck gate (matches run #1's proven loop).
- **Crypto:** PASETO **v4.public** token format implemented on **`@noble/ed25519@3`** (audited, fresh). The canonical `paseto` lib is NOT used (3 yr stale → no patch path). The hand-built v4.public encoder MUST pass the official PASETO v4.public test vectors. (ADR-A.)
- **MCP:** `@modelcontextprotocol/sdk@1.x` for the proxy server + a `Client` to downstream servers (ADR-B). **Pin to v1.x and use the low-level `extra` handler param** (`extra.sessionId`, `extra.authInfo`) — v2's structured `ctx` is migration-branch only, not the npm latest. Demo fronts `@modelcontextprotocol/server-filesystem@2026.1.14` (ADR-E).
- **Validation:** `zod` for runtime validation of requests/leases/rules at the trust boundary.

## The shared contract (bottom of the stack — lands before any consumer)

This is the single contract file (`src/contract/`), the blocking dependency. Run #1 lesson #1: it is landed/pinned **before** any consumer bead — never fanned out concurrently with its consumers. Consumers `import`, never redefine.

**Core types** (field name `: type` — the canonical identifiers):

- `Capability` — discriminated union on `kind`:
  - `fs.read` / `fs.write` → `{ kind, paths: string[] }` (glob patterns)
  - `http.call` → `{ kind, endpoints: string[] }` (host/path allow-list)
  - `spend` → `{ kind, currency: string, capMinor: number }` (cap in minor units, integer — no float money)
- `Scope` — the concrete bounds carried per capability (the union members above already carry their bounds).
- `LeaseRequest` — `{ agentId: string, taskId: string, capabilities: Capability[], requestedDurationMs: number }`
- `Lease` — `{ id: string, agentId: string, taskId: string, capabilities: Capability[], issuedAt: string, expiresAt: string, kid: string }` (the granted scope is a subset of the requested; wire form = the PASETO token whose claims are these fields)
- `Decision` — `{ effect: 'grant' | 'deny' | 'veto-required', reason: string, ruleId?: string }`
- `AuditEvent` — discriminated union on `type`: `request | decision | issuance | use | denial | revocation`, each `{ type, at: string, leaseId?, requestId?, detail, prevHash, hash }` (hash-chained — see Cross-cutting)
- `VerifyResult` — `{ ok: boolean, reason?: string }`

**Interfaces** (consumers depend on these, not impls — this is what makes ADR-A/C/D swappable):

- `Signer` — `issue(lease): string` (→ token), `verify(token): { lease } | VerifyResult` (ADR-A)
- `PolicyEngine` — `evaluate(request): Decision` (ADR-C; Cedar drop-in implements this)
- `AuditSink` — `append(event): void`, `read(): AuditEvent[]` (append-only, hash-chained)
- `PendingStore` — `put/get/list/resolve(reqId)` for veto-required requests (ADR-D)
- `RevocationList` — `revoke(leaseId)`, `isRevoked(leaseId): boolean` (ADR-D)
- `SpendLedger` — `accrue(leaseId, amountMinor): boolean` (false if it would exceed cap), `spent(leaseId): number` (ADR-B; mutable state, NOT in the lease)
- `Enforcer` — the per-call decision: `check(token, action): VerifyResult` composing verify → expiry → revocation → scope → spend.

## Module map (disjoint fleet lanes)

Each lane is one owner; lanes do not write into each other. Maps to beads in `BEADS.md`.

| Lane | Path | Owns | Depends on |
|---|---|---|---|
| **contract** | `src/contract/` | all types + interfaces + zod schemas | — (base) |
| **signing** | `src/signing/` | `Signer` impl (PASETO v4.public), keygen, `kid` rotation | contract |
| **policy** | `src/policy/` | `PolicyEngine` impl (declarative allow-rules), rule loader/validator, Cedar seam | contract |
| **audit** | `src/audit/` | `AuditSink` impl (hash-chained JSONL), `RevocationList`, `PendingStore`, `SpendLedger` (the state stores) | contract |
| **broker** | `src/broker/` | issuance orchestration: request → `evaluate` → veto/grant → `issue` → audit | contract, policy, signing, audit |
| **enforce** | `src/enforce/` | MCP middleware/proxy: intercept `tools/call`, run `Enforcer`, forward/deny, audit + spend | contract, signing(verify), audit |
| **cli** | `src/cli/` | `leasebroker` commands (request, approve/deny/pending, revoke, serve, policy, audit) | all |
| **fixtures** | `fixtures/` | strawman over-privileged agent, fs + spend demo servers, red→green `demo` script | cli, enforce |

## Dependency graph (waves — contract-first)

- **Wave 0 (blocking):** `contract` lands + is pinned first. Nothing else starts until it is on the integration base.
- **Wave 1 (parallel, depend only on contract):** `signing`, `policy`, `audit`.
- **Wave 2 (parallel, depend on wave 1):** `broker` (policy+signing+audit), `enforce` (signing+audit).
- **Wave 3:** `cli` (all), then `fixtures` (cli+enforce).
- **Integration bead (first-class, independently verified — lesson #2):** one canonical contract confirmed (`find src -name '*.ts' | grep contract | wc -l` sane, no re-fork), all consumers import it, `tsc --noEmit` = 0, `bun test` green, `agentshield scan` clean, and the e2e `demo` shows both red→green paths.

Landing: Sapling stacked PRs via `sl ghstack submit` (ADR-less but per `sapling-scm`), one PR per lane in dependency order, base advanced with the rolling-integration recipe under `--merge=local`.

## Cross-cutting design points

- **Lease binding (ADR-B detail — VERIFIED against the SDK):** the agent presents its lease token at the MCP session handshake; the proxy binds token→`sessionId` (available on the low-level handler's `extra.sessionId` in SDK v1.x) and applies it to every subsequent `tools/call`. Enforcement reads the bound lease from `extra.sessionId` per call — no per-call token argument needed. Confirmed the SDK exposes `server.setRequestHandler('tools/call', (request, extra) => …)` with `extra.sessionId`/`extra.authInfo`.
- **Spend is not in the lease:** the lease carries the *cap*; the `SpendLedger` tracks *accrued* spend per lease-id. `accrue` is atomic and returns false (→ deny) if it would breach the cap. This is why money is integer minor-units (no float drift).
- **Audit tamper-evidence:** JSONL where each event carries `prevHash` (hash of the previous event) and `hash` (hash of this event incl. prevHash) — a hash chain. Reading back detects any insertion/alteration/removal. Satisfies the append-only requirement without a database in v1.
- **Revocation + expiry are checked at verify-time,** independent of the signature: a cryptographically valid token is still rejected if expired or on the `RevocationList`.
- **Deny-by-default everywhere:** policy with no matching allow → deny; `Enforcer` on any failed check → deny; unknown capability `kind` → deny. The denial path is the default path.

## Risks / open

- ~~Lease-binding mechanism~~ — **RESOLVED:** SDK v1.x exposes `extra.sessionId` on the `tools/call` handler; bind token→session at handshake (see Cross-cutting).
- ~~PASETO lib choice~~ — **RESOLVED:** build v4.public on `@noble/ed25519` (stale `paseto` lib avoided); validate against official test vectors (ADR-A).
- **`@modelcontextprotocol/server-filesystem` interface drift** — pin `@2026.1.14`; the proxy must pass through unknown tools transparently.
- **MCP SDK v1→v2 API churn** — pin `@1.x`; do not adopt the v2 `ctx` shape until it is the npm latest.
- **Hand-built PASETO encoder** — crypto encoding is error-prone; the official v4.public test vectors are a blocking acceptance criterion on the signing bead.
- **Cedar seam scope creep** — v1 ships the interface + declarative engine only; do NOT build Cedar now (ADR-C).

## Traceability — requirement → coverage

| Spec requirement | Lane(s) | ADR |
|---|---|---|
| Lease Request | contract, broker, cli | — |
| Least-Privilege Default | policy | C |
| Policy Evaluation | policy, broker | C |
| Lease Issuance | broker, signing | A |
| Lease Verification | enforce, signing | A, B |
| Scope Enforcement | enforce | B |
| Expiry | contract, enforce | A, B |
| Revocation | audit (`RevocationList`), enforce, cli | B, D |
| Human Veto | audit (`PendingStore`), broker, cli | D |
| Audit Log | audit | B |

Every requirement maps to at least one lane and (next step) at least one bead. The Lease contract underpins all — landed first.
