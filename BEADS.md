# BEADS — leasebroker fleet run #2

Routable decomposition of `plan.md`. Each bead is one disjoint lane with a self-contained brief so a fresh polecat executes it cold. Bead prefix = rig/DB name `leasebroker-` (gt #2682 workaround: prefix MUST equal the full single-token rig name). Doc style: single-doc, inline backticks, no fenced blocks.

**Two structural guards baked in (run #1's taxes):**
- **Lesson #1 (contract-first):** `leasebroker-001` (the contract) is **Wave 0, alone** — it lands and is pinned on the integration base before ANY consumer is slung. Consumers `import` from it; they NEVER redefine its types.
- **Lesson #2 (integration is first-class):** `leasebroker-009` is a real bead with independent verification — not a polecat self-report.

Every bead's acceptance includes the universal gate: `tsc --noEmit` exits 0, `bun test` green for its lane, imports the canonical contract (no re-fork), and `agentshield scan --path <worktree>` clean.

---

## Wave 0 — the contract (blocking, lands alone)

### leasebroker-001 — contract
- **Owns:** `src/contract/` (types, interfaces, zod schemas, barrel export). No implementation logic.
- **Build:** the types and interfaces exactly as named in `plan.md` → "shared contract". Types: `Capability` (union on `kind`: `fs.read`/`fs.write`/`http.call`/`spend`), `Scope`, `LeaseRequest`, `Lease`, `Decision`, `AuditEvent`, `VerifyResult`. Interfaces: `Signer`, `PolicyEngine`, `AuditSink`, `PendingStore`, `RevocationList`, `SpendLedger`, `Enforcer`. `zod` schemas for `LeaseRequest`, `Lease`, `Capability`, and the policy allow-rule. Money is integer minor units (no float).
- **Acceptance:** all named types + interfaces exported from one barrel; zod schemas accept valid samples and reject malformed ones (missing scope, unknown `kind`, float money); `tsc --noEmit` = 0; zero runtime/impl logic (types + interfaces + schemas only).
- **Deps:** none.
- **Labels/skills:** `contract`, `types`, `zod`.

---

## Wave 1 — primitives (parallel; depend only on contract)

### leasebroker-002 — signing
- **Owns:** `src/signing/`.
- **Build:** implement `Signer` as PASETO **v4.public** on `@noble/ed25519@3` (ADR-A) — PAE + Ed25519 sign/verify + `v4.public.` framing. Ed25519 keygen, `kid` support. Do NOT depend on the canonical `paseto` lib (stale).
- **Acceptance:** **passes the official PASETO v4.public test vectors** (blocking, non-negotiable); `issue(lease)` → token; `verify(token)` → `{lease}` for authentic, fails for tampered token / wrong key; `tsc` = 0; `bun test` green; imports `Signer`/`Lease` from contract, no redefine.
- **Deps:** `leasebroker-001`.
- **Labels/skills:** `crypto`, `security`, `ed25519`, `paseto`.

### leasebroker-003 — policy
- **Owns:** `src/policy/`.
- **Build:** implement `PolicyEngine.evaluate(request) → Decision` over **declarative allow-rules** (data). Deny-by-default; rules yield `allow` with optional `veto-required`. Rule loader + zod validation. Leave a documented Cedar extension seam (a second `PolicyEngine` impl can drop in; no Cedar code now).
- **Acceptance:** allow-match → `grant`; no match → `deny` (with reason); high-risk rule → `veto-required`; malformed rule rejected at load; `tsc` = 0; `bun test` green; imports from contract.
- **Deps:** `leasebroker-001`.
- **Labels/skills:** `policy`, `authz`, `security`.

### leasebroker-004 — audit + state stores
- **Owns:** `src/audit/`.
- **Build:** `AuditSink` = append-only **hash-chained** JSONL (`prevHash`/`hash` per event); plus `RevocationList` (`revoke`/`isRevoked`), `PendingStore` (`put`/`get`/`list`/`resolve`), `SpendLedger` (`accrue` atomic → false on cap breach, `spent`). Money integer minor units.
- **Acceptance:** full lifecycle reconstructable from the log in order; hash-chain detects insertion/alteration/removal (test); `SpendLedger.accrue` denies at the boundary (`spent + amount > cap` → false; `== cap` → ok); revoke→isRevoked true; pending resolve removes; `tsc` = 0; `bun test` green; imports from contract.
- **Deps:** `leasebroker-001`.
- **Labels/skills:** `audit`, `state`, `integrity`.

---

## Wave 2 — orchestration + enforcement (parallel; depend on Wave 1)

### leasebroker-005 — broker (issuance)
- **Owns:** `src/broker/`.
- **Build:** issuance orchestration: validate `LeaseRequest` → `PolicyEngine.evaluate` → on `veto-required`: `PendingStore.put` (NO lease issued) → on `grant`: `Signer.issue` → `AuditSink.append` at request/decision/issuance. `approve(reqId)` → issue under grant rules; `deny(reqId)` → audit, no lease.
- **Acceptance:** grant path issues a scoped/expiring lease (scope ⊆ requested); deny path issues nothing + audits; veto path: pending→approve→lease, pending→deny→none; every step audited; `tsc` = 0; `bun test` green; consumes `PolicyEngine`/`Signer`/`AuditSink`/`PendingStore` via interface (no impl coupling).
- **Deps:** `leasebroker-001`, `-002`, `-003`, `-004`.
- **Labels/skills:** `broker`, `orchestration`, `security`.

### leasebroker-006 — enforce (MCP proxy middleware)
- **Owns:** `src/enforce/`.
- **Build:** an MCP proxy **server** (`@modelcontextprotocol/sdk@1.x`, low-level `setRequestHandler`) fronting a downstream server via a `Client`. At handshake bind lease-token → `extra.sessionId`. On each `tools/call`: run `Enforcer` = verify (Signer) → not-expired → not-revoked (`RevocationList`) → scope (path globs / endpoint allow-list) → spend (`SpendLedger.accrue`) → forward to downstream, else deny. Emit an `AuditEvent` per call. Pass through unknown tools transparently.
- **Acceptance:** in-scope call forwarded; out-of-scope path denied + audited; expired lease denied; revoked lease denied; over-cap spend denied (and at-cap allowed); use the v1.x `extra.sessionId` binding (not a per-call token arg); `tsc` = 0; `bun test` green (downstream mocked); imports from contract.
- **Deps:** `leasebroker-001`, `-002` (verify), `-004`.
- **Labels/skills:** `mcp`, `proxy`, `enforcement`, `security`.

---

## Wave 3 — surface

### leasebroker-007 — cli
- **Owns:** `src/cli/`, `bin/`.
- **Build:** `leasebroker` CLI (npx-able): `request`, `approve <reqId>`, `deny <reqId>`, `pending`, `revoke <leaseId>`, `serve` (start the proxy fronting a configured downstream), `policy` (load/show rules), `audit` (view the log). Wires broker + enforce + the stores.
- **Acceptance:** `request`→`pending`→`approve` yields a usable lease; `revoke` invalidates; `serve` boots the proxy; `--help` for each; `tsc` = 0; `bun test` (command smoke) green.
- **Deps:** `leasebroker-001`, `-005`, `-006` (and `-003`/`-004` transitively).
- **Labels/skills:** `cli`, `packaging`.

### leasebroker-008 — fixtures + demo
- **Owns:** `fixtures/`, `scripts/demo`.
- **Build:** (1) **fs demo** — front `@modelcontextprotocol/server-filesystem@2026.1.14` with the proxy; strawman agent leased to read `./data/**` attempts `./secrets/**` → denied. (2) **spend demo** — a deterministic mock API MCP server; strawman leased with spend cap + endpoint set attempts over-cap / off-list → denied. A `demo` script prints **red** (unbrokered / over-privileged) vs **green** (brokered) for both.
- **Acceptance:** `demo` runs offline (no real keys/network); both fixtures show a clear red→green; out-of-scope + over-cap both visibly denied; `tsc` = 0.
- **Deps:** `leasebroker-007`, `-006`.
- **Labels/skills:** `demo`, `fixtures`, `mcp`.

---

## Final — integration (first-class, independently verified)

### leasebroker-009 — integration + reconcile
- **Owns:** cross-cutting; README; spec reconcile.
- **Build/verify (NOT a self-report — verified independently per `gas-town-fleet` checklist):** one canonical contract, no re-fork (`find src -path '*contract*' -name '*.ts'` sane; `grep` shows consumers import it); `tsc --noEmit` = 0 across the merged tree; `bun test` green for all lanes; `agentshield scan --path <worktree>` clean; e2e `demo` shows BOTH red→green paths; `npx leasebroker --help` works from a clean install; README documents usage. Reconcile `specs/lease-broker/spec.md` to match shipped behaviour (SDD step 6).
- **Deps:** all (`-001`…`-008`).
- **Labels/skills:** `integration`, `verification`, `docs`.

---

## Dependency graph

| Bead | Wave | Depends on |
|---|---|---|
| `leasebroker-001` contract | 0 | — |
| `leasebroker-002` signing | 1 | 001 |
| `leasebroker-003` policy | 1 | 001 |
| `leasebroker-004` audit | 1 | 001 |
| `leasebroker-005` broker | 2 | 001, 002, 003, 004 |
| `leasebroker-006` enforce | 2 | 001, 002, 004 |
| `leasebroker-007` cli | 3 | 001, 005, 006 |
| `leasebroker-008` fixtures | 3 | 007, 006 |
| `leasebroker-009` integration | 4 | 001–008 |

## Sling plan (per `gas-town-fleet` runbook)

1. Stand up the rig: `gt rig add leasebroker <git-url> --prefix leasebroker --polecat-agent pi` (single-token name, prefix == name).
2. `bd` create all 9 beads from the briefs above (forced IDs `leasebroker-001`…`009`, `--acceptance`, `--skills`, `-l <labels>`); add dep edges per the table; `bd … dep cycles` must be empty.
3. **Wave 0:** sling `leasebroker-001` ALONE; verify-each (tsc=0, schema tests); land it; advance the rolling integration base.
4. **Wave 1:** sling `002`,`003`,`004` in parallel off the advanced base; verify-each; land; advance base.
5. **Wave 2:** sling `005`,`006`; verify-each; land; advance base.
6. **Wave 3:** sling `007`, then `008`; verify-each; land; advance base.
7. **Integration:** `009` — independent full verify + spec reconcile.
8. Land the stack via Sapling `sl ghstack submit` (one PR per lane, dependency order), per `sapling-scm`. Public-repo hygiene gate (HANDOVER §5) before any push.
