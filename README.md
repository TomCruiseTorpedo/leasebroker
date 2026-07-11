# leasebroker

A local-first broker that issues **time-bounded, narrowly-scoped capability leases** to AI agents and their tools/MCP servers — instead of standing, broad permissions.

An agent asks for exactly the capability a task needs ("read these paths / call this API / spend ≤ $Y, for task T, for N minutes"); a policy decides; the broker issues a **signed, scoped, expiring lease** the agent must present to act. The broker enforces the scope in-path (MCP middleware proxy), logs every event to a tamper-evident audit trail, can **revoke** a lease mid-flight, and can require a **human veto** on high-risk grants. Deny-by-default, least-privilege.

> Status: **shipped.** All lanes implemented and green: `tsc --noEmit`, `vitest`, `bun run build`, `node dist/cli/index.js --help`, and the end-to-end demo all pass.

## Install

```bash
npm install leasebroker
# or
bun add leasebroker
```

Requires Node ≥ 20.

Run without installing:

```bash
npx leasebroker --help
```

## CLI Commands

All commands share a `--state-dir <path>` flag (default: `.leasebroker/` in cwd). Override with `LEASEBROKER_STATE_DIR`.

### `leasebroker request`

Submit a lease request. Pass JSON via `--request` or stdin. Add `--rules-file <path>` to evaluate against a specific policy file.

```bash
leasebroker request --request '{
  "agentId": "my-agent",
  "taskId": "task-42",
  "capabilities": [
    { "kind": "fs.read", "paths": ["./data/**"] }
  ],
  "requestedDurationMs": 3600000
}'
```

Prints a JSON outcome — `{ type: 'granted', token, leaseId }`, `{ type: 'pending', reqId }` (veto-required), or `{ type: 'denied', reason }` (exits 2).

### `leasebroker pending`

List all pending (veto-required) requests awaiting approval.

```bash
leasebroker pending
```

### `leasebroker approve <reqId>`

Approve a pending request; issues the lease.

```bash
leasebroker approve req-abc123
```

### `leasebroker deny <reqId>`

Deny a pending request; no lease is issued.

```bash
leasebroker deny req-abc123
```

### `leasebroker revoke <leaseId>`

Revoke an active lease before it expires.

```bash
leasebroker revoke lease-xyz789
```

### `leasebroker serve`

Start the MCP enforcement proxy fronting a downstream MCP server. The proxy intercepts every `tools/call`, verifies the lease, enforces scope, and forwards or denies.

```bash
# Front a downstream MCP server (stdio)
leasebroker serve \
  --downstream-cmd node \
  --downstream-args '["./my-mcp-server.js"]'

# With a custom policy file
leasebroker serve \
  --downstream-cmd node \
  --downstream-args '["./my-mcp-server.js"]' \
  --rules-file ./rules.json
```

Agents present their lease token in `_meta['x-lease-token']` at the MCP `initialize` handshake. All subsequent `tools/call` requests are verified against that bound lease.

### `leasebroker policy`

View or load policy rules.

```bash
# View current rules
leasebroker policy show

# Load rules from a JSON file
leasebroker policy load --rules-file ./rules.json
```

### `leasebroker audit`

View the audit log (hash-chained, append-only).

```bash
# View last 20 events
leasebroker audit --last 20

# Filter by event type
leasebroker audit --type issuance

# Verify hash-chain integrity only (exit code, no output)
leasebroker audit --verify

# Verify chain integrity AND external anchor proofs (local, no network)
leasebroker audit --verify-anchor
```

### `leasebroker anchor`

Anchor the audit chain tip to public [OpenTimestamps](https://opentimestamps.org) calendars (ADR-G). The tip hash commits to the entire chain, so one small proof file externally witnesses the whole log up to that point — independent of the machine (and operator) the log lives on. Local tamper-evidence says *this file is internally consistent*; an anchor says *this history existed before that Bitcoin block*, which is what holds up when the log's own custodian is the party in question.

```bash
# Submit the current tip (idempotent per tip — safe to over-fire from cron)
leasebroker anchor

# ~1-2 hours later: collect the completed Bitcoin attestations
leasebroker anchor --upgrade

# Local verification report (no network)
leasebroker anchor --status
```

Proofs are standard detached `.ots` files under `<state-dir>/anchors/` — independently verifiable with the reference `ots` client — plus an `anchors.jsonl` index. Only the 32-byte tip digest ever leaves the machine; log content stays local. A tampered log refuses to anchor, and `--verify-anchor` fails closed on any proof that stops matching the stored chain. The dashboard surfaces the same verdict as an `anchor` badge (`anchored` / `pending` / `none` / `broken`).

A daily [cron](https://en.wikipedia.org/wiki/Cron) example:

```cron
# Collect yesterday's attestations, then anchor today's tip
0 6 * * * cd /path/to/project && leasebroker anchor --upgrade && leasebroker anchor
```

## Running the Demo

The demo shows two red→green scenarios entirely offline (no network, no real keys):

```bash
bun run demo
# or
npm run demo
```

**Demo 1 — Filesystem path-scope:**  
Unbrokered agent reads both `./fixtures/data/` and `./fixtures/private/`. Brokered agent (lease: `fs.read ./fixtures/data/**`) — private directory read is DENIED.

**Demo 2 — Spend cap + endpoint scope:**  
Unbrokered agent charges any amount to any endpoint. Brokered agent (lease: `spend cap=100 USD`, `http.call api.example.com/**`) — over-cap charge DENIED, off-list endpoint DENIED.

## Programmatic API

```typescript
import {
  generateKeyPair, PasetoV4PublicSigner,
  loadRules, DeclarativePolicyEngine,
  InMemoryAuditSink, InMemoryPendingStore,
  InMemoryRevocationList, InMemorySpendLedger,
  Broker, LeaseEnforcer, LeasebrokerProxy,
} from 'leasebroker';

// Set up the stack
const kp = generateKeyPair('k1');
const signer = new PasetoV4PublicSigner(kp);
const policy = new DeclarativePolicyEngine(
  loadRules([{ ruleId: 'allow-fs-read', effect: 'allow', capabilityKind: 'fs.read' }])
);
const broker = new Broker(policy, signer, new InMemoryAuditSink(), new InMemoryPendingStore(), kp.kid);

// Issue a lease
const result = broker.request({
  agentId: 'my-agent',
  taskId: 'task-1',
  capabilities: [{ kind: 'fs.read', paths: ['./data/**'] }],
  requestedDurationMs: 3_600_000,
});

if (result.type === 'granted') {
  console.log('Token:', result.token); // v4.public.…

  // Enforce it
  const enforcer = new LeaseEnforcer(signer, new InMemoryRevocationList(), new InMemorySpendLedger());
  const check = enforcer.check(result.token, { kind: 'fs.read', path: './data/hello.txt' });
  console.log(check.ok); // true
}
```

## A2A lease extension

Leases also travel over [A2A](https://a2a-protocol.org/) v1.0 **agent-to-agent
delegation** — the same capability attenuation, one protocol layer up. A2A's
`securitySchemes` carry standing credentials; this extension carries a scoped,
expiring lease per message instead.

The normative profile is [`docs/a2a-lease-extension-v1.md`](docs/a2a-lease-extension-v1.md)
(extension URI, `A2A-Extensions` negotiation, token carriage in message
metadata, per-context binding, the four-stage deny ladder, pinned task
states). The helpers are deliberately **SDK-free** — plain JSON manipulation;
the consumer owns the wire:

```typescript
import {
  LEASE_EXT_URI,          // the extension URI agents declare + clients echo
  leaseCardExtension,     // capabilities.extensions[] entry (required: true)
  attachLeaseToken,       // put the token on an outbound message
  extractLeaseToken,      // read it on the enforcing side
  A2aLeaseBinding,        // contextId → token (no mid-context swapping)
  evaluateA2aLeaseGate,   // extension-support → lease → veto → allow
} from 'leasebroker';
```

The gate reuses `LeaseEnforcer.check` unchanged. The reference consumer is
[gatewarden](https://github.com/TomCruiseTorpedo/gatewarden), which enforces
this profile at its A2A server face and carries leases on outbound delegations.

> **npm note:** the A2A lane ships in `leasebroker` ≥ 0.2.0 on npm
> (`src/a2a/` helpers exported from the package barrel; the profile doc lives
> in this repo).

## Dashboard

A local-first governance console for operators, in [`dashboard/`](dashboard/): a live, sortable leases table with one-click **revoke**, a pending-approvals panel (**approve** / **deny** veto-required requests), a virtualized live audit feed, and a **tamper-evidence badge** for the audit log. Actions call the broker's **compiled, verified** read-layer and actions from `dist/` — the same surface a package consumer sees, never the core's TypeScript source. It is deliberately **not** part of the published npm package (it would drag React into a security CLI's dependency tree); it ships in-repo.

```bash
# 1. Build the core so the dashboard can import dist/
npm run build

# 2. Install and run the dashboard
cd dashboard
npm install
npm run seed   # optional: write demo state to ./.leasebroker
npm run dev    # http://localhost:3210
```

To watch a **real** broker instead of demo state, point it at that broker's state directory — the resolved directory is always shown in the console topbar, so there is never a silent mismatch:

```bash
LEASEBROKER_STATE_DIR=/path/to/your/.leasebroker npm run dev
```

The integrity badge verifies the audit log's **stored** hash chain on every poll: any edit, insertion, or deletion in `audit.jsonl` flips it to `tampered`, while the events stay visible so the operator can see what changed. A missing or empty state directory reads as empty-and-intact, not tampered.

The dashboard is a local operator tool with no authentication of its own — keep it bound to localhost.

## Development

```bash
bun install

npm run typecheck   # tsc --noEmit
npm run test        # vitest run
npm run build       # compile to dist/
npm run demo        # red→green capability-brokering demo
```

## Design

- Specification (WHAT/WHY): `specs/lease-broker/spec.md`
- Architecture decisions: `docs/adrs.md`
- Implementation plan (HOW): `plan.md`

**Key architecture decisions:**
- Enforcement is **MCP middleware** (ADR-B): a proxy that fronts downstream MCP servers, verifying scope on every tool call.
- Leases are **PASETO v4.public** tokens (Ed25519, via `@noble/ed25519`) — tamper-evident and verifiable offline (ADR-A).
- Policy is **declarative allow-rules**, with a seam to Cedar later (ADR-C).
- The lease is immutable; cumulative spend and revocation are tracked as state keyed by lease id (ADR-B/D).
- A2A delegation carries leases via a **required protocol extension** bound per `contextId` — an awareness gate; the security boundary is always token validation (ADR-F).
- The audit chain tip is **externally anchored** via OpenTimestamps — proofs a third party can verify even against the log's own custodian (ADR-G).

`leasebroker` is the **govern** third of a trilogy: [mcp-fit](https://github.com/TomCruiseTorpedo/mcp-fit)
scores what a server or agent card exposes, and [gatewarden](https://github.com/TomCruiseTorpedo/gatewarden)
fuses score + govern into one in-path gateway.

## License

Apache-2.0 — see `LICENSE`.
