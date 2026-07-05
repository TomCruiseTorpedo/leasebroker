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

> **npm note:** the published `leasebroker` package (0.1.1) predates the A2A
> lane — `src/a2a/` and the profile doc are on `main` and will ship in the
> next release.

## Dashboard (in development)

> **Status: in development — not yet shipped.** A local governance dashboard lives in [`dashboard/`](dashboard/), but it is **not** part of the published `leasebroker` npm package, and its surface may still change.

A [TanStack Start](https://tanstack.com/start) app for operators: a live leases table, the audit feed, and a pending-approvals panel with revoke / approve / deny actions. It runs entirely against your local state directory and imports the broker's **compiled, verified** read-layer and actions from `dist/` — the same surface a package consumer sees, never the core's TypeScript source.

It builds and runs locally, but treat it as a preview: the core must be built first, and it carries no automated UI tests yet.

```bash
# 1. Build the core so the dashboard can import dist/
npm run build

# 2. Install and run the dashboard
cd dashboard
npm install
npm run seed   # optional: write demo state to ./.leasebroker
npm run dev    # http://localhost:3210
```

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

`leasebroker` is the **govern** third of a trilogy: [mcp-fit](https://github.com/TomCruiseTorpedo/mcp-fit)
scores what a server or agent card exposes, and [gatewarden](https://github.com/TomCruiseTorpedo/gatewarden)
fuses score + govern into one in-path gateway.

## License

Apache-2.0 — see `LICENSE`.
