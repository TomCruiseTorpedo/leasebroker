# leasebroker

A local-first broker that issues **time-bounded, narrowly-scoped capability leases** to AI agents and their tools/MCP servers — instead of standing, broad permissions.

An agent asks for exactly the capability a task needs ("read these paths / call this API / spend ≤ $Y, for task T, for N minutes"); a policy decides; the broker issues a **signed, scoped, expiring lease** the agent must present to act. The broker enforces the scope in-path, logs every event to a tamper-evident audit trail, can **revoke** a lease mid-flight, and can require a **human veto** on high-risk grants. Deny-by-default, least-privilege.

> Status: **design committed, pre-build.** The design is the source of truth — see the docs below. Implementation follows.

## Design (source of truth)

- Specification (WHAT/WHY): `specs/lease-broker/spec.md`
- Architecture decisions: `docs/adrs.md`
- Implementation plan (HOW): `plan.md`

## Approach

- Enforcement is **MCP middleware**: a proxy that fronts downstream MCP servers, verifies the lease and its scope on every tool call, then forwards or denies.
- Leases are **PASETO v4.public** tokens (Ed25519) — tamper-evident and verifiable offline.
- Policy is **declarative allow-rules**, with a seam to a richer policy language later.
- The lease is immutable; cumulative spend and revocation are tracked as state, keyed by lease id.

## Development

- `npm run typecheck` — `tsc --noEmit`
- `npm run test` — run the test suite (vitest)
- `npm run build` — compile to `dist/`
- `npm run demo` — run the red→green capability-brokering demo

## License

Apache-2.0.
