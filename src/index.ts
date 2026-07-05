/**
 * leasebroker — public API barrel.
 *
 * Exports everything a programmatic consumer needs to embed leasebroker
 * in their own application:
 *
 *   Contract (types, interfaces, zod schemas):
 *     import type { Lease, Signer, PolicyEngine } from 'leasebroker';
 *     import { LeaseSchema } from 'leasebroker';
 *
 *   Signing (PASETO v4.public):
 *     import { PasetoV4PublicSigner, generateKeyPair } from 'leasebroker';
 *
 *   Policy (declarative allow-rules):
 *     import { DeclarativePolicyEngine, loadRules } from 'leasebroker';
 *
 *   Audit (in-memory state stores):
 *     import { InMemoryAuditSink, InMemoryRevocationList, InMemorySpendLedger, InMemoryPendingStore } from 'leasebroker';
 *
 *   Broker (issuance orchestration):
 *     import { Broker } from 'leasebroker';
 *     import type { IssueResult } from 'leasebroker';
 *
 *   Enforce (MCP proxy + per-call enforcer):
 *     import { LeaseEnforcer, LeasebrokerProxy } from 'leasebroker';
 *     import type { ToolActionResolver } from 'leasebroker';
 *
 * The CLI binary is distributed as `dist/cli/index.js` (the `leasebroker` bin).
 * It is not re-exported here — use the CLI commands directly.
 */

// ---------------------------------------------------------------------------
// Contract (types, interfaces, zod schemas) — the base of the stack
// ---------------------------------------------------------------------------
export * from './contract/index.js';

// ---------------------------------------------------------------------------
// Signing lane (PASETO v4.public Signer)
// ---------------------------------------------------------------------------
export { PasetoV4PublicSigner } from './signing/signer.js';
export { generateKeyPair, keyPairFromSeed } from './signing/keygen.js';
export type { KeyPair } from './signing/keygen.js';

// ---------------------------------------------------------------------------
// Policy lane (declarative allow-rule PolicyEngine)
// ---------------------------------------------------------------------------
export { DeclarativePolicyEngine } from './policy/engine.js';
export { loadRules } from './policy/loader.js';

// ---------------------------------------------------------------------------
// Audit lane (in-memory state stores)
// ---------------------------------------------------------------------------
export { InMemoryAuditSink } from './audit/audit-sink.js';
export { InMemoryPendingStore } from './audit/pending-store.js';
export { InMemoryRevocationList } from './audit/revocation-list.js';
export { InMemorySpendLedger } from './audit/spend-ledger.js';

// ---------------------------------------------------------------------------
// Broker lane (issuance orchestration)
// ---------------------------------------------------------------------------
export { Broker } from './broker/broker.js';
export type { IssueResult, GrantedResult, PendingResult, DeniedResult } from './broker/broker.js';

// ---------------------------------------------------------------------------
// Enforce lane (MCP middleware proxy + per-call LeaseEnforcer)
// ---------------------------------------------------------------------------
export { LeaseEnforcer } from './enforce/enforcer.js';
export { LeasebrokerProxy } from './enforce/proxy.js';
export type { ToolActionResolver, ProxyServerOptions } from './enforce/proxy.js';

// ---------------------------------------------------------------------------
// A2A lane (lease extension profile — docs/a2a-lease-extension-v1.md, ADR-F)
// ---------------------------------------------------------------------------
export * from './a2a/index.js';
