/**
 * Broker lane barrel export.
 *
 * Consumers import from here:
 *   import { Broker } from './broker/index.js';
 *   import type { IssueResult, GrantedResult } from './broker/index.js';
 *
 * The Broker class depends ONLY on contract interfaces (PolicyEngine, Signer,
 * AuditSink, PendingStore) — it never imports concrete implementations directly.
 * Concrete impls (e.g. DeclarativePolicyEngine, PasetoV4PublicSigner) are wired
 * in by the CLI or integration tests.
 */

export { Broker } from './broker.js';
export type { IssueResult, GrantedResult, PendingResult, DeniedResult } from './broker.js';
