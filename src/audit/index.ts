/**
 * Audit module barrel.
 *
 * Exports the concrete implementations of the audit-lane interfaces.
 * Consumers should depend on the interfaces from src/contract, not on
 * these concrete classes — except where construction requires setCap
 * or other concrete-only methods.
 */

export { InMemoryAuditSink } from './audit-sink.js';
export { buildWorkflowReport } from './workflow-report.js';
export { OtelExportingAuditSink } from './otel-exporter.js';
export type { OtelExportOptions } from './otel-exporter.js';
export type { WorkflowReport, WorkflowStats } from './workflow-report.js';
export { parseStoredAuditJsonl } from './stored-chain.js';
export type { AuditIntegrity, StoredAuditLog } from './stored-chain.js';
export { InMemoryPendingStore } from './pending-store.js';
export { InMemoryRevocationList } from './revocation-list.js';
export { InMemorySpendLedger } from './spend-ledger.js';
