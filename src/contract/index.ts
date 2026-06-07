/**
 * Contract barrel — re-exports all types, interfaces, and schemas.
 *
 * Consumers import from here:
 *   import type { Lease, Signer } from 'leasebroker/contract';
 *   import { LeaseSchema, CapabilitySchema } from 'leasebroker/contract';
 */

export type {
  // Capability
  CapabilityKind,
  FsReadCapability,
  FsWriteCapability,
  HttpCallCapability,
  SpendCapability,
  Capability,
  Scope,
  // Core types
  LeaseRequest,
  Lease,
  Decision,
  AuditEventType,
  AuditEvent,
  VerifyResult,
  Action,
  PolicyRule,
} from './types.js';

export type {
  // Interfaces
  Signer,
  PolicyEngine,
  AuditSink,
  PendingStore,
  RevocationList,
  SpendLedger,
  Enforcer,
} from './interfaces.js';

export {
  // Zod schemas
  CapabilitySchema,
  LeaseRequestSchema,
  LeaseSchema,
  PolicyRuleSchema,
} from './schemas.js';

export type {
  // Inferred schema input types
  CapabilityInput,
  LeaseRequestInput,
  LeaseInput,
  PolicyRuleInput,
} from './schemas.js';
