/**
 * Zod schemas for leasebroker contract types.
 *
 * These schemas validate incoming data at the trust boundary (e.g. API requests,
 * policy rule files). They are the runtime enforcement of the type definitions
 * in types.ts.
 *
 * Key invariant: money (capMinor, amountMinor) is always an integer — never float.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Capability schemas
// ---------------------------------------------------------------------------

const FsReadCapabilitySchema = z.object({
  kind: z.literal('fs.read'),
  paths: z.array(z.string()).min(1, 'At least one path glob is required'),
});

const FsWriteCapabilitySchema = z.object({
  kind: z.literal('fs.write'),
  paths: z.array(z.string()).min(1, 'At least one path glob is required'),
});

const HttpCallCapabilitySchema = z.object({
  kind: z.literal('http.call'),
  endpoints: z.array(z.string()).min(1, 'At least one endpoint is required'),
});

const SpendCapabilitySchema = z.object({
  kind: z.literal('spend'),
  currency: z.string().min(1, 'Currency is required'),
  /**
   * Spend cap in integer minor units (e.g. cents). MUST be a non-negative integer.
   * Float values are rejected — money is never float.
   */
  capMinor: z
    .number()
    .int('capMinor must be an integer (money is never float)')
    .nonnegative('capMinor must be non-negative'),
});

/**
 * Validated Capability discriminated union.
 * Rejects any unknown `kind` values.
 */
export const CapabilitySchema = z.discriminatedUnion('kind', [
  FsReadCapabilitySchema,
  FsWriteCapabilitySchema,
  HttpCallCapabilitySchema,
  SpendCapabilitySchema,
]);

/** Inferred TypeScript type from the Capability schema. */
export type CapabilityInput = z.infer<typeof CapabilitySchema>;

// ---------------------------------------------------------------------------
// LeaseRequest schema
// ---------------------------------------------------------------------------

/**
 * Validates a lease request from an agent.
 * Rejects missing fields, empty capabilities, and negative durations.
 */
export const LeaseRequestSchema = z.object({
  agentId: z.string().min(1, 'agentId is required'),
  taskId: z.string().min(1, 'taskId is required'),
  capabilities: z
    .array(CapabilitySchema)
    .min(1, 'At least one capability must be requested'),
  requestedDurationMs: z
    .number()
    .positive('requestedDurationMs must be positive'),
});

/** Inferred TypeScript type from the LeaseRequest schema. */
export type LeaseRequestInput = z.infer<typeof LeaseRequestSchema>;

// ---------------------------------------------------------------------------
// Lease schema
// ---------------------------------------------------------------------------

/**
 * Validates a Lease object (e.g. when deserialising from a PASETO token payload).
 */
export const LeaseSchema = z.object({
  id: z.string().min(1, 'id is required'),
  agentId: z.string().min(1, 'agentId is required'),
  taskId: z.string().min(1, 'taskId is required'),
  capabilities: z
    .array(CapabilitySchema)
    .min(1, 'At least one capability must be in the lease'),
  issuedAt: z.string().datetime({ message: 'issuedAt must be an ISO 8601 datetime' }),
  expiresAt: z.string().datetime({ message: 'expiresAt must be an ISO 8601 datetime' }),
  kid: z.string().min(1, 'kid (key ID) is required'),
});

/** Inferred TypeScript type from the Lease schema. */
export type LeaseInput = z.infer<typeof LeaseSchema>;

// ---------------------------------------------------------------------------
// PolicyRule schema
// ---------------------------------------------------------------------------

/**
 * Validates a declarative allow-rule for the policy engine (ADR-C).
 *
 * Rules are stored as data (e.g. YAML/JSON config files) and loaded at startup.
 * No matching allow-rule → deny (deny-by-default).
 */
export const PolicyRuleSchema = z.object({
  ruleId: z.string().min(1, 'ruleId is required'),
  /** If set, the rule matches only this agent. Omit to match any agent. */
  agentId: z.string().optional(),
  /** If set, the rule matches only this capability kind. */
  capabilityKind: z
    .enum(['fs.read', 'fs.write', 'http.call', 'spend'])
    .optional(),
  /** The policy effect when this rule matches. */
  effect: z.enum(['allow', 'veto-required']),
  /** Optional upper bound on lease duration. */
  maxDurationMs: z.number().int().positive().optional(),
  /** For fs.read / fs.write: allowed path glob patterns. */
  paths: z.array(z.string()).optional(),
  /** For http.call: allowed endpoint patterns. */
  endpoints: z.array(z.string()).optional(),
  /**
   * For spend: maximum allowed cap in integer minor units.
   * Enforces that the rule cannot authorise more than this amount.
   */
  maxCapMinor: z
    .number()
    .int('maxCapMinor must be an integer (money is never float)')
    .nonnegative()
    .optional(),
  /** For spend: required currency code. */
  currency: z.string().optional(),
});

/** Inferred TypeScript type from the PolicyRule schema. */
export type PolicyRuleInput = z.infer<typeof PolicyRuleSchema>;
