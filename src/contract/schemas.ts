/**
 * Zod schemas for leasebroker contract types.
 *
 * These schemas validate incoming data at the trust boundary (e.g. API requests,
 * policy rule files). They are the runtime enforcement of the type definitions
 * in types.ts.
 *
 * Key invariant: money (capMinor, amountMinor) is always an integer — never float.
 */

import { posix as posixPath } from 'node:path';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Path canonicalization
// ---------------------------------------------------------------------------

/**
 * Canonicalize a filesystem path or path glob at the trust boundary.
 *
 * WHY THIS LIVES HERE and not in a matcher. The system has TWO path matchers
 * and they disagreed on the same input:
 *
 *   policy engine  pathIsCovered('./data/../../.ssh/id_rsa', './data/**')  true
 *   enforcer       minimatch('./data/../../.ssh/id_rsa', './data/**')      false
 *
 * The policy engine's matcher is a string-prefix test, so `./data/…` covers
 * anything spelled with that prefix — including a path that climbs back out.
 * minimatch resolves the segments and refuses. The result was a lease MINTED
 * and AUDIT-LOGGED as scoped to `./data` while actually naming `~/.ssh`, then
 * denied later at use time.
 *
 * That fails closed today, which is luck rather than design: it flips open if
 * the documented Cedar swap lands, or if either end starts normalizing on its
 * own. Patching one matcher would leave the two able to disagree again. So the
 * input is canonicalized ONCE, here, before either matcher ever sees it —
 * requests and policy rules alike, so both sides compare like with like.
 *
 * `posix.normalize` resolves `.` and `..` segments lexically and leaves glob
 * syntax intact (`./data/**` becomes `data/**`). Lexical is the right level:
 * this is a scope grammar, not a filesystem probe — there is no symlink to
 * follow at issuance time and the path need not exist.
 *
 * APPLY IT AT EVERY DOOR, NOT JUST THIS ONE. The schema covers lease requests
 * and policy rules, but an Action reaches the enforcer at RUNTIME without
 * passing through any schema, and a library caller can hand the policy engine
 * capabilities directly. So both matchers canonicalize their own inputs too
 * (`enforce/enforcer.ts`, `policy/engine.ts`). The function is idempotent, so
 * normalizing already-normalized input costs nothing — and normalizing only
 * one side is worse than normalizing neither, because it turns an agreement
 * into a mismatch: a lease scoped to `data/**` stops matching an action
 * spelled `./data/file.txt`.
 */
export function canonicalizePath(input: string): string {
  return posixPath.normalize(input);
}

/**
 * A filesystem path or path glob, canonicalized at the boundary.
 *
 * Empty and whitespace-only are rejected rather than normalized: `normalize('')`
 * returns `'.'`, which would silently WIDEN an empty entry into the current
 * directory.
 */
const PathPatternSchema = z
  .string()
  .min(1, 'A path may not be empty')
  .refine((value) => value.trim().length > 0, 'A path may not be whitespace-only')
  .transform(canonicalizePath);

// ---------------------------------------------------------------------------
// Capability schemas
// ---------------------------------------------------------------------------

const FsReadCapabilitySchema = z.object({
  kind: z.literal('fs.read'),
  paths: z.array(PathPatternSchema).min(1, 'At least one path glob is required'),
});

const FsWriteCapabilitySchema = z.object({
  kind: z.literal('fs.write'),
  paths: z.array(PathPatternSchema).min(1, 'At least one path glob is required'),
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
  /**
   * For fs.read / fs.write: allowed path glob patterns.
   *
   * Canonicalized on the same terms as a request's paths — both sides of every
   * comparison must be normalized or the matchers can disagree again.
   */
  paths: z.array(PathPatternSchema).optional(),
  /**
   * For http.call: allowed endpoint patterns.
   *
   * NOT canonicalized. These are URLs, and running a filesystem path
   * normalizer over one is wrong (`https://a//b` is not `https:/a/b`). The
   * `..`-divergence this guards against is a filesystem-path problem; endpoint
   * matching has its own separate weakness — it checks a DECLARED endpoint
   * string and nothing intercepts sockets — which is the D3 egress question,
   * not this one.
   */
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
