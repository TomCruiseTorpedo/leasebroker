/**
 * Core types for the leasebroker contract.
 *
 * All types are pure data shapes — no runtime logic.
 * Money is always integer minor units (e.g. cents). Never float.
 */

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/** Discriminant values for Capability. */
export type CapabilityKind = 'fs.read' | 'fs.write' | 'http.call' | 'spend';

/** Read access to filesystem paths matching the given glob patterns. */
export type FsReadCapability = {
  kind: 'fs.read';
  /** Glob patterns for allowed read paths. */
  paths: string[];
};

/** Write access to filesystem paths matching the given glob patterns. */
export type FsWriteCapability = {
  kind: 'fs.write';
  /** Glob patterns for allowed write paths. */
  paths: string[];
};

/** HTTP call access to the listed endpoints (host/path allow-list). */
export type HttpCallCapability = {
  kind: 'http.call';
  /** Allowed host/path endpoint patterns. */
  endpoints: string[];
};

/**
 * Spend capability — authorises spending up to `capMinor` in minor units.
 * `capMinor` MUST be a non-negative integer (e.g. 1000 = $10.00 in USD cents).
 */
export type SpendCapability = {
  kind: 'spend';
  /** ISO 4217 currency code or similar identifier. */
  currency: string;
  /**
   * Spend cap in integer minor units (e.g. cents).
   * Never a float — use `Math.round` if converting from major units.
   */
  capMinor: number;
};

/** Discriminated union of all capability kinds. */
export type Capability =
  | FsReadCapability
  | FsWriteCapability
  | HttpCallCapability
  | SpendCapability;

/**
 * Scope — the concrete bounds carried per capability.
 * The union members of Capability already carry their bounds,
 * so Scope is an alias for Capability.
 */
export type Scope = Capability;

// ---------------------------------------------------------------------------
// LeaseRequest
// ---------------------------------------------------------------------------

/** An agent's request for a capability lease. */
export type LeaseRequest = {
  /** Stable identifier for the requesting agent. */
  agentId: string;
  /** Identifier for the task requiring these capabilities. */
  taskId: string;
  /** The capabilities being requested. */
  capabilities: Capability[];
  /** How long the agent needs the lease, in milliseconds. */
  requestedDurationMs: number;
};

// ---------------------------------------------------------------------------
// Lease
// ---------------------------------------------------------------------------

/**
 * A granted, signed, time-bounded capability lease.
 * The wire form is the PASETO v4.public token whose claims are these fields.
 */
export type Lease = {
  /** Unique lease identifier. */
  id: string;
  /** The agent this lease was issued to. */
  agentId: string;
  /** The task this lease covers. */
  taskId: string;
  /** Granted capabilities (subset of or equal to what was requested). */
  capabilities: Capability[];
  /** ISO 8601 timestamp of issuance. */
  issuedAt: string;
  /** ISO 8601 timestamp of expiry. */
  expiresAt: string;
  /** Key ID used to sign this lease (for key rotation). */
  kid: string;
};

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/** The policy engine's verdict for a lease request. */
export type Decision = {
  /** The policy outcome. */
  effect: 'grant' | 'deny' | 'veto-required';
  /** Human-readable reason for the decision. */
  reason: string;
  /** Optional: the policy rule that produced this decision. */
  ruleId?: string;
};

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/** Discriminant values for AuditEvent. */
export type AuditEventType =
  | 'request'
  | 'decision'
  | 'issuance'
  | 'use'
  | 'denial'
  | 'revocation';

/** Shared fields for all audit events (hash-chained append-only log). */
type AuditEventBase = {
  /** ISO 8601 timestamp of the event. */
  at: string;
  /** Lease ID, if applicable. */
  leaseId?: string;
  /** Request ID, if applicable. */
  requestId?: string;
  /** Event-specific detail payload. */
  detail: Record<string, unknown>;
  /** Hash of the previous event (empty string for the first event). */
  prevHash: string;
  /** Hash of this event (including prevHash). */
  hash: string;
};

/**
 * Discriminated union of all audit event kinds.
 * Every event carries `prevHash` and `hash` forming a tamper-evident hash chain.
 */
export type AuditEvent =
  | (AuditEventBase & { type: 'request' })
  | (AuditEventBase & { type: 'decision' })
  | (AuditEventBase & { type: 'issuance' })
  | (AuditEventBase & { type: 'use' })
  | (AuditEventBase & { type: 'denial' })
  | (AuditEventBase & { type: 'revocation' });

// ---------------------------------------------------------------------------
// VerifyResult
// ---------------------------------------------------------------------------

/** Result of a lease or action verification. */
export type VerifyResult = {
  /** Whether the verification passed. */
  ok: boolean;
  /** Human-readable reason when `ok` is false. */
  reason?: string;
};

// ---------------------------------------------------------------------------
// Action (used by Enforcer)
// ---------------------------------------------------------------------------

/**
 * A concrete action an agent is attempting, checked against the lease scope.
 * Mirrors Capability but uses actual values instead of allowed value sets.
 */
export type Action =
  | { kind: 'fs.read'; path: string }
  | { kind: 'fs.write'; path: string }
  | { kind: 'http.call'; endpoint: string }
  | { kind: 'spend'; currency: string; amountMinor: number };

// ---------------------------------------------------------------------------
// PolicyRule
// ---------------------------------------------------------------------------

/**
 * A declarative allow-rule for the policy engine.
 * Absence of a matching allow-rule → deny (deny-by-default).
 */
export type PolicyRule = {
  /** Unique identifier for this rule. */
  ruleId: string;
  /** If set, the rule applies only to this agent. Omit to match any agent. */
  agentId?: string;
  /** If set, the rule applies only to this capability kind. */
  capabilityKind?: CapabilityKind;
  /** The policy effect when this rule matches. */
  effect: 'allow' | 'veto-required';
  /** Optional cap on lease duration. */
  maxDurationMs?: number;
  /** For fs.read/fs.write: allowed path patterns. */
  paths?: string[];
  /** For http.call: allowed endpoint patterns. */
  endpoints?: string[];
  /** For spend: maximum allowed cap in minor units. */
  maxCapMinor?: number;
  /** For spend: required currency. */
  currency?: string;
};
