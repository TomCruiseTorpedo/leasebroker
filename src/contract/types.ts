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
  /**
   * Duration the policy is willing to grant, already clamped to the matched
   * rule's `maxDurationMs`. Present whenever a rule matched.
   *
   * The broker may clamp this FURTHER against the rule's duration budget; this
   * is the policy ceiling, not the final issued duration.
   */
  grantedDurationMs?: number;
  /**
   * EVERY rule the request matched, with its duration budget if it has one —
   * passed through so the broker can consult the ledger without holding the
   * rule set.
   *
   * All of them, not just `ruleId`. A request carrying several capabilities
   * matches several rules and the issued lease grants authority under all of
   * them, so all of them must be charged. Charging only one would let an agent
   * dilute its budget by bundling an expensive capability with a cheap one
   * whose rule has a larger allowance.
   */
  matchedRules?: MatchedRule[];
};

/** A rule that matched, with the duration-budget parameters it carries. */
export type MatchedRule = {
  ruleId: string;
  /** Absent when the rule sets no duration budget. */
  maxTotalDurationMs?: number;
  /** Present whenever `maxTotalDurationMs` is (the schema requires the pair). */
  durationHalfLifeMs?: number;
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
  | 'revocation'
  /**
   * A call the proxy forwarded WITHOUT any lease check, because no capability
   * was mapped to that tool name.
   *
   * Deliberately not folded into 'use'. A 'use' event asserts that a lease was
   * verified and the call fell within its scope; a passthrough means neither
   * happened. Conflating them would make the log claim governance it did not
   * perform, which is the most expensive kind of lie an audit trail can tell.
   */
  | 'passthrough';

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
  | (AuditEventBase & { type: 'revocation' })
  | (AuditEventBase & { type: 'passthrough' });

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
  /**
   * Optional cap on the duration of a SINGLE lease.
   *
   * An over-long request is CLAMPED to this, not denied. Denying is what
   * trains an agent to ask for exactly the maximum and renew forever.
   */
  maxDurationMs?: number;
  /**
   * Optional cap on TOTAL granted lease time attributable to this rule,
   * measured in milliseconds and decayed with `durationHalfLifeMs`.
   *
   * This is what stops renewal accretion: without it, a thousand sequential
   * short leases cost exactly what one short lease costs, and standing
   * permission can be assembled one minute at a time.
   *
   * Read it as a DUTY CYCLE rather than a raw number — how much of wall-clock
   * time this authority may be live. 24h per 24h is 100%, i.e. the standing
   * permission leases are meant to replace.
   *
   * Omit to leave the rule unbudgeted (the pre-existing behaviour).
   */
  maxTotalDurationMs?: number;
  /**
   * Half-life for `maxTotalDurationMs`, in milliseconds. Required whenever
   * `maxTotalDurationMs` is set.
   *
   * Spend decays continuously, so headroom regenerates instead of resetting on
   * a boundary an agent can wait for. After one half-life, half of what was
   * spent has been forgiven. Short approximates a rate limit; long
   * approximates a hard budget with slow forgiveness.
   */
  durationHalfLifeMs?: number;
  /** For fs.read/fs.write: allowed path patterns. */
  paths?: string[];
  /** For http.call: allowed endpoint patterns. */
  endpoints?: string[];
  /** For spend: maximum allowed cap in minor units. */
  maxCapMinor?: number;
  /** For spend: required currency. */
  currency?: string;
};
