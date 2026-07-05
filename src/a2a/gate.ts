/**
 * A2A lease gate — the deny ladder (ADR-F, profile §Deny ladder).
 *
 * Evaluated in order, first failure wins:
 *   1. extension support  → ExtensionSupportRequiredError (protocol-level)
 *   2. lease              → task `rejected` (missing/conflicting/failed token)
 *   3. veto               → task `auth-required` (pending human approval)
 *   4. allow              → bind context, hand the token to the caller
 *
 * Reuses `Enforcer.check` — the ADR-B pipeline (signature → expiry →
 * revocation → scope → spend) byte-for-byte unchanged. Veto-pending state is
 * an injected predicate so ADR-D's PendingStore stays decoupled. Pure
 * decision logic: no I/O, no protocol client — the consumer (gatewarden W4)
 * owns transport, task-state transitions, and audit emission.
 */

import type { Action, Enforcer } from '../contract/index.js';
import { declaresLeaseExtension, extractLeaseToken } from './extension.js';
import type { A2aLeaseBinding } from './binding.js';

// ---------------------------------------------------------------------------
// Error + task-state pins (profile §Deny ladder, §Task-state pins)
// ---------------------------------------------------------------------------

/**
 * The A2A v1.0 error an agent MUST return when a client has not declared a
 * required extension (spec §3.3.4), in all three transport dialects.
 */
export const EXTENSION_SUPPORT_REQUIRED_ERROR = Object.freeze({
  name: 'ExtensionSupportRequiredError',
  jsonrpcCode: -32008,
  httpStatus: 400,
  grpcStatus: 'FAILED_PRECONDITION',
} as const);

/**
 * Pinned task-state conventions — A2A mandates NO denial terminal state, so
 * this profile pins one (interop convention, not spec; foreign agents may
 * map denial to failed/canceled — match on terminal-ness when consuming).
 */
export const A2A_TASK_STATE_PINS = Object.freeze({
  /** Lease denied / veto denied. */
  denied: 'rejected',
  /** Human approval pending (A2A §7.6 In-Task Authorization). */
  vetoPending: 'auth-required',
  /** Client gives up while pending (CancelTask; success not guaranteed). */
  clientCancelled: 'canceled',
} as const);

// ---------------------------------------------------------------------------
// Gate types
// ---------------------------------------------------------------------------

/** One inbound message, reduced to what the ladder needs. */
export interface A2aGateRequest {
  /**
   * Extension URIs the client declared — parse the `A2A-Extensions` header
   * with parseExtensionsHeader(), or pass Message.extensions.
   */
  declaredExtensions: readonly string[];
  /** The message metadata (token carried at metadata[LEASE_EXT_URI]). */
  metadata?: Record<string, unknown> | null;
  /** A2A context id — the binding unit (profile §Context binding). */
  contextId: string;
  /** The concrete action this message asks for (resolved by the consumer). */
  action: Action;
}

/** Collaborators the ladder consults. */
export interface A2aGateDeps {
  binding: A2aLeaseBinding;
  /** The ADR-B enforcement pipeline, unchanged. */
  enforcer: Pick<Enforcer, 'check'>;
  /**
   * True when a pending human-approval request exists for this context
   * (ADR-D veto: no lease is issued until the operator approves). Omit when
   * the consumer has no veto surface — the ladder then rejects instead of
   * pausing.
   */
  hasPendingApproval?: (contextId: string) => boolean;
}

/** The ladder's verdict — the consumer maps it onto transport + task state. */
export type A2aGateDecision =
  | {
      /** Ladder stage 1: protocol-level rejection, no task is created. */
      outcome: 'reject-protocol';
      error: typeof EXTENSION_SUPPORT_REQUIRED_ERROR;
      reason: string;
    }
  | {
      /** Ladder stage 2: task reaches the pinned denial terminal state. */
      outcome: 'reject-task';
      taskState: typeof A2A_TASK_STATE_PINS.denied;
      reason: string;
    }
  | {
      /** Ladder stage 3: task pauses awaiting out-of-band approval. */
      outcome: 'pause-task';
      taskState: typeof A2A_TASK_STATE_PINS.vetoPending;
      reason: string;
    }
  | {
      /** Ladder stage 4: permitted — audit `use` and forward. */
      outcome: 'allow';
      token: string;
    };

// ---------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------

export function evaluateA2aLeaseGate(
  request: A2aGateRequest,
  deps: A2aGateDeps,
): A2aGateDecision {
  // ── 1. Extension support (awareness gate, NOT a security boundary) ───────
  if (!declaresLeaseExtension(request.declaredExtensions)) {
    return {
      outcome: 'reject-protocol',
      error: EXTENSION_SUPPORT_REQUIRED_ERROR,
      reason:
        'client did not declare the lease extension in A2A-Extensions (profile §Negotiation)',
    };
  }

  // ── 2a. Resolve the token: presented, or bound to the context ────────────
  const presented = extractLeaseToken(request.metadata);
  const bound = deps.binding.tokenFor(request.contextId);

  if (presented !== undefined && bound !== undefined && presented !== bound) {
    return {
      outcome: 'reject-task',
      taskState: A2A_TASK_STATE_PINS.denied,
      reason: 'context is already bound to a different lease token',
    };
  }

  const token = presented ?? bound;

  // ── 3. No token: veto-pending pauses, otherwise reject ───────────────────
  if (token === undefined) {
    if (deps.hasPendingApproval?.(request.contextId) === true) {
      return {
        outcome: 'pause-task',
        taskState: A2A_TASK_STATE_PINS.vetoPending,
        reason:
          'lease issuance awaits human approval (leasebroker approve <reqId>) — A2A §7.6 out-of-band resume',
      };
    }
    return {
      outcome: 'reject-task',
      taskState: A2A_TASK_STATE_PINS.denied,
      reason: 'no lease token presented and none bound to this context',
    };
  }

  // ── 2b. Enforce: the unchanged ADR-B pipeline ─────────────────────────────
  const verdict = deps.enforcer.check(token, request.action);
  if (!verdict.ok) {
    return {
      outcome: 'reject-task',
      taskState: A2A_TASK_STATE_PINS.denied,
      reason: verdict.reason ?? 'enforcement denied',
    };
  }

  // ── 4. Allow: bind (idempotent for the same token) and proceed ───────────
  if (presented !== undefined) {
    deps.binding.bind(request.contextId, presented);
  }
  return { outcome: 'allow', token };
}
