/**
 * Broker — issuance orchestration (policy + sign + audit + veto).
 *
 * Orchestrates the lease issuance lifecycle:
 *   1. Validate incoming LeaseRequest via zod (trust-boundary enforcement)
 *   2. Audit the incoming request
 *   3. Evaluate policy (PolicyEngine.evaluate)
 *   4. Audit the decision
 *   5a. grant   → issue lease via Signer.issue, audit issuance, return token
 *   5b. veto-required → PendingStore.put (NO lease issued), return pending reqId
 *   5c. deny    → audit denial, return denial reason
 *
 * approve(reqId) retrieves the pending request and issues under normal grant rules.
 * deny(reqId) removes from pending and audits the denial; no lease is issued.
 *
 * Design constraints (from the attached args and plan):
 * - Depends on contract INTERFACES via constructor injection; never on concrete classes.
 * - Issued scope is always a subset of (or equal to) the requested scope.
 * - The `kid` for issued leases is a constructor parameter; it must match the
 *   Signer's active signing key so verification succeeds.
 */

import { randomUUID } from 'node:crypto';

import type {
  AuditSink,
  Lease,
  LeaseRequest,
  PolicyEngine,
  PendingStore,
  Signer,
} from '../contract/index.js';
import { LeaseRequestSchema } from '../contract/index.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** A lease was successfully issued. */
export type GrantedResult = {
  type: 'granted';
  /** PASETO v4.public token — the wire form of the lease. */
  token: string;
  /** The issued Lease (structured claims). */
  lease: Lease;
};

/**
 * The policy required human veto approval before a lease can be issued.
 * The caller should surface `reqId` to the operator (e.g. via CLI).
 */
export type PendingResult = {
  type: 'pending';
  /** ID of the stored pending request. Use with `approve`/`deny`. */
  reqId: string;
};

/** The request was denied (no lease issued). */
export type DeniedResult = {
  type: 'denied';
  reason: string;
};

/** Union of all possible outcomes from `Broker.request` or `Broker.approve`. */
export type IssueResult = GrantedResult | PendingResult | DeniedResult;

// ---------------------------------------------------------------------------
// Broker
// ---------------------------------------------------------------------------

/**
 * Issuance orchestrator for the leasebroker.
 *
 * All dependencies are injected as contract interfaces — never as concrete
 * implementations — so each component is swappable without changing this class.
 */
export class Broker {
  readonly #policy: PolicyEngine;
  readonly #signer: Signer;
  readonly #audit: AuditSink;
  readonly #pending: PendingStore;
  /** Key ID embedded in every issued lease (must match the Signer's active key). */
  readonly #kid: string;

  /**
   * @param policy  Evaluates lease requests against policy rules.
   * @param signer  Signs leases into PASETO tokens and verifies them.
   * @param audit   Append-only, hash-chained audit log.
   * @param pending Storage for veto-required requests awaiting human review.
   * @param kid     Key ID for issued leases (must match the Signer's active kid).
   */
  constructor(
    policy: PolicyEngine,
    signer: Signer,
    audit: AuditSink,
    pending: PendingStore,
    kid: string,
  ) {
    this.#policy = policy;
    this.#signer = signer;
    this.#audit = audit;
    this.#pending = pending;
    this.#kid = kid;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Process a lease request.
   *
   * Validates, evaluates, and dispatches to grant / veto / deny.
   * Audit events are appended for every request and every decision.
   *
   * @returns `GrantedResult` — lease issued and token returned
   * @returns `PendingResult` — veto required; awaiting human approval
   * @returns `DeniedResult`  — request was denied by policy or validation
   */
  request(req: LeaseRequest): IssueResult {
    // 1. Validate at the trust boundary
    const parsed = LeaseRequestSchema.safeParse(req);
    if (!parsed.success) {
      return {
        type: 'denied',
        reason: `Invalid request: ${parsed.error.message}`,
      };
    }
    const validReq = parsed.data;
    const reqId = randomUUID();

    // 2. Audit the incoming request
    this.#appendRequestEvent(reqId, validReq);

    // 3. Evaluate policy
    const decision = this.#policy.evaluate(validReq);

    // 4. Audit the decision
    this.#appendDecisionEvent(reqId, decision.effect, decision.reason, decision.ruleId);

    // 5. Dispatch on effect
    if (decision.effect === 'deny') {
      return { type: 'denied', reason: decision.reason };
    }

    if (decision.effect === 'veto-required') {
      // Store for human review — NO lease is issued yet.
      this.#pending.put(reqId, validReq);
      return { type: 'pending', reqId };
    }

    // effect === 'grant': issue the lease
    return this.#issueLease(reqId, validReq);
  }

  /**
   * Approve a pending (veto-required) request.
   *
   * The human operator approved the veto. The request is removed from the
   * PendingStore and a lease is issued under the same grant rules as a
   * normal approval (same scope, same duration math, same audit trail).
   *
   * @returns `GrantedResult` — lease issued
   * @returns `DeniedResult`  — reqId not found in pending
   */
  approve(reqId: string): IssueResult {
    const req = this.#pending.get(reqId);
    if (req === undefined) {
      return {
        type: 'denied',
        reason: `No pending request found for reqId "${reqId}"`,
      };
    }

    // Remove from pending before issuing, so re-approval cannot double-issue.
    this.#pending.resolve(reqId, 'approve');

    return this.#issueLease(reqId, req);
  }

  /**
   * Deny a pending (veto-required) request.
   *
   * Removes from pending and appends a denial audit event. No lease is issued.
   * No-op if the reqId is not found.
   */
  deny(reqId: string): void {
    const req = this.#pending.get(reqId);
    this.#pending.resolve(reqId, 'deny');

    this.#audit.append({
      type: 'denial',
      at: new Date().toISOString(),
      requestId: reqId,
      detail: {
        reason: 'Denied by operator',
        agentId: req?.agentId,
      },
      prevHash: '',
      hash: '',
    });
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Build and sign a lease from the approved request, then audit the issuance.
   *
   * Issued scope = the requested capabilities (a subset of or equal to what was
   * requested, which the policy has already validated against the allow-rules).
   */
  #issueLease(reqId: string, req: LeaseRequest): GrantedResult {
    const now = new Date();
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + req.requestedDurationMs).toISOString();

    const lease: Lease = {
      id: randomUUID(),
      agentId: req.agentId,
      taskId: req.taskId,
      // Issued scope is a subset of (or equal to) requested scope.
      // Policy already validated that requested capabilities are within bounds.
      capabilities: req.capabilities,
      issuedAt,
      expiresAt,
      kid: this.#kid,
    };

    const token = this.#signer.issue(lease);

    this.#audit.append({
      type: 'issuance',
      at: new Date().toISOString(),
      leaseId: lease.id,
      requestId: reqId,
      detail: {
        agentId: lease.agentId,
        taskId: lease.taskId,
        issuedAt,
        expiresAt,
        capabilities: lease.capabilities,
      },
      prevHash: '',
      hash: '',
    });

    return { type: 'granted', token, lease };
  }

  #appendRequestEvent(reqId: string, req: LeaseRequest): void {
    this.#audit.append({
      type: 'request',
      at: new Date().toISOString(),
      requestId: reqId,
      detail: {
        agentId: req.agentId,
        taskId: req.taskId,
        capabilities: req.capabilities,
        requestedDurationMs: req.requestedDurationMs,
      },
      prevHash: '',
      hash: '',
    });
  }

  #appendDecisionEvent(
    reqId: string,
    effect: 'grant' | 'deny' | 'veto-required',
    reason: string,
    ruleId?: string,
  ): void {
    this.#audit.append({
      type: 'decision',
      at: new Date().toISOString(),
      requestId: reqId,
      detail: {
        effect,
        reason,
        ...(ruleId !== undefined ? { ruleId } : {}),
      },
      prevHash: '',
      hash: '',
    });
  }
}
