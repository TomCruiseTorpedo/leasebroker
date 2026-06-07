/**
 * In-memory pending request store.
 *
 * Implements the PendingStore interface from src/contract.
 *
 * Stores lease requests that received a `veto-required` decision and are
 * awaiting human approval or denial. The broker places them here; the CLI
 * surfaces them for human review and calls `resolve` to complete the decision.
 */

import type { LeaseRequest, PendingStore } from '../contract/index.js';

export class InMemoryPendingStore implements PendingStore {
  private readonly pending = new Map<string, LeaseRequest>();

  /**
   * Persist a pending request awaiting human approval.
   * If a request with the same reqId already exists, it is overwritten.
   */
  put(reqId: string, request: LeaseRequest): void {
    this.pending.set(reqId, request);
  }

  /**
   * Retrieve a pending request by ID.
   * Returns undefined if no request is found for the given reqId.
   */
  get(reqId: string): LeaseRequest | undefined {
    return this.pending.get(reqId);
  }

  /**
   * List all pending requests.
   * Returned in no guaranteed order.
   */
  list(): Array<{ reqId: string; request: LeaseRequest }> {
    return Array.from(this.pending.entries()).map(([reqId, request]) => ({
      reqId,
      request,
    }));
  }

  /**
   * Resolve a pending request by removing it from the store.
   * The caller (broker) is responsible for issuing a lease on 'approve'
   * or recording the denial on 'deny'. This store simply removes the entry.
   * No-op if the reqId is not found.
   */
  resolve(reqId: string, _decision: 'approve' | 'deny'): void {
    this.pending.delete(reqId);
  }
}
