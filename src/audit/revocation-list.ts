/**
 * In-memory revocation list.
 *
 * Implements the RevocationList interface from src/contract.
 *
 * Tracks revoked lease IDs in a Set. Enforcement points call `isRevoked`
 * before permitting any action under a lease.
 *
 * This is intentionally simple — a persistent variant would use the same
 * interface and swap the Set for a durable store.
 */

import type { RevocationList } from '../contract/index.js';

export class InMemoryRevocationList implements RevocationList {
  private readonly revoked = new Set<string>();

  /**
   * Revoke an active lease by ID.
   * Idempotent — revoking an already-revoked lease has no effect.
   */
  revoke(leaseId: string): void {
    this.revoked.add(leaseId);
  }

  /**
   * Returns true if the lease has been revoked, false otherwise.
   */
  isRevoked(leaseId: string): boolean {
    return this.revoked.has(leaseId);
  }
}
