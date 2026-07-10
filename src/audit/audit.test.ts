/**
 * Tests for the audit module: AuditSink, RevocationList, PendingStore, SpendLedger.
 *
 * Required coverage:
 *   - Full-lifecycle reconstruction (all event types, chain linkage)
 *   - Hash-chain tamper detection (content mutation, prevHash mutation, insertion)
 *   - Spend cap boundary (at-cap allowed, over-cap denied, total unchanged on deny)
 *   - RevocationList lifecycle
 *   - PendingStore lifecycle
 */

import { beforeEach, describe, expect, it } from 'vitest';
import type { AuditEvent, LeaseRequest } from '../contract/index.js';
import { InMemoryAuditSink } from './audit-sink.js';
import { InMemoryPendingStore } from './pending-store.js';
import { InMemoryRevocationList } from './revocation-list.js';
import { InMemorySpendLedger } from './spend-ledger.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal AuditEvent for a given type.
 * The `prevHash` and `hash` fields are intentionally empty — the sink overwrites them.
 */
function makeEvent(
  type: AuditEvent['type'],
  detail: Record<string, unknown> = {},
): AuditEvent {
  return {
    type,
    at: new Date().toISOString(),
    detail,
    prevHash: '',
    hash: '',
  };
}

function makeLeaseRequest(overrides?: Partial<LeaseRequest>): LeaseRequest {
  return {
    agentId: 'agent-1',
    taskId: 'task-1',
    capabilities: [{ kind: 'fs.read', paths: ['/tmp/**'] }],
    requestedDurationMs: 60_000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// AuditSink
// ---------------------------------------------------------------------------

describe('InMemoryAuditSink', () => {
  let sink: InMemoryAuditSink;

  beforeEach(() => {
    sink = new InMemoryAuditSink();
  });

  it('starts empty', () => {
    expect(sink.read()).toHaveLength(0);
  });

  it('loadVerbatim preserves stored hashes exactly (no re-chaining)', () => {
    const source = new InMemoryAuditSink();
    source.append(makeEvent('request', {}));
    source.append(makeEvent('decision', {}));
    const stored = source.read();

    sink.loadVerbatim(stored);
    expect(sink.read()).toEqual(stored); // intact chain verifies as-is
  });

  it('loadVerbatim keeps a broken stored chain broken — read() throws', () => {
    const source = new InMemoryAuditSink();
    source.append(makeEvent('request', { agentId: 'honest' }));
    source.append(makeEvent('decision', {}));
    const stored = source.read();
    // Tamper with content while keeping the stored hash.
    stored[0] = { ...stored[0]!, detail: { agentId: 'attacker' } };

    sink.loadVerbatim(stored);
    expect(() => sink.read()).toThrow(/tampered/);
    expect(sink.readVerbatim()).toHaveLength(2); // evidence still inspectable
  });

  it('loadVerbatim throws on a non-empty sink', () => {
    sink.append(makeEvent('request', {}));
    expect(() => sink.loadVerbatim([])).toThrow(/empty sink/);
  });

  it('appends a single event and reads it back', () => {
    sink.append(makeEvent('request', { agentId: 'agent-1' }));
    const events = sink.read();
    expect(events).toHaveLength(1);
    expect(events[0]?.type).toBe('request');
    expect(events[0]?.detail).toEqual({ agentId: 'agent-1' });
  });

  it('preserves append order across multiple events', () => {
    sink.append(makeEvent('request', {}));
    sink.append(makeEvent('decision', {}));
    sink.append(makeEvent('issuance', {}));
    const types = sink.read().map((e) => e.type);
    expect(types).toEqual(['request', 'decision', 'issuance']);
  });

  it('sets prevHash to empty string for the first event', () => {
    sink.append(makeEvent('request', {}));
    expect(sink.read()[0]?.prevHash).toBe('');
  });

  it('computes a non-empty 64-char hex hash for every event', () => {
    sink.append(makeEvent('request', { id: 'r1' }));
    const event = sink.read()[0];
    expect(event?.hash).toBeTruthy();
    expect(event?.hash).toHaveLength(64); // SHA-256 hex = 64 chars
  });

  it('chains prevHash correctly: each event.prevHash === previous event.hash', () => {
    sink.append(makeEvent('request', {}));
    sink.append(makeEvent('decision', {}));
    sink.append(makeEvent('issuance', {}));
    const events = sink.read();
    expect(events[1]?.prevHash).toBe(events[0]?.hash);
    expect(events[2]?.prevHash).toBe(events[1]?.hash);
  });

  it('overwrites caller-supplied prevHash/hash with computed values', () => {
    const event = makeEvent('request', {});
    event.prevHash = 'caller-supplied-prevHash';
    event.hash = 'caller-supplied-hash';
    sink.append(event);
    const stored = sink.read()[0];
    expect(stored?.prevHash).toBe(''); // first event → prevHash must be ""
    expect(stored?.hash).toHaveLength(64); // real hash, not caller's value
    expect(stored?.hash).not.toBe('caller-supplied-hash');
  });

  it('includes optional leaseId and requestId in stored events', () => {
    const event: AuditEvent = {
      ...makeEvent('issuance', {}),
      leaseId: 'lease-42',
      requestId: 'req-7',
    };
    sink.append(event);
    const stored = sink.read()[0];
    expect(stored?.leaseId).toBe('lease-42');
    expect(stored?.requestId).toBe('req-7');
  });

  // ----- Full lifecycle reconstruction -----

  it('full-lifecycle reconstruction: all six event types in order', () => {
    sink.append(makeEvent('request', { agentId: 'agent-1', taskId: 'task-1' }));
    sink.append(makeEvent('decision', { effect: 'grant', ruleId: 'rule-fs-read' }));
    sink.append(makeEvent('issuance', { leaseId: 'lease-1', kid: 'key-2026' }));
    sink.append(makeEvent('use', { leaseId: 'lease-1', tool: 'read_file' }));
    sink.append(makeEvent('denial', { leaseId: 'lease-1', reason: 'path outside scope' }));
    sink.append(makeEvent('revocation', { leaseId: 'lease-1', reason: 'task complete' }));

    const events = sink.read();
    expect(events).toHaveLength(6);
    expect(events.map((e) => e.type)).toEqual([
      'request',
      'decision',
      'issuance',
      'use',
      'denial',
      'revocation',
    ]);

    // Verify the full chain links
    for (let i = 1; i < events.length; i++) {
      expect(events[i]?.prevHash).toBe(events[i - 1]?.hash);
    }

    // Verify payload fidelity
    expect(events[0]?.detail).toEqual({ agentId: 'agent-1', taskId: 'task-1' });
    expect(events[2]?.detail).toMatchObject({ leaseId: 'lease-1' });
  });

  // ----- Hash-chain tamper detection -----

  describe('hash-chain tamper detection', () => {
    /**
     * Access the internal events array to simulate storage-level tampering.
     * TypeScript `private` is compile-time only; at runtime the field is accessible.
     */
    function internalEvents(s: InMemoryAuditSink): AuditEvent[] {
      return (s as unknown as { events: AuditEvent[] }).events;
    }

    it('detects mutation of event detail (content hash mismatch)', () => {
      sink.append(makeEvent('request', { id: 'original' }));
      sink.append(makeEvent('decision', { effect: 'grant' }));

      const events = internalEvents(sink);
      const first = events[0];
      if (first) {
        (first.detail as Record<string, unknown>)['id'] = 'tampered';
      }

      expect(() => sink.read()).toThrow(/tampered/i);
    });

    it('detects mutation of event timestamp (content hash mismatch)', () => {
      sink.append(makeEvent('request', {}));

      const events = internalEvents(sink);
      const first = events[0];
      if (first) {
        // Cast through unknown to allow mutation of the readonly-ish field
        (first as unknown as { at: string }).at = '1970-01-01T00:00:00.000Z';
      }

      expect(() => sink.read()).toThrow(/tampered/i);
    });

    it('detects mutation of prevHash field (chain integrity check)', () => {
      sink.append(makeEvent('request', {}));
      sink.append(makeEvent('decision', {}));

      const events = internalEvents(sink);
      const second = events[1];
      if (second) {
        // Break the prevHash link on event[1]
        (second as unknown as { prevHash: string }).prevHash =
          'deadbeef'.repeat(8);
      }

      expect(() => sink.read()).toThrow(/tampered/i);
    });

    it('detects insertion of a spurious event mid-chain', () => {
      sink.append(makeEvent('request', { id: '1' }));
      sink.append(makeEvent('decision', { effect: 'grant' }));

      const events = internalEvents(sink);
      // Insert a fake event with a plausible prevHash but an invalid hash value.
      const spurious: AuditEvent = {
        type: 'use',
        at: new Date().toISOString(),
        detail: { injected: true },
        prevHash: events[0]?.hash ?? '',
        hash: 'not-a-real-sha256-hash',
      };
      events.splice(1, 0, spurious);

      // event[1] (the spurious one) will fail its hash integrity check.
      expect(() => sink.read()).toThrow(/tampered/i);
    });

    it('detects removal of an event (chain break)', () => {
      sink.append(makeEvent('request', {}));
      sink.append(makeEvent('decision', {}));
      sink.append(makeEvent('issuance', {}));

      const events = internalEvents(sink);
      // Remove the middle event — event[2].prevHash now points to event[0].hash
      events.splice(1, 1);

      expect(() => sink.read()).toThrow(/tampered/i);
    });
  });
});

// ---------------------------------------------------------------------------
// RevocationList
// ---------------------------------------------------------------------------

describe('InMemoryRevocationList', () => {
  let list: InMemoryRevocationList;

  beforeEach(() => {
    list = new InMemoryRevocationList();
  });

  it('reports nothing as revoked initially', () => {
    expect(list.isRevoked('lease-1')).toBe(false);
  });

  it('revokes a lease and reports it revoked', () => {
    list.revoke('lease-1');
    expect(list.isRevoked('lease-1')).toBe(true);
  });

  it('does not affect other leases when one is revoked', () => {
    list.revoke('lease-1');
    expect(list.isRevoked('lease-2')).toBe(false);
  });

  it('revoke is idempotent', () => {
    list.revoke('lease-1');
    list.revoke('lease-1');
    expect(list.isRevoked('lease-1')).toBe(true);
  });

  it('multiple leases can be independently revoked', () => {
    list.revoke('lease-1');
    list.revoke('lease-3');
    expect(list.isRevoked('lease-1')).toBe(true);
    expect(list.isRevoked('lease-2')).toBe(false);
    expect(list.isRevoked('lease-3')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PendingStore
// ---------------------------------------------------------------------------

describe('InMemoryPendingStore', () => {
  let store: InMemoryPendingStore;

  beforeEach(() => {
    store = new InMemoryPendingStore();
  });

  it('starts empty', () => {
    expect(store.list()).toHaveLength(0);
  });

  it('put and get round-trips a request', () => {
    const req = makeLeaseRequest();
    store.put('req-1', req);
    expect(store.get('req-1')).toEqual(req);
  });

  it('get returns undefined for an unknown reqId', () => {
    expect(store.get('no-such-req')).toBeUndefined();
  });

  it('list returns all pending requests', () => {
    store.put('req-1', makeLeaseRequest({ taskId: 'task-1' }));
    store.put('req-2', makeLeaseRequest({ taskId: 'task-2' }));
    const items = store.list();
    expect(items).toHaveLength(2);
    expect(items.map((i) => i.reqId).sort()).toEqual(['req-1', 'req-2']);
  });

  it('put overwrites an existing request with the same reqId', () => {
    const original = makeLeaseRequest({ taskId: 'task-original' });
    const updated = makeLeaseRequest({ taskId: 'task-updated' });
    store.put('req-1', original);
    store.put('req-1', updated);
    expect(store.get('req-1')?.taskId).toBe('task-updated');
    expect(store.list()).toHaveLength(1);
  });

  it('resolve (approve) removes the request from the store', () => {
    store.put('req-1', makeLeaseRequest());
    store.resolve('req-1', 'approve');
    expect(store.get('req-1')).toBeUndefined();
    expect(store.list()).toHaveLength(0);
  });

  it('resolve (deny) removes the request from the store', () => {
    store.put('req-1', makeLeaseRequest());
    store.resolve('req-1', 'deny');
    expect(store.get('req-1')).toBeUndefined();
  });

  it('resolve is a no-op for unknown reqIds', () => {
    expect(() => store.resolve('no-such-req', 'deny')).not.toThrow();
  });

  it('resolve leaves other pending requests untouched', () => {
    store.put('req-1', makeLeaseRequest({ taskId: 'task-1' }));
    store.put('req-2', makeLeaseRequest({ taskId: 'task-2' }));
    store.resolve('req-1', 'approve');
    expect(store.list()).toHaveLength(1);
    expect(store.get('req-2')).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// SpendLedger
// ---------------------------------------------------------------------------

describe('InMemorySpendLedger', () => {
  let ledger: InMemorySpendLedger;

  beforeEach(() => {
    ledger = new InMemorySpendLedger();
  });

  it('spent returns 0 for an unknown leaseId', () => {
    expect(ledger.spent('unknown-lease')).toBe(0);
  });

  it('accrue throws if no cap has been registered for the lease', () => {
    expect(() => ledger.accrue('lease-1', 100)).toThrow(/cap/i);
  });

  it('accrue returns true and records the amount when within cap', () => {
    ledger.setCap('lease-1', 1000);
    expect(ledger.accrue('lease-1', 400)).toBe(true);
    expect(ledger.spent('lease-1')).toBe(400);
  });

  it('accrue accumulates across multiple calls', () => {
    ledger.setCap('lease-1', 1000);
    ledger.accrue('lease-1', 300);
    ledger.accrue('lease-1', 250);
    expect(ledger.spent('lease-1')).toBe(550);
  });

  // ----- Spend cap boundary -----

  it('at-cap: accrue of exactly the cap amount returns true', () => {
    ledger.setCap('lease-1', 1000);
    expect(ledger.accrue('lease-1', 1000)).toBe(true);
    expect(ledger.spent('lease-1')).toBe(1000);
  });

  it('over-cap: accrue that would exceed the cap returns false', () => {
    ledger.setCap('lease-1', 1000);
    expect(ledger.accrue('lease-1', 1001)).toBe(false);
    expect(ledger.spent('lease-1')).toBe(0); // nothing accrued
  });

  it('spend cap boundary: accumulate to cap, then deny the next accrue', () => {
    ledger.setCap('lease-1', 1000);

    expect(ledger.accrue('lease-1', 500)).toBe(true); // 500 / 1000
    expect(ledger.spent('lease-1')).toBe(500);

    expect(ledger.accrue('lease-1', 500)).toBe(true); // 1000 / 1000 — at cap, allowed
    expect(ledger.spent('lease-1')).toBe(1000);

    expect(ledger.accrue('lease-1', 1)).toBe(false); // 1001 > 1000 — denied
    expect(ledger.spent('lease-1')).toBe(1000); // unchanged

    // A zero-amount accrue after reaching cap is still allowed (no increase)
    expect(ledger.accrue('lease-1', 0)).toBe(true);
    expect(ledger.spent('lease-1')).toBe(1000);
  });

  it('failed accrue does not modify the spent total', () => {
    ledger.setCap('lease-1', 100);
    ledger.accrue('lease-1', 50);
    const beforeFailed = ledger.spent('lease-1');
    expect(ledger.accrue('lease-1', 60)).toBe(false); // 110 > 100
    expect(ledger.spent('lease-1')).toBe(beforeFailed); // still 50
  });

  it('multiple leases are tracked independently', () => {
    ledger.setCap('lease-1', 1000);
    ledger.setCap('lease-2', 500);

    expect(ledger.accrue('lease-1', 800)).toBe(true);
    expect(ledger.accrue('lease-2', 300)).toBe(true);

    // lease-1: 800 + 300 = 1100 > 1000 → denied
    expect(ledger.accrue('lease-1', 300)).toBe(false);
    // lease-2: 300 + 200 = 500 == cap → allowed
    expect(ledger.accrue('lease-2', 200)).toBe(true);

    expect(ledger.spent('lease-1')).toBe(800); // only 800 accrued
    expect(ledger.spent('lease-2')).toBe(500); // at cap
  });

  it('setCap can be updated for an existing lease without resetting spent', () => {
    ledger.setCap('lease-1', 500);
    ledger.accrue('lease-1', 300);
    // Raise the cap
    ledger.setCap('lease-1', 1000);
    expect(ledger.spent('lease-1')).toBe(300); // spent unchanged
    expect(ledger.accrue('lease-1', 600)).toBe(true); // 900 <= 1000 — allowed
  });
});
