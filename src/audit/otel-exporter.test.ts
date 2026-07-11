/**
 * Tests for the OTel-exporting audit sink decorator.
 *
 * Required coverage:
 *   - Emitted log records map 1:1 to appended events (type, attribution,
 *     detail payload, timestamp).
 *   - The delegate receives everything unmodified, in order, hash-chained
 *     (composition must not drop, reorder, or alter data).
 *   - Hash-chain fields are NOT exported.
 *   - Delegate throw (tamper stance) prevents export entirely.
 *   - Export failure never breaks the append and surfaces via onExportError.
 */

import { describe, expect, it, vi } from 'vitest';
import type { Logger, LogRecord } from '@opentelemetry/api-logs';
import type { AuditEvent } from '../contract/index.js';
import { InMemoryAuditSink } from './audit-sink.js';
import { OtelExportingAuditSink } from './otel-exporter.js';

function makeEvent(type: AuditEvent['type'], detail: Record<string, unknown> = {}): AuditEvent {
  return { type, at: '2026-07-11T11:00:00.000Z', detail, prevHash: '', hash: '' };
}

/** Minimal in-memory Logger capturing emitted records. */
function mockLogger(): { logger: Logger; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { logger: { emit: (r: LogRecord) => void records.push(r), enabled: () => true }, records };
}

describe('OtelExportingAuditSink', () => {
  it('emits one log record per appended event with attribution attributes', () => {
    const { logger, records } = mockLogger();
    const sink = new OtelExportingAuditSink(new InMemoryAuditSink(), logger);

    sink.append({ ...makeEvent('issuance', { taskId: 't1' }), leaseId: 'l1', requestId: 'r1' });
    sink.append(makeEvent('denial', { reason: 'nope' }));

    expect(records).toHaveLength(2);
    expect(records[0]?.attributes).toMatchObject({
      'leasebroker.event.type': 'issuance',
      'leasebroker.lease.id': 'l1',
      'leasebroker.request.id': 'r1',
      'leasebroker.task.id': 't1',
    });
    expect(records[0]?.body).toBe('leasebroker audit: issuance');
    expect(records[0]?.timestamp).toEqual(new Date('2026-07-11T11:00:00.000Z'));
    expect(records[1]?.attributes?.['leasebroker.event.type']).toBe('denial');
    expect(JSON.parse(records[1]?.attributes?.['leasebroker.event.detail'] as string)).toEqual({
      reason: 'nope',
    });
  });

  it('never exports hash-chain fields', () => {
    const { logger, records } = mockLogger();
    const sink = new OtelExportingAuditSink(new InMemoryAuditSink(), logger);
    sink.append(makeEvent('request', { taskId: 't1' }));
    const attrs = records[0]?.attributes ?? {};
    expect(Object.keys(attrs).join(' ')).not.toMatch(/hash/i);
    expect(JSON.stringify(records[0])).not.toMatch(/prevHash/);
  });

  it('delegate receives everything unmodified, in order, and hash-chains as usual', () => {
    const { logger } = mockLogger();
    const delegate = new InMemoryAuditSink();
    const sink = new OtelExportingAuditSink(delegate, logger);

    sink.append(makeEvent('request', { taskId: 't1' }));
    sink.append(makeEvent('decision', { effect: 'allow' }));
    sink.append(makeEvent('issuance', { taskId: 't1' }));

    const events = sink.read(); // read() delegates; also verifies the chain
    expect(events.map((e) => e.type)).toEqual(['request', 'decision', 'issuance']);
    expect(events[1]?.prevHash).toBe(events[0]?.hash);
    expect(events[2]?.prevHash).toBe(events[1]?.hash);
  });

  it('a delegate throw prevents export (delegate is authoritative)', () => {
    const { logger, records } = mockLogger();
    const throwingDelegate = {
      append: () => {
        throw new Error('tampered');
      },
      read: () => [],
    };
    const sink = new OtelExportingAuditSink(throwingDelegate, logger);
    expect(() => sink.append(makeEvent('use'))).toThrow('tampered');
    expect(records).toHaveLength(0);
  });

  it('an export failure never breaks the append and surfaces via onExportError', () => {
    const onExportError = vi.fn();
    const failingLogger: Logger = {
      emit: () => {
        throw new Error('collector down');
      },
      enabled: () => true,
    };
    const delegate = new InMemoryAuditSink();
    const sink = new OtelExportingAuditSink(delegate, failingLogger, { onExportError });

    expect(() => sink.append(makeEvent('use', { taskId: 't1' }))).not.toThrow();
    expect(delegate.read()).toHaveLength(1);
    expect(onExportError).toHaveBeenCalledTimes(1);
    expect((onExportError.mock.calls[0]?.[0] as Error).message).toBe('collector down');
  });
});
