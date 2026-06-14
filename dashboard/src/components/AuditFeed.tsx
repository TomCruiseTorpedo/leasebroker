import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { AuditEvent } from '../../../dist/contract/index.js';

const ROW = 28;
const short = (id: string) => (id.length > 14 ? id.slice(0, 14) + '…' : id);
const timeOnly = (iso: string) => {
  try {
    return new Date(iso).toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return iso;
  }
};

function detailSummary(ev: AuditEvent): string {
  const d = ev.detail ?? {};
  const keys = ['toolName', 'effect', 'reason', 'action'];
  const parts: string[] = [];
  for (const k of keys) {
    if (k in d) {
      const v = (d as Record<string, unknown>)[k];
      parts.push(`${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`);
    }
  }
  return parts.join('  ');
}

/** Virtualized audit event feed. Events are expected already in display order. */
export function AuditFeed({ events }: { events: AuditEvent[] }) {
  const rows = events;
  const parent = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW,
    overscan: 15,
  });
  const items = v.getVirtualItems();
  const padTop = items.length ? items[0].start : 0;
  const padBottom = items.length ? v.getTotalSize() - items[items.length - 1].end : 0;

  return (
    <div className="feed" ref={parent}>
      {rows.length === 0 && <div className="ev mono-dim">No audit events.</div>}
      <div style={{ height: padTop }} />
      {items.map((vi) => {
        const ev = rows[vi.index]!;
        return (
          <div className="ev" key={vi.index} style={{ height: ROW, overflow: 'hidden' }}>
            <span className="t">{timeOnly(ev.at)}</span>
            <span className={`ty ${ev.type}`}>{ev.type}</span>
            <span className="d" title={ev.leaseId ?? ''}>
              {ev.leaseId ? <span className="mono-dim">{short(ev.leaseId)} </span> : null}
              {detailSummary(ev)}
            </span>
          </div>
        );
      })}
      <div style={{ height: padBottom }} />
    </div>
  );
}
