/**
 * OTel-exporting audit sink — an OPT-IN decorator over any AuditSink.
 *
 * Wraps a delegate sink (composes, never replaces — the same
 * swap-behind-the-interface philosophy as ADR-A/C/D) and additionally emits
 * each appended event as an OpenTelemetry LOG RECORD. Audit events are
 * discrete instantaneous facts (issuance, denial, revocation…) with no
 * duration, so log records are the right primitive — not spans; leasebroker
 * is not a tracing tool and does not pretend to be one.
 *
 * Posture guarantees:
 * - NEVER wired by default. leasebroker is local-first; audit data leaves the
 *   process only when the consumer explicitly constructs this sink with a
 *   Logger they configured themselves.
 * - The delegate stays authoritative: it appends FIRST, and a delegate throw
 *   (e.g. tamper detection) prevents any export. Export failures never break
 *   enforcement — they are reported via `onExportError` (default:
 *   console.error), not swallowed and not fatal.
 * - Hash-chain fields are NOT exported: `prevHash`/`hash` are computed by the
 *   delegate on its stored copy, and the tamper evidence lives (and is
 *   verified) locally — an OTel pipeline is observability, not evidence.
 *
 * Consumer wiring (the transport is the consumer's dependency, not ours):
 *
 *   import { logs } from '@opentelemetry/api-logs';
 *   // consumer installs @opentelemetry/sdk-logs + an exporter, e.g.
 *   // @opentelemetry/exporter-logs-otlp-http, registers a LoggerProvider…
 *   const sink = new OtelExportingAuditSink(
 *     new InMemoryAuditSink(),
 *     logs.getLogger('leasebroker'),
 *   );
 */

import { SeverityNumber } from '@opentelemetry/api-logs';
import type { Logger } from '@opentelemetry/api-logs';
import type { AuditEvent, AuditSink } from '../contract/index.js';

export interface OtelExportOptions {
  /** Called when emitting a log record throws. Default: console.error. */
  onExportError?: (error: unknown, event: AuditEvent) => void;
}

export class OtelExportingAuditSink implements AuditSink {
  constructor(
    private readonly delegate: AuditSink,
    private readonly logger: Logger,
    private readonly options: OtelExportOptions = {},
  ) {}

  append(event: AuditEvent): void {
    // Delegate first — it owns hashing and the fail-closed tamper stance.
    this.delegate.append(event);

    try {
      const taskId = typeof event.detail['taskId'] === 'string' ? event.detail['taskId'] : undefined;
      this.logger.emit({
        timestamp: new Date(event.at),
        severityNumber: SeverityNumber.INFO,
        severityText: 'INFO',
        body: `leasebroker audit: ${event.type}`,
        attributes: {
          'leasebroker.event.type': event.type,
          ...(event.leaseId !== undefined ? { 'leasebroker.lease.id': event.leaseId } : {}),
          ...(event.requestId !== undefined ? { 'leasebroker.request.id': event.requestId } : {}),
          ...(taskId !== undefined ? { 'leasebroker.task.id': taskId } : {}),
          'leasebroker.event.detail': JSON.stringify(event.detail),
        },
      });
    } catch (err) {
      const onError =
        this.options.onExportError ??
        ((error: unknown, ev: AuditEvent) => {
          console.error(`OTel audit export failed for ${ev.type} event:`, error);
        });
      onError(err, event);
    }
  }

  read(): AuditEvent[] {
    return this.delegate.read();
  }
}
