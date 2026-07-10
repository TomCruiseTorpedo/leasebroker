import type { Capability } from '../../../dist/contract/index.js';

/**
 * Compact one-line summary of a capability set, for dense table/panel cells.
 * Shared by the leases table and the pending-approvals panel so the two never
 * drift in how a capability reads (e.g. `fs.read·2, spend 100.00 USD`).
 */
export function capSummary(caps: Capability[]): string {
  if (!caps.length) return '—';
  return caps
    .map((c) => {
      switch (c.kind) {
        case 'fs.read':
          return `fs.read·${c.paths.length}`;
        case 'fs.write':
          return `fs.write·${c.paths.length}`;
        case 'http.call':
          return `http·${c.endpoints.length}`;
        case 'spend':
          return `spend ${(c.capMinor / 100).toFixed(2)} ${c.currency}`;
        default:
          return 'unknown';
      }
    })
    .join(', ');
}
