#!/usr/bin/env node
/**
 * Seed a realistic .leasebroker/ state dir for the dashboard.
 *
 * Builds a VALID hash-chained audit log via the core's InMemoryAuditSink
 * (append() computes the chain), then writes audit.jsonl + revoked.json +
 * spend.json — so `readDashboard()` reports integrity:"intact".
 *
 * Run from the dashboard dir:  npm run seed   (writes ./.leasebroker)
 */
import { InMemoryAuditSink } from '../dist/audit/audit-sink.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const sink = new InMemoryAuditSink();
const now = Date.now();
const iso = (ms) => new Date(ms).toISOString();

function issue(leaseId, agentId, taskId, expiresMs, capabilities) {
  sink.append({
    type: 'issuance',
    at: iso(now - 60_000),
    leaseId,
    requestId: `req-${leaseId}`,
    detail: { agentId, taskId, expiresAt: iso(expiresMs), capabilities, kid: 'k1' },
    prevHash: '',
    hash: '',
  });
}
function event(type, leaseId, detail) {
  sink.append({ type, at: iso(now - 30_000), leaseId, detail, prevHash: '', hash: '' });
}

issue('lease-alpha', 'agent-research', 'task-crawl', now + 3_600_000, [
  { kind: 'fs.read', paths: ['/data/**'] },
  { kind: 'http.call', endpoints: ['api.example.com/**'] },
]);
issue('lease-bravo', 'agent-ops', 'task-spend', now + 1_800_000, [
  { kind: 'spend', currency: 'USD', capMinor: 10_000 },
]);
issue('lease-charlie', 'agent-research', 'task-write', now + 7_200_000, [
  { kind: 'fs.write', paths: ['/tmp/out/**'] },
]);
issue('lease-delta', 'agent-legacy', 'task-old', now - 600_000, [
  { kind: 'fs.read', paths: ['/etc/**'] },
]); // already expired

event('request', 'lease-alpha', { agentId: 'agent-research' });
event('decision', 'lease-alpha', { effect: 'grant', reason: 'matched rule allow-data-read' });
event('use', 'lease-bravo', { toolName: 'charge', action: { kind: 'spend', amountMinor: 4200 } });
event('denial', 'lease-bravo', {
  toolName: 'charge',
  reason: 'spend cap exceeded',
  action: { kind: 'spend', amountMinor: 9000 },
});
event('revocation', 'lease-charlie', { reason: 'Revoked by operator (seed)' });

const dir = join(process.cwd(), '.leasebroker');
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, 'audit.jsonl'), sink.read().map((e) => JSON.stringify(e)).join('\n') + '\n');
writeFileSync(join(dir, 'revoked.json'), JSON.stringify(['lease-charlie'], null, 2));
writeFileSync(join(dir, 'spend.json'), JSON.stringify({ 'lease-bravo': { spent: 4200, cap: 10_000 } }, null, 2));
// One veto-required request awaiting operator approve/deny.
writeFileSync(
  join(dir, 'pending.json'),
  JSON.stringify(
    {
      'req-echo': {
        agentId: 'agent-echo',
        taskId: 'task-partner-sync',
        capabilities: [{ kind: 'http.call', endpoints: ['api.partner.com/**'] }],
        requestedDurationMs: 900_000,
      },
    },
    null,
    2,
  ),
);
console.log(
  `Seeded ${dir} — ${sink.read().length} events (alpha+bravo active, charlie revoked, delta expired) + 1 pending`,
);
