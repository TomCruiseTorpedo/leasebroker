/**
 * `leasebroker request` — submit a lease request.
 *
 * Reads a LeaseRequest as JSON from --request flag or stdin, submits it to
 * the broker, and prints the result.
 *
 * Usage:
 *   leasebroker request --request '{"agentId":"a1","taskId":"t1","capabilities":[...],"requestedDurationMs":3600000}'
 *   echo '{"agentId":"a1",...}' | leasebroker request
 *
 * Output (JSON):
 *   { "type": "granted", "token": "...", "leaseId": "..." }
 *   { "type": "pending", "reqId": "..." }
 *   { "type": "denied", "reason": "..." }
 */

import { readFileSync } from 'node:fs';
import type { LeaseRequest } from '../../contract/index.js';
import { LeaseRequestSchema } from '../../contract/index.js';
import type { CliState } from '../state.js';
import { saveState } from '../state.js';
import { wireComponents } from '../wire.js';

export interface RequestOptions {
  request?: string;
  rulesFile?: string;
  stdinData?: string;
}

export async function cmdRequest(state: CliState, opts: RequestOptions): Promise<void> {
  const rawJson = opts.request ?? opts.stdinData ?? readStdin();

  if (!rawJson || rawJson.trim() === '') {
    console.error('Error: provide a LeaseRequest JSON via --request or stdin');
    process.exit(1);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    console.error('Error: invalid JSON for LeaseRequest');
    process.exit(1);
  }

  const result = LeaseRequestSchema.safeParse(parsed);
  if (!result.success) {
    console.error('Error: invalid LeaseRequest:', result.error.message);
    process.exit(1);
  }

  const req: LeaseRequest = result.data;
  const { broker } = wireComponents(state, opts.rulesFile);
  const outcome = broker.request(req);

  saveState(state);

  if (outcome.type === 'granted') {
    console.log(JSON.stringify({ type: 'granted', token: outcome.token, leaseId: outcome.lease.id }));
  } else if (outcome.type === 'pending') {
    console.log(JSON.stringify({ type: 'pending', reqId: outcome.reqId }));
  } else {
    console.log(JSON.stringify({ type: 'denied', reason: outcome.reason }));
    process.exit(2);
  }
}

function readStdin(): string | undefined {
  try {
    return readFileSync('/dev/stdin', 'utf8');
  } catch {
    return undefined;
  }
}
