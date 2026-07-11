/**
 * OpenTimestamps calendar server client.
 *
 * Speaks the reference remote-calendar protocol (python-opentimestamps
 * calendar.py):
 * - POST {calendar}/digest with the raw digest bytes → serialized timestamp
 *   tree committing to that digest (ends in a pending attestation)
 * - GET {calendar}/timestamp/{commitment-hex} → serialized timestamp tree for
 *   a previously submitted commitment, once the calendar has aggregated it
 *   into Bitcoin (HTTP 404 until then)
 *
 * Built on global fetch — no dependency.
 */

import { ByteReader, parseTimestamp, bytesToHex } from './ots.js';
import type { TimestampNode } from './ots.js';

/**
 * Public calendars operated by independent parties. Anchoring submits to all
 * of them; any single acceptance is an anchor (see cmdAnchor).
 */
export const DEFAULT_CALENDARS: readonly string[] = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
];

const ACCEPT_HEADER = 'application/vnd.opentimestamps.v1';
const DEFAULT_TIMEOUT_MS = 10_000;

export class CalendarError extends Error {}

export class CalendarClient {
  constructor(
    readonly url: string,
    private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ) {}

  /**
   * Submit a digest; returns the calendar's timestamp tree over it.
   *
   * @throws {CalendarError} on network failure or non-200 response.
   */
  async submit(digest: Uint8Array): Promise<TimestampNode> {
    const body = await this.request('POST', '/digest', digest);
    return parseTimestamp(new ByteReader(body), digest);
  }

  /**
   * Fetch the (possibly completed) timestamp for a commitment.
   *
   * Returns null while the calendar has not yet anchored the commitment
   * (HTTP 404) — pending is a normal state for ~hours after submission.
   *
   * @throws {CalendarError} on network failure or unexpected status.
   */
  async getTimestamp(commitment: Uint8Array): Promise<TimestampNode | null> {
    let body: Uint8Array;
    try {
      body = await this.request('GET', `/timestamp/${bytesToHex(commitment)}`);
    } catch (err) {
      if (err instanceof CalendarError && err.message.includes('status 404')) {
        return null;
      }
      throw err;
    }
    return parseTimestamp(new ByteReader(body), commitment);
  }

  private async request(method: 'GET' | 'POST', path: string, body?: Uint8Array): Promise<Uint8Array> {
    const url = this.url.replace(/\/$/, '') + path;
    const init: NonNullable<Parameters<typeof fetch>[1]> = {
      method,
      headers: { Accept: ACCEPT_HEADER },
      signal: AbortSignal.timeout(this.timeoutMs),
    };
    if (body !== undefined) {
      init.body = body;
    }
    let response: Response;
    try {
      response = await fetch(url, init);
    } catch (err) {
      throw new CalendarError(`Calendar ${this.url} unreachable: ${(err as Error).message}`);
    }
    if (!response.ok) {
      throw new CalendarError(`Calendar ${this.url} returned status ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }
}
