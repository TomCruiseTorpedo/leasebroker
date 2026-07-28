/**
 * Tests for the duration ledger.
 *
 * `now` is injected throughout, so decay is exercised without waiting for
 * wall-clock time — and so the clock-skew case can be tested at all.
 */

import { describe, it, expect } from 'vitest';
import { InMemoryDurationLedger } from './duration-ledger.js';

const HOUR = 3_600_000;

describe('InMemoryDurationLedger — accrual and headroom', () => {
  it('starts with a full budget for an unseen key', () => {
    const l = new InMemoryDurationLedger();
    expect(l.spentMs('rule-a', HOUR, 0)).toBe(0);
    expect(l.headroomMs('rule-a', 8 * HOUR, HOUR, 0)).toBe(8 * HOUR);
  });

  it('subtracts accrued time from headroom', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 2 * HOUR, HOUR, 0);
    expect(l.headroomMs('rule-a', 8 * HOUR, HOUR, 0)).toBe(6 * HOUR);
  });

  it('never reports negative headroom', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 100 * HOUR, HOUR, 0);
    expect(l.headroomMs('rule-a', 8 * HOUR, HOUR, 0)).toBe(0);
  });

  it('keeps keys independent', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 8 * HOUR, HOUR, 0);
    expect(l.headroomMs('rule-b', 8 * HOUR, HOUR, 0)).toBe(8 * HOUR);
  });
});

describe('InMemoryDurationLedger — decay', () => {
  it('forgives exactly half a half-life later', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 4 * HOUR, 6 * HOUR, 0);
    expect(l.spentMs('rule-a', 6 * HOUR, 6 * HOUR)).toBeCloseTo(2 * HOUR, 6);
    expect(l.spentMs('rule-a', 6 * HOUR, 12 * HOUR)).toBeCloseTo(HOUR, 6);
  });

  it('regenerates headroom continuously, with no cliff and no reset to wait for', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 8 * HOUR, 6 * HOUR, 0); // fully spent
    expect(l.headroomMs('rule-a', 8 * HOUR, 6 * HOUR, 0)).toBe(0);

    const oneHour = l.headroomMs('rule-a', 8 * HOUR, 6 * HOUR, HOUR);
    const threeHours = l.headroomMs('rule-a', 8 * HOUR, 6 * HOUR, 3 * HOUR);
    expect(oneHour).toBeGreaterThan(0);
    expect(threeHours).toBeGreaterThan(oneHour);
  });

  it('decays from the last update, never twice over the same interval', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 4 * HOUR, 6 * HOUR, 0);
    // Accruing again at t=6h: prior spend has halved to 2h, plus 1h new = 3h.
    l.accrue('rule-a', HOUR, 6 * HOUR, 6 * HOUR);
    expect(l.spentMs('rule-a', 6 * HOUR, 6 * HOUR)).toBeCloseTo(3 * HOUR, 6);
  });

  it('does NOT inflate spend when the clock runs backwards', () => {
    // A negative elapsed would make the exponent positive and multiply spend
    // upward. A stalled or rewound clock must never invent budget consumption.
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 4 * HOUR, 6 * HOUR, 10 * HOUR);
    expect(l.spentMs('rule-a', 6 * HOUR, 5 * HOUR)).toBe(4 * HOUR);
  });

  it('treats a non-positive or non-finite half-life as NO decay, never as instant refill', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 4 * HOUR, 6 * HOUR, 0);
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(l.spentMs('rule-a', bad, 100 * HOUR)).toBe(4 * HOUR);
    }
  });
});

describe('InMemoryDurationLedger — persistence', () => {
  it('round-trips through JSON', () => {
    const l = new InMemoryDurationLedger();
    l.accrue('rule-a', 2 * HOUR, 6 * HOUR, 1000);
    const restored = InMemoryDurationLedger.fromJSON(JSON.parse(JSON.stringify(l.toJSON())));
    expect(restored.spentMs('rule-a', 6 * HOUR, 1000)).toBeCloseTo(2 * HOUR, 6);
  });

  it('skips malformed entries rather than throwing', () => {
    const restored = InMemoryDurationLedger.fromJSON({
      good: { spentMs: 1000, updatedAt: 5 },
      negative: { spentMs: -1, updatedAt: 5 },
      missingStamp: { spentMs: 1000 },
      notAnObject: 42,
      nan: { spentMs: Number.NaN, updatedAt: 5 },
    });
    expect(restored.spentMs('good', HOUR, 5)).toBe(1000);
    for (const key of ['negative', 'missingStamp', 'notAnObject', 'nan']) {
      expect(restored.spentMs(key, HOUR, 5)).toBe(0);
    }
  });

  it('survives a non-object snapshot', () => {
    expect(InMemoryDurationLedger.fromJSON(null).spentMs('x', HOUR, 0)).toBe(0);
    expect(InMemoryDurationLedger.fromJSON('nope').spentMs('x', HOUR, 0)).toBe(0);
  });
});
