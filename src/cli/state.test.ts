/**
 * CLI state-load integrity tests (stored chain).
 *
 * Regression guard for the evidence-laundering bug: loadAuditSink() used to
 * re-append persisted events through InMemoryAuditSink.append(), which
 * recomputes `prevHash`/`hash` — a tampered audit.jsonl re-verified clean
 * against its own fresh chain, and the next saveState() wrote the laundered
 * chain back over the evidence. Loading must be verbatim, verification must
 * be against the STORED hashes, and a tampered file must never be overwritten.
 *
 * Mirrors the dashboard read.test.ts integrity cases (edited content, deleted
 * event, intact, missing) on the CLI load/save path.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryAuditSink } from '../audit/index.js';
import { AuditTamperError, loadAuditSink, loadState, saveAuditSink, saveState } from './state.js';
import { cmdAudit } from './commands/audit.js';
import { cmdRevoke } from './commands/revoke.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Capture console.log / console.error output during a thunk. */
function captureOutput(fn: () => void): { stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args: unknown[]) => stdout.push(args.map(String).join(' '));
  console.error = (...args: unknown[]) => stderr.push(args.map(String).join(' '));
  try {
    fn();
  } finally {
    console.log = origLog;
    console.error = origErr;
  }
  return { stdout, stderr };
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'lb-state-'));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

/** Write a valid three-event chained log into the state dir. */
function writeValidLog(): void {
  const sink = new InMemoryAuditSink();
  sink.append({ type: 'request', at: '2026-06-07T10:00:00Z', requestId: 'r1', detail: { agentId: 'a' } } as never);
  sink.append({
    type: 'issuance',
    at: '2026-06-07T10:00:01Z',
    leaseId: 'lease-1',
    requestId: 'r1',
    detail: { agentId: 'a', taskId: 't', expiresAt: '2099-01-01T00:00:00Z', capabilities: [], kid: 'k1' },
  } as never);
  sink.append({ type: 'use', at: '2026-06-07T10:00:02Z', leaseId: 'lease-1', detail: {} } as never);
  saveAuditSink(tmpDir, sink);
}

const auditPath = (): string => join(tmpDir, 'audit.jsonl');

/** Mutate one event's content in place, keeping its stored hash. */
function tamperEditContent(): void {
  const lines = readFileSync(auditPath(), 'utf8').trim().split('\n');
  const ev = JSON.parse(lines[1]!) as { detail: Record<string, unknown> };
  ev.detail['agentId'] = 'attacker';
  lines[1] = JSON.stringify(ev);
  writeFileSync(auditPath(), lines.join('\n') + '\n');
}

/** Delete the middle event (linkage break). */
function tamperDeleteEvent(): void {
  const lines = readFileSync(auditPath(), 'utf8').trim().split('\n');
  lines.splice(1, 1);
  writeFileSync(auditPath(), lines.join('\n') + '\n');
}

// ---------------------------------------------------------------------------
// loadAuditSink — stored-chain verification, verbatim load
// ---------------------------------------------------------------------------

describe('loadAuditSink (stored chain)', () => {
  it('intact file loads intact with all events, verbatim', () => {
    writeValidLog();
    const before = readFileSync(auditPath(), 'utf8');
    const { sink, integrity } = loadAuditSink(tmpDir);
    expect(integrity).toBe('intact');
    expect(sink.read()).toHaveLength(3);
    // Round-trip is byte-identical: no re-chaining happened.
    saveAuditSink(tmpDir, sink);
    expect(readFileSync(auditPath(), 'utf8')).toBe(before);
  });

  it('edited event content loads as tampered, events still visible', () => {
    writeValidLog();
    tamperEditContent();
    const { sink, integrity } = loadAuditSink(tmpDir);
    expect(integrity).toBe('tampered');
    expect(sink.readVerbatim()).toHaveLength(3); // evidence stays inspectable
    // The tampered content survived the load verbatim — not silently dropped.
    expect(sink.readVerbatim()[1]?.detail['agentId']).toBe('attacker');
  });

  it('a deleted event loads as tampered (linkage break)', () => {
    writeValidLog();
    tamperDeleteEvent();
    expect(loadAuditSink(tmpDir).integrity).toBe('tampered');
  });

  it('missing file is empty and intact, not tampered', () => {
    const { sink, integrity } = loadAuditSink(tmpDir);
    expect(integrity).toBe('intact');
    expect(sink.read()).toEqual([]);
  });

  it('an unparseable line is tampered, keeping the parsed prefix (no silent start-fresh)', () => {
    writeValidLog();
    writeFileSync(auditPath(), readFileSync(auditPath(), 'utf8') + 'not json{{{\n');
    const { sink, integrity } = loadAuditSink(tmpDir);
    expect(integrity).toBe('tampered');
    expect(sink.readVerbatim()).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// saveState — refuses to overwrite tamper evidence
// ---------------------------------------------------------------------------

describe('saveState on a tampered log', () => {
  it('loadState warns on stderr when the chain fails verification', () => {
    writeValidLog();
    tamperEditContent();
    const { stderr } = captureOutput(() => {
      const state = loadState(tmpDir);
      expect(state.auditIntegrity).toBe('tampered');
    });
    expect(stderr.some((l) => l.includes('hash-chain verification'))).toBe(true);
  });

  it('throws AuditTamperError and writes no state files', () => {
    writeValidLog();
    tamperEditContent();
    const evidence = readFileSync(auditPath(), 'utf8');
    captureOutput(() => {
      const state = loadState(tmpDir);
      expect(() => saveState(state)).toThrow(AuditTamperError);
    });
    // Evidence preserved byte-for-byte; the gate fired before any write.
    expect(readFileSync(auditPath(), 'utf8')).toBe(evidence);
    expect(existsSync(join(tmpDir, 'pending.json'))).toBe(false);
    expect(existsSync(join(tmpDir, 'revoked.json'))).toBe(false);
    expect(existsSync(join(tmpDir, 'spend.json'))).toBe(false);
  });

  it('a mutating command (revoke) fails on a tampered log and preserves the evidence', () => {
    writeValidLog();
    tamperEditContent();
    const evidence = readFileSync(auditPath(), 'utf8');
    captureOutput(() => {
      const state = loadState(tmpDir);
      expect(() => cmdRevoke(state, { leaseId: 'lease-1' })).toThrow(AuditTamperError);
    });
    expect(readFileSync(auditPath(), 'utf8')).toBe(evidence);
  });

  it('saves normally on an intact log, and an appended event extends the stored chain', () => {
    writeValidLog();
    const state = loadState(tmpDir);
    state.auditSink.append({ type: 'revocation', at: '2026-06-07T11:00:00Z', leaseId: 'lease-1', detail: {}, prevHash: '', hash: '' });
    saveState(state);
    const reloaded = loadAuditSink(tmpDir);
    expect(reloaded.integrity).toBe('intact');
    expect(reloaded.sink.read()).toHaveLength(4);
  });
});

// ---------------------------------------------------------------------------
// cmdAudit — evidence stays readable, --verify judges the stored chain
// ---------------------------------------------------------------------------

describe('cmdAudit on a tampered log', () => {
  it('still prints the events (evidence display)', () => {
    writeValidLog();
    tamperEditContent();
    const { stdout } = captureOutput(() => {
      cmdAudit(loadState(tmpDir), {});
    });
    const events = JSON.parse(stdout[0]!) as unknown[];
    expect(events).toHaveLength(3);
  });

  it('--verify reports tampered with exit code 1', () => {
    writeValidLog();
    tamperEditContent();
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
    const { stderr } = captureOutput(() => {
      cmdAudit(loadState(tmpDir), { verify: true });
    });
    // stderr carries the loadState warning first, then the verify verdict.
    const verdictLine = stderr.find((l) => l.startsWith('{'));
    expect((JSON.parse(verdictLine!) as { ok: boolean }).ok).toBe(false);
    expect(exitSpy).toHaveBeenCalledWith(1);
    exitSpy.mockRestore();
  });

  it('--verify passes on an intact persisted chain', () => {
    writeValidLog();
    const { stdout } = captureOutput(() => {
      cmdAudit(loadState(tmpDir), { verify: true });
    });
    expect((JSON.parse(stdout[0]!) as { ok: boolean }).ok).toBe(true);
  });
});
