/**
 * The serve session's audit merge is a commit under the state lock, so it is fenced like every other:
 * if the lock is no longer this save's own, another command may have changed audit.jsonl since it was
 * read, and writing the merge would erase that change.
 *
 * The lock is replaced by a handle that reports it was lost, because losing a lock between taking it and
 * committing cannot be arranged any other way from outside.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

vi.mock('./file-lock.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('./file-lock.js')>();
  return {
    ...original,
    // A handle for a lock that was taken from us before the commit.
    acquireFileLock: vi.fn(() => ({ release: vi.fn(), isHeld: () => false })),
  };
});

import { LockLostError, openServeSession } from './state.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'session-fence-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('the serve session save is fenced', () => {
  it('refuses to write the merge if it no longer holds the lock, and keeps its events', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const session = openServeSession(dir);
    session.state.auditSink.append({
      type: 'denial',
      at: new Date().toISOString(),
      detail: { from: 'session' },
      prevHash: '',
      hash: '',
    });

    expect(() => session.save()).toThrow(LockLostError);

    expect(existsSync(join(dir, 'audit.jsonl'))).toBe(false); // nothing merged into the log
    expect(readdirSync(dir).filter((f) => f.startsWith('audit.unsaved.'))).toHaveLength(1); // but not lost
  });
});
