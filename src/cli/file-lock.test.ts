import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquireFileLock, FileLockTimeout, takeOverAbandonedLock } from './file-lock.js';

let dir: string;
let lock: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'file-lock-'));
  lock = join(dir, 'x.lock');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('acquireFileLock', () => {
  it('records who holds it, and removes the file on release', () => {
    const release = acquireFileLock(lock);

    const held = JSON.parse(readFileSync(lock, 'utf8')) as { pid: number; host: string };
    expect(held.pid).toBe(process.pid);
    expect(held.host).toBe(hostname());

    release();
    expect(existsSync(lock)).toBe(false);
  });

  it('excludes a second holder until the first releases', () => {
    const release = acquireFileLock(lock);

    expect(() => acquireFileLock(lock, { timeoutMs: 100 })).toThrow(FileLockTimeout);

    release();
    const second = acquireFileLock(lock, { timeoutMs: 100 }); // control: free once released
    second();
  });

  it('release is idempotent', () => {
    const release = acquireFileLock(lock);
    release();
    expect(() => release()).not.toThrow();
  });

  // A release function belongs to ONE acquisition. If it could be invoked again after the same
  // process has re-acquired, matching on pid and host alone would remove the new holder's lock.
  it('a stale release function cannot remove a later acquisition by the same process', () => {
    const releaseFirst = acquireFileLock(lock);
    releaseFirst();
    const releaseSecond = acquireFileLock(lock);

    releaseFirst(); // called again, e.g. from a second finally block

    expect(existsSync(lock)).toBe(true); // the second acquisition still holds it
    releaseSecond();
    expect(existsSync(lock)).toBe(false);
  });

  it("a holder whose stalled lock was taken over, even by this same process, cannot release the new holder's", () => {
    const a = acquireFileLock(lock, { staleMs: 20 });
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60); // a stalls past staleMs
    const b = acquireFileLock(lock, { staleMs: 20, timeoutMs: 500 }); // takes over a's lock

    a(); // a wakes and releases: same pid, same host, but not its lock any more

    expect(existsSync(lock)).toBe(true);
    b();
    expect(existsSync(lock)).toBe(false);
  });

  it('two acquisitions by the same process do not share an identity', () => {
    const a = acquireFileLock(lock);
    const idA = (JSON.parse(readFileSync(lock, 'utf8')) as { token: string }).token;
    a();
    const b = acquireFileLock(lock);
    const idB = (JSON.parse(readFileSync(lock, 'utf8')) as { token: string }).token;
    b();
    expect(idA).toMatch(/^[0-9a-f]{16}$/);
    expect(idB).not.toBe(idA);
  });

  it("release never removes a lock that has since been taken by someone else", () => {
    const releaseMine = acquireFileLock(lock);
    // Mine was judged abandoned and replaced by another process's lock.
    writeFileSync(lock, JSON.stringify({ pid: process.pid + 1, host: hostname(), pidns: null }));

    releaseMine();

    expect(existsSync(lock)).toBe(true);
  });
});

describe('taking over an abandoned lock', () => {
  const record = (token: string) => JSON.stringify({ pid: 1, host: hostname(), pidns: null, token });

  it('removes the lock it judged abandoned', () => {
    writeFileSync(lock, record('old'));
    takeOverAbandonedLock(lock, record('old'));
    expect(existsSync(lock)).toBe(false);
  });

  // Between judging a lock abandoned and removing it, the lock can be released and taken afresh by
  // another process. Removing "whatever is at the path" would then delete a live holder's lock.
  it('leaves a lock alone if it is no longer the one that was judged abandoned', () => {
    const fresh = record('fresh-holder');
    writeFileSync(lock, fresh);

    takeOverAbandonedLock(lock, record('the-old-one-we-judged'));

    expect(existsSync(lock)).toBe(true);
    expect(readFileSync(lock, 'utf8')).toBe(fresh);
    expect(readdirSync(dir).filter((f) => f.includes('.stale.'))).toEqual([]); // and no debris
  });

  it('does nothing when the lock has already gone', () => {
    expect(() => takeOverAbandonedLock(lock, record('old'))).not.toThrow();
  });
});
