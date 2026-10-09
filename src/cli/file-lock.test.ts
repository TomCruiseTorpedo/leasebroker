import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquireFileLock, FileLockTimeout, takeOverAbandonedLock } from './file-lock.js';

let dir: string;
let lock: string;

/** The pid namespace a lock records for this process: a real value on Linux, none elsewhere. */
const ownNamespace = (): string | null => {
  try {
    return readlinkSync('/proc/self/ns/pid');
  } catch {
    return null;
  }
};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'file-lock-'));
  lock = join(dir, 'x.lock');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('acquireFileLock', () => {
  it('records who holds it, and removes the file on release', () => {
    const handle = acquireFileLock(lock);

    const held = JSON.parse(readFileSync(lock, 'utf8')) as { pid: number; host: string };
    expect(held.pid).toBe(process.pid);
    expect(held.host).toBe(hostname());

    handle.release();
    expect(existsSync(lock)).toBe(false);
  });

  it('excludes a second holder until the first releases', () => {
    const first = acquireFileLock(lock);

    expect(() => acquireFileLock(lock, { timeoutMs: 100 })).toThrow(FileLockTimeout);

    first.release();
    acquireFileLock(lock, { timeoutMs: 100 }).release(); // control: free once released
  });

  it('release is idempotent', () => {
    const handle = acquireFileLock(lock);
    handle.release();
    expect(() => handle.release()).not.toThrow();
  });

  // A release function belongs to ONE acquisition. If it could be invoked again after the same
  // process has re-acquired, matching on pid and host alone would remove the new holder's lock.
  it('a stale release function cannot remove a later acquisition by the same process', () => {
    const first = acquireFileLock(lock);
    first.release();
    const second = acquireFileLock(lock);

    first.release(); // called again, e.g. from a second finally block

    expect(existsSync(lock)).toBe(true); // the second acquisition still holds it
    second.release();
    expect(existsSync(lock)).toBe(false);
  });

  it('a release never removes a lock carrying a different token, even from the same pid and host', () => {
    const mine = acquireFileLock(lock);
    // Another acquisition in this very process (same pid, same host) now owns the file.
    writeFileSync(lock, JSON.stringify({ pid: process.pid, host: hostname(), pidns: null, token: 'someone-else' }));

    mine.release();

    expect(existsSync(lock)).toBe(true);
  });

  it('two acquisitions by the same process do not share an identity', () => {
    const a = acquireFileLock(lock);
    const idA = (JSON.parse(readFileSync(lock, 'utf8')) as { token: string }).token;
    a.release();
    const b = acquireFileLock(lock);
    const idB = (JSON.parse(readFileSync(lock, 'utf8')) as { token: string }).token;
    b.release();
    expect(idA).toMatch(/^[0-9a-f]{16}$/);
    expect(idB).not.toBe(idA);
  });

  it("release never removes a lock that has since been taken by someone else", () => {
    const mine = acquireFileLock(lock);
    // Mine was judged abandoned and replaced by another process's lock.
    writeFileSync(lock, JSON.stringify({ pid: process.pid + 1, host: hostname(), pidns: null, token: 'other' }));

    mine.release();

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

describe('a holder that is alive is never taken over', () => {
  // Taking a lock from a holder that is merely SLOW lets two processes run their read-modify-write at
  // once, and the stalled one then commits a snapshot taken before the other's change. Measured: a
  // `revoke` reported success while a live holder was stalled, and the holder's later save erased it.
  const aliveRecord = (token = 'live-holder') =>
    JSON.stringify({ pid: process.pid, host: hostname(), pidns: ownNamespace(), token });
  const ageIt = () => {
    const old = new Date(Date.now() - 600_000);
    utimesSync(lock, old, old);
  };

  it('keeps waiting on a live holder on this host however old the lock is, then times out', () => {
    writeFileSync(lock, aliveRecord());
    ageIt();

    expect(() => acquireFileLock(lock, { staleMs: 20, timeoutMs: 200 })).toThrow(FileLockTimeout);
    expect(readFileSync(lock, 'utf8')).toBe(aliveRecord()); // and it left the holder's lock untouched
  });

  it('still takes over from a holder that has exited, however fresh the lock', () => {
    writeFileSync(lock, JSON.stringify({ pid: 2 ** 22 + 12345, host: hostname(), pidns: ownNamespace(), token: 'dead' }));
    acquireFileLock(lock, { staleMs: 600_000, timeoutMs: 500 }).release();
  });

  it('still expires a holder whose liveness cannot be checked here (another host), by age', () => {
    writeFileSync(lock, JSON.stringify({ pid: process.pid, host: 'some-other-host', pidns: null, token: 'remote' }));
    ageIt();
    acquireFileLock(lock, { staleMs: 20, timeoutMs: 500 }).release();
  });

  it('still expires an unparseable lock by age, so a holder that crashed mid-create cannot wedge it', () => {
    writeFileSync(lock, '');
    ageIt();
    acquireFileLock(lock, { staleMs: 20, timeoutMs: 500 }).release();
  });
});

describe('a lock handle can say whether it is still the holder', () => {
  it('is held after acquire, not held once released', () => {
    const handle = acquireFileLock(lock);
    expect(handle.isHeld()).toBe(true);
    handle.release();
    expect(handle.isHeld()).toBe(false);
  });

  it('is not held if the lock file now carries another token', () => {
    const handle = acquireFileLock(lock);
    writeFileSync(lock, JSON.stringify({ pid: process.pid, host: hostname(), pidns: null, token: 'someone-else' }));
    expect(handle.isHeld()).toBe(false);
  });

  it('is not held if the lock file has gone', () => {
    const handle = acquireFileLock(lock);
    rmSync(lock);
    expect(handle.isHeld()).toBe(false);
  });
});
