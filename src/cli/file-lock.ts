/**
 * An exclusive advisory lock on a file path, for the CLI's state directory.
 *
 * Taken by creating the lock file with O_EXCL; the file records who holds it.
 * Synchronous on purpose: the callers (the spend ledger, behind a synchronous
 * enforcer; the state transaction around a command) cannot await.
 *
 * ABANDONED LOCKS. A holder that crashes leaves its file behind, so a lock is
 * taken over when it is judged abandoned:
 *   - it has not been touched for `staleMs`, whoever holds it; or
 *   - its holder is on THIS host and in THIS pid namespace and is no longer
 *     running.
 * The second rule is only valid where the pid means something. A pid recorded on
 * another host, or in another pid namespace that shares the directory through a
 * volume, looks dead from here whether or not it is; trusting that would steal
 * the lock from a process that is mid-transaction. Those holders expire by age
 * alone. (A holder that is alive but stalled for longer than `staleMs` is also
 * taken over. The critical sections here are milliseconds, so that means a
 * wedged process, and refusing to wait forever is the safer side.)
 *
 * NOT A NETWORK LOCK. Do not put a state directory on a filesystem whose
 * O_EXCL create is not atomic (some NFS configurations).
 *
 * OWNERSHIP. Each acquisition writes a random token into the file, and its
 * release function removes the file only if that token is still there. Matching
 * on pid and host alone would let a release called after the same process
 * re-acquired (or took over its own stalled lock) remove the NEW holder's lock.
 *
 * TAKEOVER is verified, not blind. Between judging a lock abandoned and removing
 * it, the lock can be released and taken afresh by someone else, and removing
 * "whatever is at the path" would delete a live holder's lock. So the file is
 * renamed aside first (atomic: it takes exactly one of the competing takers),
 * compared with what was judged, and put back if it turns out to be a different
 * lock.
 *
 * RESIDUAL. If the lock WAS replaced in the instant between the rename and the
 * put-back, a third process can create a lock in that gap, the put-back then
 * fails, and two holders overlap. That needs an abandoned lock, a competing fresh
 * acquisition and a third waiter inside a few microseconds. It is narrowed, not
 * closed; closing it needs a different primitive than files.
 */

import {
  closeSync,
  linkSync,
  openSync,
  readFileSync,
  readlinkSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';

export interface FileLockOptions {
  /** How long to wait to take the lock. Default 5s. */
  timeoutMs?: number;
  /** A lock untouched for this long is abandoned. Default 10s. */
  staleMs?: number;
}

export class FileLockTimeout extends Error {}

interface LockRecord {
  pid: number;
  host: string;
  pidns: string | null;
  /** Unique to one acquisition; what makes a release refer to THIS lock. */
  token: string;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_STALE_MS = 10_000;

/** The pid namespace this process is in, where the OS exposes one (Linux). */
function ownPidNamespace(): string | null {
  try {
    return readlinkSync('/proc/self/ns/pid');
  } catch {
    return null;
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM'; // exists, not ours to signal
  }
}

function parseRecord(raw: string): LockRecord | null {
  try {
    const parsed = JSON.parse(raw) as Partial<LockRecord> | null;
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      Number.isInteger(parsed.pid) &&
      typeof parsed.host === 'string' &&
      typeof parsed.token === 'string'
    ) {
      return { pid: parsed.pid as number, host: parsed.host, pidns: parsed.pidns ?? null, token: parsed.token };
    }
  } catch {
    /* empty, partial or foreign content */
  }
  return null;
}

function readRaw(lockPath: string): string | null {
  try {
    return readFileSync(lockPath, 'utf8');
  } catch {
    return null;
  }
}

/** The lock's current content if it is abandoned, else null (also null if it has vanished). */
function abandonedContent(lockPath: string, staleMs: number): string | null {
  let ageMs: number;
  try {
    ageMs = Date.now() - statSync(lockPath).mtimeMs;
  } catch {
    return null; // vanished between the failed create and now; the caller retries
  }
  const raw = readRaw(lockPath);
  if (raw === null) return null;
  if (ageMs >= staleMs) return raw;
  const record = parseRecord(raw);
  // Unparseable or empty: a holder between creating the file and writing its record.
  if (record === null) return null;
  if (record.host !== hostname() || record.pidns !== ownPidNamespace()) return null;
  return isAlive(record.pid) ? null : raw;
}

/**
 * Remove a lock that was judged abandoned, but only if it is still that lock.
 * `observed` is the content it had when it was judged. Exported for tests.
 */
export function takeOverAbandonedLock(lockPath: string, observed: string): void {
  const aside = `${lockPath}.stale.${process.pid}.${randomBytes(4).toString('hex')}`;
  try {
    renameSync(lockPath, aside); // atomic: exactly one taker gets the file
  } catch {
    return; // already gone
  }
  if (readRaw(aside) !== observed) {
    // We took a lock other than the one we judged: it was replaced. Put it back.
    try {
      linkSync(aside, lockPath);
    } catch {
      /* the path was re-created in the gap; see RESIDUAL */
    }
  }
  try {
    unlinkSync(aside);
  } catch {
    /* already gone */
  }
}

/**
 * Take the lock, waiting up to `timeoutMs`. Returns a function that releases it
 * (idempotent; removes the file only if it is still this process's).
 *
 * @throws {FileLockTimeout} if the lock could not be taken in time.
 */
export function acquireFileLock(lockPath: string, opts: FileLockOptions = {}): () => void {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS;
  const deadline = Date.now() + timeoutMs;
  const me: LockRecord = {
    pid: process.pid,
    host: hostname(),
    pidns: ownPidNamespace(),
    token: randomBytes(8).toString('hex'),
  };

  for (;;) {
    try {
      const fd = openSync(lockPath, 'wx');
      writeSync(fd, JSON.stringify(me));
      closeSync(fd);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
    const abandoned = abandonedContent(lockPath, staleMs);
    if (abandoned !== null) {
      takeOverAbandonedLock(lockPath, abandoned);
      continue;
    }
    if (Date.now() >= deadline) {
      throw new FileLockTimeout(`could not take ${lockPath} within ${timeoutMs}ms`);
    }
    sleepSync(10);
  }

  return () => {
    try {
      const raw = readRaw(lockPath);
      if (raw !== null && parseRecord(raw)?.token === me.token) unlinkSync(lockPath);
    } catch {
      /* already gone */
    }
  };
}
