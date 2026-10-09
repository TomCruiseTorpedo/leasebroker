/**
 * The state directory lock: every command that changes state runs
 * load -> change -> save as one transaction.
 *
 * WHY. `saveState` rewrites every state file from the snapshot the command
 * loaded. Two short commands running at once each loaded the same snapshot, so
 * the later save erased the earlier one's change. Measured with real processes
 * (12 `revoke` and 12 `request` launched together, four trials): 24 of 48
 * revocations and about 37 of 84 audit events per trial were lost, and the audit
 * chain still verified, because each surviving file was internally consistent.
 *
 * The cross-process behaviour is covered end to end (the clean-room harness fires
 * the same storm at packed tarballs). These tests cover the lock's contract.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquireFileLock, FileLockTimeout } from './file-lock.js';
import {
  loadOrCreateKeyPair,
  loadState,
  openServeSession,
  publishExclusively,
  saveState,
  withStateLock,
} from './state.js';

let dir: string;
const lockPath = () => join(dir, 'state.lock');

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'state-lock-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('withStateLock', () => {
  it('returns what the function returns, awaiting an async one', async () => {
    expect(await withStateLock(dir, () => 7)).toBe(7);
    expect(await withStateLock(dir, async () => 'done')).toBe('done');
  });

  it('holds the lock while the function runs, including the load', async () => {
    let heldDuring = false;
    await withStateLock(dir, () => {
      heldDuring = existsSync(lockPath());
      loadState(dir); // the load is inside the lock: that is the point
    });
    expect(heldDuring).toBe(true);
  });

  it('keeps another command out until it finishes', async () => {
    await withStateLock(dir, () => {
      expect(() => acquireFileLock(lockPath(), { timeoutMs: 100 })).toThrow(FileLockTimeout);
    });
    acquireFileLock(lockPath(), { timeoutMs: 100 })(); // control: free once it has finished
  });

  it('releases the lock when the function succeeds', async () => {
    await withStateLock(dir, () => undefined);
    expect(existsSync(lockPath())).toBe(false);
  });

  it('releases the lock and rethrows when the function throws', async () => {
    await expect(
      withStateLock(dir, () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(existsSync(lockPath())).toBe(false);
  });

  // Several commands call process.exit() inside the transaction (a denied `request` exits 2). That
  // skips a finally block, so without an exit hook the lock file is left behind.
  it('also releases on process exit, so a command that calls process.exit() does not leave the lock', async () => {
    const before = process.listeners('exit');
    await withStateLock(dir, () => {
      const added = process.listeners('exit').filter((l) => !before.includes(l));
      expect(added).toHaveLength(1);
      added[0]!.call(process, 0); // what process.exit() would run
      expect(existsSync(lockPath())).toBe(false);
    });
    expect(process.listeners('exit')).toEqual(before); // and it does not leak a listener per call
  });

  it('says what is wrong when another command holds the lock too long', async () => {
    const release = acquireFileLock(lockPath());
    try {
      await expect(withStateLock(dir, () => 1, { timeoutMs: 100 })).rejects.toThrow(
        /another command is using the state directory/,
      );
    } finally {
      release();
    }
  });
});

describe('the serve session save', () => {
  it('waits on the state lock and writes nothing if it cannot take it', () => {
    const session = openServeSession(dir, { lockTimeoutMs: 100 });
    session.state.auditSink.append({
      type: 'denial',
      at: new Date().toISOString(),
      detail: { from: 'session' },
      prevHash: '',
      hash: '',
    });

    const release = acquireFileLock(lockPath()); // another command is mid-transaction
    expect(() => session.save()).toThrow(FileLockTimeout);
    expect(existsSync(join(dir, 'audit.jsonl'))).toBe(false); // nothing written while it was locked out

    release();
    session.save(); // control: the same save goes through once the lock is free
    expect(readFileSync(join(dir, 'audit.jsonl'), 'utf8')).toContain('"from":"session"');
  });
});

describe('writes replace files rather than rewriting them in place', () => {
  // A reader that opens a file while a writer truncates and refills it can see it empty or half
  // written, and the loaders treat an unparseable list as empty. Writing a temp file and renaming
  // it over the target gives readers a whole old version or a whole new one. A new inode is the
  // observable difference between the two.
  it('saveState gives each state file a new inode, and leaves no temp files', () => {
    const state = loadState(dir);
    state.revocationList.revoke('lease-1');
    saveState(state);
    const before = statSync(join(dir, 'revoked.json')).ino;

    state.revocationList.revoke('lease-2');
    saveState(state);

    expect(statSync(join(dir, 'revoked.json')).ino).not.toBe(before);
    expect(JSON.parse(readFileSync(join(dir, 'revoked.json'), 'utf8'))).toEqual(['lease-1', 'lease-2']);
    expect(existsSync(join(dir, 'revoked.json.tmp'))).toBe(false);
  });

  it('the serve session save replaces audit.jsonl rather than rewriting it in place', () => {
    const event = () => ({
      type: 'denial' as const,
      at: new Date().toISOString(),
      detail: { from: 'x' },
      prevHash: '',
      hash: '',
    });
    const first = loadState(dir);
    first.auditSink.append(event());
    saveState(first);
    const before = statSync(join(dir, 'audit.jsonl')).ino;

    const session = openServeSession(dir);
    session.state.auditSink.append(event());
    session.save();

    expect(statSync(join(dir, 'audit.jsonl')).ino).not.toBe(before);
    expect(readFileSync(join(dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean)).toHaveLength(2);
  });
});

describe('the signing key', () => {
  it('is created readable by its owner only', () => {
    loadOrCreateKeyPair(dir);
    expect(statSync(join(dir, 'keys.json')).mode & 0o777).toBe(0o600);
  });

  it('is not replaced if it already exists', () => {
    const first = loadOrCreateKeyPair(dir);
    const second = loadOrCreateKeyPair(dir);
    expect(Buffer.from(second.publicKey).toString('hex')).toBe(Buffer.from(first.publicKey).toString('hex'));
    expect(JSON.parse(readFileSync(join(dir, 'keys.json'), 'utf8')).kid).toBe(first.kid);
  });

  it('refuses to generate a new key over a key file it cannot read', () => {
    writeFileSync(join(dir, 'keys.json'), 'placeholder');

    expect(() => loadOrCreateKeyPair(dir)).toThrow(); // reads the existing file; never replaces it
    expect(readFileSync(join(dir, 'keys.json'), 'utf8')).toBe('placeholder');
  });

  it('publishExclusively installs a file once and never replaces it', () => {
    const target = join(dir, 'once.json');

    expect(publishExclusively(target, 'first', 0o600)).toBe(true);
    expect(publishExclusively(target, 'second', 0o600)).toBe(false); // lost the race: must not overwrite

    expect(readFileSync(target, 'utf8')).toBe('first');
    expect(statSync(target).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir).filter((f) => f.includes('.tmp'))).toEqual([]);
  });

  it('leaves no temp file behind after creating the key', () => {
    loadOrCreateKeyPair(dir);
    expect(readdirSync(dir).filter((f) => f.includes('.tmp'))).toEqual([]);
  });
});
