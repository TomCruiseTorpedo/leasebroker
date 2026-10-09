/**
 * The lock on a platform that reports a pid namespace (Linux).
 *
 * `/proc/self/ns/pid` is a real value on Linux and absent on macOS, so a test that hand-writes lock
 * records with `pidns: null` silently models only macOS: on Linux the same record names a DIFFERENT
 * namespace from the running process, so a "live local holder" looks foreign and is aged out. CI
 * found exactly that. Here the namespace lookup is mocked to a Linux-style value, so the Linux
 * behaviour is exercised on any development machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';

const NS = 'pid:[4026531836]';

vi.mock('node:fs', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:fs')>();
  return {
    ...original,
    readlinkSync: ((path: Parameters<typeof original.readlinkSync>[0], ...rest: unknown[]) =>
      path === '/proc/self/ns/pid'
        ? NS
        : (original.readlinkSync as (...a: unknown[]) => unknown)(path, ...rest)) as typeof original.readlinkSync,
  };
});

import { acquireFileLock, FileLockTimeout } from './file-lock.js';

let dir: string;
let lock: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'file-lock-linux-'));
  lock = join(dir, 'x.lock');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const record = (pid: number, pidns: string | null, token = 'holder') =>
  JSON.stringify({ pid, host: hostname(), pidns, token });
const age = () => {
  const old = new Date(Date.now() - 600_000);
  utimesSync(lock, old, old);
};

describe('with a Linux-style pid namespace', () => {
  it('records the namespace in the lock it writes', () => {
    const handle = acquireFileLock(lock);
    expect(JSON.parse(readFileSync(lock, 'utf8')).pidns).toBe(NS);
    handle.release();
  });

  it('never takes over a holder that is alive in the same namespace, however old', () => {
    writeFileSync(lock, record(process.pid, NS));
    age();
    expect(() => acquireFileLock(lock, { staleMs: 20, timeoutMs: 200 })).toThrow(FileLockTimeout);
  });

  it('takes over a holder in the same namespace that has exited', () => {
    writeFileSync(lock, record(2 ** 22 + 12345, NS));
    acquireFileLock(lock, { staleMs: 600_000, timeoutMs: 500 }).release();
  });

  it('treats a record with NO namespace as foreign (it cannot be checked here), expiring it by age', () => {
    writeFileSync(lock, record(process.pid, null));
    expect(() => acquireFileLock(lock, { staleMs: 600_000, timeoutMs: 150 })).toThrow(FileLockTimeout); // fresh
    age();
    acquireFileLock(lock, { staleMs: 20, timeoutMs: 500 }).release(); // old
  });
});
