/**
 * `leasebroker anchor` — external anchoring of the audit chain tip (ADR-G).
 *
 * Default mode submits the current chain tip hash to public OpenTimestamps
 * calendars and persists the returned proof beside audit.jsonl. Meant to be
 * run on a schedule (cron/launchd); it is idempotent per tip, so over-firing
 * is harmless.
 *
 * `--upgrade` is the follow-up network step: it asks the calendars for the
 * completed (Bitcoin-attested) timestamps of pending anchors, grafts them
 * into the stored proofs, and flips record status to confirmed. Calendars
 * typically take ~1-2 hours to aggregate a submission into Bitcoin.
 *
 * `--status` reports local anchor verification (no network) as JSON.
 *
 * Usage:
 *   leasebroker anchor
 *   leasebroker anchor --calendar <url> --calendar <url>
 *   leasebroker anchor --upgrade
 *   leasebroker anchor --status
 *
 * Output: JSON. Exit 1 on tampered log, total submission failure, or (for
 * --status) a broken anchor verdict.
 */

import {
  CalendarClient,
  DEFAULT_CALENDARS,
  allAttestations,
  appendAnchorRecord,
  hexToBytes,
  loadAnchorRecords,
  mergeTimestamp,
  parseDetached,
  proofFileName,
  readProofFile,
  saveAnchorRecords,
  serializeDetached,
  verifyAnchors,
  writeProofFile,
} from '../../anchor/index.js';
import type { AnchorRecord, TimestampNode } from '../../anchor/index.js';
import type { CliState } from '../state.js';

export interface AnchorOptions {
  upgrade?: boolean;
  status?: boolean;
  calendars?: string[];
}

export async function cmdAnchor(state: CliState, opts: AnchorOptions): Promise<void> {
  // Fail closed on tamper, mirroring saveState(): anchoring a tampered chain
  // would timestamp forged history, lending it exactly the credibility this
  // feature exists to deny.
  if (state.auditIntegrity === 'tampered') {
    console.error(
      JSON.stringify({
        ok: false,
        error:
          'Audit log fails stored hash-chain verification — refusing to anchor. ' +
          'Inspect it with `leasebroker audit`, then archive the file manually before resuming.',
      }),
    );
    process.exit(1);
  }

  if (opts.status === true) {
    cmdAnchorStatus(state);
    return;
  }

  if (opts.upgrade === true) {
    await cmdAnchorUpgrade(state);
    return;
  }

  await cmdAnchorSubmit(state, opts.calendars ?? [...DEFAULT_CALENDARS]);
}

/** Local-only verification report (the same verdict `audit --verify-anchor` gates on). */
function cmdAnchorStatus(state: CliState): void {
  const events = state.auditSink.read();
  const load = loadAnchorRecords(state.stateDir);
  const verification = verifyAnchors(load, events, state.auditIntegrity, (f) =>
    readProofFile(state.stateDir, f),
  );
  console.log(
    JSON.stringify(
      {
        ok: verification.ok,
        state: verification.state,
        coveredEvents: verification.coveredEvents,
        totalEvents: events.length,
        anchors: verification.results.map((r) => ({
          anchoredAt: r.record.anchoredAt,
          eventCount: r.record.eventCount,
          tipHash: r.record.tipHash,
          status: r.status,
          ...(r.bitcoinHeight !== undefined ? { bitcoinHeight: r.bitcoinHeight } : {}),
          detail: r.detail,
        })),
      },
      null,
      2,
    ),
  );
  if (!verification.ok) {
    process.exit(1);
  }
}

async function cmdAnchorSubmit(state: CliState, calendarUrls: string[]): Promise<void> {
  const events = state.auditSink.read();
  if (events.length === 0) {
    console.log(JSON.stringify({ ok: true, message: 'Audit log is empty — nothing to anchor' }));
    return;
  }

  const tipEvent = events[events.length - 1];
  const tipHash = tipEvent?.hash ?? '';
  const eventCount = events.length;

  // Idempotence: a tip that is already anchored needs no second submission.
  const { records } = loadAnchorRecords(state.stateDir);
  const existing = records.find((r) => r.tipHash === tipHash && r.eventCount === eventCount);
  if (existing !== undefined) {
    console.log(
      JSON.stringify({
        ok: true,
        message: `Tip already anchored at ${existing.anchoredAt} (status: ${existing.status}) — nothing to do`,
      }),
    );
    return;
  }

  const digest = hexToBytes(tipHash);
  const settled = await Promise.allSettled(
    calendarUrls.map((url) => new CalendarClient(url).submit(digest)),
  );

  const accepted: string[] = [];
  const failures: string[] = [];
  let root: TimestampNode | undefined;
  settled.forEach((result, i) => {
    const url = calendarUrls[i] ?? '';
    if (result.status === 'fulfilled') {
      accepted.push(url);
      if (root === undefined) {
        root = result.value;
      } else {
        mergeTimestamp(root, result.value);
      }
    } else {
      failures.push(`${url}: ${(result.reason as Error).message}`);
    }
  });

  // One accepting calendar is an anchor — the proof stands on its own — but
  // every acceptance widens the set of independent witnesses, so all
  // successes are merged into the proof and all failures are reported.
  if (root === undefined) {
    console.error(
      JSON.stringify({ ok: false, error: 'No calendar accepted the submission', failures }),
    );
    process.exit(1);
    return;
  }

  const anchoredAt = new Date().toISOString();
  const proofFile = proofFileName(anchoredAt, tipHash);
  const record: AnchorRecord = {
    anchoredAt,
    eventCount,
    tipHash,
    calendars: accepted,
    proofFile,
    status: 'pending',
  };
  const proofBytes = serializeDetached(digest, root);

  // Proof before record: a record pointing at a missing proof reads as
  // broken, while an orphaned proof file is merely unreferenced.
  try {
    // Defensive parse — never persist a record for a proof we can't read back.
    parseDetached(proofBytes);
  } catch (err) {
    console.error(
      JSON.stringify({ ok: false, error: `Refusing to persist unreadable proof: ${(err as Error).message}` }),
    );
    process.exit(1);
    return;
  }
  writeProofFile(state.stateDir, proofFile, proofBytes);
  appendAnchorRecord(state.stateDir, record);

  console.log(
    JSON.stringify({
      ok: true,
      anchoredAt,
      eventCount,
      tipHash,
      proofFile,
      calendars: accepted,
      ...(failures.length > 0 ? { failures } : {}),
      message: 'Submitted — run `leasebroker anchor --upgrade` in ~1-2 hours to collect the Bitcoin attestation',
    }),
  );
}

async function cmdAnchorUpgrade(state: CliState): Promise<void> {
  const load = loadAnchorRecords(state.stateDir);
  const pending = load.records.filter((r) => r.status === 'pending');
  if (pending.length === 0) {
    console.log(JSON.stringify({ ok: true, message: 'No pending anchors to upgrade' }));
    return;
  }

  const upgraded: string[] = [];
  const stillPending: string[] = [];
  const errors: string[] = [];

  for (const record of load.records) {
    if (record.status !== 'pending') continue;

    const proofBytes = readProofFile(state.stateDir, record.proofFile);
    if (proofBytes === null) {
      errors.push(`${record.proofFile}: proof file missing`);
      continue;
    }

    let detached;
    try {
      detached = parseDetached(proofBytes);
    } catch (err) {
      errors.push(`${record.proofFile}: ${(err as Error).message}`);
      continue;
    }

    // Ask each calendar that carries a pending attestation for its completed
    // timestamp of that commitment, and graft what comes back.
    let changed = false;
    for (const leaf of allAttestations(detached.root)) {
      if (leaf.attestation.kind !== 'pending') continue;
      try {
        const client = new CalendarClient(leaf.attestation.uri);
        const completed = await client.getTimestamp(leaf.commitment);
        if (completed !== null) {
          mergeTimestamp(leaf.node, completed);
          changed = true;
        }
      } catch (err) {
        errors.push(`${leaf.attestation.uri}: ${(err as Error).message}`);
      }
    }

    const heights = allAttestations(detached.root)
      .filter((l) => l.attestation.kind === 'bitcoin')
      .map((l) => (l.attestation as { height: number }).height);

    if (changed) {
      writeProofFile(state.stateDir, record.proofFile, serializeDetached(detached.digest, detached.root));
    }

    if (heights.length > 0) {
      record.status = 'confirmed';
      record.bitcoinHeight = Math.min(...heights);
      upgraded.push(record.proofFile);
    } else {
      stillPending.push(record.proofFile);
    }
  }

  if (upgraded.length > 0) {
    saveAnchorRecords(state.stateDir, load.records);
  }

  console.log(
    JSON.stringify({
      ok: true,
      upgraded,
      stillPending,
      ...(errors.length > 0 ? { errors } : {}),
    }),
  );
}
