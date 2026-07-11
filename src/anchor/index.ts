/**
 * External anchoring (ADR-G) — public surface.
 *
 * OpenTimestamps-style anchoring of the audit hash-chain tip: an outside
 * witness that a given chain prefix existed at a given time, independent of
 * the machine (and operator) the log lives on.
 */

export {
  HEADER_MAGIC,
  MAJOR_VERSION,
  OtsParseError,
  OtsUnsupportedOpError,
  ByteReader,
  ByteWriter,
  hexToBytes,
  bytesToHex,
  bytesEqual,
  applyOp,
  serializeTimestamp,
  parseTimestamp,
  serializeDetached,
  parseDetached,
  mergeTimestamp,
  allAttestations,
} from './ots.js';
export type { Attestation, TimestampOp, TimestampNode, DetachedTimestamp, AttestationLeaf } from './ots.js';

export { CalendarClient, CalendarError, DEFAULT_CALENDARS } from './calendar.js';

export {
  anchorsDir,
  loadAnchorRecords,
  appendAnchorRecord,
  saveAnchorRecords,
  proofFileName,
  writeProofFile,
  readProofFile,
} from './store.js';
export type { AnchorRecord, AnchorRecordsLoad, AnchorStatus } from './store.js';

export { verifyAnchorRecord, summarizeAnchors, verifyAnchors } from './verify.js';
export type {
  AnchorCheckStatus,
  AnchorCheckResult,
  AnchorState,
  AnchorVerification,
} from './verify.js';
