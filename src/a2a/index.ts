/**
 * A2A lane barrel — the lease extension profile helpers (ADR-F).
 * Normative profile: docs/a2a-lease-extension-v1.md.
 */

export {
  LEASE_EXT_URI,
  LeaseExtensionPayloadSchema,
  leaseCardExtension,
  parseExtensionsHeader,
  declaresLeaseExtension,
  attachLeaseToken,
  extractLeaseToken,
} from './extension.js';
export type { LeaseExtensionPayload, LeaseCardExtension, LeaseCarryingMessage } from './extension.js';

export { A2aLeaseBinding } from './binding.js';
export type { BindResult } from './binding.js';

export {
  evaluateA2aLeaseGate,
  EXTENSION_SUPPORT_REQUIRED_ERROR,
  A2A_TASK_STATE_PINS,
} from './gate.js';
export type { A2aGateRequest, A2aGateDeps, A2aGateDecision } from './gate.js';
