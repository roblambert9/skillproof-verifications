/**
 * SkillProof x Tollbooth metering hooks — STUB / REFERENCE ONLY.
 *
 * Design (see TOLLBOOTH_INTEGRATION.md):
 *   - Trust-check metering: every install-time / policy-refresh trust check
 *     (manifest lookup + signature verify) can be metered at fractions of a
 *     cent. That is the billions-of-agents revenue line.
 *   - Verification fees themselves can be invoiced through the Tollbooth
 *     gateway rather than manual payment instructions.
 *
 * DO NOT implement real billing here. The human wires the live Tollbooth
 * signing key at deploy time (see README.md "Deploying on the VPS").
 *
 * Each function below is called by server.js at the marked integration
 * point and currently no-ops (logs to stderr so you can see the hook fire).
 *
 * Wiring checklist (human lane):
 *   1. pip/npm install the tollbooth client in the Tollbooth lane
 *      (packages/nano-empire-tollbooth/ — already built, 11/11 PASS).
 *   2. Copy the VPS signing key into the Secure Vault / env, NOT into this file.
 *   3. Implement meterTrustCheck() to POST the usage event to the local
 *      Tollbooth gateway (VPS, port 8403 behind nginx).
 *   4. Replace payment_instructions in the quote response with a Tollbooth
 *      invoice URL (see TODO in server.js /v1/quote handler).
 */

let config = { enabled: false, gatewayUrl: null };

function configure(opts = {}) {
  // TODO(human): config.enabled = true; config.gatewayUrl = process.env.TOLLBOOTH_GATEWAY
  config = { ...config, ...opts };
  console.error(`[metering] configure: enabled=${config.enabled} (stub — no live billing)`);
}

function _event(type, data) {
  if (!config.enabled) {
    console.error(`[metering] stub event: ${type} ${JSON.stringify(data)}`);
    return { metered: false, reason: 'metering_not_wired' };
  }
  // TODO(human): sign + POST to Tollbooth gateway here.
  throw new Error('metering enabled but no live implementation wired');
}

/** Quote issued — potential invoice-open event. Called from POST /v1/quote. */
function meterQuote({ quoteId, tier, feeUsd }) {
  return _event('quote_issued', { quoteId, tier, feeUsd });
}

/** Job opened from an accepted quote — potential charge-authorize event. Called from POST /v1/request. */
function meterRequest({ jobId, quoteId, tier, feeUsd }) {
  return _event('job_opened', { jobId, quoteId, tier, feeUsd });
}

/** Job lifecycle events (queued -> running -> complete). Called from job transitions. */
function meterJobEvent({ jobId, from, to }) {
  return _event('job_transition', { jobId, from, to });
}

/**
 * Install-time / policy-refresh trust check against an issued manifest.
 * Per TOLLBOOTH_INTEGRATION.md this is the meter-at-fractions-of-a-cent
 * primitive: gateway calls this BEFORE returning allow/quarantine/block.
 * Not exercised by the reference server (no registry here) — implement when
 * the manifest registry / gateway is built.
 */
function meterTrustCheck({ manifestId, skillId, version, decision }) {
  return _event('trust_check', { manifestId, skillId, version, decision });
}

module.exports = { configure, meterQuote, meterRequest, meterJobEvent, meterTrustCheck };
