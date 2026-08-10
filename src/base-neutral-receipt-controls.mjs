import { createHash } from "node:crypto";

// This module deliberately contains no chain, ABI, wallet, runtime, or provider
// assumptions. It only seals and checks evidence supplied by an already-authorized
// adapter; it never broadcasts, signs, posts, or mutates an external ledger.

const SCHEMA_VERSION = "base-neutral-receipt-controls-v1";
const REORG_SCHEMA_VERSION = "base-neutral-typed-reorg-v1";
const LEDGER_SCHEMA_VERSION = "base-neutral-ledger-anchor-v1";
const RECEIPT_EVIDENCE_SCHEMA_VERSION = "base-neutral-receipt-evidence-v2";
const AMOUNT_CONTROL_SCHEMA_VERSION = "base-neutral-amount-control-v1";
const IDENTITY_CONTROL_SCHEMA_VERSION = "base-neutral-identity-control-v1";
const IDEMPOTENCY_SCHEMA_VERSION = "base-neutral-canonical-idempotency-v1";
const ERP_REORG_SCHEMA_VERSION = "base-neutral-erp-origin-reorg-v1";
const PROVENANCE_SCHEMA_VERSION = "base-neutral-reproducible-provenance-v1";
const HASH_PATTERN = /^[0-9a-f]{64}$/i;
const TX_HASH_PATTERN = /^0x[0-9a-f]{64}$/i;
const HEX_PATTERN = /^0x[0-9a-f]*$/i;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,18}))?$/;
const DECIMAL_SCALE = 18n;
const DECIMAL_SCALE_UNITS = 10n ** DECIMAL_SCALE;
const PREVIEW_TYPES = Object.freeze(["payment_entry", "bank_transaction", "gl", "payment_ledger"]);
const IDENTITY_FIELDS = Object.freeze(["caseId", "partyId", "companyId", "treasuryId", "accountId"]);

function failClosed(reason, details = {}) {
  return Object.freeze({ ok: false, fail_closed: true, reason, ...details });
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("evidence cannot contain non-finite numbers");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  throw new TypeError("evidence contains an unsupported value");
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

function field(value, snake, camel) {
  return value?.[snake] ?? value?.[camel];
}

function normalizedHash(value, name) {
  const hash = requiredString(value, name).toLowerCase();
  if (!HASH_PATTERN.test(hash)) throw new TypeError(`${name} must be a 32-byte digest`);
  return hash;
}

function normalizedTransactionHash(value, name) {
  const hash = requiredString(value, name).toLowerCase();
  if (!TX_HASH_PATTERN.test(hash)) throw new TypeError(`${name} must be a 32-byte transaction hash`);
  return hash;
}

function normalizedHex(value, name) {
  const hex = requiredString(value, name).toLowerCase();
  if (!HEX_PATTERN.test(hex) || hex.length % 2 !== 0) throw new TypeError(`${name} must be even-length hex`);
  return hex;
}

function normalizedDecimal(value, name) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a decimal string`);
  const trimmed = value.trim();
  const match = DECIMAL_PATTERN.exec(trimmed);
  if (!match) throw new TypeError(`${name} must be a non-negative decimal with at most 18 places`);
  const whole = match[1].replace(/^0+(?=\d)/, "");
  const fraction = match[2] ?? "";
  const units = BigInt(whole) * DECIMAL_SCALE_UNITS + BigInt((fraction + "0".repeat(18)).slice(0, 18));
  const compactFraction = fraction.replace(/0+$/, "");
  return {
    text: compactFraction ? `${whole}.${compactFraction}` : whole,
    units,
  };
}

function normalizedBlockNumber(value, name) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative block number`);
    return value;
  }
  const text = requiredString(value, name).toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(text)) throw new TypeError(`${name} must be a hex block number`);
  const number = Number.parseInt(text.slice(2), 16);
  if (!Number.isSafeInteger(number)) throw new TypeError(`${name} exceeds safe block-number range`);
  return number;
}

function identityRecord(value, name) {
  const candidate = value?.identity && typeof value.identity === "object" ? value.identity : value;
  if (!candidate || typeof candidate !== "object") throw new TypeError(`${name} must be an identity object`);
  const identity = Object.fromEntries(IDENTITY_FIELDS.map((key) => [key, requiredString(candidate[key], `${name}.${key}`)]));
  return identity;
}

function identityFingerprint(identity) {
  return digest(identity);
}

function failIfCallerClaimDisagrees(value, computed, reason) {
  if (value !== undefined && value !== computed) return failClosed(reason);
  return null;
}

function sourceEvidence(input) {
  if (!input || typeof input !== "object") throw new TypeError("source evidence must be an object");
  const receiptIdentity = requiredString(input.receipt_identity ?? input.receiptIdentity, "receiptIdentity");
  const canonicalEventKey = requiredString(input.canonical_event_key ?? input.canonicalEventKey, "canonicalEventKey");
  if (!Array.isArray(input.raw_logs ?? input.rawLogs)) throw new TypeError("rawLogs must be an array");
  if (!input.getter_readback && !input.getterReadback) throw new TypeError("getterReadback is required");
  return {
    receipt_identity: receiptIdentity,
    raw_logs: clone(input.raw_logs ?? input.rawLogs),
    getter_readback: clone(input.getter_readback ?? input.getterReadback),
    canonical_event_key: canonicalEventKey,
  };
}

function projectionValue(projection) {
  if (!projection || typeof projection !== "object" || Array.isArray(projection)) {
    throw new TypeError("projection must be an object");
  }
  return clone(projection);
}

/** Seal source-derived receipt evidence together with the first ERP projection. */
export function sealReceiptProjection({ evidence, projection }) {
  const source = sourceEvidence(evidence);
  const projectionRecord = projectionValue(projection);
  const sourceDigest = digest(source);
  const projectionDigest = digest({ source_digest: sourceDigest, projection: projectionRecord });
  return Object.freeze({
    schema_version: SCHEMA_VERSION,
    source,
    source_digest: sourceDigest,
    projection: projectionRecord,
    projection_digest: projectionDigest,
  });
}

/** Verify that neither source evidence nor a sealed projection was altered. */
export function verifyReceiptProjection(sealed) {
  try {
    if (!sealed || sealed.schema_version !== SCHEMA_VERSION) return failClosed("unsupported_receipt_schema");
    const source = sourceEvidence(sealed.source);
    const projection = projectionValue(sealed.projection);
    const sourceDigest = digest(source);
    if (sourceDigest !== sealed.source_digest) return failClosed("source_evidence_digest_mismatch");
    const projectionDigest = digest({ source_digest: sourceDigest, projection });
    if (projectionDigest !== sealed.projection_digest) return failClosed("sealed_projection_mismatch");
    return Object.freeze({ ok: true, fail_closed: false, source_digest: sourceDigest, projection_digest: projectionDigest });
  } catch (error) {
    return failClosed("invalid_receipt_evidence", { message: error.message });
  }
}

/** A re-projection may only reproduce the sealed projection byte-for-byte. */
export function reprojectReceipt(sealed, projection) {
  const verified = verifyReceiptProjection(sealed);
  if (!verified.ok) return verified;
  let next;
  try {
    next = projectionValue(projection);
  } catch (error) {
    return failClosed("invalid_projection", { message: error.message });
  }
  if (digest(next) !== digest(sealed.projection)) return failClosed("sealed_projection_mismatch");
  return Object.freeze({ ok: true, fail_closed: false, sealed });
}

function receiptIdentity(receipt, name) {
  if (!receipt || typeof receipt !== "object") throw new TypeError(`${name} must be an object`);
  return requiredString(receipt.receipt_identity ?? receipt.receiptIdentity, `${name}.receiptIdentity`);
}

function receiptLogicalKey(receipt, name) {
  return requiredString(receipt.logical_key ?? receipt.logicalKey, `${name}.logicalKey`);
}

/** Create a typed replacement record; it preserves one logical consequence. */
export function buildTypedReorgReplacement({ logicalKey, priorReceipt, replacementReceipt, authority }) {
  const key = requiredString(logicalKey, "logicalKey");
  const priorId = receiptIdentity(priorReceipt, "priorReceipt");
  const replacementId = receiptIdentity(replacementReceipt, "replacementReceipt");
  if (receiptLogicalKey(priorReceipt, "priorReceipt") !== key || receiptLogicalKey(replacementReceipt, "replacementReceipt") !== key) {
    throw new RangeError("prior and replacement receipts must bind to the same logical key");
  }
  if (priorId === replacementId) throw new RangeError("replacement receipt identity must differ from prior receipt");
  if (priorReceipt.reorged !== true && priorReceipt.status !== "reorged") {
    throw new RangeError("prior receipt must be typed as reorged");
  }
  if (replacementReceipt.status !== "success" || replacementReceipt.finality !== "final" || replacementReceipt.reorged === true) {
    throw new RangeError("replacement receipt must be final, successful and not reorged");
  }
  if (!authority || authority.type !== "typed_reorg_replacement" || authority.approved !== true) {
    throw new RangeError("typed reorg authority is required");
  }
  const record = {
    schema_version: REORG_SCHEMA_VERSION,
    logical_key: key,
    prior_receipt: clone(priorReceipt),
    replacement_receipt: clone(replacementReceipt),
    authority: clone(authority),
    authority_digest: digest(authority),
    consequence_count: 1,
    status: "replaced",
  };
  return Object.freeze(record);
}

export function verifyTypedReorgReplacement(record) {
  try {
    if (!record || record.schema_version !== REORG_SCHEMA_VERSION) return failClosed("unsupported_reorg_schema");
    const priorId = receiptIdentity(record.prior_receipt, "priorReceipt");
    const replacementId = receiptIdentity(record.replacement_receipt, "replacementReceipt");
    if (receiptLogicalKey(record.prior_receipt, "priorReceipt") !== record.logical_key || receiptLogicalKey(record.replacement_receipt, "replacementReceipt") !== record.logical_key) {
      return failClosed("reorg_logical_key_mismatch");
    }
    if (priorId === replacementId) return failClosed("replacement_identity_not_distinct");
    if (record.prior_receipt.reorged !== true && record.prior_receipt.status !== "reorged") return failClosed("prior_receipt_not_reorged");
    if (record.replacement_receipt.status !== "success" || record.replacement_receipt.finality !== "final" || record.replacement_receipt.reorged === true) {
      return failClosed("replacement_receipt_not_final_success");
    }
    if (!record.authority || record.authority.type !== "typed_reorg_replacement" || record.authority.approved !== true) {
      return failClosed("reorg_authority_missing");
    }
    if (digest(record.authority) !== record.authority_digest) return failClosed("reorg_authority_digest_mismatch");
    if (record.consequence_count !== 1 || record.status !== "replaced") return failClosed("multiple_logical_consequences");
    return Object.freeze({ ok: true, fail_closed: false, logical_key: record.logical_key });
  } catch (error) {
    return failClosed("invalid_reorg_replacement", { message: error.message });
  }
}

export function createLedgerAnchor(ledgerId) {
  return Object.freeze({ schema_version: LEDGER_SCHEMA_VERSION, ledger_id: requiredString(ledgerId, "ledgerId"), head_hash: null, entries: [] });
}

export function verifyLedgerAnchor(anchor) {
  try {
    if (!anchor || anchor.schema_version !== LEDGER_SCHEMA_VERSION || !Array.isArray(anchor.entries)) return failClosed("unsupported_ledger_schema");
    let previous = null;
    const keys = new Set();
    for (const entry of anchor.entries) {
      if (keys.has(entry.logical_key)) return failClosed("duplicate_logical_key");
      keys.add(entry.logical_key);
      if (entry.previous_hash !== previous) return failClosed("ledger_hash_chain_drift");
      const expected = digest({ ledger_id: anchor.ledger_id, logical_key: entry.logical_key, payload: entry.payload, payload_digest: entry.payload_digest, previous_hash: entry.previous_hash });
      if (entry.entry_hash !== expected) return failClosed("ledger_entry_digest_mismatch");
      if (digest(entry.payload) !== entry.payload_digest) return failClosed("ledger_payload_digest_mismatch");
      previous = entry.entry_hash;
    }
    if (anchor.head_hash !== previous) return failClosed("ledger_head_mismatch");
    return Object.freeze({ ok: true, fail_closed: false, head_hash: previous, entry_count: anchor.entries.length });
  } catch (error) {
    return failClosed("invalid_ledger_anchor", { message: error.message });
  }
}

/** Append immutably; exact replay is a no-op, disagreement is fail-closed. */
export function appendLedgerEntry(anchor, { logicalKey, payload, previousHash } = {}) {
  const verified = verifyLedgerAnchor(anchor);
  if (!verified.ok) return { ...verified, anchor };
  const key = requiredString(logicalKey, "logicalKey");
  const existing = anchor.entries.find((entry) => entry.logical_key === key);
  const payloadDigest = digest(payload);
  if (existing) {
    if (existing.payload_digest === payloadDigest) return { ok: true, outcome: "replay_noop", anchor };
    return { ...failClosed("same_key_disagreement"), outcome: "conflict", anchor };
  }
  if (previousHash !== undefined && previousHash !== anchor.head_hash) {
    return { ...failClosed("previous_hash_mismatch"), outcome: "conflict", anchor };
  }
  const entry = {
    logical_key: key,
    payload: clone(payload),
    payload_digest: payloadDigest,
    previous_hash: anchor.head_hash,
  };
  entry.entry_hash = digest({ ledger_id: anchor.ledger_id, ...entry });
  const next = Object.freeze({ ...anchor, head_hash: entry.entry_hash, entries: Object.freeze([...anchor.entries, Object.freeze(entry)]) });
  return { ok: true, outcome: "appended", anchor: next, entry };
}

function candidateId(candidate) {
  return requiredString(candidate.candidate_id ?? candidate.candidateId, "candidate.candidateId");
}

/** Bind only to authoritative candidates; unresolved or ambiguous input has no consequence. */
export function bindCandidate({ candidates, selectedId, expected = {} } = {}) {
  if (!Array.isArray(candidates) || candidates.length === 0) return failClosed("candidate_unresolved");
  if (typeof selectedId !== "string" || selectedId.trim() === "") return failClosed("candidate_selection_missing");
  const selected = candidates.filter((candidate) => {
    try { return candidateId(candidate) === selectedId; } catch { return false; }
  });
  if (selected.length !== 1) return failClosed(selected.length === 0 ? "candidate_unresolved" : "candidate_ambiguous");
  const candidate = selected[0];
  if (candidate.authoritative !== true || candidate.resolved !== true) return failClosed("candidate_not_authoritative");
  const bindingFields = ["amount", "account", "party", "voucher"];
  for (const field of bindingFields) {
    if (expected[field] !== undefined && expected[field] !== candidate[field]) return failClosed(`candidate_${field}_mismatch`);
    if (candidate[field] === undefined || candidate[field] === null || candidate[field] === "") return failClosed(`candidate_${field}_missing`);
  }
  return Object.freeze({
    ok: true,
    fail_closed: false,
    candidate_id: candidateId(candidate),
    binding: Object.fromEntries(bindingFields.map((field) => [field, candidate[field]])),
    source: "authoritative_candidate",
    consequence_allowed: true,
  });
}

/** Validate adapter-supplied receipt evidence before any ERP consequence. */
export function validateReceiptEvidence({ evidence, expected = {} } = {}) {
  try {
    if (!evidence || typeof evidence !== "object") return failClosed("receipt_evidence_missing");
    const receipt = evidence.receipt ?? evidence;
    const transactionHash = normalizedTransactionHash(field(receipt, "transaction_hash", "transactionHash"), "transactionHash");
    const chainId = field(receipt, "chain_id", "chainId");
    if (!Number.isInteger(chainId) || chainId < 1) return failClosed("receipt_chain_missing");
    if (expected.chainId !== undefined && expected.chainId !== chainId) return failClosed("receipt_chain_mismatch");
    if (field(receipt, "status", "status") !== "success" && field(receipt, "status", "status") !== "0x1") return failClosed("receipt_not_success");
    if (field(receipt, "finality", "finality") !== "final") return failClosed("receipt_not_final");
    if (receipt.reorged !== false || receipt.stateChange !== true) return failClosed("receipt_not_state_changing_final");
    const blockHash = normalizedTransactionHash(field(receipt, "block_hash", "blockHash"), "blockHash");
    const blockNumber = normalizedBlockNumber(field(receipt, "block_number", "blockNumber"), "blockNumber");
    const logs = receipt.logs;
    if (!Array.isArray(logs) || logs.length === 0) return failClosed("receipt_logs_missing");
    let previousLogIndex = -1;
    for (const log of logs) {
      const logIndex = log?.logIndex ?? log?.log_index ?? log?.index;
      if (!Number.isInteger(logIndex) || logIndex <= previousLogIndex) return failClosed("receipt_log_order_invalid");
      previousLogIndex = logIndex;
    }

    const caseId = requiredString(expected.caseId ?? evidence.caseId ?? evidence.case_id, "caseId");
    const paymentId = requiredString(expected.paymentId ?? evidence.paymentId ?? evidence.payment_id, "paymentId");
    const event = evidence.canonicalEvent ?? evidence.canonical_event;
    if (!event || typeof event !== "object") return failClosed("canonical_event_missing");
    const canonicalEventKey = requiredString(event.key ?? event.canonicalKey ?? event.canonical_event_key, "canonicalEventKey");
    if (canonicalEventKey !== `${caseId}/${paymentId}`) return failClosed("canonical_event_identity_mismatch");
    if (event.caseId !== caseId || event.paymentId !== paymentId) return failClosed("case_payment_binding_mismatch");
    const eventLogIndex = event.logIndex ?? event.log_index;
    const eventLog = logs.find((log) => (log?.logIndex ?? log?.log_index ?? log?.index) === eventLogIndex);
    if (!eventLog || eventLog.canonicalEventKey !== canonicalEventKey) return failClosed("canonical_event_log_mismatch");

    const calldata = evidence.calldata;
    if (!calldata || typeof calldata !== "object" || calldata.abiValid !== true) return failClosed("calldata_abi_validation_missing");
    const encodedData = normalizedHex(calldata.encodedData ?? calldata.encoded_data, "encodedData");
    const selector = requiredString(calldata.selector, "calldata.selector").toLowerCase();
    if (!/^0x[0-9a-f]{8}$/.test(selector) || encodedData.slice(0, 10) !== selector) return failClosed("calldata_selector_mismatch");
    if (!Object.prototype.hasOwnProperty.call(calldata, "decodedArgs")) return failClosed("calldata_decoded_args_missing");
    const calldataDigest = digest({ selector, encodedData, decodedArgs: calldata.decodedArgs });
    if (calldata.canonicalDigest !== calldataDigest) return failClosed("calldata_digest_mismatch");

    const getter = evidence.getterReadback ?? evidence.getter_readback;
    if (!getter || typeof getter !== "object" || getter.authoritative !== true || !Object.prototype.hasOwnProperty.call(getter, "result")) {
      return failClosed("getter_readback_validation_missing");
    }
    const getterDigest = digest({ method: requiredString(getter.method, "getter.method"), result: getter.result });
    if (getter.canonicalDigest !== getterDigest) return failClosed("getter_digest_mismatch");

    const fingerprint = digest({ caseId, paymentId, canonicalEventKey, transactionHash });
    if (expected.fingerprint !== undefined && expected.fingerprint !== fingerprint) return failClosed("receipt_fingerprint_mismatch");
    if (evidence.fingerprint !== undefined && evidence.fingerprint !== fingerprint) return failClosed("forged_receipt_fingerprint");
    return Object.freeze({
      ok: true,
      fail_closed: false,
      receipt_identity: `${transactionHash}:${eventLogIndex}`,
      transaction_hash: transactionHash,
      chain_id: chainId,
      block_hash: blockHash,
      block_number: blockNumber,
      case_id: caseId,
      payment_id: paymentId,
      canonical_event_key: canonicalEventKey,
      fingerprint,
      status: "success",
      finality: "final",
      state_change: true,
      evidence_digest: digest({ transactionHash, chainId, blockHash, blockNumber, caseId, paymentId, canonicalEventKey, calldataDigest, getterDigest }),
    });
  } catch (error) {
    return failClosed("invalid_receipt_evidence", { message: error.message });
  }
}

/** Keep original reference amount separate from the currently settled amount. */
export function validateAmountConservation({ originalReferenceAmount, currentAmount, settlementKind, previews, callerFlags = {} } = {}) {
  try {
    const reference = normalizedDecimal(originalReferenceAmount, "originalReferenceAmount");
    const current = normalizedDecimal(currentAmount, "currentAmount");
    if (!["refund", "partial", "advance", "full"].includes(settlementKind)) return failClosed("settlement_kind_invalid");
    if (current.units === 0n || current.units > reference.units) return failClosed("current_amount_out_of_range");
    if (settlementKind === "full" && current.units !== reference.units) return failClosed("full_amount_not_conserved");
    if (!Array.isArray(previews) || previews.length !== PREVIEW_TYPES.length) return failClosed("typed_preview_set_incomplete");
    const seen = new Set();
    for (const preview of previews) {
      const type = requiredString(preview?.type, "preview.type");
      if (!PREVIEW_TYPES.includes(type) || seen.has(type)) return failClosed("typed_preview_set_invalid");
      seen.add(type);
      if (normalizedDecimal(preview.amount, `${type}.amount`).units !== current.units) return failClosed("preview_amount_mismatch");
      if (preview.originalReferenceAmount !== undefined && normalizedDecimal(preview.originalReferenceAmount, `${type}.originalReferenceAmount`).units !== reference.units) {
        return failClosed("reference_amount_overwrite");
      }
    }
    const claimed = failIfCallerClaimDisagrees(callerFlags.amountConserved, true, "forged_amount_conservation_flag");
    if (claimed) return claimed;
    return Object.freeze({
      ok: true,
      fail_closed: false,
      schema_version: AMOUNT_CONTROL_SCHEMA_VERSION,
      settlement_kind: settlementKind,
      original_reference_amount: reference.text,
      current_amount: current.text,
      preview_types: [...seen].sort(),
      amount_conserved: true,
    });
  } catch (error) {
    return failClosed("invalid_amount_control", { message: error.message });
  }
}

/** Recompute identity and close eligibility from source and authoritative ERP readback. */
export function bindIdentityReadback({ source, erpReadback, expected = {}, callerFlags = {} } = {}) {
  try {
    const sourceIdentity = identityRecord(source, "source");
    const expectedIdentity = identityRecord(expected, "expected");
    for (const key of IDENTITY_FIELDS) if (sourceIdentity[key] !== expectedIdentity[key]) return failClosed(`source_${key}_mismatch`);
    const fingerprint = identityFingerprint(sourceIdentity);
    if (source.fingerprint !== fingerprint) return failClosed("forged_source_fingerprint");
    if (!erpReadback || erpReadback.authoritative !== true || erpReadback.status !== "posted") return failClosed("erp_readback_not_authoritative_posted");
    const readbackIdentity = identityRecord(erpReadback, "erpReadback");
    for (const key of IDENTITY_FIELDS) if (readbackIdentity[key] !== sourceIdentity[key]) return failClosed(`erp_${key}_mismatch`);
    if (erpReadback.fingerprint !== fingerprint) return failClosed("forged_erp_fingerprint");
    const outstanding = normalizedDecimal(erpReadback.outstandingAmount ?? erpReadback.outstanding_amount, "outstandingAmount");
    const closeEligible = outstanding.units === 0n;
    const callerClaim = callerFlags.closeEligible ?? source.closeEligible ?? erpReadback.closeEligible;
    const claimed = failIfCallerClaimDisagrees(callerClaim, closeEligible, "forged_close_eligibility");
    if (claimed) return claimed;
    return Object.freeze({
      ok: true,
      fail_closed: false,
      schema_version: IDENTITY_CONTROL_SCHEMA_VERSION,
      identity: sourceIdentity,
      fingerprint,
      close_eligible: closeEligible,
      document_id: requiredString(erpReadback.documentId, "erpReadback.documentId"),
    });
  } catch (error) {
    return failClosed("invalid_identity_readback", { message: error.message });
  }
}

export function createCanonicalIdempotencyState(stateId) {
  const id = requiredString(stateId, "stateId");
  return Object.freeze({
    schema_version: IDEMPOTENCY_SCHEMA_VERSION,
    state_id: id,
    version: 0,
    lock_id: null,
    records: [],
    ledger_anchor: createLedgerAnchor(`${id}:ledger`),
  });
}

export function verifyCanonicalIdempotencyState(state) {
  try {
    if (!state || state.schema_version !== IDEMPOTENCY_SCHEMA_VERSION || !Array.isArray(state.records)) return failClosed("unsupported_idempotency_schema");
    if (!Number.isInteger(state.version) || state.version < 0 || state.version !== state.records.length) return failClosed("idempotency_version_mismatch");
    const ledger = verifyLedgerAnchor(state.ledger_anchor);
    if (!ledger.ok) return failClosed("idempotency_ledger_invalid", { ledger_reason: ledger.reason });
    if (ledger.entry_count !== state.records.length) return failClosed("idempotency_ledger_length_mismatch");
    for (let index = 0; index < state.records.length; index += 1) {
      const record = state.records[index];
      if (record.consequence_count !== 1 || digest(record.projection) !== record.projection_digest) return failClosed("idempotency_projection_invalid");
      const entry = state.ledger_anchor.entries[index];
      if (entry.logical_key !== record.logical_key || entry.payload.source_digest !== record.source_digest || entry.payload.projection_digest !== record.projection_digest) {
        return failClosed("idempotency_ledger_record_mismatch");
      }
    }
    return Object.freeze({ ok: true, fail_closed: false, version: state.version, entry_count: state.records.length });
  } catch (error) {
    return failClosed("invalid_idempotency_state", { message: error.message });
  }
}

export function acquireCanonicalLock(state, lockId, expectedVersion = state?.version) {
  const verified = verifyCanonicalIdempotencyState(state);
  if (!verified.ok) return { ...verified, state };
  const id = requiredString(lockId, "lockId");
  if (expectedVersion !== state.version) return { ...failClosed("idempotency_cas_version_mismatch"), state };
  if (state.lock_id !== null && state.lock_id !== id) return { ...failClosed("idempotency_lock_held"), state };
  return { ok: true, fail_closed: false, outcome: state.lock_id === id ? "lock_reentrant" : "locked", state: Object.freeze({ ...state, lock_id: id }) };
}

export function releaseCanonicalLock(state, lockId) {
  const verified = verifyCanonicalIdempotencyState(state);
  if (!verified.ok) return { ...verified, state };
  if (state.lock_id !== lockId) return { ...failClosed("idempotency_lock_mismatch"), state };
  return { ok: true, fail_closed: false, outcome: "unlocked", state: Object.freeze({ ...state, lock_id: null }) };
}

/** Persistent callers can store the returned state; the head hash is the CAS token. */
export function compareAndSetCanonical({ state, lockId, expectedVersion, logicalKey, sourceDigest, projection } = {}) {
  const verified = verifyCanonicalIdempotencyState(state);
  if (!verified.ok) return { ...verified, state };
  const key = requiredString(logicalKey, "logicalKey");
  const sourceHash = normalizedHash(sourceDigest, "sourceDigest");
  if (state.lock_id !== lockId) return { ...failClosed("idempotency_lock_mismatch"), state };
  const projectionDigest = digest(projection);
  const existing = state.records.find((record) => record.logical_key === key);
  if (existing) {
    if (existing.source_digest === sourceHash && existing.projection_digest === projectionDigest) {
      return { ok: true, fail_closed: false, outcome: "replay_noop", consequence_delta: 0, state, record: existing };
    }
    return { ...failClosed("same_key_disagreement"), outcome: "conflict", consequence_delta: 0, state };
  }
  if (expectedVersion !== state.version) return { ...failClosed("idempotency_cas_version_mismatch"), state };
  const ledgerResult = appendLedgerEntry(state.ledger_anchor, {
    logicalKey: key,
    payload: { source_digest: sourceHash, projection_digest: projectionDigest },
    previousHash: state.ledger_anchor.head_hash,
  });
  if (!ledgerResult.ok) return { ...ledgerResult, state };
  const record = Object.freeze({
    logical_key: key,
    source_digest: sourceHash,
    projection: clone(projection),
    projection_digest: projectionDigest,
    consequence_count: 1,
  });
  const nextState = Object.freeze({
    ...state,
    version: state.version + 1,
    records: Object.freeze([...state.records, record]),
    ledger_anchor: ledgerResult.anchor,
  });
  return { ok: true, fail_closed: false, outcome: "committed", consequence_delta: 1, state: nextState, record };
}

export function buildErpOriginReorgReplacement({ logicalKey, priorRow, replacementReceipt, authority } = {}) {
  const key = requiredString(logicalKey, "logicalKey");
  if (!priorRow || priorRow.origin !== "erp" || (priorRow.status !== "reorged" && priorRow.reorged !== true)) {
    throw new RangeError("ERP-origin reorg must fail closed before replacement");
  }
  if (!priorRow.payload || typeof priorRow.payload !== "object") throw new TypeError("prior ERP row payload is required");
  const priorReceiptId = receiptIdentity(priorRow, "priorRow");
  const replacementId = receiptIdentity(replacementReceipt, "replacementReceipt");
  if (receiptLogicalKey(priorRow, "priorRow") !== key || receiptLogicalKey(replacementReceipt, "replacementReceipt") !== key) throw new RangeError("reorg logical key mismatch");
  if (priorReceiptId === replacementId) throw new RangeError("replacement receipt identity must differ from prior receipt");
  if (replacementReceipt.status !== "success" || replacementReceipt.finality !== "final" || replacementReceipt.reorged === true) throw new RangeError("replacement receipt must be final, successful and not reorged");
  if (!authority || authority.type !== "typed_reorg_replacement" || authority.approved !== true) throw new RangeError("typed reorg authority is required");
  return Object.freeze({
    schema_version: ERP_REORG_SCHEMA_VERSION,
    logical_key: key,
    prior_row: clone(priorRow),
    prior_payload: clone(priorRow.payload),
    prior_row_digest: digest(priorRow),
    replacement_receipt: clone(replacementReceipt),
    authority: clone(authority),
    authority_digest: digest(authority),
    consequence_count: 1,
    status: "replaced",
    fail_closed_until_replacement: false,
  });
}

export function verifyErpOriginReorgReplacement(record) {
  try {
    if (!record || record.schema_version !== ERP_REORG_SCHEMA_VERSION) return failClosed("unsupported_erp_reorg_schema");
    if (!record.prior_row || record.prior_row.origin !== "erp" || (record.prior_row.status !== "reorged" && record.prior_row.reorged !== true)) return failClosed("erp_reorg_prior_row_not_fail_closed");
    if (digest(record.prior_row) !== record.prior_row_digest || digest(record.prior_payload) !== digest(record.prior_row.payload)) return failClosed("prior_erp_row_payload_drift");
    if (receiptLogicalKey(record.prior_row, "priorRow") !== record.logical_key || receiptLogicalKey(record.replacement_receipt, "replacementReceipt") !== record.logical_key) return failClosed("reorg_logical_key_mismatch");
    if (receiptIdentity(record.prior_row, "priorRow") === receiptIdentity(record.replacement_receipt, "replacementReceipt")) return failClosed("replacement_identity_not_distinct");
    if (record.replacement_receipt.status !== "success" || record.replacement_receipt.finality !== "final" || record.replacement_receipt.reorged === true) return failClosed("replacement_receipt_not_final_success");
    if (!record.authority || record.authority.type !== "typed_reorg_replacement" || record.authority.approved !== true) return failClosed("reorg_authority_missing");
    if (digest(record.authority) !== record.authority_digest || record.consequence_count !== 1 || record.status !== "replaced") return failClosed("erp_reorg_consequence_invalid");
    return Object.freeze({ ok: true, fail_closed: false, logical_key: record.logical_key, consequence_count: 1 });
  } catch (error) {
    return failClosed("invalid_erp_reorg_replacement", { message: error.message });
  }
}

function rollbackSnapshot(snapshot, name) {
  if (!snapshot || typeof snapshot !== "object") throw new TypeError(`${name} must be an object`);
  const authority = snapshot.authority;
  if (!authority || !Number.isInteger(authority.sequence) || authority.sequence < 0) throw new TypeError(`${name}.authority.sequence is required`);
  const ledger = snapshot.ledger;
  if (!ledger || !Number.isInteger(ledger.entryCount) || ledger.entryCount < 0) throw new TypeError(`${name}.ledger.entryCount is required`);
  const headHash = ledger.headHash === null ? null : normalizedHash(ledger.headHash, `${name}.ledger.headHash`);
  const checkpoint = snapshot.checkpoint;
  if (!checkpoint || !Number.isInteger(checkpoint.sequence) || checkpoint.sequence < 0) throw new TypeError(`${name}.checkpoint.sequence is required`);
  const checkpointDigest = checkpoint.digest === null ? null : normalizedHash(checkpoint.digest, `${name}.checkpoint.digest`);
  if (!Array.isArray(snapshot.files) || snapshot.files.length < 2) throw new TypeError(`${name}.files must contain at least two files`);
  const seen = new Set();
  const files = snapshot.files.map((file) => {
    const path = requiredString(file?.path, `${name}.file.path`);
    if (seen.has(path)) throw new TypeError(`${name}.files contain duplicate paths`);
    seen.add(path);
    if (!Number.isInteger(file.version) || file.version < 0) throw new TypeError(`${name}.${path}.version is required`);
    const fileDigest = digest(file.content);
    if (file.digest !== fileDigest) throw new TypeError(`${name}.${path}.digest mismatch`);
    return { path, version: file.version, digest: fileDigest };
  }).sort((left, right) => left.path.localeCompare(right.path));
  const manifestDigest = digest(files);
  if (snapshot.manifestDigest !== manifestDigest) throw new TypeError(`${name}.manifestDigest mismatch`);
  return { authorityId: requiredString(authority.id, `${name}.authority.id`), authoritySequence: authority.sequence, ledger: { entryCount: ledger.entryCount, headHash }, checkpoint: { sequence: checkpoint.sequence, digest: checkpointDigest }, files, manifestDigest };
}

/** A rollback may be observed only behind an advanced monotonic authority sequence. */
export function verifyRollbackIsolation({ before, after } = {}) {
  try {
    const prior = rollbackSnapshot(before, "before");
    const next = rollbackSnapshot(after, "after");
    if (prior.authorityId !== next.authorityId) return failClosed("rollback_authority_identity_mismatch");
    if (next.authoritySequence < prior.authoritySequence) return failClosed("rollback_authority_decreased");
    const priorFiles = new Map(prior.files.map((file) => [file.path, file]));
    const nextFiles = new Map(next.files.map((file) => [file.path, file]));
    if (priorFiles.size !== nextFiles.size || [...priorFiles.keys()].some((path) => !nextFiles.has(path))) return failClosed("rollback_file_set_changed");
    let fileRollback = false;
    for (const [path, oldFile] of priorFiles) {
      const newFile = nextFiles.get(path);
      if (newFile.version < oldFile.version) fileRollback = true;
      if (newFile.version === oldFile.version && newFile.digest !== oldFile.digest) return failClosed("file_changed_without_version_advance");
    }
    const ledgerRollback = next.ledger.entryCount < prior.ledger.entryCount || (next.ledger.entryCount === prior.ledger.entryCount && next.ledger.headHash !== prior.ledger.headHash);
    const checkpointRollback = next.checkpoint.sequence < prior.checkpoint.sequence || (next.checkpoint.sequence === prior.checkpoint.sequence && next.checkpoint.digest !== prior.checkpoint.digest);
    const rollbackObserved = ledgerRollback || checkpointRollback || fileRollback;
    if (rollbackObserved && next.authoritySequence <= prior.authoritySequence) return failClosed("rollback_authority_not_advanced");
    return Object.freeze({
      ok: true,
      fail_closed: false,
      authority_monotonic: true,
      rollback_isolated: rollbackObserved,
      consequence_allowed: !rollbackObserved,
      rolled_back: { ledger: ledgerRollback, checkpoint: checkpointRollback, files: fileRollback },
      authority_sequence: next.authoritySequence,
    });
  } catch (error) {
    return failClosed("invalid_rollback_snapshot", { message: error.message });
  }
}

function normalizedManifest(manifest) {
  if (!Array.isArray(manifest) || manifest.length === 0) throw new TypeError("frozen manifest is required");
  const seen = new Set();
  return manifest.map((entry) => {
    const path = requiredString(entry?.path, "manifest.path");
    if (seen.has(path)) throw new TypeError("manifest contains duplicate paths");
    seen.add(path);
    return { path, digest: normalizedHash(entry.digest, `manifest.${path}.digest`) };
  }).sort((left, right) => left.path.localeCompare(right.path));
}

export function sealReproducibleProvenance({ manifest, artifacts, relocationIdentity, liveEnvironment, frozenRootDigest } = {}) {
  try {
    const frozenManifest = normalizedManifest(manifest);
    const rootDigest = digest(frozenManifest);
    if (frozenRootDigest !== undefined && frozenRootDigest !== rootDigest) return failClosed("frozen_root_digest_mismatch");
    if (!Array.isArray(artifacts) || new Set(artifacts.map((artifact) => artifact?.kind)).size !== 2 || !artifacts.some((artifact) => artifact.kind === "wheel") || !artifacts.some((artifact) => artifact.kind === "sdist")) return failClosed("install_only_artifacts_incomplete");
    const normalizedArtifacts = artifacts.map((artifact) => ({
      kind: requiredString(artifact.kind, "artifact.kind"),
      name: requiredString(artifact.name, "artifact.name"),
      digest: normalizedHash(artifact.digest, `artifact.${artifact.kind}.digest`),
      install_only: artifact.installOnly === true,
    }));
    if (normalizedArtifacts.some((artifact) => artifact.install_only !== true)) return failClosed("artifact_not_install_only");
    if (!Array.isArray(relocationIdentity) || relocationIdentity.length !== 3 || new Set(relocationIdentity.map((entry) => entry?.label)).size !== 3) return failClosed("three_way_relocation_missing");
    const normalizedRelocation = relocationIdentity.map((entry) => ({ label: requiredString(entry.label, "relocation.label"), root_digest: normalizedHash(entry.rootDigest, "relocation.rootDigest") }));
    if (normalizedRelocation.some((entry) => entry.root_digest !== rootDigest)) return failClosed("relocation_root_identity_mismatch");
    if (!liveEnvironment || liveEnvironment.available !== false || liveEnvironment.claimed !== false) return failClosed("live_environment_must_be_unavailable_unclaimed");
    const record = {
      schema_version: PROVENANCE_SCHEMA_VERSION,
      frozen_root_digest: rootDigest,
      manifest: frozenManifest,
      artifacts: normalizedArtifacts,
      relocation_identity: normalizedRelocation,
      live_environment: { available: false, claimed: false },
    };
    return Object.freeze({ ...record, provenance_digest: digest(record) });
  } catch (error) {
    return failClosed("invalid_reproducible_provenance", { message: error.message });
  }
}

export function verifyReproducibleProvenance(record) {
  try {
    if (!record || record.schema_version !== PROVENANCE_SCHEMA_VERSION) return failClosed("unsupported_provenance_schema");
    const sealed = sealReproducibleProvenance({
      manifest: record.manifest,
      artifacts: record.artifacts.map((artifact) => ({ kind: artifact.kind, name: artifact.name, digest: artifact.digest, installOnly: artifact.install_only })),
      relocationIdentity: record.relocation_identity.map((entry) => ({ label: entry.label, rootDigest: entry.root_digest })),
      liveEnvironment: record.live_environment,
      frozenRootDigest: record.frozen_root_digest,
    });
    if (!sealed.ok && sealed.fail_closed) return sealed;
    if (sealed.provenance_digest !== record.provenance_digest) return failClosed("provenance_digest_mismatch");
    return Object.freeze({ ok: true, fail_closed: false, frozen_root_digest: record.frozen_root_digest, install_only: true, live_environment_claimed: false });
  } catch (error) {
    return failClosed("invalid_provenance_record", { message: error.message });
  }
}

/** Replay receives a clone and never writes the supplied source tree. */
export function replayReadOnly({ source, replay, expectedDigest } = {}) {
  try {
    if (typeof replay !== "function") return failClosed("readonly_replay_function_missing");
    const before = digest(source);
    const replayed = replay(clone(source));
    const after = digest(source);
    const replayDigest = digest(replayed);
    const driftDetected = expectedDigest !== undefined ? replayDigest !== normalizedHash(expectedDigest, "expectedDigest") : false;
    if (before !== after) return failClosed("source_mutated_during_replay", { read_only: true, source_unchanged: false, source_digest: before, replay_digest: replayDigest });
    return Object.freeze({ ok: !driftDetected, fail_closed: driftDetected, reason: driftDetected ? "replay_drift_detected" : undefined, read_only: true, source_unchanged: true, drift_detected: driftDetected, source_digest: before, replay_digest: replayDigest });
  } catch (error) {
    return failClosed("invalid_readonly_replay", { message: error.message, read_only: true });
  }
}

export { canonicalize, digest };
