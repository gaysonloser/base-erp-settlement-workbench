import test from "node:test";
import assert from "node:assert/strict";
import {
  acquireCanonicalLock,
  appendLedgerEntry,
  bindIdentityReadback,
  bindCandidate,
  buildErpOriginReorgReplacement,
  buildTypedReorgReplacement,
  compareAndSetCanonical,
  createLedgerAnchor,
  createCanonicalIdempotencyState,
  digest,
  replayReadOnly,
  reprojectReceipt,
  sealReproducibleProvenance,
  sealReceiptProjection,
  validateAmountConservation,
  validateReceiptEvidence,
  verifyCanonicalIdempotencyState,
  verifyErpOriginReorgReplacement,
  verifyReproducibleProvenance,
  verifyRollbackIsolation,
  verifyLedgerAnchor,
  verifyReceiptProjection,
  verifyTypedReorgReplacement,
} from "../src/base-neutral-receipt-controls.mjs";

const sourceEvidence = {
  receiptIdentity: "receipt-001",
  rawLogs: [{ index: 0, topic: "Transfer", data: "0x01" }],
  getterReadback: { status: "settled", amount: "12.50" },
  canonicalEventKey: "case-001/payment-001",
};

test("receipt reprojection seals source evidence and rejects projection drift", () => {
  const sealed = sealReceiptProjection({
    evidence: sourceEvidence,
    projection: { caseId: "case-001", amount: "12.50", status: "draft" },
  });
  assert.equal(verifyReceiptProjection(sealed).ok, true);
  assert.equal(reprojectReceipt(sealed, sealed.projection).ok, true);
  assert.equal(reprojectReceipt(sealed, { ...sealed.projection, amount: "12.51" }).reason, "sealed_projection_mismatch");

  const mutated = structuredClone(sealed);
  mutated.source.raw_logs[0].data = "0x02";
  assert.equal(verifyReceiptProjection(mutated).reason, "source_evidence_digest_mismatch");
});

test("typed reorg replacement keeps one logical consequence and requires authority", () => {
  const replacement = buildTypedReorgReplacement({
    logicalKey: "case-001/payment-001",
    priorReceipt: { receiptIdentity: "receipt-old", logicalKey: "case-001/payment-001", status: "reorged", reorged: true },
    replacementReceipt: { receiptIdentity: "receipt-new", logicalKey: "case-001/payment-001", status: "success", finality: "final", reorged: false },
    authority: { type: "typed_reorg_replacement", approved: true, observation: "finality-observer-1" },
  });
  assert.equal(verifyTypedReorgReplacement(replacement).ok, true);
  assert.equal(replacement.consequence_count, 1);

  const mutated = structuredClone(replacement);
  mutated.authority.approved = false;
  assert.equal(verifyTypedReorgReplacement(mutated).reason, "reorg_authority_missing");
  assert.throws(() => buildTypedReorgReplacement({
    logicalKey: "case-001/payment-001",
    priorReceipt: { receiptIdentity: "receipt-old", logicalKey: "case-001/payment-001", status: "success", reorged: false },
    replacementReceipt: { receiptIdentity: "receipt-new", logicalKey: "case-001/payment-001", status: "success", finality: "final" },
    authority: { type: "typed_reorg_replacement", approved: true },
  }), /prior receipt must be typed as reorged/);
});

test("append-only anchor is idempotent and rejects rollback or same-key disagreement", () => {
  let anchor = createLedgerAnchor("base-case-ledger-001");
  const first = appendLedgerEntry(anchor, { logicalKey: "case-001/payment-001", payload: { amount: "12.50", state: "settled" } });
  assert.equal(first.outcome, "appended");
  anchor = first.anchor;
  assert.equal(verifyLedgerAnchor(anchor).ok, true);

  const replay = appendLedgerEntry(anchor, { logicalKey: "case-001/payment-001", payload: { state: "settled", amount: "12.50" } });
  assert.equal(replay.outcome, "replay_noop");
  const conflict = appendLedgerEntry(anchor, { logicalKey: "case-001/payment-001", payload: { amount: "99.00", state: "settled" } });
  assert.equal(conflict.reason, "same_key_disagreement");
  const next = appendLedgerEntry(anchor, { logicalKey: "case-001/payment-002", payload: { amount: "3.00" } });
  assert.equal(next.outcome, "appended");

  const rolledBack = structuredClone(anchor);
  rolledBack.head_hash = null;
  assert.equal(verifyLedgerAnchor(rolledBack).reason, "ledger_head_mismatch");
  const drift = appendLedgerEntry(anchor, { logicalKey: "case-001/payment-002", payload: { amount: "3.00" }, previousHash: "wrong" });
  assert.equal(drift.reason, "previous_hash_mismatch");
});

test("candidate binding is authoritative and fail-closed for unresolved or ambiguous selections", () => {
  const candidates = [{
    candidateId: "candidate-001",
    authoritative: true,
    resolved: true,
    amount: "12.50",
    account: "ACCT-001",
    party: "customer-001",
    voucher: "voucher-001",
  }];
  const bound = bindCandidate({ candidates, selectedId: "candidate-001", expected: { amount: "12.50", account: "ACCT-001" } });
  assert.equal(bound.ok, true);
  assert.equal(bound.consequence_allowed, true);
  assert.equal(bindCandidate({ candidates, selectedId: "candidate-001", expected: { amount: "99.00" } }).reason, "candidate_amount_mismatch");
  assert.equal(bindCandidate({ candidates: [], selectedId: "candidate-001" }).reason, "candidate_unresolved");
  assert.equal(bindCandidate({ candidates: [...candidates, { ...candidates[0] }], selectedId: "candidate-001" }).reason, "candidate_ambiguous");
  assert.equal(bindCandidate({ candidates: [{ ...candidates[0], authoritative: false }], selectedId: "candidate-001" }).reason, "candidate_not_authoritative");
});

function receiptEvidence(overrides = {}) {
  const caseId = overrides.caseId ?? "case-001";
  const paymentId = overrides.paymentId ?? "payment-001";
  const transactionHash = overrides.transactionHash ?? `0x${"1".repeat(64)}`;
  const canonicalEventKey = `${caseId}/${paymentId}`;
  const calldata = {
    selector: "0x12345678",
    encodedData: "0x12345678",
    decodedArgs: { caseId, paymentId },
    abiValid: true,
  };
  calldata.canonicalDigest = digest({ selector: calldata.selector, encodedData: calldata.encodedData, decodedArgs: calldata.decodedArgs });
  const getterReadback = { method: "readSettlement", result: { caseId, paymentId, status: "settled" }, authoritative: true };
  getterReadback.canonicalDigest = digest({ method: getterReadback.method, result: getterReadback.result });
  return {
    caseId,
    paymentId,
    receipt: {
      transactionHash,
      chainId: 8453,
      status: "0x1",
      finality: "final",
      reorged: false,
      stateChange: true,
      blockHash: `0x${"2".repeat(64)}`,
      blockNumber: "0x10",
      logs: [{ logIndex: 0, canonicalEventKey }],
    },
    canonicalEvent: { caseId, paymentId, key: canonicalEventKey, logIndex: 0 },
    calldata,
    getterReadback,
    ...overrides,
  };
}

test("receipt evidence binds status/finality, ordered logs, calldata/getter and case/payment identity", () => {
  const valid = validateReceiptEvidence({ evidence: receiptEvidence(), expected: { chainId: 8453, caseId: "case-001", paymentId: "payment-001" } });
  assert.equal(valid.ok, true);
  assert.equal(validateReceiptEvidence({ evidence: receiptEvidence({ fingerprint: "forged" }) }).reason, "forged_receipt_fingerprint");
  const badStatus = receiptEvidence();
  badStatus.receipt.status = "0x0";
  assert.equal(validateReceiptEvidence({ evidence: badStatus }).reason, "receipt_not_success");
  const badOrder = receiptEvidence();
  badOrder.receipt.logs = [{ logIndex: 1, canonicalEventKey: "case-001/payment-001" }, { logIndex: 0, canonicalEventKey: "case-001/payment-001" }];
  assert.equal(validateReceiptEvidence({ evidence: badOrder }).reason, "receipt_log_order_invalid");
  const badCalldata = receiptEvidence();
  badCalldata.calldata.canonicalDigest = "0".repeat(64);
  assert.equal(validateReceiptEvidence({ evidence: badCalldata }).reason, "calldata_digest_mismatch");
});

test("refund, partial and advance previews conserve current amount without overwriting reference amount", () => {
  const previews = ["payment_entry", "bank_transaction", "gl", "payment_ledger"].map((type) => ({ type, amount: "12.50" }));
  for (const settlementKind of ["refund", "partial", "advance"]) {
    const result = validateAmountConservation({ originalReferenceAmount: "100.00", currentAmount: "12.50", settlementKind, previews });
    assert.equal(result.ok, true);
    assert.equal(result.original_reference_amount, "100");
  }
  assert.equal(validateAmountConservation({ originalReferenceAmount: "10", currentAmount: "11", settlementKind: "partial", previews }).reason, "current_amount_out_of_range");
  const overwritten = previews.map((preview) => ({ ...preview, amount: "2", originalReferenceAmount: "9" }));
  assert.equal(validateAmountConservation({ originalReferenceAmount: "10", currentAmount: "2", settlementKind: "refund", previews: overwritten }).reason, "reference_amount_overwrite");
  assert.equal(validateAmountConservation({ originalReferenceAmount: "10", currentAmount: "2", settlementKind: "refund", previews: previews.map((preview) => ({ ...preview, amount: "2" })), callerFlags: { amountConserved: false } }).reason, "forged_amount_conservation_flag");
});

test("identity and ERP readback are cross-bound and close eligibility is recomputed", () => {
  const identity = { caseId: "case-identity", partyId: "party-1", companyId: "company-1", treasuryId: "treasury-1", accountId: "account-1" };
  const fingerprint = digest(identity);
  const result = bindIdentityReadback({
    source: { ...identity, fingerprint },
    expected: identity,
    erpReadback: { ...identity, fingerprint, authoritative: true, status: "posted", outstandingAmount: "0", documentId: "PE-001" },
  });
  assert.equal(result.ok, true);
  assert.equal(result.close_eligible, true);
  assert.equal(bindIdentityReadback({
    source: { ...identity, fingerprint: "f".repeat(64) },
    expected: identity,
    erpReadback: { ...identity, fingerprint, authoritative: true, status: "posted", outstandingAmount: "0", documentId: "PE-001" },
  }).reason, "forged_source_fingerprint");
  assert.equal(bindIdentityReadback({
    source: { ...identity, fingerprint },
    expected: identity,
    erpReadback: { ...identity, fingerprint, authoritative: true, status: "posted", outstandingAmount: "4", closeEligible: true, documentId: "PE-001" },
  }).reason, "forged_close_eligibility");
});

test("canonical idempotency uses persistent ledger validation, lock and CAS with zero duplicate consequence", () => {
  let state = createCanonicalIdempotencyState("settlement-store");
  const locked = acquireCanonicalLock(state, "worker-1", 0);
  assert.equal(locked.ok, true);
  state = locked.state;
  const sourceDigest = digest({ receipt: "receipt-001" });
  const first = compareAndSetCanonical({ state, lockId: "worker-1", expectedVersion: 0, logicalKey: "case-001/payment-001", sourceDigest, projection: { amount: "12.50", status: "posted" } });
  assert.equal(first.outcome, "committed");
  assert.equal(first.consequence_delta, 1);
  const replay = compareAndSetCanonical({ state: first.state, lockId: "worker-1", expectedVersion: 0, logicalKey: "case-001/payment-001", sourceDigest, projection: { status: "posted", amount: "12.50" } });
  assert.equal(replay.outcome, "replay_noop");
  assert.equal(replay.consequence_delta, 0);
  assert.equal(compareAndSetCanonical({ state: first.state, lockId: "worker-1", expectedVersion: 1, logicalKey: "case-001/payment-001", sourceDigest, projection: { amount: "99" } }).reason, "same_key_disagreement");
  assert.equal(acquireCanonicalLock(first.state, "worker-2", 1).reason, "idempotency_lock_held");
  assert.equal(verifyCanonicalIdempotencyState(first.state).ok, true);
});

test("ERP-origin reorg preserves the prior row/payload and allows one typed replacement consequence", () => {
  const replacement = buildErpOriginReorgReplacement({
    logicalKey: "case-001/payment-001",
    priorRow: { receiptIdentity: "receipt-old", logicalKey: "case-001/payment-001", origin: "erp", status: "reorged", reorged: true, rowId: "ROW-1", payload: { amount: "12.50", accountId: "ACCT-1" } },
    replacementReceipt: { receiptIdentity: "receipt-new", logicalKey: "case-001/payment-001", status: "success", finality: "final", reorged: false },
    authority: { type: "typed_reorg_replacement", approved: true, observation: "finality-readback" },
  });
  assert.equal(verifyErpOriginReorgReplacement(replacement).ok, true);
  const mutated = structuredClone(replacement);
  mutated.prior_payload.amount = "99";
  assert.equal(verifyErpOriginReorgReplacement(mutated).reason, "prior_erp_row_payload_drift");
  assert.throws(() => buildErpOriginReorgReplacement({
    logicalKey: "case-001/payment-001",
    priorRow: replacement.prior_row,
    replacementReceipt: replacement.replacement_receipt,
  }), /authority/);
});

function rollbackFixture({ authoritySequence, ledgerEntryCount, ledgerHeadHash, checkpointSequence, checkpointDigest, fileVersions, fileContents }) {
  const files = Object.keys(fileContents).sort().map((path) => ({ path, version: fileVersions[path], content: fileContents[path], digest: digest(fileContents[path]) }));
  return {
    authority: { id: "authority-1", sequence: authoritySequence },
    ledger: { entryCount: ledgerEntryCount, headHash: ledgerHeadHash },
    checkpoint: { sequence: checkpointSequence, digest: checkpointDigest },
    files,
    manifestDigest: digest(files.map(({ path, version, digest: fileDigest }) => ({ path, version, digest: fileDigest }))),
  };
}

test("rollback of ledger/checkpoint/files is isolated behind an advanced authority sequence", () => {
  const before = rollbackFixture({ authoritySequence: 5, ledgerEntryCount: 2, ledgerHeadHash: digest("head-2"), checkpointSequence: 2, checkpointDigest: digest("checkpoint-2"), fileVersions: { "anchor.json": 2, "projection.json": 2 }, fileContents: { "anchor.json": "two", "projection.json": "two" } });
  const after = rollbackFixture({ authoritySequence: 6, ledgerEntryCount: 1, ledgerHeadHash: digest("head-1"), checkpointSequence: 1, checkpointDigest: digest("checkpoint-1"), fileVersions: { "anchor.json": 1, "projection.json": 1 }, fileContents: { "anchor.json": "one", "projection.json": "one" } });
  const isolated = verifyRollbackIsolation({ before, after });
  assert.equal(isolated.ok, true);
  assert.equal(isolated.rollback_isolated, true);
  assert.equal(isolated.consequence_allowed, false);
  const unsafe = verifyRollbackIsolation({ before, after: { ...after, authority: { id: "authority-1", sequence: 5 } } });
  assert.equal(unsafe.reason, "rollback_authority_not_advanced");
});

test("frozen-root provenance and read-only replay are reproducible and isolated", () => {
  const manifest = [{ path: "src/main.mjs", digest: digest("main") }, { path: "package.json", digest: digest("package") }];
  const rootDigest = digest([...manifest].sort((left, right) => left.path.localeCompare(right.path)));
  const provenance = sealReproducibleProvenance({
    manifest,
    frozenRootDigest: rootDigest,
    artifacts: [{ kind: "wheel", name: "workbench.whl", digest: digest("wheel"), installOnly: true }, { kind: "sdist", name: "workbench.tar.gz", digest: digest("sdist"), installOnly: true }],
    relocationIdentity: [{ label: "original", rootDigest }, { label: "relocated", rootDigest }, { label: "reinstalled", rootDigest }],
    liveEnvironment: { available: false, claimed: false },
  });
  assert.equal(provenance.ok, undefined);
  assert.equal(verifyReproducibleProvenance(provenance).ok, true);
  const source = { caseId: "case-001", projection: { amount: "12.50" } };
  const replay = replayReadOnly({ source, expectedDigest: digest(source), replay: (copy) => ({ ...copy, projection: { ...copy.projection } }) });
  assert.equal(replay.ok, true);
  assert.equal(replay.source_unchanged, true);
  assert.equal(replayReadOnly({ source, expectedDigest: digest(source), replay: (copy) => ({ ...copy, projection: { amount: "99" } }) }).reason, "replay_drift_detected");
});
