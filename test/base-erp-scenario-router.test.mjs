import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  BASE_WALLET_PROVIDER_CONTRACT,
  PRIMARY_BASE_ACCOUNT,
  applyErpReadback,
  applyReceipt,
  buildSettlementCase,
  mapBaseFinality,
  mapWalletCallsStatus,
  readCurrentBaseRuntimeBinding,
  validateBaseAtomicOwnerPreflight,
  validateBaseAuthorityConsistency,
  validateBaseCapabilityPreflight,
  validateBaseBusinessClosureEvidenceGap,
  validateBaseGatePreflight,
  validateReleaseIntegrity,
} from "../src/base-erp-scenario-router.mjs";
import { digest } from "../src/base-neutral-receipt-controls.mjs";

const txHash = `0x${"1".repeat(64)}`;
const receipt = (chainId, overrides = {}) => ({
  transactionHash: txHash,
  chainId,
  status: "success",
  unique: true,
  finality: "final",
  reorged: false,
  stateChange: true,
  ...overrides,
});

const B04_PLATFORMS = [
  "github",
  "render",
  "base_app",
  "base_dashboard",
  "base_dev",
  "talent",
  "guild",
  "basename_base_org",
];

const B08_LIVE_RUNTIME = readCurrentBaseRuntimeBinding();
const B08_RUNTIME_AUTHORITY = (({ binding_version, source, runtime_sha256, run_id, date_cst, cursor, writer_idle_authority }) => ({ binding_version, source, runtime_sha256, run_id, date_cst, cursor, writer_idle_authority: structuredClone(writer_idle_authority) }))(B08_LIVE_RUNTIME);
const B08_RELEASE_RUNTIME_BINDING = {
  schema_version: B08_LIVE_RUNTIME.binding_version,
  source: B08_LIVE_RUNTIME.source,
  mutable_source: true,
  snapshot_only: true,
  snapshot: {
    runtime_sha256: B08_LIVE_RUNTIME.runtime_sha256,
    run_id: B08_LIVE_RUNTIME.run_id,
    date_cst: B08_LIVE_RUNTIME.date_cst,
    status: B08_LIVE_RUNTIME.status,
    cursor: B08_LIVE_RUNTIME.cursor,
    observed_at: B08_LIVE_RUNTIME.writer_idle_authority.observed_at,
  },
  authority_record: {
    path: "runtime/runtime_authority.json",
    ...structuredClone(B08_LIVE_RUNTIME.writer_idle_authority),
  },
  invalidation: "Any byte change to current_run.json or any authority-record hash/cursor/writer-idle drift invalidates this snapshot and requires fresh Build revalidation.",
  runtime_authority_revalidated: true,
};

const B08_PREFLIGHT = {
  gate_id: "base_release_readback_gate",
  authority: {
    current_release: {
      release_id: "base-erp-current-release-001",
      release_fingerprint: "c".repeat(64),
      bom_fingerprint: "d".repeat(64),
      current: true,
      historical: false,
      synthetic: false,
    },
    current_runtime: B08_RUNTIME_AUTHORITY,
  },
  current_release: {
    release_id: "base-erp-current-release-001",
    release_fingerprint: "c".repeat(64),
    bom_fingerprint: "d".repeat(64),
    current: true,
    historical: false,
    synthetic: false,
  },
  runtime: B08_LIVE_RUNTIME,
  owner_gate: {
    status: "not_observed",
    current: true,
    observed: false,
    owner_confirmation_status: "NOT_GRANTED",
  },
  receipt_finality: {
    network: "base_mainnet",
    chain_id: 8453,
    status: "not_observed",
    current: true,
    required_receipt_status: "0x1",
    required_finality_stage: "l1_batch_finality",
    finality_stages: [
      "flashblock_preconfirmation",
      "l2_block_inclusion",
      "l1_batch_inclusion",
      "l1_batch_finality",
    ],
    reorg_policy: "reject",
  },
  erp_readback: {
    required: true,
    current: true,
    status: "not_observed",
    chain_success_is_not_erp: true,
    binding: ["caseId", "fingerprint", "documentId", "authoritative", "status"],
  },
  required_inputs: ["current_release", "base_runtime", "owner_gate", "receipt_finality", "erp_readback"],
  required_readbacks: ["base_receipt", "base_finality", "wallet_calls_status", "erp_readback", "eight_platform_current_release_receipts"],
  stop_conditions: [
    "owner_confirmation_not_observed",
    "runtime_or_terminal_status_conflict",
    "receipt_or_finality_missing_or_invalid",
    "erp_readback_missing_or_mismatched",
    "historical_partial_or_synthetic_evidence",
    "release_binding_drift",
  ],
  recovery: ["do_not_execute_or_retry", "re_read_current_release_and_readbacks", "replay_lock_exact_candidate"],
  executable: false,
  payload: null,
};

const ATOMIC_OWNER_PREFLIGHT = {
  capability: {
    method: "wallet_getCapabilities",
    account_scope: {
      address: PRIMARY_BASE_ACCOUNT,
      chain_id: "0x2105",
      owner_revalidated: true,
      provider_revalidated: true,
    },
    chain_id: "0x2105",
    atomic_status: "supported",
    source_ref: "https://docs.base.org/base-account/reference/core/provider-rpc-methods/wallet_getCapabilities",
    observed_at: "2026-08-10T22:00:00+08:00",
    response_sha256: "a".repeat(64),
  },
  provider_contract: structuredClone(BASE_WALLET_PROVIDER_CONTRACT),
  send_calls: {
    version: "2.0.0",
    from: PRIMARY_BASE_ACCOUNT,
    chainId: "0x2105",
    atomicRequired: true,
    calls: [{ to: "0x1111111111111111111111111111111111111111", value: "0x00", data: "0x" }],
  },
  owner_gate: structuredClone(B08_PREFLIGHT.owner_gate),
  runtime: structuredClone(B08_LIVE_RUNTIME),
  current_release: structuredClone(B08_PREFLIGHT.current_release),
  receipt_finality: structuredClone(B08_PREFLIGHT.receipt_finality),
};

const B11_BUSINESS_CLOSURE_CONTRACTS = {
  "Sales Invoice": {
    required_inputs: ["case_id", "current_release_id", "current_release_fingerprint", "immutable_bom", "customer_reference", "amount", "currency"],
    authoritative_readback: ["invoice_id", "posted_status", "same_case_id", "same_release_binding", "amount_currency_match"],
  },
  "Payment Entry": {
    required_inputs: ["case_id", "invoice_id", "receipt_identity", "amount", "currency", "current_release_binding"],
    authoritative_readback: ["payment_entry_id", "posted_status", "invoice_link", "same_receipt_identity", "amount_currency_match"],
  },
  "Bank Transaction": {
    required_inputs: ["case_id", "bank_reference", "value_date", "amount", "currency", "current_release_binding"],
    authoritative_readback: ["bank_transaction_id", "matched_status", "same_case_id", "amount_currency_match"],
  },
  GL: {
    required_inputs: ["case_id", "posting_date", "account_mapping", "amount", "currency", "current_release_binding"],
    authoritative_readback: ["gl_entry_id", "posted_status", "debit_credit_balance", "same_case_id", "same_release_binding"],
  },
  "Payment Ledger": {
    required_inputs: ["case_id", "receipt_identity", "payment_entry_id", "amount", "idempotency_key", "current_release_binding"],
    authoritative_readback: ["ledger_entry_id", "allocation_status", "duplicate_check", "same_case_id", "same_receipt_identity"],
  },
  "Accounting Period": {
    required_inputs: ["period_id", "period_start", "period_end", "period_status", "current_release_binding"],
    authoritative_readback: ["period_id", "open_or_closed_status", "same_release_binding", "readback_timestamp"],
  },
  "Period Closing Voucher": {
    required_inputs: ["period_id", "close_voucher_reference", "close_reason", "current_release_binding", "owner_gate_dossier_id"],
    authoritative_readback: ["voucher_id", "approved_or_posted_status", "period_id", "same_release_binding", "close_evidence_timestamp"],
  },
};

const B11_BUSINESS_CLOSURE_DOMAINS = Object.keys(B11_BUSINESS_CLOSURE_CONTRACTS).map((record_type) => ({
  record_type,
  release_id: B08_PREFLIGHT.current_release.release_id,
  release_fingerprint: B08_PREFLIGHT.current_release.release_fingerprint,
  bom_fingerprint: B08_PREFLIGHT.current_release.bom_fingerprint,
  current: true,
  historical: false,
  partial: false,
  synthetic: false,
  evidence_status: "not_observed",
  required_inputs: B11_BUSINESS_CLOSURE_CONTRACTS[record_type].required_inputs,
  authoritative_readback: B11_BUSINESS_CLOSURE_CONTRACTS[record_type].authoritative_readback,
  gap_if_missing: `${record_type} evidence is not observed for the current release.`,
  stop_condition: `${record_type} readback missing, stale, cross-release or synthetic.`,
  owner_confirmation: "absent",
}));

const B11_PLATFORM_BINDINGS = B04_PLATFORMS.map((platform) => ({
  platform,
  release_id: B08_PREFLIGHT.current_release.release_id,
  release_fingerprint: B08_PREFLIGHT.current_release.release_fingerprint,
  bom_fingerprint: B08_PREFLIGHT.current_release.bom_fingerprint,
  current: true,
  historical: false,
  partial: false,
  synthetic: false,
  evidence_status: "not_observed",
  historical_credit: 0,
  partial_credit: 0,
}));

const B11_LIVE_RUNTIME_TEXT = readFileSync(new URL("../../2026-06_Base_Guild_Onchain_Score/runtime/current_run.json", import.meta.url), "utf8");
const B11_LIVE_RUNTIME = JSON.parse(B11_LIVE_RUNTIME_TEXT);
const B11_LIVE_RUNTIME_HASH = createHash("sha256").update(B11_LIVE_RUNTIME_TEXT).digest("hex");
const B11_LIVE_RUNTIME_BINDING = {
  binding_version: B08_LIVE_RUNTIME.binding_version,
  source: "projects/2026-06_Base_Guild_Onchain_Score/runtime/current_run.json",
  runtime_sha256: B11_LIVE_RUNTIME_HASH,
  run_id: B11_LIVE_RUNTIME.run_id,
  date_cst: B11_LIVE_RUNTIME.date_cst,
  cursor: B11_LIVE_RUNTIME.cursor ?? B11_LIVE_RUNTIME.resume?.cursor,
  session: "02_Build",
  status: B11_LIVE_RUNTIME.status,
  current: true,
  writer_idle: B08_LIVE_RUNTIME.writer_idle,
  writer_idle_authority: structuredClone(B08_LIVE_RUNTIME.writer_idle_authority),
  terminal_statuses: ["complete"],
};

const B11_EVIDENCE_GAP = {
  preflight: {
    ...structuredClone(B08_PREFLIGHT),
    runtime: B11_LIVE_RUNTIME_BINDING,
    authority: {
      ...structuredClone(B08_PREFLIGHT.authority),
      current_runtime: {
        binding_version: B11_LIVE_RUNTIME_BINDING.binding_version,
        source: B11_LIVE_RUNTIME_BINDING.source,
        runtime_sha256: B11_LIVE_RUNTIME_BINDING.runtime_sha256,
        run_id: B11_LIVE_RUNTIME_BINDING.run_id,
        date_cst: B11_LIVE_RUNTIME_BINDING.date_cst,
        cursor: B11_LIVE_RUNTIME_BINDING.cursor,
        writer_idle_authority: structuredClone(B11_LIVE_RUNTIME_BINDING.writer_idle_authority),
      },
    },
    readbacks: { receipt: null, erp: null, platforms: [] },
  },
  business_closure_domains: B11_BUSINESS_CLOSURE_DOMAINS,
  platform_bindings: B11_PLATFORM_BINDINGS,
  execution_authority: "none_until_02_Build_revalidates",
};

function buildReleaseFixture({
  independentSolMedium = "pass",
  ownerGate = "owner_visible",
  releaseId = "base-erp-b04-release-001",
  immutableBomSha256,
  releaseFingerprintBasis,
} = {}) {
  const releaseFileDigest = (path) => createHash("sha256").update(readFileSync(new URL(`../${path}`, import.meta.url))).digest("hex");
  const immutableReleaseBom = [
    { path: "src/base-erp-scenario-router.mjs", digest: releaseFileDigest("src/base-erp-scenario-router.mjs") },
    { path: "test/base-erp-scenario-router.test.mjs", digest: releaseFileDigest("test/base-erp-scenario-router.test.mjs") },
  ].sort((left, right) => left.path.localeCompare(right.path));
  const currentReleaseDelta = { batch: "B04", control: "release_integrity", version: "1" };
  const interactionEvidence = { source: "Base Docs read-only contract probe", external_actions: 0 };
  const acceptanceState = { independent_sol_medium: independentSolMedium, owner_gate: ownerGate };
  const release = {
    release_id: releaseId,
    runtime_binding: structuredClone(B08_RELEASE_RUNTIME_BINDING),
    current_release_delta: currentReleaseDelta,
    immutable_release_bom: immutableReleaseBom,
    interaction_evidence: interactionEvidence,
    acceptance_state: acceptanceState,
    bom_fingerprint: digest(immutableReleaseBom),
  };
  if (immutableBomSha256 !== undefined) release.immutable_bom_sha256 = immutableBomSha256;
  if (releaseFingerprintBasis !== undefined) {
    release.release_fingerprint_basis = releaseFingerprintBasis;
    release.release_fingerprint = digest([...releaseFingerprintBasis].sort());
  } else {
    release.release_fingerprint = digest({
      release_id: release.release_id,
      current_release_delta: currentReleaseDelta,
      immutable_release_bom: immutableReleaseBom,
      interaction_evidence: interactionEvidence,
      acceptance_state: acceptanceState,
    });
  }
  const materialOutcomeDigest = digest({ release_id: release.release_id, outcome: "settlement-workbench-release" });
  release.eight_surface_evidence_map = Object.fromEntries(B04_PLATFORMS.map((platform) => [platform, {
    platform,
    receipt_id: `${platform}-b04-receipt`,
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    ...(release.immutable_bom_sha256 ? { immutable_bom_sha256: release.immutable_bom_sha256 } : {}),
    material_outcome_digest: materialOutcomeDigest,
    evidence_origin: "official_platform_readback",
    proof_ref: `${platform}-b04-official-readback`,
    synthetic: false,
    current: true,
    independent: true,
    status: "verified",
    historical: false,
  }]));
  return release;
}

function buildChainEvidence(release, overrides = {}) {
  const transactionHash = `0x${"4".repeat(64)}`;
  return {
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    ...(release.immutable_bom_sha256 ? { immutable_bom_sha256: release.immutable_bom_sha256 } : {}),
    evidence_origin: "authorized_base_readback",
    readback_ref: "base-b04-authorized-readback",
    synthetic: false,
    case_id: "case-b04-001",
    chain_id: 8453,
    sender: PRIMARY_BASE_ACCOUNT,
    transaction_hash: transactionHash,
    target: `0x${"2".repeat(40)}`,
    target_semantics: "settlement.apply_receipt",
    calldata_hash: "3".repeat(64),
    receipt_status: "0x1",
    finality_stage: "l1_batch_finality",
    l1_finalized: true,
    finality: "final",
    state_change: true,
    unique: true,
    reorged: false,
    dedup_verified: true,
    replay_locked: true,
    wallet_calls_status: {
      version: "1.0",
      chainId: "0x2105",
      id: "calls-b04-001",
      status: 200,
      atomic: true,
      receipts: [{ transactionHash, status: "0x1" }],
    },
    ...overrides,
  };
}

function buildErpReadback(release, overrides = {}) {
  return {
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    ...(release.immutable_bom_sha256 ? { immutable_bom_sha256: release.immutable_bom_sha256 } : {}),
    evidence_origin: "authorized_erp_readback",
    readback_ref: "erp-b04-authorized-readback",
    synthetic: false,
    authoritative: true,
    status: "posted",
    case_id: "case-b04-001",
    ...overrides,
  };
}

test("routes a Base Mainnet Smart Wallet receivable and keeps it uncounted before receipt", () => {
  const settlement = buildSettlementCase({
    source: "wallet",
    direction: "inbound",
    network: "base_mainnet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "125.00",
    asset: "USDC",
    businessReference: "INV-BASE-001",
  });
  assert.equal(settlement.scenario, "smart_wallet_inbound");
  assert.equal(settlement.identityStatus, "primary_base_account");
  assert.equal(settlement.dailyCountEligible, false);
});

test("only a unique successful Base Mainnet primary-wallet receipt becomes daily-count eligible", () => {
  const settlement = buildSettlementCase({
    source: "contract",
    direction: "outbound",
    network: "base_mainnet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "10.00",
    asset: "USDC",
    businessReference: "PO-BASE-007",
  });
  const confirmed = applyReceipt(settlement, receipt(8453));
  assert.equal(confirmed.dailyCountEligible, true);
  assert.equal(confirmed.chainStatus, "confirmed_unique");
});

test("testnet receipts are product evidence but never daily Mainnet counts", () => {
  const settlement = buildSettlementCase({
    source: "x402",
    direction: "outbound",
    network: "base_sepolia",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "0.01",
    asset: "USDC",
    businessReference: "API-TEST-001",
  });
  const confirmed = applyReceipt(settlement, receipt(84532));
  assert.equal(confirmed.dailyCountEligible, false);
  assert.equal(confirmed.evidenceLevel, "L2");
});

test("B20 cases fail closed outside Vibenet", () => {
  assert.throws(() => buildSettlementCase({
    source: "b20",
    direction: "inbound",
    network: "base_sepolia",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "1",
    asset: "B20-INVENTORY",
  }), /Base Vibenet/);
  const vibenet = buildSettlementCase({
    source: "b20",
    direction: "inbound",
    network: "base_vibenet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "1",
    asset: "B20-INVENTORY",
    businessReference: "B20-VIBENET-001",
  });
  assert.equal(vibenet.experimental, true);
});

test("Smart Wallet lanes do not silently enter the B20-only experimental network", () => {
  assert.throws(() => buildSettlementCase({
    source: "wallet",
    direction: "inbound",
    network: "base_vibenet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "1",
    asset: "USDC",
  }), /wallet cases are unsupported/);
});

test("x402 accepts Base Mainnet and Base Sepolia but rejects experimental Vibenet", () => {
  const sepolia = buildSettlementCase({
    source: "x402",
    direction: "outbound",
    network: "base_sepolia",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "0.10",
    asset: "USDC",
    businessReference: "API-TEST-002",
  });
  assert.equal(sepolia.scenario, "x402_service_settlement");
  assert.throws(() => buildSettlementCase({
    source: "x402",
    direction: "outbound",
    network: "base_vibenet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "0.10",
    asset: "USDC",
  }), /Base Mainnet or Base Sepolia/);
});

test("swap is mainnet-only and agentic evidence stays within Base Mainnet/Sepolia", () => {
  assert.throws(() => buildSettlementCase({
    source: "swap",
    direction: "outbound",
    network: "base_sepolia",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "1",
    asset: "USDC/ETH",
  }), /testnet swaps are unsupported/);
  const agent = buildSettlementCase({
    source: "agent",
    direction: "outbound",
    network: "base_sepolia",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "0.01",
    asset: "USDC",
    businessReference: "AGENT-TEST-001",
  });
  assert.equal(agent.scenario, "agentic_workflow_evidence");
});

test("receipt evidence fails closed until final, unique state-change evidence exists", () => {
  const settlement = buildSettlementCase({
    source: "contract",
    direction: "outbound",
    network: "base_sepolia",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "1",
    asset: "USDC",
    businessReference: "CONTRACT-TEST-001",
  });
  assert.throws(() => applyReceipt(settlement, receipt(84532, { finality: "pending" })), /finality must be final/);
  assert.throws(() => applyReceipt(settlement, receipt(84532, { stateChange: false })), /state-changing execution/);
  assert.throws(() => applyReceipt(settlement, receipt(8453)), /receipt chain does not match/);
});

test("ERP posting requires both chain truth and an explicit business reference", () => {
  const settlement = buildSettlementCase({
    source: "swap",
    direction: "outbound",
    network: "base_mainnet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "50.00",
    asset: "USDC/ETH",
    businessReference: "TREASURY-REB-001",
  });
  const confirmed = applyReceipt(settlement, receipt(8453));
  const posted = applyErpReadback(confirmed, {
    authoritative: true,
    status: "posted",
    documentId: "GL-BASE-0001",
    caseId: confirmed.caseId,
    fingerprint: confirmed.fingerprint,
  });
  assert.equal(posted.erpStatus, "posted_readback_verified");
  assert.equal(posted.evidenceLevel, "L3");
});

test("ERP readback cannot be borrowed from another case", () => {
  const settlement = buildSettlementCase({
    source: "wallet",
    direction: "inbound",
    network: "base_mainnet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "5",
    asset: "USDC",
    businessReference: "INV-BASE-002",
  });
  const confirmed = applyReceipt(settlement, receipt(8453));
  assert.throws(() => applyErpReadback(confirmed, {
    authoritative: true,
    status: "posted",
    documentId: "GL-BASE-OTHER",
    caseId: "base-erp-other",
    fingerprint: confirmed.fingerprint,
  }), /case does not match/);
});

test("B03 keeps Base finality stages distinct and only L1 batch finality permits settlement", () => {
  const stages = [
    "flashblock_preconfirmation",
    "l2_block_inclusion",
    "l1_batch_inclusion",
    "l1_batch_finality",
  ];
  const mapped = stages.map((stage) => mapBaseFinality({
    stage,
    receiptStatus: "0x1",
    l1Finalized: stage === "l1_batch_finality",
  }));

  assert.deepEqual(mapped.map(({ stage_order: order }) => order), [1, 2, 3, 4]);
  assert.deepEqual(mapped.map(({ stage_label: label }) => label), [
    "Flashblock preconfirmation",
    "L2 block inclusion",
    "L1 batch inclusion",
    "L1 batch finality",
  ]);
  assert.deepEqual(mapped.slice(0, 3).map(({ reason, finality, consequence_allowed: allowed }) => ({
    reason,
    finality,
    allowed,
  })), [
    { reason: "base_finality_not_final", finality: "not_final", allowed: false },
    { reason: "base_finality_not_final", finality: "not_final", allowed: false },
    { reason: "base_finality_not_final", finality: "not_final", allowed: false },
  ]);
  assert.equal(mapped[3].ok, true);
  assert.equal(mapped[3].finality, "final");
  assert.equal(mapped[3].consequence_allowed, true);
  assert.equal(mapBaseFinality({ stage: "unknown", receiptStatus: "0x1" }).reason, "base_finality_stage_unknown");
  assert.equal(mapBaseFinality({ stage: "l1_batch_finality", receiptStatus: "0x0", l1Finalized: true }).reason, "receipt_status_not_success");
  assert.equal(mapBaseFinality({ stage: "l2_block_inclusion", receiptStatus: "0x1", l1Finalized: true }).reason, "l1_finality_stage_mismatch");
  assert.equal(mapBaseFinality({ stage: "l1_batch_finality", receiptStatus: "0x1", l1Finalized: true, reorged: true }).reason, "base_finality_reorged");
});

test("B03 maps wallet_getCallsStatus pending, confirmed, failure and atomic receipt boundaries fail closed", () => {
  const firstReceipt = { transactionHash: txHash, status: "0x1" };
  const secondReceipt = { transactionHash: `0x${"2".repeat(64)}`, status: "0x1" };
  const base = {
    version: "1.0",
    chainId: "0x2105",
    id: "calls-b03-001",
    atomic: true,
    status: 200,
  };

  const confirmed = mapWalletCallsStatus({ ...base, receipts: [firstReceipt] });
  assert.equal(confirmed.ok, true);
  assert.equal(confirmed.status_code, 200);
  assert.equal(confirmed.status_category, "confirmed");
  assert.equal(confirmed.receipt_count, 1);
  assert.equal(confirmed.consequence_allowed, true);
  assert.deepEqual(confirmed.receipts, [{ transaction_hash: txHash, status: "0x1" }]);
  assert.equal(mapWalletCallsStatus({ ...base, receipts: [firstReceipt, secondReceipt] }).reason, "atomic_receipt_cardinality_mismatch");
  assert.equal(mapWalletCallsStatus({ ...base, atomic: false, receipts: [firstReceipt, secondReceipt] }).ok, true);
  assert.equal(mapWalletCallsStatus({ ...base, receipts: [{ ...firstReceipt, status: "0x0" }] }).reason, "confirmed_batch_receipt_not_success");
  assert.equal(mapWalletCallsStatus(base).reason, "confirmed_batch_receipts_missing");
  assert.equal(mapWalletCallsStatus({ ...base, status: 100 }).reason, "wallet_calls_pending");
  assert.equal(mapWalletCallsStatus({ ...base, status: 100, receipts: [firstReceipt] }).reason, "pending_batch_has_receipts");
  assert.equal(mapWalletCallsStatus({ ...base, status: 400 }).reason, "wallet_calls_offchain_failure");
  assert.equal(mapWalletCallsStatus({ ...base, status: 500 }).reason, "wallet_calls_chain_failure");
  const partial = mapWalletCallsStatus({ ...base, status: 600, receipts: [firstReceipt] });
  assert.equal(partial.reason, "wallet_calls_partial_failure");
  assert.equal(partial.partial_onchain, true);
  assert.equal(partial.consequence_allowed, false);
  assert.equal(mapWalletCallsStatus({ ...base, status: 999 }).reason, "wallet_calls_status_unknown");
  assert.equal(mapWalletCallsStatus({ ...base, chainId: "0x1" }).reason, "wallet_calls_chain_unknown");
});

test("B03 stores the finality and wallet call mappings on a confirmed receipt", () => {
  const settlement = buildSettlementCase({
    source: "wallet",
    direction: "outbound",
    network: "base_mainnet",
    wallet: PRIMARY_BASE_ACCOUNT,
    amount: "2.00",
    asset: "USDC",
    businessReference: "B03-CALLS-001",
  });
  const confirmed = applyReceipt(settlement, receipt(8453, {
    finalityStage: "l1_batch_finality",
    receiptStatus: "0x1",
    l1Finalized: true,
    walletCallsStatus: {
      version: "1.0",
      chainId: "0x2105",
      id: "calls-b03-002",
      atomic: true,
      status: 200,
      receipts: [{ transactionHash: txHash, status: "0x1" }],
    },
  }));

  assert.equal(confirmed.baseFinality.finality, "final");
  assert.equal(confirmed.baseFinality.stage, "l1_batch_finality");
  assert.equal(confirmed.walletCallsStatus.status_code, 200);
  assert.equal(confirmed.walletCallsStatus.receipt_count, 1);
  assert.equal(confirmed.dailyCountEligible, true);
});

test("B04 binds the current release, BOM and all independent publication receipts", () => {
  const currentRelease = buildReleaseFixture();
  const result = validateReleaseIntegrity({
    currentRelease,
    chainEvidence: buildChainEvidence(currentRelease),
    erpReadback: buildErpReadback(currentRelease),
  });

  assert.equal(result.ok, true);
  assert.equal(result.release_identity_valid, true);
  assert.equal(result.chain_valid, true);
  assert.equal(result.erp_complete, true);
  assert.equal(result.platform_complete, true);
  assert.equal(result.platform_count, 8);
  assert.equal(result.publication_complete, true);
});

test("B04 never infers ERP posting or publication completion from chain success", () => {
  const currentRelease = buildReleaseFixture();
  const result = validateReleaseIntegrity({
    currentRelease,
    chainEvidence: buildChainEvidence(currentRelease),
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "erp_readback_missing");
  assert.equal(result.chain_valid, true);
  assert.equal(result.erp_complete, false);
  assert.equal(result.publication_complete, false);
});

test("B04 rejects historical release receipts and fingerprint drift", () => {
  const currentRelease = buildReleaseFixture();
  const staleChain = validateReleaseIntegrity({
    currentRelease,
    chainEvidence: buildChainEvidence(currentRelease, { release_id: "base-erp-b03-release-001" }),
    erpReadback: buildErpReadback(currentRelease),
  });
  assert.equal(staleChain.reason, "historical_receipt_guard");

  const stalePlatformRelease = buildReleaseFixture();
  stalePlatformRelease.eight_surface_evidence_map.github = {
    ...stalePlatformRelease.eight_surface_evidence_map.github,
    release_fingerprint: "f".repeat(64),
  };
  const stalePlatform = validateReleaseIntegrity({
    currentRelease: stalePlatformRelease,
    chainEvidence: buildChainEvidence(stalePlatformRelease),
    erpReadback: buildErpReadback(stalePlatformRelease),
  });
  assert.equal(stalePlatform.reason, "historical_receipt_guard");

  const bomDrift = buildReleaseFixture();
  bomDrift.bom_fingerprint = "0".repeat(64);
  assert.equal(validateReleaseIntegrity({ currentRelease: bomDrift }).reason, "bom_fingerprint_mismatch");

  const manifestDrift = buildReleaseFixture({ immutableBomSha256: "9".repeat(64) });
  manifestDrift.immutable_release_bom[0].digest = "c".repeat(64);
  assert.equal(validateReleaseIntegrity({ currentRelease: manifestDrift }).reason, "bom_fingerprint_mismatch");

  const fileHashDrift = buildReleaseFixture();
  fileHashDrift.immutable_release_bom[0].digest = "c".repeat(64);
  fileHashDrift.bom_fingerprint = digest(fileHashDrift.immutable_release_bom);
  fileHashDrift.release_fingerprint = digest({
    release_id: fileHashDrift.release_id,
    current_release_delta: fileHashDrift.current_release_delta,
    immutable_release_bom: fileHashDrift.immutable_release_bom,
    interaction_evidence: fileHashDrift.interaction_evidence,
    acceptance_state: fileHashDrift.acceptance_state,
  });
  assert.equal(validateReleaseIntegrity({ currentRelease: fileHashDrift }).reason, "bom_file_hash_mismatch");

  const missingRuntimeBinding = buildReleaseFixture();
  delete missingRuntimeBinding.runtime_binding;
  assert.equal(validateReleaseIntegrity({ currentRelease: missingRuntimeBinding }).reason, "release_runtime_binding_missing");
});

test("B04 requires eight independent current receipts with one shared material outcome", () => {
  const missingPlatform = buildReleaseFixture();
  delete missingPlatform.eight_surface_evidence_map.guild;
  const missing = validateReleaseIntegrity({
    currentRelease: missingPlatform,
    chainEvidence: buildChainEvidence(missingPlatform),
    erpReadback: buildErpReadback(missingPlatform),
  });
  assert.equal(missing.reason, "eight_platform_gate_incomplete");

  const duplicateReceipt = buildReleaseFixture();
  duplicateReceipt.eight_surface_evidence_map.render.receipt_id = duplicateReceipt.eight_surface_evidence_map.github.receipt_id;
  const duplicate = validateReleaseIntegrity({
    currentRelease: duplicateReceipt,
    chainEvidence: buildChainEvidence(duplicateReceipt),
    erpReadback: buildErpReadback(duplicateReceipt),
  });
  assert.equal(duplicate.reason, "platform_receipt_not_independent");

  const outcomeDrift = buildReleaseFixture();
  outcomeDrift.eight_surface_evidence_map.talent.material_outcome_digest = "e".repeat(64);
  const drift = validateReleaseIntegrity({
    currentRelease: outcomeDrift,
    chainEvidence: buildChainEvidence(outcomeDrift),
    erpReadback: buildErpReadback(outcomeDrift),
  });
  assert.equal(drift.reason, "platform_outcome_mismatch");
});

test("B04 keeps independent review and owner gate separate from local validator readiness", () => {
  const pendingReview = buildReleaseFixture({ independentSolMedium: "pending" });
  const reviewResult = validateReleaseIntegrity({
    currentRelease: pendingReview,
    chainEvidence: buildChainEvidence(pendingReview),
    erpReadback: buildErpReadback(pendingReview),
  });
  assert.equal(reviewResult.reason, "independent_review_pending");
  assert.equal(reviewResult.chain_valid, true);
  assert.equal(reviewResult.erp_complete, true);
  assert.equal(reviewResult.platform_complete, true);
  assert.equal(reviewResult.publication_complete, false);

  const missingOwnerGate = buildReleaseFixture({ ownerGate: "not_visible" });
  const ownerResult = validateReleaseIntegrity({
    currentRelease: missingOwnerGate,
    chainEvidence: buildChainEvidence(missingOwnerGate),
    erpReadback: buildErpReadback(missingOwnerGate),
  });
  assert.equal(ownerResult.reason, "owner_gate_missing");
  assert.equal(ownerResult.publication_complete, false);
});

test("B04 rejects synthetic evidence and calls receipts that are not bound to the top-level transaction", () => {
  const release = buildReleaseFixture();
  const synthetic = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: buildChainEvidence(release, { synthetic: true }),
    erpReadback: buildErpReadback(release),
  });
  assert.equal(synthetic.reason, "chain_evidence_provenance_missing");

  const mismatchedCalls = buildChainEvidence(release, {
    wallet_calls_status: {
      version: "1.0",
      chainId: "0x2105",
      id: "calls-b04-mismatch",
      atomic: true,
      status: 200,
      receipts: [{ transactionHash: `0x${"5".repeat(64)}`, status: "0x1" }],
    },
  });
  const mismatch = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: mismatchedCalls,
    erpReadback: buildErpReadback(release),
  });
  assert.equal(mismatch.reason, "wallet_calls_receipts_transaction_mismatch");

  const secondTransactionHash = `0x${"6".repeat(64)}`;
  const multiReceiptEvidence = buildChainEvidence(release, {
    receipt_transaction_hashes: [`0x${"4".repeat(64)}`, secondTransactionHash],
    wallet_calls_status: {
      version: "1.0",
      chainId: "0x2105",
      id: "calls-b04-multi",
      atomic: false,
      status: 200,
      receipts: [
        { transactionHash: `0x${"4".repeat(64)}`, status: "0x1" },
        { transactionHash: secondTransactionHash, status: "0x1" },
      ],
    },
  });
  const multiReceipt = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: multiReceiptEvidence,
    erpReadback: buildErpReadback(release),
  });
  assert.equal(multiReceipt.chain_valid, true);

  const multiTopLevelDrift = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: {
      ...multiReceiptEvidence,
      transaction_hash: `0x${"7".repeat(64)}`,
    },
    erpReadback: buildErpReadback(release),
  });
  assert.equal(multiTopLevelDrift.reason, "wallet_calls_receipts_transaction_mismatch");

  const multiDuplicate = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: {
      ...multiReceiptEvidence,
      receipt_transaction_hashes: [`0x${"4".repeat(64)}`, `0x${"4".repeat(64)}`],
    },
    erpReadback: buildErpReadback(release),
  });
  assert.equal(multiDuplicate.reason, "wallet_calls_receipts_transaction_mismatch");

  const syntheticErp = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: buildChainEvidence(release),
    erpReadback: buildErpReadback(release, { synthetic: true }),
  });
  assert.equal(syntheticErp.reason, "erp_readback_provenance_missing");

  const caseDrift = validateReleaseIntegrity({
    currentRelease: release,
    chainEvidence: buildChainEvidence(release),
    erpReadback: buildErpReadback(release, { case_id: "case-b04-other" }),
  });
  assert.equal(caseDrift.reason, "erp_case_identity_mismatch");

  const syntheticPlatformRelease = buildReleaseFixture();
  syntheticPlatformRelease.eight_surface_evidence_map.guild.synthetic = true;
  const syntheticPlatform = validateReleaseIntegrity({
    currentRelease: syntheticPlatformRelease,
    chainEvidence: buildChainEvidence(syntheticPlatformRelease),
    erpReadback: buildErpReadback(syntheticPlatformRelease),
  });
  assert.equal(syntheticPlatform.reason, "platform_evidence_provenance_missing");
});

test("B04 revalidates the current exact packet binding without treating provenance as Base execution proof", () => {
  const exchange = JSON.parse(readFileSync(new URL("../shared/base_erp_exchange_v1.json", import.meta.url), "utf8"));
  const packet = exchange.packets.find((candidate) => candidate.id === "base-erp-semantic-delta-a12-r19-p6-candidate-20260806");
  assert.ok(packet);
  assert.equal(packet.status, "accepted_for_02_Build");
  assert.equal(packet.execution_authority, "none_until_02_Build_revalidates");

  const frozen = packet.frozen_manifest;
  const basis = [
    frozen.r19_authority.sha256,
    frozen.p6_candidate_inputs.delta.sha256,
    frozen.p6_candidate_inputs.bom.sha256,
    frozen.p6_candidate_inputs.interaction_evidence.sha256,
    frozen.p6_candidate_inputs.evidence_map.sha256,
    frozen.p6_candidate_inputs.acceptance.sha256,
  ];
  const commonBinding = packet.eight_platform_candidate_design.common_binding;
  assert.equal(frozen.p6_candidate_inputs.queue.path.endsWith("programme_continuation_queue_v1.json#v3_2_a12"), true);
  assert.equal(frozen.p6_candidate_inputs.acceptance.status, "p6_stable_terminal_freeze_pending_sol_medium");
  assert.equal(digest([...basis].sort()), commonBinding.release_fingerprint);
  assert.equal(commonBinding.release_fingerprint, packet.base_candidate_release_binding.release_fingerprint);
  assert.equal(commonBinding.immutable_bom_sha256, packet.base_candidate_release_binding.immutable_bom_sha256);
  assert.equal(packet.base_candidate_release_binding.candidate_only, true);
  assert.equal(packet.base_candidate_release_binding.public_release, false);

  for (const platform of packet.eight_platform_candidate_design.platforms) {
    assert.equal(platform.credited_count, 0);
    assert.equal(platform.eligible, false);
    assert.equal(platform.receipt, null);
  }

  const currentRelease = buildReleaseFixture({
    releaseId: commonBinding.release_id,
    independentSolMedium: "pending",
    ownerGate: "not_visible",
    immutableBomSha256: commonBinding.immutable_bom_sha256,
    releaseFingerprintBasis: basis,
  });
  assert.equal(currentRelease.release_fingerprint, commonBinding.release_fingerprint);
  assert.equal(currentRelease.immutable_bom_sha256, commonBinding.immutable_bom_sha256);
  assert.equal(currentRelease.bom_fingerprint, digest(currentRelease.immutable_release_bom));
  const result = validateReleaseIntegrity({
    currentRelease,
    chainEvidence: buildChainEvidence(currentRelease),
    erpReadback: buildErpReadback(currentRelease),
  });

  assert.equal(result.reason, "independent_review_pending");
  assert.equal(result.release_identity_valid, true);
  assert.equal(result.release_fingerprint_algorithm, "sha256(sorted_six_hash_array_json)");
  assert.equal(result.immutable_bom_sha256, commonBinding.immutable_bom_sha256);
  assert.equal(result.chain_valid, true);
  assert.equal(result.erp_complete, true);
  assert.equal(result.platform_complete, true);
  assert.equal(result.publication_complete, false);

  const reordered = { ...currentRelease, releaseFingerprintBasis: undefined };
  reordered.release_fingerprint_basis = [...basis].reverse();
  assert.equal(validateReleaseIntegrity({ currentRelease: reordered }).reason, "chain_evidence_missing");

  const forged = { ...currentRelease, release_fingerprint_basis: [...basis.slice(0, 5), "f".repeat(64)] };
  assert.equal(validateReleaseIntegrity({ currentRelease: forged }).reason, "release_fingerprint_mismatch");
});

test("B05 revalidates the newer accepted packet's seven-hash current-release binding", () => {
  const exchange = JSON.parse(readFileSync(new URL("../shared/base_erp_exchange_v1.json", import.meta.url), "utf8"));
  const runtime = JSON.parse(readFileSync(new URL("../runtime/current_state.json", import.meta.url), "utf8"));
  const packet = exchange.packets.find((candidate) => candidate.id === "base-erp-semantic-delta-a12-r19-p6-upstream-pass-readiness-candidate-20260806");
  const priorPacket = exchange.packets.find((candidate) => candidate.id === "base-erp-semantic-delta-a12-r19-p6-candidate-20260806");
  assert.ok(packet);
  assert.ok(priorPacket);
  assert.equal(packet.status, "accepted_for_02_Build");
  assert.equal(packet.typed_handoff.execution_authority, "none_until_02_Build_revalidates");

  const priorFrozen = priorPacket.frozen_manifest;
  const basis = [
    priorFrozen.r19_authority.sha256,
    runtime.planning_artifacts.a12_r19_follow_up.p6_upstream_verdict_sha256,
    priorFrozen.p6_candidate_inputs.delta.sha256,
    priorFrozen.p6_candidate_inputs.bom.sha256,
    priorFrozen.p6_candidate_inputs.interaction_evidence.sha256,
    priorFrozen.p6_candidate_inputs.evidence_map.sha256,
    priorFrozen.p6_candidate_inputs.acceptance.sha256,
  ];
  const commonBinding = packet.eight_platform_candidate_design.common_binding;
  assert.equal(basis.length, 7);
  assert.equal(digest([...basis].sort()), commonBinding.release_fingerprint);
  assert.equal(commonBinding.release_fingerprint, packet.base_candidate_release_binding.release_fingerprint);
  assert.equal(commonBinding.immutable_bom_sha256, packet.base_candidate_release_binding.immutable_bom_sha256);
  assert.equal(packet.base_candidate_release_binding.candidate_only, true);
  assert.equal(packet.base_candidate_release_binding.public_release, false);
  assert.equal(packet.eight_platform_candidate_design.rows.length, 8);
  assert.equal(packet.eight_platform_candidate_design.rows.every((row) => row.credited_count === 0), true);

  const currentRelease = buildReleaseFixture({
    releaseId: commonBinding.release_id,
    independentSolMedium: "pending",
    ownerGate: "not_visible",
    immutableBomSha256: commonBinding.immutable_bom_sha256,
    releaseFingerprintBasis: basis,
  });
  const result = validateReleaseIntegrity({
    currentRelease,
    chainEvidence: buildChainEvidence(currentRelease),
    erpReadback: buildErpReadback(currentRelease),
  });
  assert.equal(result.reason, "independent_review_pending");
  assert.equal(result.release_identity_valid, true);
  assert.equal(result.release_fingerprint_algorithm, "sha256(sorted_seven_hash_array_json)");
  assert.equal(result.chain_valid, true);
  assert.equal(result.erp_complete, true);
  assert.equal(result.platform_complete, true);
  assert.equal(result.publication_complete, false);

  const candidateBomDrift = { ...currentRelease, immutable_bom_sha256: "f".repeat(64) };
  assert.equal(validateReleaseIntegrity({ currentRelease: candidateBomDrift }).reason, "immutable_bom_basis_mismatch");
});

test("B06 keeps the accepted packet's eight-surface candidate boundary non-creditable", () => {
  const exchange = JSON.parse(readFileSync(new URL("../shared/base_erp_exchange_v1.json", import.meta.url), "utf8"));
  const packet = exchange.packets.find((candidate) => candidate.id === "base-erp-semantic-delta-a12-r19-p6-upstream-pass-readiness-candidate-20260806");
  assert.ok(packet);
  assert.equal(packet.status, "accepted_for_02_Build");
  assert.equal(packet.typed_handoff.handoff_status, "accepted_for_02_Build_bounded_pending_revalidation");
  assert.equal(packet.typed_handoff.execution_authority, "none_until_02_Build_revalidates");
  assert.equal(packet.build_revalidation.acceptance.external_authority, "none; current Base MCP namespace absent and no owner-visible external gate");

  const commonBinding = packet.eight_platform_candidate_design.common_binding;
  assert.equal(commonBinding.credited_count, 0);
  assert.equal(commonBinding.eligible, false);
  assert.equal(commonBinding.official_readback_required, true);

  const platforms = packet.eight_platform_candidate_design.rows.map((row) => row.platform);
  assert.deepEqual(platforms, ["GitHub", "Render", "Base App", "Base Dashboard", "Base.dev", "Talent", "Guild", "Basename/base.org"]);
  assert.equal(new Set(platforms).size, 8);
  for (const row of packet.eight_platform_candidate_design.rows) {
    assert.equal(row.evidence_status, "current_official_readback_required");
    assert.equal(row.credited_count, 0);
    assert.equal(row.receipt, undefined);
  }
});

test("B07 accepts an explicit Base authority set only when every record is terminal and writer-idle", () => {
  const authorityIds = ["base_product_owner", "base_build_owner"];
  const terminalStatuses = ["complete"];
  const authorityRecords = [
    { authority_id: "base_product_owner", status: "complete", writer_idle: true },
    { authority_id: "base_build_owner", status: "complete", writer_idle: true },
  ];

  const valid = validateBaseAuthorityConsistency({ authorityIds, authorityRecords, terminalStatuses });
  assert.equal(valid.ok, true);
  assert.equal(valid.authority_count, 2);
  assert.deepEqual(valid.authority_ids, authorityIds);
  assert.deepEqual(valid.records, authorityRecords);
  assert.equal(valid.writer_idle_required, true);

  const missing = validateBaseAuthorityConsistency({ authorityIds, authorityRecords: authorityRecords.slice(0, 1), terminalStatuses });
  assert.equal(missing.reason, "base_authority_id_set_mismatch");
  assert.deepEqual(missing.conflict_ids, ["base_build_owner"]);

  const extra = validateBaseAuthorityConsistency({
    authorityIds,
    authorityRecords: [...authorityRecords, { authority_id: "untrusted_extra", status: "complete", writer_idle: true }],
    terminalStatuses,
  });
  assert.equal(extra.reason, "base_authority_id_set_mismatch");
  assert.deepEqual(extra.conflict_ids, ["untrusted_extra"]);

  const active = validateBaseAuthorityConsistency({
    authorityIds,
    authorityRecords: [{ ...authorityRecords[0], status: "active" }, authorityRecords[1]],
    terminalStatuses,
  });
  assert.equal(active.reason, "base_authority_status_conflict");
  assert.deepEqual(active.conflict_ids, ["base_product_owner"]);

  const nonIdle = validateBaseAuthorityConsistency({
    authorityIds,
    authorityRecords: [{ ...authorityRecords[0], writer_idle: false }, authorityRecords[1]],
    terminalStatuses,
  });
  assert.equal(nonIdle.reason, "base_authority_writer_idle_conflict");
  assert.deepEqual(nonIdle.conflict_ids, ["base_product_owner"]);

  const statusConflict = validateBaseAuthorityConsistency({
    authorityIds,
    authorityRecords: [authorityRecords[0], { ...authorityRecords[0], status: "blocked" }, authorityRecords[1]],
    terminalStatuses,
  });
  assert.equal(statusConflict.reason, "base_authority_status_conflict");
  assert.deepEqual(statusConflict.conflict_ids, ["base_product_owner"]);

  const missingStatus = validateBaseAuthorityConsistency({
    authorityIds,
    authorityRecords: [{ authority_id: "base_product_owner", writer_idle: true }, authorityRecords[1]],
    terminalStatuses,
  });
  assert.equal(missingStatus.reason, "base_authority_status_missing");
  assert.deepEqual(missingStatus.conflict_ids, ["base_product_owner"]);
});

test("B08 emits a Base-native non-executable per-gate preflight with owner confirmation absent", () => {
  const result = validateBaseGatePreflight(B08_PREFLIGHT);
  assert.equal(result.ok, true);
  assert.equal(result.fail_closed, false);
  assert.equal(result.gate_id, "base_release_readback_gate");
  assert.equal(result.executable, false);
  assert.equal(result.payload, null);
  assert.equal(Object.hasOwn(result, "owner_confirmation"), false);
  assert.equal(Object.hasOwn(result.owner_gate, "owner_confirmation"), false);
  assert.equal(result.owner_gate.owner_confirmation_status, "NOT_GRANTED");
  assert.equal(result.owner_gate.status, "not_observed");
  assert.deepEqual(result.runtime.terminal_statuses, ["complete"]);
  assert.equal(result.receipt_finality.required_receipt_status, "0x1");
  assert.equal(result.receipt_finality.required_finality_stage, "l1_batch_finality");
  assert.equal(result.erp_readback.chain_success_is_not_erp, true);
  assert.deepEqual(result.required_readbacks, B08_PREFLIGHT.required_readbacks);
  assert.deepEqual(result.stop_conditions, B08_PREFLIGHT.stop_conditions);
  assert.deepEqual(result.recovery, B08_PREFLIGHT.recovery);
  assert.deepEqual(result.readback_state, {
    receipt: "not_observed",
    erp: "not_observed",
    platform_receipts: "not_observed",
    chain_success_not_erp: true,
  });
});

test("B08 accepts only complete current Base receipt, ERP and eight-platform readbacks", () => {
  const transactionHash = `0x${"e".repeat(64)}`;
  const release = B08_PREFLIGHT.current_release;
  const readbacks = {
    receipt: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "authorized_base_readback",
      readback_ref: "base-b08-receipt-readback",
      case_id: "case-b08-001",
      chain_id: 8453,
      transaction_hash: transactionHash,
      receipt_status: "0x1",
      finality_stage: "l1_batch_finality",
      l1_finalized: true,
      reorged: false,
      state_change: true,
      unique: true,
      wallet_calls_status: {
        version: "1.0",
        chainId: "0x2105",
        id: "calls-b08-001",
        status: 200,
        atomic: true,
        receipts: [{ transactionHash, status: "0x1" }],
      },
    },
    erp: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "authorized_erp_readback",
      readback_ref: "base-b08-erp-readback",
      case_id: "case-b08-001",
      documentId: "ERP-B08-0001",
      authoritative: true,
      status: "posted",
    },
    platforms: B04_PLATFORMS.map((platform, index) => ({
      platform,
      receipt_id: `base-b08-${platform}-${index}`,
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "official_platform_readback",
      independent: true,
      status: "verified",
      proof_ref: `base-b08-${platform}-readback`,
    })),
  };
  const result = validateBaseGatePreflight({ ...structuredClone(B08_PREFLIGHT), readbacks });
  assert.equal(result.ok, true);
  assert.deepEqual(result.readback_state, {
    receipt: "observed",
    erp: "observed",
    platform_receipts: "complete",
    chain_success_not_erp: true,
  });
  assert.equal(result.executable, false);
  assert.equal(result.payload, null);
});

test("B08 rejects owner-action inference, executable payloads and unknown Base runtime vocabulary", () => {
  const ownerConfirmation = structuredClone(B08_PREFLIGHT);
  ownerConfirmation.owner_confirmation = { observed: true };
  assert.equal(validateBaseGatePreflight(ownerConfirmation).reason, "base_preflight_owner_confirmation_present");

  const ownerStatus = structuredClone(B08_PREFLIGHT);
  ownerStatus.owner_gate.status = "awaiting_owner_action";
  assert.equal(validateBaseGatePreflight(ownerStatus).reason, "base_preflight_owner_gate_not_unobserved");

  const executable = structuredClone(B08_PREFLIGHT);
  executable.executable = true;
  assert.equal(validateBaseGatePreflight(executable).reason, "base_preflight_executable_not_false");

  const payload = structuredClone(B08_PREFLIGHT);
  payload.payload = { to: `0x${"1".repeat(40)}` };
  assert.equal(validateBaseGatePreflight(payload).reason, "base_preflight_payload_not_null");

  const runtimeStatus = structuredClone(B08_PREFLIGHT);
  runtimeStatus.runtime.status = "active";
  assert.equal(validateBaseGatePreflight(runtimeStatus).reason, "base_preflight_runtime_status_conflict");

  const runtimeBinding = structuredClone(B08_PREFLIGHT);
  delete runtimeBinding.runtime.runtime_sha256;
  assert.equal(validateBaseGatePreflight(runtimeBinding).reason, "base_preflight_runtime_binding_invalid");

  const missingWriterIdle = structuredClone(B08_PREFLIGHT);
  delete missingWriterIdle.runtime.writer_idle_authority;
  assert.equal(validateBaseGatePreflight(missingWriterIdle).reason, "base_preflight_writer_idle_unbound");

  const writerHashMismatch = structuredClone(B08_PREFLIGHT);
  writerHashMismatch.runtime.writer_idle_authority.runtime_sha256 = "f".repeat(64);
  assert.equal(validateBaseGatePreflight(writerHashMismatch).reason, "base_preflight_writer_idle_unbound");

  const writerNotIdle = structuredClone(B08_PREFLIGHT);
  const { record_sha256: ignoredRecordHash, ...unsignedWriterRecord } = writerNotIdle.runtime.writer_idle_authority;
  unsignedWriterRecord.writer_idle = false;
  writerNotIdle.runtime.writer_idle = false;
  writerNotIdle.runtime.writer_idle_authority = { ...unsignedWriterRecord, record_sha256: digest(unsignedWriterRecord) };
  assert.equal(validateBaseGatePreflight(writerNotIdle).reason, "base_preflight_writer_idle_unbound");

  const fakeRuntime = structuredClone(B08_PREFLIGHT);
  fakeRuntime.runtime.date_cst = "2099-01-01";
  fakeRuntime.authority.current_runtime.date_cst = "2099-01-01";
  fakeRuntime.runtime.runtime_sha256 = "f".repeat(64);
  fakeRuntime.authority.current_runtime.runtime_sha256 = "f".repeat(64);
  assert.equal(validateBaseGatePreflight(fakeRuntime).reason, "base_preflight_runtime_authority_mismatch");

  const releaseAuthorityMismatch = structuredClone(B08_PREFLIGHT);
  releaseAuthorityMismatch.current_release.release_id = "stale-release";
  assert.equal(validateBaseGatePreflight(releaseAuthorityMismatch).reason, "base_preflight_authoritative_release_mismatch");

  const unknownRuntime = structuredClone(B08_PREFLIGHT);
  unknownRuntime.runtime.arc_status = "stable_terminal";
  assert.equal(validateBaseGatePreflight(unknownRuntime).reason, "base_preflight_runtime_unknown_field");

  const terminalVocabulary = structuredClone(B08_PREFLIGHT);
  terminalVocabulary.runtime.terminal_statuses = ["stable_terminal_freeze_pending_sol_medium"];
  assert.equal(validateBaseGatePreflight(terminalVocabulary).reason, "base_preflight_terminal_status_vocabulary_invalid");
});

test("B08 rejects missing, stale, conflicting and incomplete preflight declarations", () => {
  const missingReadbacks = structuredClone(B08_PREFLIGHT);
  delete missingReadbacks.required_readbacks;
  assert.equal(validateBaseGatePreflight(missingReadbacks).reason, "base_preflight_required_field_missing");

  const missingInputBinding = structuredClone(B08_PREFLIGHT);
  missingInputBinding.required_inputs = missingInputBinding.required_inputs.filter((field) => field !== "receipt_finality");
  assert.equal(validateBaseGatePreflight(missingInputBinding).reason, "base_preflight_required_input_missing");

  const staleRelease = structuredClone(B08_PREFLIGHT);
  staleRelease.current_release.current = false;
  assert.equal(validateBaseGatePreflight(staleRelease).reason, "base_preflight_release_stale");

  const conflictingStop = structuredClone(B08_PREFLIGHT);
  conflictingStop.stop_conditions = conflictingStop.stop_conditions.filter((field) => field !== "release_binding_drift");
  assert.equal(validateBaseGatePreflight(conflictingStop).reason, "base_preflight_stop_condition_missing");

  const unknownDeclaration = structuredClone(B08_PREFLIGHT);
  unknownDeclaration.required_inputs.push("circle_owner_gate");
  assert.equal(validateBaseGatePreflight(unknownDeclaration).reason, "base_preflight_required_input_unknown");

  const invalidFinality = structuredClone(B08_PREFLIGHT);
  invalidFinality.receipt_finality.required_finality_stage = "unknown_finality";
  assert.equal(validateBaseGatePreflight(invalidFinality).reason, "base_preflight_receipt_finality_contract_invalid");

  const invalidErp = structuredClone(B08_PREFLIGHT);
  invalidErp.erp_readback.status = "posted";
  assert.equal(validateBaseGatePreflight(invalidErp).reason, "base_preflight_erp_readback_contract_invalid");
});

test("B08 rejects stale, cross-release, historical, synthetic and non-final receipt readbacks", () => {
  const release = B08_PREFLIGHT.current_release;
  const transactionHash = `0x${"f".repeat(64)}`;
  const receiptReadback = {
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    current: true,
    historical: false,
    synthetic: false,
    evidence_origin: "authorized_base_readback",
    readback_ref: "base-b08-receipt-negative",
    case_id: "case-b08-negative",
    chain_id: 8453,
    transaction_hash: transactionHash,
    receipt_status: "0x1",
    finality_stage: "l1_batch_finality",
    l1_finalized: true,
    reorged: false,
    state_change: true,
    unique: true,
    wallet_calls_status: {
      version: "1.0",
      chainId: "0x2105",
      id: "calls-b08-negative",
      status: 200,
      atomic: true,
      receipts: [{ transactionHash, status: "0x1" }],
    },
  };

  const chainOnly = validateBaseGatePreflight({
    ...structuredClone(B08_PREFLIGHT),
    readbacks: { receipt: receiptReadback, erp: null, platforms: [] },
  });
  assert.equal(chainOnly.ok, true);
  assert.equal(chainOnly.readback_state.erp, "not_observed");
  assert.equal(chainOnly.readback_state.chain_success_not_erp, true);

  const crossChainCalls = structuredClone(B08_PREFLIGHT);
  crossChainCalls.readbacks = {
    receipt: { ...receiptReadback, wallet_calls_status: { ...receiptReadback.wallet_calls_status, chainId: "0x14a34" } },
    erp: null,
    platforms: [],
  };
  assert.equal(validateBaseGatePreflight(crossChainCalls).reason, "base_preflight_wallet_calls_chain_mismatch");

  const stale = structuredClone(B08_PREFLIGHT);
  stale.readbacks = { receipt: { ...receiptReadback, current: false }, erp: null, platforms: [] };
  assert.equal(validateBaseGatePreflight(stale).reason, "base_preflight_stale_readback");

  const crossRelease = structuredClone(B08_PREFLIGHT);
  crossRelease.readbacks = { receipt: { ...receiptReadback, release_fingerprint: "a".repeat(64) }, erp: null, platforms: [] };
  assert.equal(validateBaseGatePreflight(crossRelease).reason, "base_preflight_readback_release_mismatch");

  const historical = structuredClone(B08_PREFLIGHT);
  historical.readbacks = { receipt: { ...receiptReadback, historical: true }, erp: null, platforms: [] };
  assert.equal(validateBaseGatePreflight(historical).reason, "base_preflight_historical_evidence");

  const synthetic = structuredClone(B08_PREFLIGHT);
  synthetic.readbacks = { receipt: { ...receiptReadback, synthetic: true }, erp: null, platforms: [] };
  assert.equal(validateBaseGatePreflight(synthetic).reason, "base_preflight_synthetic_evidence");

  const caseMismatch = structuredClone(B08_PREFLIGHT);
  caseMismatch.readbacks = {
    receipt: receiptReadback,
    erp: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "authorized_erp_readback",
      readback_ref: "base-b08-erp-mismatch",
      case_id: "case-b08-other",
      documentId: "ERP-B08-OTHER",
      authoritative: true,
      status: "posted",
    },
    platforms: [],
  };
  assert.equal(validateBaseGatePreflight(caseMismatch).reason, "base_preflight_readback_case_mismatch");

  const erpWithoutReceipt = structuredClone(B08_PREFLIGHT);
  erpWithoutReceipt.readbacks = {
    receipt: null,
    erp: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "authorized_erp_readback",
      readback_ref: "base-b08-erp-without-receipt",
      case_id: "case-b08-negative",
      documentId: "ERP-B08-NO-RECEIPT",
      authoritative: true,
      status: "posted",
    },
    platforms: [],
  };
  assert.equal(validateBaseGatePreflight(erpWithoutReceipt).reason, "base_preflight_erp_receipt_binding_missing");

  const erpWithoutDocument = structuredClone(B08_PREFLIGHT);
  erpWithoutDocument.readbacks = {
    receipt: receiptReadback,
    erp: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "authorized_erp_readback",
      readback_ref: "base-b08-erp-without-document",
      case_id: "case-b08-negative",
      authoritative: true,
      status: "posted",
    },
    platforms: [],
  };
  assert.equal(validateBaseGatePreflight(erpWithoutDocument).reason, "base_preflight_erp_readback_invalid");

  const nonFinal = structuredClone(B08_PREFLIGHT);
  nonFinal.readbacks = { receipt: { ...receiptReadback, finality_stage: "l2_block_inclusion", l1_finalized: false }, erp: null, platforms: [] };
  assert.equal(validateBaseGatePreflight(nonFinal).reason, "base_preflight_receipt_finality_invalid");
});

test("B08 treats partial or conflicting eight-platform readbacks as zero-credit", () => {
  const release = B08_PREFLIGHT.current_release;
  const rows = B04_PLATFORMS.map((platform, index) => ({
    platform,
    receipt_id: `base-b08-platform-${index}`,
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    current: true,
    historical: false,
    synthetic: false,
    evidence_origin: "official_platform_readback",
    independent: true,
    status: "verified",
    proof_ref: `base-b08-platform-proof-${index}`,
  }));

  const partial = structuredClone(B08_PREFLIGHT);
  partial.readbacks = { receipt: null, erp: null, platforms: rows.slice(0, 7) };
  assert.equal(validateBaseGatePreflight(partial).reason, "base_preflight_platform_readbacks_incomplete");

  const duplicate = structuredClone(B08_PREFLIGHT);
  duplicate.readbacks = { receipt: null, erp: null, platforms: [...rows.slice(0, 7), { ...rows[0], receipt_id: "base-b08-platform-duplicate" }] };
  assert.equal(validateBaseGatePreflight(duplicate).reason, "base_preflight_platform_readbacks_conflict");

  const historical = structuredClone(B08_PREFLIGHT);
  historical.readbacks = { receipt: null, erp: null, platforms: rows.map((row, index) => index === 0 ? { ...row, historical: true } : row) };
  assert.equal(validateBaseGatePreflight(historical).reason, "base_preflight_historical_evidence");

  const synthetic = structuredClone(B08_PREFLIGHT);
  synthetic.readbacks = { receipt: null, erp: null, platforms: rows.map((row, index) => index === 0 ? { ...row, synthetic: true } : row) };
  assert.equal(validateBaseGatePreflight(synthetic).reason, "base_preflight_synthetic_evidence");

  const complete = validateBaseGatePreflight({ ...structuredClone(B08_PREFLIGHT), readbacks: { receipt: null, erp: null, platforms: rows } });
  assert.equal(complete.ok, true);
  assert.equal(complete.readback_state.platform_receipts, "complete");
  assert.equal(complete.executable, false);
  assert.equal(complete.payload, null);
});

test("wallet_getCapabilities atomic owner preflight accepts supported capability without execution authority", () => {
  const result = validateBaseAtomicOwnerPreflight(structuredClone(ATOMIC_OWNER_PREFLIGHT));
  assert.equal(result.ok, true);
  assert.equal(result.capability.method, "wallet_getCapabilities");
  assert.equal(result.capability.atomic_status, "supported");
  assert.equal(result.provider_contract.send_calls_version, "2.0.0");
  assert.equal(result.provider_contract.capability_field, "atomic");
  assert.equal(result.send_calls.atomicRequired, true);
  assert.equal(result.owner_gate.owner_confirmation_status, "NOT_GRANTED");
  assert.equal(result.owner_gate.observed, false);
  assert.equal(result.executable, false);
  assert.equal(result.payload, null);
  assert.equal(result.wallet_calls_status, "not_observed");
  assert.equal(result.receipt_state, "not_observed");
  assert.equal(result.finality_state, "not_observed");
  assert.equal(result.erp_readback, "not_observed");
  assert.equal(result.eight_platform_evidence, "not_observed");
  assert.equal(Object.hasOwn(result, "owner_confirmation"), false);

  const integrated = validateBaseGatePreflight({
    ...structuredClone(B08_PREFLIGHT),
    atomic_owner_preflight: structuredClone(ATOMIC_OWNER_PREFLIGHT),
  });
  assert.equal(integrated.ok, true);
  assert.equal(integrated.atomic_owner_preflight.executable, false);
  assert.equal(integrated.readback_state.chain_success_not_erp, true);
});

test("wallet_getCapabilities atomic owner preflight fails closed for absent unsupported and ready states", () => {
  for (const atomicStatus of ["absent", "unsupported"]) {
    const candidate = structuredClone(ATOMIC_OWNER_PREFLIGHT);
    candidate.capability.atomic_status = atomicStatus;
    const result = validateBaseCapabilityPreflight(candidate.capability);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "base_preflight_atomic_capability_unbound");
    assert.equal(result.executable, false);
    assert.equal(result.payload, null);
  }
  const ready = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  ready.capability.atomic_status = "ready";
  const readyResult = validateBaseAtomicOwnerPreflight(ready);
  assert.equal(readyResult.ok, false);
  assert.equal(readyResult.reason, "base_preflight_atomic_owner_approval_required");
  assert.equal(readyResult.owner_action_required, true);
  assert.equal(readyResult.executable, false);
  assert.equal(readyResult.payload, null);
});

test("wallet_sendCalls atomic owner preflight rejects account chain field and version drift", () => {
  const wrongAccount = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  wrongAccount.capability.account_scope.address = "0x2222222222222222222222222222222222222222";
  assert.equal(validateBaseAtomicOwnerPreflight(wrongAccount).reason, "base_preflight_sendcalls_account_mismatch");

  const wrongChain = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  wrongChain.send_calls.chainId = "0x14a34";
  assert.equal(validateBaseAtomicOwnerPreflight(wrongChain).reason, "base_preflight_sendcalls_chain_mismatch");

  const wrongCapabilityField = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  wrongCapabilityField.provider_contract.capability_field = "atomicBatch";
  assert.equal(validateBaseAtomicOwnerPreflight(wrongCapabilityField).reason, "base_preflight_atomic_capability_unbound");

  const wrongVersion = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  wrongVersion.provider_contract.send_calls_version = "1.0";
  assert.equal(validateBaseAtomicOwnerPreflight(wrongVersion).reason, "base_preflight_sendcalls_version_unbound");
  const mixedRequestVersion = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  mixedRequestVersion.send_calls.version = "1.0";
  assert.equal(validateBaseAtomicOwnerPreflight(mixedRequestVersion).reason, "base_preflight_sendcalls_version_unbound");
});

test("wallet_sendCalls atomic owner preflight rejects runtime authority drift and preserves receipt/publication gates", () => {
  const missingAuthority = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  delete missingAuthority.runtime.writer_idle_authority;
  assert.equal(validateBaseAtomicOwnerPreflight(missingAuthority).reason, "base_preflight_writer_idle_unbound");

  const staleAuthority = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  staleAuthority.runtime.writer_idle_authority.runtime_sha256 = "b".repeat(64);
  assert.equal(validateBaseAtomicOwnerPreflight(staleAuthority).reason, "base_preflight_writer_idle_unbound");

  const notIdle = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  notIdle.runtime.writer_idle = false;
  assert.equal(validateBaseAtomicOwnerPreflight(notIdle).reason, "base_preflight_runtime_authority_mismatch");

  const ownerConfirmation = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  ownerConfirmation.owner_gate.owner_confirmation = "owner-clicked";
  assert.equal(validateBaseAtomicOwnerPreflight(ownerConfirmation).reason, "base_preflight_owner_confirmation_present");

  const finality = structuredClone(ATOMIC_OWNER_PREFLIGHT);
  finality.receipt_finality.required_finality_stage = "l2_block_inclusion";
  assert.equal(validateBaseAtomicOwnerPreflight(finality).reason, "base_preflight_receipt_finality_contract_invalid");
});

test("B11 validates all seven current-release business-closure gaps and keeps execution bounded", () => {
  const result = validateBaseBusinessClosureEvidenceGap(structuredClone(B11_EVIDENCE_GAP));

  assert.equal(result.ok, true);
  assert.equal(result.batch_id, "B11_BASE_BUSINESS_CLOSURE_EVIDENCE_GAP");
  assert.equal(result.domain_count, 7);
  assert.deepEqual(result.business_closure_domains.map(({ record_type }) => record_type), [
    "Sales Invoice",
    "Payment Entry",
    "Bank Transaction",
    "GL",
    "Payment Ledger",
    "Accounting Period",
    "Period Closing Voucher",
  ]);
  assert.equal(result.platform_count, 8);
  assert.equal(result.historical_credit, 0);
  assert.equal(result.partial_credit, 0);
  assert.deepEqual(result.independent_evidence, {
    receipt: "not_observed",
    erp_posting: "not_observed",
    business_close: "not_observed",
    chain_success_not_erp: true,
    receipt_does_not_prove_erp_posting: true,
    receipt_does_not_prove_business_close: true,
    erp_posting_does_not_prove_business_close: true,
  });
  assert.equal(result.owner_gate.owner_confirmation_status, "NOT_GRANTED");
  assert.equal(result.owner_confirmation, "absent");
  assert.equal(result.execution_authority, "none_until_02_Build_revalidates");
  assert.equal(result.executable, false);
  assert.equal(result.payload, null);
  assert.equal(result.business_close_complete, false);
  assert.equal(result.external_actions, 0);
});

test("B11 rejects missing, extra and duplicate business-closure domains", () => {
  const missing = structuredClone(B11_EVIDENCE_GAP);
  missing.business_closure_domains = missing.business_closure_domains.slice(0, 6);
  assert.equal(validateBaseBusinessClosureEvidenceGap(missing).reason, "base_business_closure_domain_set_mismatch");

  const extra = structuredClone(B11_EVIDENCE_GAP);
  extra.business_closure_domains[6].record_type = "Unknown ERP Domain";
  assert.equal(validateBaseBusinessClosureEvidenceGap(extra).reason, "base_business_closure_domain_name_invalid");

  const duplicate = structuredClone(B11_EVIDENCE_GAP);
  duplicate.business_closure_domains[6].record_type = duplicate.business_closure_domains[0].record_type;
  assert.equal(validateBaseBusinessClosureEvidenceGap(duplicate).reason, "base_business_closure_domain_duplicate");
});

test("B11 enforces each domain's exact packet input and authoritative-readback contract", () => {
  const missing = structuredClone(B11_EVIDENCE_GAP);
  missing.business_closure_domains.find(({ record_type }) => record_type === "Payment Ledger").required_inputs.pop();
  assert.equal(validateBaseBusinessClosureEvidenceGap(missing).reason, "base_business_closure_domain_contract_mismatch");

  const extra = structuredClone(B11_EVIDENCE_GAP);
  extra.business_closure_domains.find(({ record_type }) => record_type === "Accounting Period").authoritative_readback.push("unexpected_field");
  assert.equal(validateBaseBusinessClosureEvidenceGap(extra).reason, "base_business_closure_domain_contract_mismatch");

  const crossDomain = structuredClone(B11_EVIDENCE_GAP);
  crossDomain.business_closure_domains.find(({ record_type }) => record_type === "Period Closing Voucher").required_inputs = [...B11_BUSINESS_CLOSURE_CONTRACTS["Payment Ledger"].required_inputs];
  assert.equal(validateBaseBusinessClosureEvidenceGap(crossDomain).reason, "base_business_closure_domain_contract_mismatch");
});

test("B11 rejects stale, historical, partial, synthetic, cross-release and claimed domain evidence", () => {
  const cases = [
    ["stale", { current: false }, "base_business_closure_domain_stale"],
    ["historical", { historical: true }, "base_business_closure_historical_evidence"],
    ["partial", { partial: true }, "base_business_closure_partial_evidence"],
    ["synthetic", { synthetic: true }, "base_business_closure_synthetic_evidence"],
    ["claimed", { evidence_status: "observed" }, "base_business_closure_domain_gap_not_preserved"],
    ["owner-confirmed", { owner_confirmation: "observed" }, "base_business_closure_owner_confirmation_present"],
    ["cross-release", { release_fingerprint: "a".repeat(64) }, "base_business_closure_release_binding_mismatch"],
  ];
  for (const [, change, reason] of cases) {
    const candidate = structuredClone(B11_EVIDENCE_GAP);
    candidate.business_closure_domains[0] = { ...candidate.business_closure_domains[0], ...change };
    assert.equal(validateBaseBusinessClosureEvidenceGap(candidate).reason, reason);
  }
});

test("B11 requires eight current-release platform bindings and assigns historical or partial evidence zero credit", () => {
  const missing = structuredClone(B11_EVIDENCE_GAP);
  missing.platform_bindings = missing.platform_bindings.slice(0, 7);
  assert.equal(validateBaseBusinessClosureEvidenceGap(missing).reason, "base_business_closure_platform_set_mismatch");

  const crossRelease = structuredClone(B11_EVIDENCE_GAP);
  crossRelease.platform_bindings[0].bom_fingerprint = "a".repeat(64);
  assert.equal(validateBaseBusinessClosureEvidenceGap(crossRelease).reason, "base_business_closure_platform_release_binding_mismatch");

  const historical = structuredClone(B11_EVIDENCE_GAP);
  historical.platform_bindings[0].historical = true;
  assert.equal(validateBaseBusinessClosureEvidenceGap(historical).reason, "base_business_closure_historical_platform_evidence");

  const partial = structuredClone(B11_EVIDENCE_GAP);
  partial.platform_bindings[0].partial = true;
  assert.equal(validateBaseBusinessClosureEvidenceGap(partial).reason, "base_business_closure_partial_platform_evidence");

  const credited = structuredClone(B11_EVIDENCE_GAP);
  credited.platform_bindings[0].partial_credit = 1;
  assert.equal(validateBaseBusinessClosureEvidenceGap(credited).reason, "base_business_closure_platform_credit_nonzero");
});

test("B11 keeps an observed receipt independent from ERP posting and business close", () => {
  const release = B11_EVIDENCE_GAP.preflight.current_release;
  const transactionHash = `0x${"e".repeat(64)}`;
  const candidate = structuredClone(B11_EVIDENCE_GAP);
  candidate.preflight.readbacks = {
    receipt: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      current: true,
      historical: false,
      synthetic: false,
      evidence_origin: "authorized_base_readback",
      readback_ref: "base-b11-receipt-readback",
      case_id: "case-b11-001",
      chain_id: 8453,
      transaction_hash: transactionHash,
      receipt_status: "0x1",
      finality_stage: "l1_batch_finality",
      l1_finalized: true,
      reorged: false,
      state_change: true,
      unique: true,
      wallet_calls_status: {
        version: "1.0",
        chainId: "0x2105",
        id: "calls-b11-001",
        status: 200,
        atomic: true,
        receipts: [{ transactionHash, status: "0x1" }],
      },
    },
    erp: null,
    platforms: [],
  };

  const result = validateBaseBusinessClosureEvidenceGap(candidate);
  assert.equal(result.ok, true);
  assert.equal(result.independent_evidence.receipt, "observed");
  assert.equal(result.independent_evidence.erp_posting, "not_observed");
  assert.equal(result.independent_evidence.business_close, "not_observed");
  assert.equal(result.independent_evidence.chain_success_not_erp, true);
  assert.equal(result.business_close_complete, false);
});

test("B11 keeps execution authority and payload fail-closed", () => {
  const wrongAuthority = structuredClone(B11_EVIDENCE_GAP);
  wrongAuthority.execution_authority = "owner_visible";
  assert.equal(validateBaseBusinessClosureEvidenceGap(wrongAuthority).reason, "base_business_closure_execution_authority_invalid");

  const ownerConfirmation = structuredClone(B11_EVIDENCE_GAP);
  ownerConfirmation.preflight.owner_confirmation = "observed";
  assert.equal(validateBaseBusinessClosureEvidenceGap(ownerConfirmation).reason, "base_business_closure_preflight_invalid");

  const executable = structuredClone(B11_EVIDENCE_GAP);
  executable.preflight.executable = true;
  assert.equal(validateBaseBusinessClosureEvidenceGap(executable).reason, "base_business_closure_preflight_invalid");
});
