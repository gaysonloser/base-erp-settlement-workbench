import { digest } from "./base-neutral-receipt-controls.mjs";

const HASH_PATTERN = /^[0-9a-f]{64}$/i;
const AMOUNT_PATTERN = /^(0|[1-9][0-9]*)(?:\.[0-9]{1,6})?$/;
const REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,79}$/;

const NETWORKS = Object.freeze({
  base_mainnet: Object.freeze({ chain_id: 8453, production: true }),
  base_sepolia: Object.freeze({ chain_id: 84532, production: false }),
});

const ERP_DOMAINS = Object.freeze([
  "Sales Invoice",
  "Payment Entry",
  "Bank Transaction",
  "General Ledger",
  "Payment Ledger",
  "Accounting Period",
  "Period Closing Voucher",
]);

/**
 * Public product profiles from H209. These are descriptions only: they carry
 * no wallet, credential, target contract or owner capability.
 */
export const SETTLEMENT_PROFILE_CATALOG = Object.freeze([
  Object.freeze({
    profile_id: "supplier_advance",
    label: "Supplier advance",
    party_role: "supplier",
    direction: "outbound",
    source_document: "Purchase Invoice",
    default_network: "base_sepolia",
    refund_required: false,
  }),
  Object.freeze({
    profile_id: "supplier_corporate_payable",
    label: "Supplier corporate payable",
    party_role: "supplier",
    direction: "outbound",
    source_document: "Purchase Invoice",
    default_network: "base_sepolia",
    refund_required: false,
  }),
  Object.freeze({
    profile_id: "employee_payable",
    label: "Employee payable",
    party_role: "employee",
    direction: "outbound",
    source_document: "Expense Claim",
    default_network: "base_sepolia",
    refund_required: false,
  }),
  Object.freeze({
    profile_id: "customer_invoice_receipt",
    label: "Customer invoice receipt",
    party_role: "customer",
    direction: "inbound",
    source_document: "Sales Invoice",
    default_network: "base_sepolia",
    refund_required: false,
  }),
  Object.freeze({
    profile_id: "customer_advance_receipt",
    label: "Customer advance receipt",
    party_role: "customer",
    direction: "inbound",
    source_document: "Sales Order",
    default_network: "base_sepolia",
    refund_required: false,
  }),
  Object.freeze({
    profile_id: "payment_refund_incoming",
    label: "Payment refund incoming",
    party_role: "customer",
    direction: "inbound",
    source_document: "Payment Entry",
    default_network: "base_sepolia",
    refund_required: true,
  }),
  Object.freeze({
    profile_id: "receipt_refund_outgoing",
    label: "Receipt refund outgoing",
    party_role: "customer",
    direction: "outbound",
    source_document: "Payment Entry",
    default_network: "base_sepolia",
    refund_required: true,
  }),
]);

const PROFILE_INDEX = new Map(SETTLEMENT_PROFILE_CATALOG.map((profile) => [profile.profile_id, profile]));

function requiredString(value, name) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${name} must be a non-empty string`);
  return value.trim();
}

function releaseBinding(release) {
  if (!release || typeof release !== "object" || Array.isArray(release)) throw new TypeError("release is required");
  const releaseId = requiredString(release.release_id, "release.release_id");
  const releaseFingerprint = requiredString(release.release_fingerprint, "release.release_fingerprint").toLowerCase();
  const bomFingerprint = requiredString(release.bom_fingerprint, "release.bom_fingerprint").toLowerCase();
  if (!HASH_PATTERN.test(releaseFingerprint) || !HASH_PATTERN.test(bomFingerprint)) throw new TypeError("release fingerprints must be 32-byte digests");
  return Object.freeze({
    release_id: releaseId,
    release_fingerprint: releaseFingerprint,
    bom_fingerprint: bomFingerprint,
    current: true,
    historical: false,
    synthetic: false,
  });
}

function profileFor(profileId) {
  const id = requiredString(profileId, "profile_id");
  const profile = PROFILE_INDEX.get(id);
  if (!profile) throw new RangeError(`unknown settlement profile: ${id}`);
  return profile;
}

function normalizedAmount(value) {
  const amount = requiredString(value, "amount");
  if (!AMOUNT_PATTERN.test(amount) || Number(amount) <= 0) throw new RangeError("amount must be a positive decimal with at most six places");
  return amount;
}

function normalizedReference(value) {
  const reference = requiredString(value, "business_reference");
  if (!REFERENCE_PATTERN.test(reference)) throw new RangeError("business_reference contains unsupported characters or length");
  return reference;
}

function normalizedCurrency(value) {
  const currency = requiredString(value, "currency").toUpperCase();
  if (!/^[A-Z]{3,8}$/.test(currency)) throw new RangeError("currency must be an uppercase symbol");
  return currency;
}

export function buildVisitorCaseCatalog({ release }) {
  const binding = releaseBinding(release);
  return Object.freeze({
    schema_version: "base-erp-visitor-case-catalog-v1",
    mode: "visitor_read_only",
    release: binding,
    erp_domains: ERP_DOMAINS,
    profiles: SETTLEMENT_PROFILE_CATALOG.map((profile) => Object.freeze({
      ...profile,
      chain_id: NETWORKS[profile.default_network].chain_id,
      supported_networks: Object.keys(NETWORKS),
      safety: Object.freeze({
        simulation_only: true,
        owner_confirmation: "NOT_GRANTED",
        wallet_write_allowed: false,
        refund_ceiling: profile.refund_required ? "original_case_remaining_amount" : "not_applicable",
      }),
    })),
    layers: Object.freeze([
      "visitor_read_only",
      "Base_Account_connect_preflight",
      "simulation_non_executable",
      "owner_review_executable_payload",
      "payment_status_receipt_finality",
      "event_history_admission",
      "ERP_reconciliation",
      "release_and_eight_surface_acceptance",
    ]),
    limitations: Object.freeze([
      "A visitor catalog contains no wallet, signature, transaction, receipt or ERP write capability.",
      "Base Sepolia is the default rehearsal network; a testnet result is never a Base Mainnet receipt.",
      "An ERP proposal, event admission or platform metadata row is not a posting, close or publication receipt.",
    ]),
  });
}

export function buildReadOnlySimulation({ release, profile_id, amount = "100.00", currency = "USDC", network, business_reference = "visitor-demo-001" }) {
  const binding = releaseBinding(release);
  const profile = profileFor(profile_id);
  const chosenNetwork = network === undefined || network === "" ? profile.default_network : requiredString(network, "network");
  const networkInfo = NETWORKS[chosenNetwork];
  if (!networkInfo) throw new RangeError(`unsupported simulation network: ${chosenNetwork}`);
  const normalized = {
    profile_id: profile.profile_id,
    amount: normalizedAmount(amount),
    currency: normalizedCurrency(currency),
    network: chosenNetwork,
    business_reference: normalizedReference(business_reference),
  };
  const input_digest = digest({ release: binding, ...normalized });
  const case_id = `base-erp-sim-${input_digest.slice(0, 16)}`;
  const simulation_id = `sim-${digest({ case_id, release: binding, input_digest }).slice(0, 24)}`;
  const replay_key = `${binding.release_id}:${profile.profile_id}:${normalized.business_reference}`;
  return Object.freeze({
    schema_version: "base-erp-read-only-simulation-v1",
    mode: "simulation_non_executable",
    simulation_id,
    case_id,
    input_digest,
    release: binding,
    case: Object.freeze({
      profile_id: profile.profile_id,
      label: profile.label,
      party_role: profile.party_role,
      direction: profile.direction,
      source_document: profile.source_document,
      amount: normalized.amount,
      currency: normalized.currency,
      business_reference: normalized.business_reference,
      network: normalized.network,
      chain_id: networkInfo.chain_id,
    }),
    normalized_call_plan: Object.freeze({
      network: normalized.network,
      chain_id: networkInfo.chain_id,
      target: "owner_review_required",
      value: normalized.amount,
      asset: normalized.currency,
      calldata: "not_generated_in_visitor_mode",
      nonce: "owner_review_required",
    }),
    expected_effects: Object.freeze({
      payment_status: "not_requested",
      receipt: "not_observed",
      finality: "not_observed",
      event_history: "not_observed",
      erp_reconciliation: "proposal_only",
      publication: "not_evaluated",
    }),
    safety: Object.freeze({
      owner_confirmation: "NOT_GRANTED",
      signed: false,
      broadcast: false,
      transaction_hash: null,
      countable_daily_trace: false,
      replay_key,
      deduplication: "same_key_noop",
      unresolved_request_replay: "forbidden",
      refund_ceiling: profile.refund_required ? "original_case_remaining_amount_unverified" : "not_applicable",
      stale_release: "fail_closed",
      removed_or_reorged_event: "fail_closed",
    }),
    evidence_level: "L1_read_only_simulation",
  });
}

export function buildEventAdmissionPreview({ release, case_id = "visitor-preview-case" }) {
  const binding = releaseBinding(release);
  const caseId = requiredString(case_id, "case_id");
  return Object.freeze({
    schema_version: "base-erp-event-admission-v1",
    mode: "event_history_admission",
    case_id: caseId,
    release: binding,
    status: "blocked_missing_event_history",
    observed: false,
    current_release_bound: true,
    historical_or_old_binding_absent: true,
    required_evidence: Object.freeze([
      "source",
      "object_reference",
      "captured_at",
      "raw_payload",
      "signature_digest",
      "durable_store_pointer",
    ]),
    raw_payload_digest: null,
    durable_store_pointer: null,
    failure_reason: "No native event/history observation was supplied; release metadata, payment status, receipt and finality cannot synthesize one.",
    credit: 0,
  });
}

export function buildStandardWebAppMetadata({ release, primary_url = "https://base-erp-settlement-workbench.onrender.com/" } = {}) {
  const binding = releaseBinding(release);
  const primaryUrl = requiredString(primary_url, "primary_url");
  if (!/^https:\/\//i.test(primaryUrl)) throw new TypeError("primary_url must be HTTPS");
  return Object.freeze({
    schema_version: "base-erp-standard-web-app-metadata-v1",
    project_name: "Base ERP Settlement Workbench",
    name: "Base ERP Settlement Workbench",
    tagline: "Receipt-first ERP settlement",
    description: "A visitor-first Base-native workbench for simulation, receipt evidence and ERP reconciliation boundaries.",
    category: "Finance",
    primary_url: primaryUrl,
    icon: "/assets/base-app/base-erp-workbench-thumbnail-1200x628.jpg",
    screenshots: Object.freeze([
      "/assets/base-app/base-erp-workbench-screenshot-1284x2778.jpg",
      "/assets/base-app/base-erp-workbench-thumbnail-1200x628.jpg",
    ]),
    builder_code: "bc_gi6sq70f",
    builder_code_source: "owner_supplied_metadata_pending_native_readback",
    release: binding,
    evidence_status: "candidate_only",
    public_write_authorized: false,
    wallet_actions_exposed: false,
    limitations: Object.freeze([
      "Metadata is a standard web-app candidate and is not a Base App, Dashboard or Base.dev receipt.",
      "The primary URL must be verified against the live Base release before any platform credit.",
    ]),
  });
}

const WORKBENCH_CASE_BLUEPRINTS = Object.freeze({
  supplier_advance: Object.freeze({
    verb: "Review supplier advance", party: "Northstar Components", amount: "2,500.00 USDC", age: "18m", evidence_tier: "B",
    exception: "Invoice close prohibited", next_owner: "Finance reviewer", source_reference: "PO-BASE-2026-041",
    consequence: "Unallocated supplier advance; Dr Supplier Advance / Cr Base USDC Clearing",
  }),
  supplier_corporate_payable: Object.freeze({
    verb: "Review supplier payment", party: "Atlas Cloud Services", amount: "1,240.00 USDC", age: "9m", evidence_tier: "A",
    exception: "Receipt required", next_owner: "Wallet payer", source_reference: "PINV-BASE-0088",
    consequence: "Payment Entry against submitted invoice; outstanding remains unchanged before ERP readback",
  }),
  employee_payable: Object.freeze({
    verb: "Review employee reimbursement", party: "Employee expense queue", amount: "186.40 USDC", age: "31m", evidence_tier: "C",
    exception: "Counterparty confirmation", next_owner: "AP operator", source_reference: "EXP-BASE-0261",
    consequence: "Expense Claim settlement proposal; no payroll or GL consequence before controller submit",
  }),
  customer_invoice_receipt: Object.freeze({
    verb: "Match incoming customer receipt", party: "Blue Harbor Labs", amount: "980.00 USDC", age: "4m", evidence_tier: "A",
    exception: "Finality pending", next_owner: "AR operator", source_reference: "SINV-BASE-1042",
    consequence: "Receive Payment Entry; Dr Base USDC Clearing / Cr Receivables after final receipt",
  }),
  customer_advance_receipt: Object.freeze({
    verb: "Classify customer advance", party: "Orbit Retail", amount: "5,000.00 USDC", age: "44m", evidence_tier: "C",
    exception: "Allocation intentionally empty", next_owner: "AR operator", source_reference: "SO-BASE-0317",
    consequence: "Unallocated customer advance liability; no Sales Invoice close",
  }),
  payment_refund_incoming: Object.freeze({
    verb: "Resolve payment refund", party: "Original supplier payee", amount: "320.00 USDC", age: "1h", evidence_tier: "B",
    exception: "Refund ceiling check", next_owner: "Finance reviewer", source_reference: "PAY-BASE-REF-003",
    consequence: "Recovery against original outgoing payment; cumulative refund ceiling preserved",
  }),
  receipt_refund_outgoing: Object.freeze({
    verb: "Review receipt refund", party: "Original customer payer", amount: "145.00 USDC", age: "2h", evidence_tier: "D",
    exception: "Original payer proof missing", next_owner: "Exception owner", source_reference: "RCPT-BASE-REF-011",
    consequence: "Refund obligation remains open; wallet request blocked until original receipt identity resolves",
  }),
});

/** Build a deterministic visitor-safe operator workbench, never an execution payload. */
export function buildOperatorWorkbench({ release, selected_profile_id = "customer_invoice_receipt" } = {}) {
  const binding = releaseBinding(release);
  const selectedProfile = profileFor(selected_profile_id);
  const selectedBlueprint = WORKBENCH_CASE_BLUEPRINTS[selectedProfile.profile_id];
  const queue = SETTLEMENT_PROFILE_CATALOG.map((profile, index) => {
    const blueprint = WORKBENCH_CASE_BLUEPRINTS[profile.profile_id];
    return Object.freeze({
      case_id: `BASE-WB-${String(index + 1).padStart(3, "0")}`,
      profile_id: profile.profile_id,
      scenario: profile.label,
      direction: profile.direction,
      party: blueprint.party,
      principal: blueprint.amount,
      age: blueprint.age,
      evidence_tier: blueprint.evidence_tier,
      exception: blueprint.exception,
      next_owner: blueprint.next_owner,
      selected: profile.profile_id === selectedProfile.profile_id,
    });
  });
  const selectedQueueRow = queue.find((row) => row.selected);
  return Object.freeze({
    schema_version: "base-erp-operator-workbench-v1",
    mode: "visitor_read_only",
    release: binding,
    landmarks: Object.freeze(["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]),
    saved_views: Object.freeze([
      Object.freeze({ id: "action_required", label: "Action required", count: 7 }),
      Object.freeze({ id: "exceptions", label: "Exceptions", count: 3 }),
      Object.freeze({ id: "receipt_pending", label: "Receipt pending", count: 2 }),
      Object.freeze({ id: "erp_reconciliation", label: "ERP reconciliation", count: 4 }),
    ]),
    queue: Object.freeze(queue),
    selected_case: Object.freeze({
      ...selectedQueueRow,
      verb: selectedBlueprint.verb,
      source_document: selectedProfile.source_document,
      source_reference: selectedBlueprint.source_reference,
      stop_condition: selectedBlueprint.exception,
      decision_state: selectedBlueprint.evidence_tier === "D" ? "blocked" : "review_required",
      timeline: Object.freeze([
        Object.freeze({ stage: "source", status: "observed", detail: `${selectedProfile.source_document} ${selectedBlueprint.source_reference}` }),
        Object.freeze({ stage: "match", status: selectedBlueprint.evidence_tier === "D" ? "blocked" : "candidate", detail: `Evidence tier ${selectedBlueprint.evidence_tier}; business meaning remains reviewer-owned` }),
        Object.freeze({ stage: "wallet", status: "not_requested", detail: "No Base Account approval request exists in visitor mode" }),
        Object.freeze({ stage: "receipt", status: "not_observed", detail: "No transaction hash, receipt, finality or reorg readback" }),
        Object.freeze({ stage: "erp", status: "proposal_only", detail: "ERP draft, submit, reconciliation and close remain separate controller gates" }),
      ]),
      consequence_preview: Object.freeze({
        accounting: selectedBlueprint.consequence,
        chain_success_implies_erp_posting: false,
        erp_submit_allowed: false,
        business_close_claimed: false,
      }),
    }),
    inspector: Object.freeze({
      tabs: Object.freeze(["evidence", "wallet", "erp_consequence", "recovery"]),
      current_tab: "evidence",
      facts: Object.freeze([
        Object.freeze({ label: "Network", value: "Base Sepolia rehearsal", provenance: "product profile" }),
        Object.freeze({ label: "Receipt", value: "not observed", provenance: "chain gate" }),
        Object.freeze({ label: "Finality", value: "not observed", provenance: "Base four-stage model" }),
        Object.freeze({ label: "ERP readback", value: "not observed", provenance: "controller gate" }),
      ]),
    }),
    safety: Object.freeze({
      wallet_write_allowed: false, erp_write_allowed: false, platform_write_allowed: false,
      signed: false, broadcast: false, synthetic_receipt_credit: 0,
      primary_action: "Review evidence", primary_action_enabled: false, primary_action_blocker: selectedBlueprint.exception,
    }),
  });
}
