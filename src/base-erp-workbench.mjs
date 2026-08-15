import { createHash } from "node:crypto";
import { digest } from "./base-neutral-receipt-controls.mjs";
import { bindRecurringCase, evaluateStatusAdapter, effectivePeriod } from "./base-recurring-settlement-contract.mjs";
import {
  BASE_SEPOLIA_DESCRIPTOR,
  EXECUTION_AUTHORITY,
  H217_BATCH_ID,
  H217_PACKET_ID,
  H217_PLATFORM_ROW_IDS,
  H217_RELEASE_ENVELOPE,
  H217_RELEASE_JOIN,
  H217_SOURCE_HASHES,
  READBACK_SCHEMA_VERSION,
  validateBaseCircleIsolation,
  validateH217Envelope,
  validateH217PublicEnvelope,
  validateH217ReleaseEnvelope,
} from "./base-native-platform-execution-gates.mjs";

const HASH_PATTERN = /^[0-9a-f]{64}$/i;
const AMOUNT_PATTERN = /^(0|[1-9][0-9]*)(?:\.[0-9]{1,6})?$/;
const REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,79}$/;

const H218_PLATFORM_GATES_SCHEMA_VERSION = "base-erp-h218-platform-gates-public-v1";
const H217_MODULE_PATH = "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-native-platform-execution-gates.mjs";
const H217_READBACK_PATH = "projects/2026-08_Base_ERP_Settlement_Workbench/runtime/h217_remaining_platform_readback_2026-08-15.json";
const H217_MODULE_SHA256 = "96f9839cbebb6bff775a5b0cc84a7ae7d71b0168847f2a1eb08c0b59d6f80b42";
const H217_READBACK_SHA256 = "f7aea1ec1ea6d3377334f8f1d32938054f4bd4b809f622673fb056868be2c8b1";
const H217_READBACK_SELF_HASH = "H217_READBACK_SELF_HASH_PLACEHOLDER";
const CIRCLE_MATRIX_SHA256 = "c538e47c4b7951f341b36e351858bf3e1c28dd772d7d3f9c3588f1f0093f19de";
const H218_PLATFORM_GATE_ERROR = "h217_source_invalid_or_circle_collision";
const H219_RELEASE_ID = "base-erp-public-product-20260815-v8";
const H219_BASE_TARGET = Object.freeze({
  github_repo: "gaysonloser/base-erp-settlement-workbench",
  render_service_id: "srv-d9t0bsafngtc7387gqo0",
  render_domain: "base-erp-settlement-workbench.onrender.com",
  dashboard_app_id: "6a7a0717e209a55163497d2d",
  canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com",
});
const H219_HASH_PATTERN = /^[0-9a-f]{64}$/;

const NETWORKS = Object.freeze({
  base_mainnet: Object.freeze({ chain_id: 8453, production: true }),
  base_sepolia: Object.freeze({ chain_id: 84532, production: false }),
});

export const H215_VISIBLE_STATES = Object.freeze([
  "loading",
  "empty",
  "not_evaluated",
  "matched",
  "stale",
  "mismatch",
  "validation_required",
  "confirmation_required",
  "reorg_pending",
  "recovery_ready",
]);

const H215_ORIGIN_DEFINITIONS = Object.freeze([
  Object.freeze({
    id: "erp_initiated",
    label: "ERP initiated",
    source_kind: "erp_source_and_intention",
    evidence_required: Object.freeze(["source_document", "business_intent", "same_case_reference"]),
  }),
  Object.freeze({
    id: "chain_observed",
    label: "Chain observed",
    source_kind: "release_bound_chain_and_event",
    evidence_required: Object.freeze(["receipt_status_0x1", "exact_intent", "l1_batch_finality"]),
  }),
]);

function h215State(value, fallback = "not_evaluated") {
  return H215_VISIBLE_STATES.includes(value) ? value : fallback;
}

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

const RECURRING_SCHEMA_VERSION = "base-erp-h214-recurring-settlement-public-v1";

function recurringReleaseBinding(release, binding) {
  return Object.freeze({
    release_id: binding.release_id,
    release_fingerprint: binding.release_fingerprint,
    bom_fingerprint: binding.bom_fingerprint,
    material_outcome: typeof release.material_outcome === "string" && release.material_outcome.trim() !== "" ? release.material_outcome : "not_specified",
    current: true,
    historical: false,
    synthetic: false,
  });
}

function recurringNetwork(testnet = true, chain_id = 84532) {
  return Object.freeze({ name: testnet ? "Base Sepolia" : "Base Mainnet", chain_id, testnet });
}

function recurringRoutePreview({ operation, manual = false } = {}) {
  if (manual) {
    return Object.freeze({
      operation,
      execution_route: "manual_wallet_sendCalls",
      receipt_route: "calls_status_then_finality",
      calls_status_route: true,
      preview_only: false,
      descriptor_only: true,
      atomic_required: true,
      action_enabled: false,
      tx_hash: null,
      calls_id: null,
      wallet_request: null,
      calls_status: Object.freeze({ method: "wallet_getCallsStatus", status: null }),
    });
  }
  return Object.freeze({
    operation,
    execution_route: "cdp_tx_hash",
    receipt_route: "direct_receipt_finality",
    calls_status_route: false,
    preview_only: true,
    descriptor_only: false,
    action_enabled: false,
    tx_hash: null,
    calls_id: null,
    wallet_request: null,
  });
}

function recurringRoutePreviews() {
  return Object.freeze({
    charge: Object.freeze({ cdp: recurringRoutePreview({ operation: "charge" }), manual: recurringRoutePreview({ operation: "charge", manual: true }) }),
    revoke: Object.freeze({ cdp: recurringRoutePreview({ operation: "revoke" }), manual: recurringRoutePreview({ operation: "revoke", manual: true }) }),
  });
}

function recurringGates() {
  return Object.freeze({
    receipt: Object.freeze({ state: "not_observed", status: null, transaction_hash: null, calls_id: null }),
    finality: Object.freeze({ state: "not_observed", required: "l1_batch_final" }),
    erp: Object.freeze({ state: "erp_readback_pending", posting: false, authoritative_readback_required: true, business_close: false }),
  });
}

function recurringSafety() {
  return Object.freeze({
    external_actions: 0,
    wallet_request: null,
    signed: false,
    broadcast: false,
    synthetic_receipt_credit: 0,
    public_write_authorized: false,
    execution_authority: "none_until_02_Build_revalidates",
  });
}

function recurringBase({ release, binding, testnet = true, chain_id = 84532 } = {}) {
  return {
    schema_version: RECURRING_SCHEMA_VERSION,
    mode: "visitor_read_only",
    selector: "server_owned_default",
    release: recurringReleaseBinding(release, binding),
    plan: Object.freeze({
      status_adapter: "subscription",
      network: recurringNetwork(testnet, chain_id),
      recurring_charge: Object.freeze({ value: null, unit: "USDC", state: "not_observed" }),
      period: Object.freeze({ period_days: null, current_period_start: null, next_period_start: null, no_rollover: true, state: "not_observed" }),
      remaining_allowance: Object.freeze({ value: null, unit: "USDC", state: "not_observed", source: "owner_status_readback_required" }),
    }),
    status: Object.freeze({
      adapter: "subscription",
      state: "status_readback_pending",
      observed: false,
      source: "owner_status_readback_required",
      reason: "owner_status_readback_required",
      subscription: Object.freeze({ is_subscribed: null, remaining_charge_in_period: null, current_period_start: null, next_period_start: null }),
      spend_permission: null,
    }),
    route_previews: recurringRoutePreviews(),
    gates: recurringGates(),
    redaction: Object.freeze({ raw_addresses_exposed: false, raw_permission_hash_exposed: false, raw_calldata_exposed: false, credentials_exposed: false, transaction_refs_exposed: false }),
    safety: recurringSafety(),
  };
}

function recurringRecovery(base, failure) {
  const reason = typeof failure === "string" ? failure : failure?.reason ?? failure?.detail ?? "invalid_server_record";
  return Object.freeze({
    ...base,
    status: Object.freeze({
      ...base.status,
      state: "recovery_ready",
      observed: false,
      source: "h213_contract_rejected",
      reason: /^[a-z0-9_]+$/.test(reason) ? reason : "h213_contract_rejected",
      subscription: null,
      spend_permission: null,
    }),
  });
}

function mapStatus(bound, status) {
  const base = {
    adapter: bound.status_adapter,
    state: status.state,
    observed: ["active", "inactive", "expired", "revoked"].includes(status.state),
    source: "h213_status_readback",
    reason: null,
    subscription: null,
    spend_permission: null,
  };
  if (bound.status_adapter === "subscription") {
    base.subscription = Object.freeze({
      is_subscribed: status.is_subscribed ?? null,
      remaining_charge_in_period: status.remaining_charge_in_period ?? null,
      current_period_start: status.current_period_start ?? null,
      next_period_start: status.next_period_start ?? null,
    });
  } else {
    base.spend_permission = Object.freeze({
      is_active: status.is_active ?? null,
      is_revoked: status.is_revoked ?? null,
      is_expired: status.is_expired ?? null,
      remaining_spend: status.remaining_spend ?? null,
      current_period_start: status.current_period_start ?? null,
      next_period_start: status.next_period_start ?? null,
    });
  }
  return Object.freeze(base);
}

function observedPlan({ bound, period, status }) {
  const periodDays = bound.period_seconds / 86400;
  const remaining = period?.remaining ?? null;
  return Object.freeze({
    status_adapter: bound.status_adapter,
    network: recurringNetwork(bound.testnet, bound.chain_id),
    recurring_charge: Object.freeze({ value: bound.recurring_charge, unit: "USDC", state: "server_owned_configured" }),
    period: Object.freeze({ period_days: periodDays, current_period_start: period?.current_period_start ?? null, next_period_start: period?.next_period_start ?? null, no_rollover: true, state: period ? "observed" : "not_observed" }),
    remaining_allowance: Object.freeze({ value: remaining, unit: "USDC", state: period ? "observed" : "not_observed", source: period ? "h213_status_readback" : "owner_status_readback_required" }),
    status_readback: status.state,
  });
}

/**
 * Build a deterministic visitor-safe recurring settlement public projection.
 * With no server record the projection is status_readback_pending and exposes
 * only contract metadata; a server-owned record is composed through the pinned
 * H213 bindRecurringCase/evaluateStatusAdapter/effectivePeriod contract before
 * any observed value is exposed. Client hints are never accepted.
 */
export function buildRecurringSettlementProjection({ release, server_record = null } = {}) {
  const binding = releaseBinding(release);
  const base = recurringBase({ release, binding });
  if (server_record === null || server_record === undefined) {
    return Object.freeze(base);
  }
  if (typeof server_record !== "object" || Array.isArray(server_record)) {
    return recurringRecovery(base, "server_record_invalid");
  }
  if (server_record.client_hints && typeof server_record.client_hints === "object" && Object.keys(server_record.client_hints).length > 0) {
    return recurringRecovery(base, "browser_client_hints_rejected");
  }
  const caseInput = server_record.case;
  if (!caseInput || typeof caseInput !== "object" || Array.isArray(caseInput)) {
    return recurringRecovery(base, "server_record_case_required");
  }
  const releaseJoin = recurringReleaseBinding(release, binding);
  const bound = bindRecurringCase({ ...caseInput, release: releaseJoin });
  if (bound.state !== "permission_bound") return recurringRecovery(base, bound);
  const status = evaluateStatusAdapter({
    status_adapter: bound.status_adapter,
    case: bound,
    id: bound.permission_hash_digest,
    testnet: bound.testnet,
    subscription_readback: server_record.subscription_readback,
    permission_readback: server_record.permission_readback,
  });
  if (status.state === "recovery_ready") return recurringRecovery(base, status);
  if (status.state === "status_readback_pending") {
    return Object.freeze({
      ...base,
      plan: observedPlan({ bound, status }),
      status: Object.freeze({ ...mapStatus(bound, status), source: "owner_status_readback_required", reason: "owner_status_readback_required" }),
    });
  }
  const period = effectivePeriod({ case: bound, status_result: status });
  if (period.state === "recovery_ready") return recurringRecovery(base, period);
  return Object.freeze({
    ...base,
    plan: observedPlan({ bound, period, status }),
    status: mapStatus(bound, status),
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

function buildH215OperatorSurface({ binding, queue, selectedCase, server_record }) {
  const serverOrigin = server_record && typeof server_record === "object" && !Array.isArray(server_record)
    && H215_ORIGIN_DEFINITIONS.some((origin) => origin.id === server_record.origin)
    ? server_record.origin
    : null;
  const entryPoints = H215_ORIGIN_DEFINITIONS.map((origin) => Object.freeze({
    ...origin,
    state: serverOrigin === origin.id ? "validation_required" : "not_evaluated",
    selected: serverOrigin === origin.id,
    action_enabled: false,
  }));
  const decisionState = h215State(selectedCase.decision_state, "validation_required");
  const selectedOrigin = serverOrigin;
  const facts = Object.freeze({
    chain: Object.freeze({ state: "not_evaluated", route: "none", tx_hash: null, calls_id: null }),
    receipt: Object.freeze({ state: "not_evaluated", status: null, intent_bound: false }),
    finality: Object.freeze({ state: "not_evaluated", required: "l1_batch_final" }),
    erp_posting: Object.freeze({ state: "not_evaluated", claimed: false }),
    business_close: Object.freeze({ state: "not_evaluated", claimed: false }),
  });
  return Object.freeze({
    shell: Object.freeze({
      state: "not_evaluated",
      landmarks: Object.freeze(["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]),
      layout: "global_shell_queue_canvas_inspector",
      keyboard_contract: Object.freeze({ focus_visible: true, escape_closes_inspector: true, logical_order: true }),
    }),
    queue: Object.freeze({
      state: queue.length === 0 ? "empty" : "not_evaluated",
      count: queue.length,
      selected_case_id: selectedCase.case_id,
      rows: queue,
      empty_reason: queue.length === 0 ? "no_cases_available" : null,
    }),
    entry_points: Object.freeze(entryPoints),
    selected_origin: selectedOrigin,
    decision_canvas: Object.freeze({
      state: decisionState,
      case_id: selectedCase.case_id,
      decision: selectedCase.verb,
      validation: "server_owned_descriptor_required",
      confirmation: "owner_visible_gate_required",
      stop_reason: selectedCase.stop_condition,
    }),
    evidence_inspector: Object.freeze({
      state: "not_evaluated",
      tabs: Object.freeze(["chain", "receipt", "finality", "erp_posting", "business_close", "recovery"]),
      facts,
      recovery: Object.freeze({ state: "not_evaluated", reason: null }),
    }),
    consequence_inspector: Object.freeze({
      state: "not_evaluated",
      chain_success_implies_erp_posting: false,
      erp_posting_claimed: false,
      business_close_claimed: false,
      next_owner: selectedCase.next_owner,
    }),
    network_gate: Object.freeze({
      rehearsal: Object.freeze({ network: "base_sepolia", chain_id: 84532, descriptor_only: true }),
      mainnet: Object.freeze({ network: "base_mainnet", chain_id: 8453, owner_gate_required: true, enabled: false }),
    }),
    platform_gate: Object.freeze({
      github: "release_gate",
      render: "deploy_gate",
      base_dashboard: "canonical_app_route",
      base_dev: "canonical_app_route_alias",
      base_app: "readiness_consumer",
      talent: "native_domain_outcome",
      guild: "native_domain_outcome",
      basename_base_org: "native_domain_outcome",
      receipt_credit_delta: 0,
    }),
    safety: Object.freeze({
      external_actions: 0,
      wallet_request: null,
      signed: false,
      broadcast: false,
      erp_write_allowed: false,
      public_write_authorized: false,
      execution_authority: "none_until_02_Build_revalidates",
    }),
  });
}

function h218Unavailable() {
  throw new Error(H218_PLATFORM_GATE_ERROR);
}

function h218Required(value, expected) {
  return value === expected;
}

function h218Hash(value) {
  return typeof value === "string" && HASH_PATTERN.test(value);
}

function canonicalH219(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalH219).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"));
    keys.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalH219(value[key])}`).join(",")}}`;
  }
  throw new TypeError("unsupported JSON value");
}

function h219BaseTargetEqual(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const expectedKeys = Object.keys(H219_BASE_TARGET);
  const actualKeys = Object.keys(value);
  return actualKeys.length === expectedKeys.length
    && expectedKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key) && value[key] === H219_BASE_TARGET[key]);
}

function validateH219ReleaseIdentity(value) {
  if (!value || typeof value !== "object") return false;
  if (value.release_id !== H219_RELEASE_ID
    || typeof value.release_fingerprint !== "string"
    || typeof value.bom_fingerprint !== "string"
    || !H219_HASH_PATTERN.test(value.release_fingerprint)
    || !H219_HASH_PATTERN.test(value.bom_fingerprint)
    || !h219BaseTargetEqual(value.base_target)) return false;
  const expected = createHash("sha256").update(canonicalH219({
    schema_version: "base-erp-v8-release-identity-v1",
    release_id: H219_RELEASE_ID,
    bom_fingerprint: value.bom_fingerprint,
    base_target: H219_BASE_TARGET,
  }), "utf8").digest("hex");
  return value.release_fingerprint === expected && value.release_identity_valid !== false;
}

function buildH218PublicEnvelopeInputs(readback) {
  const publicEnvelope = readback?.public_envelope;
  const expected = publicEnvelope?.expected;
  const live = publicEnvelope?.independent_live_readback;
  if (!expected || !live) h218Unavailable();
  const githubLive = live.github ?? {};
  const renderLive = live.render ?? {};
  return {
    expected,
    github: {
      ...expected,
      repo: "gaysonloser/base-erp-settlement-workbench",
      branch: "main",
      commit_sha: expected.commit_sha,
      ...(githubLive.target_commitish ? { target_commitish: githubLive.target_commitish } : {}),
    },
    render: {
      ...expected,
      service_id: expected.render_service_id,
      deployment_id: expected.render_deployment_id,
      commit_sha: expected.commit_sha,
      health_ready: renderLive.health_ready,
      health_status: renderLive.health_status,
    },
    dashboard: {
      app_id: expected.canonical_dashboard_app_id,
      primary_url: expected.canonical_primary_url,
    },
    githubLive,
    renderLive,
  };
}

function validateH218Readback({ release, h217_readback, h217_module_sha256, h217_readback_sha256, circle_matrix_sha256 }) {
  if (!h217_readback || typeof h217_readback !== "object") h218Unavailable();
  if (!h218Required(h217_module_sha256, H217_MODULE_SHA256)
    || !h218Required(h217_readback_sha256, H217_READBACK_SHA256)
    || !h218Required(circle_matrix_sha256, CIRCLE_MATRIX_SHA256)) h218Unavailable();
  if (!h218Required(h217_readback.schema_version, READBACK_SCHEMA_VERSION)
    || !h218Required(h217_readback.packet_id, H217_PACKET_ID)
    || !h218Required(h217_readback.batch_id, H217_BATCH_ID)
    || !h218Required(h217_readback.readback_id, "h217-remaining-platform-readback-20260815-v7")
    || !h218Required(h217_readback.execution_authority, EXECUTION_AUTHORITY)
    || !h218Required(h217_readback.self_hash, H217_READBACK_SELF_HASH)) h218Unavailable();

  const implementation = h217_readback.implementation ?? {};
  if (!h218Required(implementation.source, H217_MODULE_PATH)
    || !h218Required(implementation.source_sha256, H217_MODULE_SHA256)
    || !h218Required(implementation.runtime_readback, H217_READBACK_PATH)
    || implementation.product_bom_mutated !== false
    || implementation.external_actions !== 0) h218Unavailable();

  const packet = h217_readback.packet_revalidation ?? {};
  const packetHashes = packet.source_hashes ?? {};
  if (packet.ok !== true
    || packet.accepted_once !== true
    || packet.occurrence !== 1
    || packet.exchange_mode !== "0444"
    || !h218Hash(packet.exchange_sha256)
    || packet.execution_authority !== EXECUTION_AUTHORITY
    || packetHashes.manifest_sha256 !== H217_SOURCE_HASHES.manifest_sha256
    || packetHashes.artifact_sha256 !== H217_SOURCE_HASHES.artifact_sha256
    || packetHashes.handoff_sha256 !== H217_SOURCE_HASHES.handoff_sha256) h218Unavailable();

  const envelope = h217_readback.evidence_envelope;
  if (!envelope || envelope.packet_id !== H217_PACKET_ID || !validateH217Envelope(envelope).ok) h218Unavailable();
  if (!validateH217ReleaseEnvelope(h217_readback.release_join ?? {}).ok
    || !validateH219ReleaseIdentity(release)) h218Unavailable();
  const releaseJoin = h217_readback.release_join ?? {};
  if (releaseJoin.release_id !== H217_RELEASE_JOIN.release_id
    || releaseJoin.release_fingerprint !== H217_RELEASE_JOIN.release_fingerprint
    || releaseJoin.bom_fingerprint !== H217_RELEASE_JOIN.bom_fingerprint
    || releaseJoin.status !== "current_v7_github_render_dashboard_join"
    || releaseJoin.credit !== 0
    || releaseJoin.separate_dashboard_basedev_receipt !== false
    || releaseJoin.base_app_readiness_only !== true) h218Unavailable();

  const publicInputs = buildH218PublicEnvelopeInputs(h217_readback);
  const liveGithub = publicInputs.githubLive;
  const liveRender = publicInputs.renderLive;
  if (liveGithub.http_status !== 200
    || liveGithub.target_commitish !== H217_RELEASE_ENVELOPE.commit_sha
    || liveGithub.draft !== false
    || liveGithub.prerelease !== false
    || liveRender.release_http_status !== 200
    || liveRender.health_http_status !== 200
    || liveRender.service_id !== H217_RELEASE_ENVELOPE.render_service_id
    || liveRender.deployment_id !== H217_RELEASE_ENVELOPE.render_deployment_id
    || liveRender.release_id !== H217_RELEASE_ENVELOPE.release_id
    || liveRender.release_fingerprint !== H217_RELEASE_ENVELOPE.release_fingerprint
    || liveRender.bom_fingerprint !== H217_RELEASE_ENVELOPE.bom_fingerprint
    || liveRender.immutable_bom_sha256 !== H217_RELEASE_ENVELOPE.bom_fingerprint
    || liveRender.git_commit !== H217_RELEASE_ENVELOPE.commit_sha
    || liveRender.commit_placeholder !== false
    || liveRender.bom_verified !== true
    || liveRender.bom_files_verified !== true
    || liveRender.release_identity_valid !== true
    || liveRender.health_ready !== true
    || liveRender.health_status !== "ok") h218Unavailable();
  const publicCheck = validateH217PublicEnvelope({
    release: publicInputs.expected,
    github: publicInputs.github,
    render: publicInputs.render,
    dashboard: publicInputs.dashboard,
  });
  if (!publicCheck.ok
    || h217_readback.public_envelope.ok !== true
    || h217_readback.public_envelope.legs?.github !== true
    || h217_readback.public_envelope.legs?.render !== true
    || h217_readback.public_envelope.legs?.dashboard !== true) h218Unavailable();

  const isolation = validateBaseCircleIsolation({
    release: publicInputs.expected,
    github: publicInputs.github,
    render: publicInputs.render,
    dashboard: publicInputs.dashboard,
  }, { platform: "h218_platform_gates" });
  if (!isolation.ok) h218Unavailable();
  if (h217_readback.queue_cursor_counters?.changed !== false
    || h217_readback.queue_cursor_counters?.external_trace_units !== 0
    || h217_readback.queue_cursor_counters?.public_update_units !== 0) h218Unavailable();

  const observations = h217_readback.owner_gate_observations ?? {};
  const expectedObservations = {
    base_sepolia_rehearsal: { descriptor_valid: true, transaction_hash_observed: false, receipt_observed: false, finality_stage: null, credit: 0 },
    talent_native_domain: { exact_project_search: "Base ERP Settlement Workbench", projects_found: 0, project_identity_observed: false, owner_auth_required: true, credit: 0 },
    guild_native_domain: { generic_base_page_visible: true, project_identity_observed: false, release_mapping_observed: false, owner_auth_required: true, credit: 0 },
    basename_base_org_identity: { account_level_singleton: true, project_release_mapping_observed: false, identity_only: true, credit: 0 },
  };
  for (const id of H217_PLATFORM_ROW_IDS) {
    const actual = observations[id];
    const expectedObservation = expectedObservations[id];
    if (!actual || !expectedObservation || Object.keys(expectedObservation).some((key) => actual[key] !== expectedObservation[key])) h218Unavailable();
    const row = envelope.platform_rows?.find((item) => item?.platform_row_id === id);
    if (!row || row.credit !== 0 || row.publication_unit_credit !== 0 || row.external_actions !== 0 || row.native_receipt !== null || row.release_receipt !== false || row.release_join !== null) h218Unavailable();
  }
  const currentIsolation = validateBaseCircleIsolation({
    release: {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      ...(release.base_target ?? H219_BASE_TARGET),
    },
    github: { repo: H219_BASE_TARGET.github_repo, branch: "main", commit_sha: release.git_commit ?? null, ...H219_BASE_TARGET },
    render: { service_id: H219_BASE_TARGET.render_service_id, domain: H219_BASE_TARGET.render_domain, commit_sha: release.git_commit ?? null, ...H219_BASE_TARGET },
    dashboard: { app_id: H219_BASE_TARGET.dashboard_app_id, primary_url: H219_BASE_TARGET.canonical_primary_url },
  }, { platform: "h219_platform_gates" });
  if (!currentIsolation.ok) h218Unavailable();
  return { publicCheck, isolation: currentIsolation, observations };
}

/**
 * Project the accepted H217 readback into one deterministic visitor-safe object.
 * H217 remains the only evaluator; this function only validates its closure and
 * maps the four already-observed owner-gate rows into the H218 public shape.
 */
export function buildPlatformGatesProjection({
  release,
  h217_readback,
  h217_module_sha256 = H217_MODULE_SHA256,
  h217_readback_sha256 = H217_READBACK_SHA256,
  circle_matrix_sha256 = CIRCLE_MATRIX_SHA256,
} = {}) {
  const { observations } = validateH218Readback({ release, h217_readback, h217_module_sha256, h217_readback_sha256, circle_matrix_sha256 });
  const releaseJoin = {
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    commit_sha: release.git_commit ?? "PENDING_OWNER_PUBLIC_COMMIT",
    github_release_url: `https://github.com/${H219_BASE_TARGET.github_repo}/releases/tag/${release.release_id}`,
    render_release_url: `${H219_BASE_TARGET.canonical_primary_url}/release.json`,
    render_health_url: `${H219_BASE_TARGET.canonical_primary_url}/healthz`,
    canonical_dashboard_app_id: H219_BASE_TARGET.dashboard_app_id,
    canonical_primary_url: H219_BASE_TARGET.canonical_primary_url,
    dashboard_basedev_one_identity: true,
    base_app_readiness_only: true,
    separate_dashboard_basedev_receipt: false,
    current: true,
    actual_commit_bound: typeof release.git_commit === "string" && /^[0-9a-f]{40}$/.test(release.git_commit),
  };
  const makeRow = (platform_row_id, { receipt_kind, ...fields }) => ({
    platform_row_id,
    ...fields,
    release_join: null,
    receipt: {
      native_receipt: null,
      receipt_kind,
      release_receipt: false,
      observed: false,
    },
    credit: 0,
    publication_unit_credit: 0,
  });
  const rows = H217_PLATFORM_ROW_IDS.map((platform_row_id) => {
    switch (platform_row_id) {
      case "base_sepolia_rehearsal":
        return makeRow(platform_row_id, {
          evidence_state: "rehearsal_pending",
          owner_gate: "owner_authorized_receipt_and_explicit_finality_readback_required",
          target_identity: { ...BASE_SEPOLIA_DESCRIPTOR },
          public_context: null,
          owner_readback: {
            descriptor_valid: observations.base_sepolia_rehearsal.descriptor_valid,
            transaction_hash_observed: observations.base_sepolia_rehearsal.transaction_hash_observed,
            receipt_observed: observations.base_sepolia_rehearsal.receipt_observed,
            finality_stage: observations.base_sepolia_rehearsal.finality_stage,
          },
          failure_state: "sepolia_receipt_missing_or_invalid",
          receipt_kind: "rehearsal_only",
        });
      case "talent_native_domain":
        return makeRow(platform_row_id, {
          evidence_state: "owner_gate",
          owner_gate: "exact_project_owner_readback_required",
          target_identity: { project_id: null, project_url: null, title: null },
          public_context: { projects_url: "https://talent.app/~/projects", search_query: "Base ERP Settlement Workbench", projects_found: 0 },
          owner_readback: {
            project_identity_observed: observations.talent_native_domain.project_identity_observed,
            release_mapping_observed: false,
            owner_auth_required: observations.talent_native_domain.owner_auth_required,
          },
          failure_state: "talent_exact_project_absent_or_owner_auth_gate",
          receipt_kind: "native_domain_outcome",
        });
      case "guild_native_domain":
        return makeRow(platform_row_id, {
          evidence_state: "context_only",
          owner_gate: "project_specific_owner_admin_or_visitor_readback_required",
          target_identity: { guild_slug: null, project_url: null },
          public_context: { base_guild_url: "https://guild.xyz/base/home", generic_base_page_visible: true, sign_in_or_join_gate_visible: true },
          owner_readback: {
            project_identity_observed: observations.guild_native_domain.project_identity_observed,
            release_mapping_observed: observations.guild_native_domain.release_mapping_observed,
            owner_auth_required: observations.guild_native_domain.owner_auth_required,
          },
          failure_state: "guild_generic_or_sign_in_gate",
          receipt_kind: "native_domain_outcome",
        });
      case "basename_base_org_identity":
        return makeRow(platform_row_id, {
          evidence_state: "identity_only",
          owner_gate: "owner_gated_primary_or_resolver_readback_required",
          target_identity: { account_level_singleton: true, primary_name: null, resolver: null, profile_url: null },
          public_context: { names_url: "https://www.base.org/names", identity_value_omitted: true },
          owner_readback: {
            identity_only: observations.basename_base_org_identity.identity_only,
            project_release_mapping_observed: observations.basename_base_org_identity.project_release_mapping_observed,
            owner_auth_required: true,
          },
          failure_state: "basename_identity_not_project_release",
          receipt_kind: "account_level_identity",
        });
      default:
        return h218Unavailable();
    }
  });
  return Object.freeze({
    schema_version: H218_PLATFORM_GATES_SCHEMA_VERSION,
    mode: "visitor_read_only",
    packet_id: H217_PACKET_ID,
    readback_id: "h217-remaining-platform-readback-20260815-v7",
    observed_at: h217_readback.observed_at_cst,
    release_join: releaseJoin,
    rows: Object.freeze(rows),
    aggregate: Object.freeze({ row_count: rows.length, native_receipt_count: 0, release_receipt_count: 0, credit: 0, publication_unit_credit: 0, eight_surface_duplication: false }),
    isolation: Object.freeze({ circle_collision: false, circle_target_absent: true, state: "base_identity_isolated", fail_closed_on_collision: true, action_enabled: false }),
    redaction: Object.freeze({ wallet_values_exposed: false, credentials_exposed: false, hidden_identity_exposed: false, raw_calldata_exposed: false, transaction_references_exposed: false, owner_basename_value_exposed: false }),
    safety: Object.freeze({ external_actions: 0, wallet_write_allowed: false, public_write_authorized: false, deployment_authority: false, execution_authority: EXECUTION_AUTHORITY }),
  });
}

/** Build a deterministic visitor-safe operator workbench, never an execution payload. */
export function buildOperatorWorkbench({ release, selected_profile_id = "customer_invoice_receipt", server_record = null, platform_gates } = {}) {
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
  const selectedCase = Object.freeze({
    ...selectedQueueRow,
    verb: selectedBlueprint.verb,
    source_document: selectedProfile.source_document,
    source_reference: selectedBlueprint.source_reference,
    stop_condition: selectedBlueprint.exception,
    decision_state: selectedBlueprint.evidence_tier === "D" ? "recovery_ready" : "validation_required",
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
  });
  const operator_surface = buildH215OperatorSurface({ binding, queue, selectedCase, server_record });
  const workbench = {
    schema_version: "base-erp-operator-workbench-v1",
    contract_version: "base-erp-h215-operator-workbench-v1",
    mode: "visitor_read_only",
    release: binding,
    recurring_settlement: buildRecurringSettlementProjection({ release, server_record }),
    landmarks: Object.freeze(["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]),
    saved_views: Object.freeze([
      Object.freeze({ id: "action_required", label: "Action required", count: 7 }),
      Object.freeze({ id: "exceptions", label: "Exceptions", count: 3 }),
      Object.freeze({ id: "receipt_pending", label: "Receipt pending", count: 2 }),
      Object.freeze({ id: "erp_reconciliation", label: "ERP reconciliation", count: 4 }),
    ]),
    queue: Object.freeze(queue),
    selected_case: selectedCase,
    operator_surface,
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
  };
  if (platform_gates !== undefined) workbench.platform_gates = platform_gates;
  return Object.freeze(workbench);
}
