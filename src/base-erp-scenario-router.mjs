import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { digest, validateReceiptEvidence } from "./base-neutral-receipt-controls.mjs";

export const PRIMARY_BASE_ACCOUNT = "0xba36d092db2999bb1fabbaf281ac956a97189c25";

export const NETWORKS = Object.freeze({
  base_mainnet: { chainId: 8453, production: true, b20: false },
  base_sepolia: { chainId: 84532, production: false, b20: false },
  base_vibenet: { chainId: 84538453, production: false, b20: true },
});

const SOURCES = new Set(["wallet", "x402", "b20", "contract", "swap", "agent"]);
const DIRECTIONS = new Set(["inbound", "outbound", "refund"]);
const SOURCE_NETWORKS = Object.freeze({
  wallet: Object.freeze(["base_mainnet", "base_sepolia"]),
  x402: Object.freeze(["base_mainnet", "base_sepolia"]),
  b20: Object.freeze(["base_vibenet"]),
  contract: Object.freeze(["base_mainnet", "base_sepolia"]),
  swap: Object.freeze(["base_mainnet"]),
  agent: Object.freeze(["base_mainnet", "base_sepolia"]),
});

const BASE_FINALITY_STAGES = Object.freeze({
  flashblock_preconfirmation: Object.freeze({ order: 1, label: "Flashblock preconfirmation", final: false }),
  l2_block_inclusion: Object.freeze({ order: 2, label: "L2 block inclusion", final: false }),
  l1_batch_inclusion: Object.freeze({ order: 3, label: "L1 batch inclusion", final: false }),
  l1_batch_finality: Object.freeze({ order: 4, label: "L1 batch finality", final: true }),
});

const WALLET_CALL_STATUS = Object.freeze({
  100: Object.freeze({ category: "pending", consequence: false }),
  200: Object.freeze({ category: "confirmed", consequence: true }),
  400: Object.freeze({ category: "offchain_failure", consequence: false }),
  500: Object.freeze({ category: "chain_failure", consequence: false }),
  600: Object.freeze({ category: "partial_failure", consequence: false }),
});

const BASE_CHAIN_IDS = new Set(Object.values(NETWORKS).map(({ chainId }) => chainId));
const BUILD_RUNTIME_SOURCE = "projects/2026-06_Base_Guild_Onchain_Score/runtime/current_run.json";
const BUILD_RUNTIME_AUTHORITY_SOURCE = "projects/2026-08_Base_ERP_Settlement_Workbench/runtime/runtime_authority.json";
const RUNTIME_BINDING_SCHEMA_VERSION = "base-erp-runtime-binding-v1";
const RUNTIME_AUTHORITY_SCHEMA_VERSION = "base-erp-runtime-authority-v1";
const PROJECT_ROOT_PATH = fileURLToPath(new URL("../", import.meta.url));
const RELEASE_PLATFORMS = Object.freeze([
  "github",
  "render",
  "base_app",
  "base_dashboard",
  "base_dev",
  "talent",
  "guild",
  "basename_base_org",
]);
export const PUBLIC_SURFACE_RULES = Object.freeze({
  github: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/github\.com\/[^/]+\/[^/]+\/(?:releases\/[A-Za-z0-9._-]+|commit\/[0-9a-f]{40}|blob\/[0-9a-f]{40}\/.+)$/i]),
    forbidden_fragments: Object.freeze(["/releases/latest", "/blob/main/", "/blob/master/", "/login", "localhost", "127.0.0.1", "api_key=", "token="]),
    required_public_fields: Object.freeze(["owner", "repo", "release_tag_or_commit_sha", "commit_sha", "release_url_or_permalink", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest", "release_notes_or_manifest_url", "render_commit_sha"]),
  }),
  render: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/[a-z0-9][a-z0-9.-]*\.onrender\.com(?:\/[^\s]*)?$/i, /^https:\/\/(?!dashboard\.render\.com)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/[^\s]*)?$/i]),
    forbidden_fragments: Object.freeze(["dashboard.render.com", "deploy-hook", "preview", "noindex", "localhost", "127.0.0.1", "/login", "api_key="]),
    required_public_fields: Object.freeze(["service_url", "service_id", "deployment_id", "commit_sha", "git_repo_slug", "http_status", "public_manifest_path", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
  base_app: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/base\.app\/profile\/0x[0-9a-f]{40}$/i, /^https:\/\/base\.app\/coin\/base-mainnet\/0x[0-9a-f]{40}$/i, /^https:\/\/[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/[^\s]*)$/i]),
    forbidden_fragments: Object.freeze(["farcaster", "/login", "api_key=", "localhost", "127.0.0.1"]),
    required_public_fields: Object.freeze(["profile_url", "primary_url", "wallet_address", "basename_display", "app_name", "app_metadata_ref", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
  base_dashboard: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/dashboard\.base\.org\/(?!login(?:\/|$)|settings(?:\/|$)|admin(?:\/|$)|api(?:\/|$))[a-z0-9][a-z0-9/_-]*$/i, /^https:\/\/[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/[^\s]*)$/i]),
    forbidden_fragments: Object.freeze(["/login", "/settings", "/admin", "/api/", "api_key=", "localhost", "127.0.0.1"]),
    required_public_fields: Object.freeze(["dashboard_project_id_or_public_slug", "registered_app_url", "ownership_verification_status", "name", "icon", "tagline", "description", "screenshots", "category", "primary_url", "builder_code", "dashboard_public_url", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
  base_dev: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/(?:www\.)?base\.dev\/[a-z0-9][a-z0-9/_-]*$/i]),
    forbidden_fragments: Object.freeze(["/login", "/settings", "/api/", "api_key=", "localhost", "127.0.0.1"]),
    required_public_fields: Object.freeze(["base_dev_public_url", "project_name", "primary_url", "name", "icon", "tagline", "description", "screenshots", "category", "builder_code", "builder_code_source", "onchain_attribution_readback", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
  talent: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/talentprotocol\.com\/[a-z0-9][a-z0-9-]*$/i]),
    forbidden_fragments: Object.freeze(["api.talentprotocol.com", "api_key=", "/login", "localhost", "127.0.0.1"]),
    required_public_fields: Object.freeze(["profile_id", "profile_url", "name", "display_name", "connected_accounts", "human_checkmark", "onchain", "tags", "created_at", "primary_base_account_or_wallet_link", "github_link", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
  guild: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/guild\.xyz\/[a-z0-9][a-z0-9/_-]*$/i]),
    forbidden_fragments: Object.freeze(["/admin", "/editor", "/login", "localhost", "127.0.0.1"]),
    required_public_fields: Object.freeze(["guild_slug", "guild_url", "project_name", "project_description", "linked_official_urls", "verification_badge_or_public_announcement_if_claimed", "roles", "requirements", "rewards", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
  basename_base_org: Object.freeze({
    canonical_urls: Object.freeze([/^https:\/\/(?:www\.)?base\.org\/names(?:[/?#].*)?$/i]),
    forbidden_fragments: Object.freeze(["/manage-names", "api_key=", "localhost", "127.0.0.1"]),
    required_public_fields: Object.freeze(["basename", "primary_base_account", "resolved_address", "primary_name_status", "resolution_observed_at", "resolver_source", "profile_url", "release_id", "release_fingerprint", "bom_fingerprint", "material_outcome_digest"]),
  }),
});
export const BASE_EIGHT_SURFACE_CONTRACT_ID = "base-eight-surface-public-evidence-v2";
function loadBusinessClosureProductContract() {
  const productContract = JSON.parse(readFileSync(new URL("../config/base_erp_product_contract_v1.json", import.meta.url), "utf8"));
  const contract = productContract?.business_closure_contract;
  if (!contract || typeof contract !== "object" || Array.isArray(contract)) throw new TypeError("business_closure_contract is missing from the product contract");
  if (typeof contract.batch_id !== "string" || contract.batch_id.trim() === "") throw new TypeError("business_closure_contract.batch_id must be a non-empty string");
  if (!Array.isArray(contract.record_types) || !Array.isArray(contract.domains) || contract.record_types.length === 0 || contract.record_types.length !== contract.domains.length) {
    throw new TypeError("business_closure_contract record_types/domains must be parallel non-empty arrays");
  }
  const recordTypes = contract.record_types.map((recordType, index) => {
    if (typeof recordType !== "string" || recordType.trim() === "") throw new TypeError(`business_closure_contract.record_types[${index}] must be a non-empty string`);
    return recordType.trim();
  });
  if (new Set(recordTypes).size !== recordTypes.length) throw new TypeError("business_closure_contract.record_types must be unique");
  const domains = contract.domains.map((domain, index) => {
    if (!domain || typeof domain !== "object" || Array.isArray(domain)) throw new TypeError(`business_closure_contract.domains[${index}] must be an object`);
    const recordType = typeof domain.record_type === "string" ? domain.record_type.trim() : "";
    if (recordType !== recordTypes[index]) throw new TypeError(`business_closure_contract.domains[${index}] record_type order mismatch`);
    const requiredInputs = domain.required_inputs;
    const authoritativeReadback = domain.authoritative_readback;
    if (!Array.isArray(requiredInputs) || requiredInputs.length === 0 || !Array.isArray(authoritativeReadback) || authoritativeReadback.length === 0) {
      throw new TypeError(`business_closure_contract.${recordType} inputs/readback must be non-empty arrays`);
    }
    const normalizeList = (values, field) => values.map((value, valueIndex) => {
      if (typeof value !== "string" || value.trim() === "") throw new TypeError(`business_closure_contract.${recordType}.${field}[${valueIndex}] must be a non-empty string`);
      return value.trim();
    });
    const gapIfMissing = typeof domain.gap_if_missing === "string" ? domain.gap_if_missing.trim() : "";
    const stopCondition = typeof domain.stop_condition === "string" ? domain.stop_condition.trim() : "";
    if (!gapIfMissing || !stopCondition) throw new TypeError(`business_closure_contract.${recordType} gap/stop semantics are required`);
    return Object.freeze({
      required_inputs: Object.freeze(normalizeList(requiredInputs, "required_inputs")),
      authoritative_readback: Object.freeze(normalizeList(authoritativeReadback, "authoritative_readback")),
      gap_if_missing: gapIfMissing,
      stop_condition: stopCondition,
    });
  });
  const contracts = Object.fromEntries(recordTypes.map((recordType, index) => [recordType, domains[index]]));
  return Object.freeze({
    batch_id: contract.batch_id.trim(),
    record_types: Object.freeze(recordTypes),
    domains: Object.freeze(domains),
    contracts: Object.freeze(contracts),
  });
}

const BUSINESS_CLOSURE_PRODUCT_CONTRACT = loadBusinessClosureProductContract();
export const BUSINESS_CLOSURE_BATCH_ID = BUSINESS_CLOSURE_PRODUCT_CONTRACT.batch_id;
export const BUSINESS_CLOSURE_RECORD_TYPES = BUSINESS_CLOSURE_PRODUCT_CONTRACT.record_types;
export const BUSINESS_CLOSURE_CONTRACTS = BUSINESS_CLOSURE_PRODUCT_CONTRACT.contracts;
const RELEASE_DIGEST_PATTERN = /^[0-9a-f]{64}$/i;
const RELEASE_TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/i;
const RELEASE_FINGERPRINT_BASIS_ALGORITHMS = Object.freeze({
  6: "sha256(sorted_six_hash_array_json)",
  7: "sha256(sorted_seven_hash_array_json)",
});

const BASE_WALLET_CAPABILITY_SOURCE = "https://docs.base.org/base-account/reference/core/provider-rpc-methods/wallet_getCapabilities";
const BASE_WALLET_ATOMIC_SOURCE = "https://docs.base.org/base-account/reference/core/capabilities/atomic";
const BASE_WALLET_SEND_CALLS_SOURCE = "https://docs.base.org/base-account/reference/core/provider-rpc-methods/wallet_sendCalls";
const BASE_WALLET_BATCH_SOURCE = "https://docs.base.org/base-account/improve-ux/batch-transactions";
const BASE_WALLET_CALLS_STATUS_SOURCE = "https://docs.base.org/base-account/reference/core/provider-rpc-methods/wallet_getCallsStatus";
export const BASE_WALLET_SOURCE_HASHES = Object.freeze({
  wallet_getCapabilities: "eadd504e268b5ec34579c82519cc704f468ecde70c4d4388775cd2a661bda4c7",
  atomic: "2fe3b8a70bacdd3418cfce9abf3d34e53e38d9cb128945e3ba9169903060c737",
  wallet_sendCalls: "d16a1ca5effa5a739de3cd8cbad3570839f4406b2a23b79f76f62e826bcd1e28",
  batch_transactions: "c0c31cef4a2b734de6b2ebb8d5633fd2787866a3ecaa2a58c4a35a0c4ca8c1f3",
  wallet_getCallsStatus: "edd74b664ae43e89509703db0155df3019695c16bb9581d494127619c62e0331",
});
export const BASE_WALLET_PROVIDER_CONTRACT = Object.freeze({
  send_calls_version: "2.0.0",
  send_calls_source_ref: BASE_WALLET_SEND_CALLS_SOURCE,
  send_calls_source_sha256: BASE_WALLET_SOURCE_HASHES.wallet_sendCalls,
  capability_field: "atomic",
  capability_source_ref: BASE_WALLET_CAPABILITY_SOURCE,
  capability_source_sha256: BASE_WALLET_SOURCE_HASHES.wallet_getCapabilities,
  atomic_source_ref: BASE_WALLET_ATOMIC_SOURCE,
  atomic_source_sha256: BASE_WALLET_SOURCE_HASHES.atomic,
  batch_field_observed: "atomicBatch",
  batch_source_ref: BASE_WALLET_BATCH_SOURCE,
  batch_source_sha256: BASE_WALLET_SOURCE_HASHES.batch_transactions,
});
const BASE_WALLET_CAPABILITY_STATUSES = new Set(["supported", "ready", "unsupported", "absent"]);

function failClosed(reason, details = {}) {
  return Object.freeze({ ok: false, fail_closed: true, reason, ...details });
}

function releaseFailure(reason, details = {}) {
  return failClosed(reason, {
    release_identity_valid: false,
    chain_valid: false,
    erp_complete: false,
    platform_complete: false,
    publication_complete: false,
    ...details,
  });
}

function readReleaseBomFileDigest(path) {
  try {
    const filePath = resolve(PROJECT_ROOT_PATH, path);
    return createHash("sha256").update(readFileSync(filePath)).digest("hex");
  } catch {
    return null;
  }
}

function normalizeChainId(value) {
  if (Number.isInteger(value) && value > 0) return value;
  if (typeof value === "string" && /^0x[0-9a-f]+$/i.test(value)) return Number.parseInt(value.slice(2), 16);
  return null;
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function normalizeAddress(value, name) {
  const address = requiredString(value, name).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) throw new TypeError(`${name} must be an EVM address`);
  return address;
}

function normalizedRuntimeAuthorityRecord(record, runtimeSha256) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  const allowedFields = new Set(["schema_version", "source", "runtime_sha256", "writer_idle", "observed_at", "event_id", "record_sha256"]);
  if (Object.keys(record).some((field) => !allowedFields.has(field))) return null;
  if (record.schema_version !== RUNTIME_AUTHORITY_SCHEMA_VERSION || record.source !== BUILD_RUNTIME_SOURCE) return null;
  if (!RELEASE_DIGEST_PATTERN.test(typeof record.runtime_sha256 === "string" ? record.runtime_sha256 : "") || record.runtime_sha256.toLowerCase() !== runtimeSha256.toLowerCase()) return null;
  if (typeof record.writer_idle !== "boolean") return null;
  if (typeof record.observed_at !== "string" || Number.isNaN(Date.parse(record.observed_at))) return null;
  if (typeof record.event_id !== "string" || record.event_id.trim() === "") return null;
  if (!RELEASE_DIGEST_PATTERN.test(typeof record.record_sha256 === "string" ? record.record_sha256 : "")) return null;
  const unsignedRecord = {
    schema_version: record.schema_version,
    source: record.source,
    runtime_sha256: record.runtime_sha256.toLowerCase(),
    writer_idle: record.writer_idle,
    observed_at: record.observed_at,
    event_id: record.event_id,
  };
  if (digest(unsignedRecord) !== record.record_sha256.toLowerCase()) return null;
  return Object.freeze({ ...unsignedRecord, record_sha256: record.record_sha256.toLowerCase() });
}

function readRuntimeAuthorityRecord(runtimeSha256) {
  try {
    const record = JSON.parse(readFileSync(new URL("../runtime/runtime_authority.json", import.meta.url), "utf8"));
    return normalizedRuntimeAuthorityRecord(record, runtimeSha256);
  } catch {
    return null;
  }
}

function validateReleaseRuntimeBinding(runtimeBinding) {
  try {
    if (!runtimeBinding || typeof runtimeBinding !== "object" || Array.isArray(runtimeBinding)) return failClosed("release_runtime_binding_missing");
    if (runtimeBinding.schema_version !== RUNTIME_BINDING_SCHEMA_VERSION || runtimeBinding.source !== BUILD_RUNTIME_SOURCE || runtimeBinding.mutable_source !== true || runtimeBinding.snapshot_only !== true || runtimeBinding.runtime_authority_revalidated !== true || typeof runtimeBinding.invalidation !== "string" || runtimeBinding.invalidation.trim() === "") {
      return failClosed("release_runtime_binding_invalid");
    }
    const snapshot = runtimeBinding.snapshot;
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot) || !RELEASE_DIGEST_PATTERN.test(typeof snapshot.runtime_sha256 === "string" ? snapshot.runtime_sha256 : "") || typeof snapshot.run_id !== "string" || typeof snapshot.date_cst !== "string" || typeof snapshot.status !== "string" || typeof snapshot.cursor !== "string" || snapshot.cursor.trim() === "" || typeof snapshot.observed_at !== "string" || Number.isNaN(Date.parse(snapshot.observed_at))) {
      return failClosed("release_runtime_binding_invalid");
    }
    const authorityEnvelope = runtimeBinding.authority_record;
    if (!authorityEnvelope || typeof authorityEnvelope !== "object" || Array.isArray(authorityEnvelope) || authorityEnvelope.path !== "runtime/runtime_authority.json") return failClosed("release_runtime_binding_invalid");
    const { path: ignoredAuthorityPath, ...authorityRecord } = authorityEnvelope;
    const live = readCurrentBaseRuntimeBinding();
    if (!live.writer_idle_authority || live.writer_idle !== true) return failClosed("release_runtime_writer_idle_unbound");
    const normalizedAuthority = normalizedRuntimeAuthorityRecord(authorityRecord, live.runtime_sha256);
    if (!normalizedAuthority || normalizedAuthority.writer_idle !== true) return failClosed("release_runtime_writer_idle_unbound");
    if (snapshot.runtime_sha256.toLowerCase() !== live.runtime_sha256 || snapshot.run_id !== live.run_id || snapshot.date_cst !== live.date_cst || snapshot.status !== live.status || snapshot.cursor !== live.cursor || snapshot.observed_at !== normalizedAuthority.observed_at || digest(normalizedAuthority) !== digest(live.writer_idle_authority)) {
      return failClosed("release_runtime_binding_stale", { live_runtime_sha256: live.runtime_sha256, snapshot_runtime_sha256: snapshot.runtime_sha256 });
    }
    return Object.freeze({ ok: true, fail_closed: false, runtime_sha256: live.runtime_sha256, cursor: live.cursor });
  } catch (error) {
    return failClosed("release_runtime_binding_invalid", { message: error.message });
  }
}

/**
 * Read the canonical current 02_Build runtime binding used by every
 * Base-native preflight.  The runtime file is mutable by the daily runner,
 * so callers must bind the complete file digest and cursor at validation
 * time instead of carrying a historical snapshot forward.
 */
export function readCurrentBaseRuntimeBinding() {
  const runtimeText = readFileSync(new URL("../../2026-06_Base_Guild_Onchain_Score/runtime/current_run.json", import.meta.url), "utf8");
  const runtime = JSON.parse(runtimeText);
  const topLevelCursor = typeof runtime.cursor === "string" && runtime.cursor.trim() !== "" ? runtime.cursor : null;
  const resumeCursor = typeof runtime.resume?.cursor === "string" && runtime.resume.cursor.trim() !== "" ? runtime.resume.cursor : null;
  const cursor = topLevelCursor ?? resumeCursor;
  if (!runtime || typeof runtime !== "object" || Array.isArray(runtime) || typeof cursor !== "string" || cursor.trim() === "") {
    throw new TypeError("current Base runtime binding is malformed");
  }
  const runtimeSha256 = createHash("sha256").update(runtimeText).digest("hex");
  const writerIdleAuthority = readRuntimeAuthorityRecord(runtimeSha256);
  return Object.freeze({
    binding_version: RUNTIME_BINDING_SCHEMA_VERSION,
    source: BUILD_RUNTIME_SOURCE,
    runtime_sha256: runtimeSha256,
    run_id: runtime.run_id,
    date_cst: runtime.date_cst,
    cursor,
    session: "02_Build",
    status: runtime.status,
    current: true,
    writer_idle: writerIdleAuthority?.writer_idle ?? null,
    writer_idle_authority: writerIdleAuthority,
    terminal_statuses: ["complete"],
  });
}

function routeScenario(source, direction) {
  if (source === "wallet") return `smart_wallet_${direction}`;
  if (source === "x402") return "x402_service_settlement";
  if (source === "b20") return "b20_inventory_lifecycle";
  if (source === "contract") return "programmable_contract_settlement";
  if (source === "swap") return "treasury_swap_reconciliation";
  return "agentic_workflow_evidence";
}

/** Keep Base's four finality stages distinct; only L1 batch finality may settle ERP. */
export function mapBaseFinality({ stage, receiptStatus, reorged = false, stateChange = true, l1Finalized = false, claimedFinality } = {}) {
  const spec = BASE_FINALITY_STAGES[stage];
  if (!spec) return failClosed("base_finality_stage_unknown", { stage });
  const mapped = {
    stage,
    stage_label: spec.label,
    stage_order: spec.order,
    receipt_status: receiptStatus,
    finality: spec.final ? "final" : "not_final",
    consequence_allowed: false,
  };
  if (receiptStatus !== "0x1") return failClosed("receipt_status_not_success", mapped);
  if (reorged === true) return failClosed("base_finality_reorged", mapped);
  if (claimedFinality !== undefined && claimedFinality !== mapped.finality) return failClosed("finality_stage_mismatch", mapped);
  if (spec.final && l1Finalized !== true) return failClosed("l1_batch_finality_unproven", mapped);
  if (!spec.final && l1Finalized === true) return failClosed("l1_finality_stage_mismatch", mapped);
  if (!spec.final) return failClosed("base_finality_not_final", mapped);
  if (stateChange !== true) return failClosed("final_receipt_not_state_changing", mapped);
  return Object.freeze({ ok: true, fail_closed: false, ...mapped, consequence_allowed: true });
}

/** Map wallet_getCallsStatus without treating pending, partial or failed batches as settled. */
export function mapWalletCallsStatus(input = {}) {
  try {
    if (!input || typeof input !== "object") return failClosed("wallet_calls_status_missing");
    const statusCode = input.status;
    const spec = WALLET_CALL_STATUS[statusCode];
    if (!spec) return failClosed("wallet_calls_status_unknown", { status_code: statusCode });
    const chainId = normalizeChainId(input.chainId);
    if (!BASE_CHAIN_IDS.has(chainId)) return failClosed("wallet_calls_chain_unknown", { status_code: statusCode, chain_id: input.chainId });
    if (typeof input.atomic !== "boolean") return failClosed("wallet_calls_atomic_missing", { status_code: statusCode, chain_id: chainId });
    if (typeof input.version !== "string" || input.version.trim() === "") return failClosed("wallet_calls_version_missing", { status_code: statusCode, chain_id: chainId });
    if (typeof input.id !== "string" || input.id.trim() === "") return failClosed("wallet_calls_id_missing", { status_code: statusCode, chain_id: chainId });
    const receipts = input.receipts;
    const receiptCount = Array.isArray(receipts) ? receipts.length : 0;
    const base = { status_code: statusCode, status_category: spec.category, chain_id: chainId, atomic: input.atomic, receipt_count: receiptCount, consequence_allowed: spec.consequence };

    if (statusCode === 100) {
      if (input.receipts !== undefined && (!Array.isArray(receipts) || receiptCount !== 0)) return failClosed("pending_batch_has_receipts", base);
      return failClosed("wallet_calls_pending", base);
    }
    if (statusCode === 400 || statusCode === 500 || statusCode === 600) {
      if (statusCode !== 600 && receiptCount > 0) return failClosed("failed_batch_has_receipts", base);
      return failClosed(`wallet_calls_${spec.category}`, { ...base, partial_onchain: statusCode === 600 && receiptCount > 0 });
    }
    if (!Array.isArray(receipts) || receiptCount === 0) return failClosed("confirmed_batch_receipts_missing", base);
    if (input.atomic === true && receiptCount !== 1) return failClosed("atomic_receipt_cardinality_mismatch", base);
    for (const receipt of receipts) {
      if (!receipt || receipt.status !== "0x1" || typeof receipt.transactionHash !== "string" || !/^0x[0-9a-f]{64}$/i.test(receipt.transactionHash)) {
        return failClosed("confirmed_batch_receipt_not_success", base);
      }
    }
    return Object.freeze({ ok: true, fail_closed: false, ...base, status_category: "confirmed", receipts: receipts.map((receipt) => ({ transaction_hash: receipt.transactionHash.toLowerCase(), status: "0x1" })) });
  } catch (error) {
    return failClosed("invalid_wallet_calls_status", { message: error.message });
  }
}

function atomicPreflightFailure(reason, details = {}) {
  return failClosed(reason, {
    ...details,
    execution_authority: "none_until_02_Build_revalidates",
    executable: false,
    payload: null,
  });
}

function isUri(value) {
  return typeof value === "string" && /^[a-z][a-z0-9+.-]*:\/\/[^\s]+$/i.test(value.trim());
}

function normalizeCapabilityAccountScope(accountScope) {
  if (!accountScope || typeof accountScope !== "object" || Array.isArray(accountScope)) {
    return atomicPreflightFailure("base_preflight_capability_account_scope_invalid");
  }
  const allowedFields = new Set(["address", "chain_id", "owner_revalidated", "provider_revalidated"]);
  const unknownFields = Object.keys(accountScope).filter((field) => !allowedFields.has(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_capability_account_scope_unknown_field", { fields: unknownFields.sort() });
  let address;
  try {
    address = normalizeAddress(accountScope.address, "capability.account_scope.address");
  } catch (error) {
    return atomicPreflightFailure("base_preflight_capability_account_scope_invalid", { message: error.message });
  }
  if (accountScope.owner_revalidated !== true || accountScope.provider_revalidated !== true) {
    return atomicPreflightFailure("base_preflight_capability_account_scope_unbound");
  }
  const normalized = {
    address,
    owner_revalidated: true,
    provider_revalidated: true,
  };
  if (accountScope.chain_id !== undefined) {
    const chainId = normalizeChainId(accountScope.chain_id);
    if (!BASE_CHAIN_IDS.has(chainId)) return atomicPreflightFailure("base_preflight_capability_chain_mismatch", { chain_id: accountScope.chain_id });
    normalized.chain_id = chainId;
  }
  return normalized;
}

/**
 * Validate the exact, non-executable wallet_getCapabilities observation record.
 * A capability result is account/chain scoped and never grants owner approval.
 */
export function validateBaseCapabilityPreflight(record = {}, { expectedAccount, expectedChainId } = {}) {
  try {
    if (!record || typeof record !== "object" || Array.isArray(record)) return atomicPreflightFailure("base_preflight_capability_record_missing");
    const allowedFields = new Set(["method", "account_scope", "chain_id", "atomic_status", "source_ref", "observed_at", "response_sha256"]);
    const unknownFields = Object.keys(record).filter((field) => !allowedFields.has(field));
    if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_capability_record_unknown_field", { fields: unknownFields.sort() });
    if (record.method !== "wallet_getCapabilities") return atomicPreflightFailure("base_preflight_capability_method_unbound", { method: record.method ?? null });
    const accountScope = normalizeCapabilityAccountScope(record.account_scope);
    if (!accountScope || accountScope.ok === false) return accountScope;
    const chainId = normalizeChainId(record.chain_id);
    if (!BASE_CHAIN_IDS.has(chainId)) return atomicPreflightFailure("base_preflight_capability_chain_mismatch", { chain_id: record.chain_id });
    if (accountScope.chain_id !== undefined && accountScope.chain_id !== chainId) return atomicPreflightFailure("base_preflight_capability_chain_mismatch", { chain_id: record.chain_id, account_scope_chain_id: accountScope.chain_id });
    if (expectedAccount !== undefined) {
      let normalizedExpectedAccount;
      try {
        normalizedExpectedAccount = normalizeAddress(expectedAccount, "expectedAccount");
      } catch (error) {
        return atomicPreflightFailure("base_preflight_capability_account_scope_invalid", { message: error.message });
      }
      if (accountScope.address !== normalizedExpectedAccount) return atomicPreflightFailure("base_preflight_capability_account_mismatch", { account: accountScope.address });
    }
    if (expectedChainId !== undefined && normalizeChainId(expectedChainId) !== chainId) return atomicPreflightFailure("base_preflight_capability_chain_mismatch", { chain_id: record.chain_id });
    if (typeof record.atomic_status !== "string" || !BASE_WALLET_CAPABILITY_STATUSES.has(record.atomic_status)) {
      return atomicPreflightFailure("base_preflight_atomic_capability_unbound", { atomic_status: record.atomic_status ?? null });
    }
    if (!isUri(record.source_ref)) return atomicPreflightFailure("base_preflight_capability_source_unbound");
    if (typeof record.observed_at !== "string" || Number.isNaN(Date.parse(record.observed_at))) return atomicPreflightFailure("base_preflight_capability_observation_invalid");
    if (!RELEASE_DIGEST_PATTERN.test(typeof record.response_sha256 === "string" ? record.response_sha256 : "")) return atomicPreflightFailure("base_preflight_capability_response_hash_invalid");
    const capability = Object.freeze({
      method: "wallet_getCapabilities",
      account_scope: Object.freeze(accountScope),
      chain_id: chainId,
      atomic_status: record.atomic_status,
      source_ref: record.source_ref.trim(),
      observed_at: record.observed_at,
      response_sha256: record.response_sha256.toLowerCase(),
    });
    if (record.atomic_status === "unsupported" || record.atomic_status === "absent") {
      return atomicPreflightFailure("base_preflight_atomic_capability_unbound", { capability, atomic_status: record.atomic_status });
    }
    if (record.atomic_status === "ready") {
      return atomicPreflightFailure("base_preflight_atomic_owner_approval_required", {
        capability,
        atomic_status: record.atomic_status,
        owner_action_required: true,
      });
    }
    return Object.freeze({
      ok: true,
      fail_closed: false,
      capability,
      atomic_status: "supported",
      atomic_required_admissible: true,
      owner_action_required: false,
      executable: false,
      payload: null,
    });
  } catch (error) {
    return atomicPreflightFailure("invalid_base_capability_preflight", { message: error.message });
  }
}

function validateBaseWalletProviderContract(contract) {
  if (!contract || typeof contract !== "object" || Array.isArray(contract)) return atomicPreflightFailure("base_preflight_provider_contract_missing");
  const expectedFields = Object.keys(BASE_WALLET_PROVIDER_CONTRACT);
  const unknownFields = Object.keys(contract).filter((field) => !expectedFields.includes(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_provider_contract_unknown_field", { fields: unknownFields.sort() });
  for (const field of expectedFields) {
    if (typeof contract[field] !== "string" || contract[field].trim() === "") return atomicPreflightFailure("base_preflight_provider_contract_unbound", { field });
  }
  if (contract.send_calls_version !== BASE_WALLET_PROVIDER_CONTRACT.send_calls_version || contract.send_calls_source_ref !== BASE_WALLET_PROVIDER_CONTRACT.send_calls_source_ref || contract.send_calls_source_sha256.toLowerCase() !== BASE_WALLET_PROVIDER_CONTRACT.send_calls_source_sha256) {
    return atomicPreflightFailure("base_preflight_sendcalls_version_unbound", { selected_version: contract.send_calls_version });
  }
  if (contract.capability_field !== "atomic" || contract.capability_source_ref !== BASE_WALLET_PROVIDER_CONTRACT.capability_source_ref || contract.capability_source_sha256.toLowerCase() !== BASE_WALLET_PROVIDER_CONTRACT.capability_source_sha256 || contract.atomic_source_ref !== BASE_WALLET_PROVIDER_CONTRACT.atomic_source_ref || contract.atomic_source_sha256.toLowerCase() !== BASE_WALLET_PROVIDER_CONTRACT.atomic_source_sha256 || contract.batch_field_observed !== "atomicBatch" || contract.batch_source_ref !== BASE_WALLET_PROVIDER_CONTRACT.batch_source_ref || contract.batch_source_sha256.toLowerCase() !== BASE_WALLET_PROVIDER_CONTRACT.batch_source_sha256) {
    return atomicPreflightFailure("base_preflight_atomic_capability_unbound", { capability_field: contract.capability_field, batch_field_observed: contract.batch_field_observed });
  }
  return Object.freeze({ ok: true, fail_closed: false, provider_contract: Object.freeze({ ...BASE_WALLET_PROVIDER_CONTRACT }) });
}

function validateAtomicSendCallsRequest(request, capability, providerContract) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return atomicPreflightFailure("base_preflight_sendcalls_request_missing");
  const allowedFields = new Set(["version", "id", "from", "chainId", "atomicRequired", "calls", "capabilities"]);
  const unknownFields = Object.keys(request).filter((field) => !allowedFields.has(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_sendcalls_request_unknown_field", { fields: unknownFields.sort() });
  if (request.version !== providerContract.send_calls_version) return atomicPreflightFailure("base_preflight_sendcalls_version_unbound", { version: request.version ?? null });
  let from;
  try {
    from = normalizeAddress(request.from, "send_calls.from");
  } catch (error) {
    return atomicPreflightFailure("base_preflight_sendcalls_request_invalid", { message: error.message });
  }
  if (from !== capability.account_scope.address) return atomicPreflightFailure("base_preflight_sendcalls_account_mismatch", { from });
  const chainId = normalizeChainId(request.chainId);
  if (chainId !== capability.chain_id) return atomicPreflightFailure("base_preflight_sendcalls_chain_mismatch", { chain_id: request.chainId, capability_chain_id: capability.chain_id });
  if (request.atomicRequired !== true) return atomicPreflightFailure("base_preflight_atomic_required_not_true");
  if (!Array.isArray(request.calls) || request.calls.length === 0) return atomicPreflightFailure("base_preflight_sendcalls_calls_invalid");
  const calls = request.calls.map((call, index) => {
    if (!call || typeof call !== "object" || Array.isArray(call)) throw new TypeError(`send_calls.calls[${index}] must be an object`);
    const callFields = new Set(["to", "value", "data", "capabilities"]);
    const callUnknownFields = Object.keys(call).filter((field) => !callFields.has(field));
    if (callUnknownFields.length > 0) throw new TypeError(`send_calls.calls[${index}] has unknown fields`);
    const to = normalizeAddress(call.to, `send_calls.calls[${index}].to`);
    if (call.value !== undefined && (typeof call.value !== "string" || !/^0x[0-9a-f]*$/i.test(call.value) || call.value.length % 2 !== 0)) throw new TypeError(`send_calls.calls[${index}].value must be even-length hex`);
    if (call.data !== undefined && (typeof call.data !== "string" || !/^0x[0-9a-f]*$/i.test(call.data) || call.data.length % 2 !== 0)) throw new TypeError(`send_calls.calls[${index}].data must be even-length hex`);
    return { to, ...(call.value !== undefined ? { value: call.value.toLowerCase() } : {}), ...(call.data !== undefined ? { data: call.data.toLowerCase() } : {}), ...(call.capabilities !== undefined ? { capabilities: call.capabilities } : {}) };
  });
  return Object.freeze({ ok: true, fail_closed: false, send_calls: Object.freeze({ version: providerContract.send_calls_version, ...(request.id !== undefined ? { id: requiredString(request.id, "send_calls.id") } : {}), from, chainId, atomicRequired: true, calls, ...(request.capabilities !== undefined ? { capabilities: request.capabilities } : {}) }) });
}

function validateAtomicRuntimeBinding(runtime) {
  if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) return atomicPreflightFailure("base_preflight_runtime_binding_invalid");
  const allowedFields = new Set(["binding_version", "source", "runtime_sha256", "run_id", "date_cst", "cursor", "session", "status", "current", "writer_idle", "writer_idle_authority", "terminal_statuses"]);
  const unknownFields = Object.keys(runtime).filter((field) => !allowedFields.has(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_runtime_binding_invalid", { fields: unknownFields.sort() });
  let live;
  try {
    live = readCurrentBaseRuntimeBinding();
  } catch (error) {
    return atomicPreflightFailure("base_preflight_runtime_binding_invalid", { message: error.message });
  }
  if (!live.writer_idle_authority || live.writer_idle !== true) return atomicPreflightFailure("base_preflight_writer_idle_unbound");
  if (runtime.binding_version !== RUNTIME_BINDING_SCHEMA_VERSION || runtime.source !== BUILD_RUNTIME_SOURCE || !RELEASE_DIGEST_PATTERN.test(typeof runtime.runtime_sha256 === "string" ? runtime.runtime_sha256 : "") || runtime.run_id !== live.run_id || runtime.date_cst !== live.date_cst || runtime.cursor !== live.cursor || runtime.session !== "02_Build" || runtime.status !== "running" || runtime.current !== true || runtime.writer_idle !== true || !Array.isArray(runtime.terminal_statuses) || runtime.terminal_statuses.length !== 1 || runtime.terminal_statuses[0] !== "complete") {
    return atomicPreflightFailure("base_preflight_runtime_authority_mismatch");
  }
  if (runtime.runtime_sha256.toLowerCase() !== live.runtime_sha256 || !normalizedRuntimeAuthorityRecord(runtime.writer_idle_authority, runtime.runtime_sha256) || digest(runtime.writer_idle_authority) !== digest(live.writer_idle_authority)) {
    return atomicPreflightFailure("base_preflight_writer_idle_unbound");
  }
  return Object.freeze({ ok: true, fail_closed: false, runtime: Object.freeze({ binding_version: RUNTIME_BINDING_SCHEMA_VERSION, source: BUILD_RUNTIME_SOURCE, runtime_sha256: runtime.runtime_sha256.toLowerCase(), run_id: runtime.run_id, date_cst: runtime.date_cst, cursor: runtime.cursor, session: "02_Build", status: "running", current: true, writer_idle: true, writer_idle_authority: normalizedRuntimeAuthorityRecord(runtime.writer_idle_authority, runtime.runtime_sha256), terminal_statuses: ["complete"] }) });
}

function validateAtomicOwnerGate(ownerGate) {
  if (!ownerGate || typeof ownerGate !== "object" || Array.isArray(ownerGate)) return atomicPreflightFailure("base_preflight_owner_gate_missing");
  if (Object.prototype.hasOwnProperty.call(ownerGate, "owner_confirmation")) return atomicPreflightFailure("base_preflight_owner_confirmation_present");
  const allowedFields = new Set(["status", "current", "observed", "owner_confirmation_status"]);
  const unknownFields = Object.keys(ownerGate).filter((field) => !allowedFields.has(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_owner_gate_unknown_field", { fields: unknownFields.sort() });
  if (ownerGate.status !== "not_observed" || ownerGate.current !== true || ownerGate.observed !== false || ownerGate.owner_confirmation_status !== "NOT_GRANTED") return atomicPreflightFailure("base_preflight_owner_gate_not_unobserved");
  return Object.freeze({ ok: true, fail_closed: false, owner_gate: Object.freeze({ status: "not_observed", current: true, observed: false, owner_confirmation_status: "NOT_GRANTED" }) });
}

function validateAtomicReleaseBinding(release) {
  if (!release || typeof release !== "object" || Array.isArray(release)) return atomicPreflightFailure("base_preflight_current_release_missing");
  const allowedFields = new Set(["release_id", "release_fingerprint", "bom_fingerprint", "current", "historical", "synthetic"]);
  const unknownFields = Object.keys(release).filter((field) => !allowedFields.has(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_current_release_unknown_field", { fields: unknownFields.sort() });
  if (typeof release.release_id !== "string" || release.release_id.trim() === "" || !RELEASE_DIGEST_PATTERN.test(typeof release.release_fingerprint === "string" ? release.release_fingerprint : "") || !RELEASE_DIGEST_PATTERN.test(typeof release.bom_fingerprint === "string" ? release.bom_fingerprint : "") || release.current !== true || release.historical !== false || release.synthetic !== false) return atomicPreflightFailure("base_preflight_release_binding_invalid");
  return Object.freeze({ ok: true, fail_closed: false, release: Object.freeze({ release_id: release.release_id.trim(), release_fingerprint: release.release_fingerprint.toLowerCase(), bom_fingerprint: release.bom_fingerprint.toLowerCase(), current: true, historical: false, synthetic: false }) });
}

function validateAtomicReceiptFinality(receiptFinality) {
  if (!receiptFinality || typeof receiptFinality !== "object" || Array.isArray(receiptFinality)) return atomicPreflightFailure("base_preflight_receipt_finality_missing");
  const allowedFields = new Set(["network", "chain_id", "status", "current", "required_receipt_status", "required_finality_stage", "finality_stages", "reorg_policy"]);
  const unknownFields = Object.keys(receiptFinality).filter((field) => !allowedFields.has(field));
  if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_receipt_finality_unknown_field", { fields: unknownFields.sort() });
  if (receiptFinality.network !== "base_mainnet" || receiptFinality.chain_id !== NETWORKS.base_mainnet.chainId || receiptFinality.status !== "not_observed" || receiptFinality.current !== true || receiptFinality.required_receipt_status !== "0x1" || receiptFinality.required_finality_stage !== "l1_batch_finality" || receiptFinality.reorg_policy !== "reject" || JSON.stringify(receiptFinality.finality_stages) !== JSON.stringify(Object.keys(BASE_FINALITY_STAGES))) return atomicPreflightFailure("base_preflight_receipt_finality_contract_invalid");
  return Object.freeze({ ok: true, fail_closed: false, receipt_finality: Object.freeze({ network: "base_mainnet", chain_id: 8453, status: "not_observed", current: true, required_receipt_status: "0x1", required_finality_stage: "l1_batch_finality", finality_stages: [...Object.keys(BASE_FINALITY_STAGES)], reorg_policy: "reject" }) });
}

/**
 * Validate the capability-first, atomicRequired owner preflight.  This is a
 * shape/readback contract only: it never calls a provider or creates a wallet
 * request, and it keeps receipt/finality, ERP and eight-platform evidence
 * explicitly unobserved until their independent gates pass.
 */
export function validateBaseAtomicOwnerPreflight(input = {}) {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return atomicPreflightFailure("base_preflight_atomic_input_missing");
    if (Object.prototype.hasOwnProperty.call(input, "owner_confirmation")) return atomicPreflightFailure("base_preflight_owner_confirmation_present");
    const allowedFields = new Set(["capability", "provider_contract", "send_calls", "owner_gate", "runtime", "current_release", "receipt_finality"]);
    const unknownFields = Object.keys(input).filter((field) => !allowedFields.has(field));
    if (unknownFields.length > 0) return atomicPreflightFailure("base_preflight_atomic_unknown_field", { fields: unknownFields.sort() });
    const capability = validateBaseCapabilityPreflight(input.capability);
    if (!capability.ok) return capability;
    const provider = validateBaseWalletProviderContract(input.provider_contract);
    if (!provider.ok) return provider;
    const sendCalls = validateAtomicSendCallsRequest(input.send_calls, capability.capability, provider.provider_contract);
    if (!sendCalls.ok) return sendCalls;
    const ownerGate = validateAtomicOwnerGate(input.owner_gate);
    if (!ownerGate || ownerGate.ok === false) return ownerGate;
    const runtime = validateAtomicRuntimeBinding(input.runtime);
    if (!runtime.ok) return runtime;
    const release = validateAtomicReleaseBinding(input.current_release);
    if (!release.ok) return release;
    const receiptFinality = validateAtomicReceiptFinality(input.receipt_finality);
    if (!receiptFinality.ok) return receiptFinality;
    return Object.freeze({
      ok: true,
      fail_closed: false,
      method: "wallet_sendCalls",
      capability_method: "wallet_getCapabilities",
      capability: capability.capability,
      provider_contract: provider.provider_contract,
      send_calls: sendCalls.send_calls,
      atomic_required: true,
      owner_gate: ownerGate.owner_gate,
      runtime: runtime.runtime,
      current_release: release.release,
      receipt_finality: receiptFinality.receipt_finality,
      wallet_calls_status: "not_observed",
      receipt_state: "not_observed",
      finality_state: "not_observed",
      erp_readback: "not_observed",
      eight_platform_evidence: "not_observed",
      owner_confirmation_status: "NOT_GRANTED",
      execution_authority: "none_until_02_Build_revalidates",
      executable: false,
      payload: null,
      external_actions: 0,
    });
  } catch (error) {
    return atomicPreflightFailure("invalid_base_atomic_owner_preflight", { message: error.message });
  }
}

/** Validate an explicitly enumerated Base batch authority set without importing upstream status strings. */
export function validateBaseAuthorityConsistency({ authorityIds, authorityRecords, terminalStatuses } = {}) {
  try {
    if (!Array.isArray(authorityIds) || authorityIds.length === 0) return failClosed("base_authority_set_missing");
    if (!Array.isArray(terminalStatuses) || terminalStatuses.length === 0) return failClosed("base_terminal_status_vocabulary_missing");
    const normalizedTerminalStatuses = terminalStatuses.map((status, index) => requiredString(status, `terminalStatuses[${index}]`));
    if (new Set(normalizedTerminalStatuses).size !== normalizedTerminalStatuses.length || normalizedTerminalStatuses.includes("active")) {
      return failClosed("base_terminal_status_vocabulary_invalid");
    }
    const normalizedAuthorityIds = authorityIds.map((authorityId, index) => requiredString(authorityId, `authorityIds[${index}]`));
    if (new Set(normalizedAuthorityIds).size !== normalizedAuthorityIds.length) {
      return failClosed("base_authority_set_duplicate", { conflict_ids: [...new Set(normalizedAuthorityIds)].sort() });
    }
    if (!Array.isArray(authorityRecords)) {
      return failClosed("base_authority_records_missing", { missing_ids: normalizedAuthorityIds, conflict_ids: normalizedAuthorityIds });
    }

    const recordsById = new Map();
    const duplicateIds = new Set();
    for (const record of authorityRecords) {
      const authorityId = requiredString(record?.authority_id, "authorityRecords.authority_id");
      if (recordsById.has(authorityId)) {
        const prior = recordsById.get(authorityId);
        if (prior.status !== record.status || prior.writer_idle !== record.writer_idle) {
          return failClosed("base_authority_status_conflict", {
            authority_id: authorityId,
            conflict_ids: [authorityId],
            observed_statuses: [prior.status, record.status],
          });
        }
        duplicateIds.add(authorityId);
        continue;
      }
      recordsById.set(authorityId, record);
    }
    if (duplicateIds.size > 0) return failClosed("base_authority_id_duplicate", { conflict_ids: [...duplicateIds].sort() });

    const expectedIds = new Set(normalizedAuthorityIds);
    const observedIds = new Set(recordsById.keys());
    const missingIds = normalizedAuthorityIds.filter((authorityId) => !observedIds.has(authorityId));
    const extraIds = [...observedIds].filter((authorityId) => !expectedIds.has(authorityId)).sort();
    if (missingIds.length > 0 || extraIds.length > 0) {
      return failClosed("base_authority_id_set_mismatch", {
        missing_ids: missingIds,
        extra_ids: extraIds,
        conflict_ids: [...missingIds, ...extraIds].sort(),
      });
    }

    const normalizedRecords = [];
    for (const authorityId of normalizedAuthorityIds) {
      const record = recordsById.get(authorityId);
      const status = typeof record.status === "string" ? record.status.trim() : "";
      if (status === "") return failClosed("base_authority_status_missing", { authority_id: authorityId, conflict_ids: [authorityId] });
      if (!normalizedTerminalStatuses.includes(status)) {
        return failClosed("base_authority_status_conflict", {
          authority_id: authorityId,
          conflict_ids: [authorityId],
          observed_status: status,
          terminal_statuses: normalizedTerminalStatuses,
        });
      }
      if (record.writer_idle !== true) {
        return failClosed("base_authority_writer_idle_conflict", { authority_id: authorityId, conflict_ids: [authorityId], writer_idle: record.writer_idle });
      }
      normalizedRecords.push({ authority_id: authorityId, status, writer_idle: true });
    }

    return Object.freeze({
      ok: true,
      fail_closed: false,
      authority_ids: [...normalizedAuthorityIds],
      authority_count: normalizedAuthorityIds.length,
      terminal_statuses: [...normalizedTerminalStatuses],
      writer_idle_required: true,
      records: normalizedRecords,
    });
  } catch (error) {
    return failClosed("invalid_base_authority_consistency_input", { message: error.message });
  }
}

/** Validate a Base-native per-gate preflight without creating an owner action or executable payload. */
export function validateBaseGatePreflight(input = {}) {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return failClosed("base_preflight_input_missing");
    const hasOwn = Object.prototype.hasOwnProperty;
    if (hasOwn.call(input, "owner_confirmation")) return failClosed("base_preflight_owner_confirmation_present");
    const allowedInputFields = new Set([
      "gate_id",
      "authority",
      "current_release",
      "runtime",
      "owner_gate",
      "receipt_finality",
      "erp_readback",
      "required_inputs",
      "required_readbacks",
      "stop_conditions",
      "recovery",
      "executable",
      "payload",
      "atomic_owner_preflight",
      "readbacks",
    ]);
    const unknownInputFields = Object.keys(input).filter((field) => !allowedInputFields.has(field));
    if (unknownInputFields.length > 0) return failClosed("base_preflight_unknown_field", { fields: unknownInputFields.sort() });

    const gateId = requiredString(input.gate_id, "gate_id");
    const authority = input.authority;
    if (!authority || typeof authority !== "object" || Array.isArray(authority)) return failClosed("base_preflight_authority_missing");
    const unknownAuthorityFields = Object.keys(authority).filter((field) => !new Set(["current_release", "current_runtime"]).has(field));
    if (unknownAuthorityFields.length > 0) return failClosed("base_preflight_authority_unknown_field", { fields: unknownAuthorityFields.sort() });
    const currentRelease = input.current_release;
    if (!currentRelease || typeof currentRelease !== "object" || Array.isArray(currentRelease)) return failClosed("base_preflight_current_release_missing");
    const unknownReleaseFields = Object.keys(currentRelease).filter((field) => !new Set(["release_id", "release_fingerprint", "bom_fingerprint", "current", "historical", "synthetic"]).has(field));
    if (unknownReleaseFields.length > 0) return failClosed("base_preflight_current_release_unknown_field", { fields: unknownReleaseFields.sort() });
    const releaseId = requiredString(currentRelease.release_id, "current_release.release_id");
    const releaseFingerprint = requiredString(currentRelease.release_fingerprint, "current_release.release_fingerprint").toLowerCase();
    const bomFingerprint = requiredString(currentRelease.bom_fingerprint, "current_release.bom_fingerprint").toLowerCase();
    if (!RELEASE_DIGEST_PATTERN.test(releaseFingerprint) || !RELEASE_DIGEST_PATTERN.test(bomFingerprint)) return failClosed("base_preflight_release_binding_invalid");
    if (currentRelease.current !== true) return failClosed("base_preflight_release_stale");
    if (currentRelease.historical !== false) return failClosed("base_preflight_historical_release");
    if (currentRelease.synthetic !== false) return failClosed("base_preflight_synthetic_release");
    const trustedRelease = authority.current_release;
    if (!trustedRelease || typeof trustedRelease !== "object" || Array.isArray(trustedRelease)) return failClosed("base_preflight_authoritative_release_missing");
    const unknownTrustedReleaseFields = Object.keys(trustedRelease).filter((field) => !new Set(["release_id", "release_fingerprint", "bom_fingerprint", "current", "historical", "synthetic"]).has(field));
    if (unknownTrustedReleaseFields.length > 0) return failClosed("base_preflight_authoritative_release_unknown_field", { fields: unknownTrustedReleaseFields.sort() });
    if (trustedRelease.release_id !== releaseId || typeof trustedRelease.release_fingerprint !== "string" || trustedRelease.release_fingerprint.toLowerCase() !== releaseFingerprint || typeof trustedRelease.bom_fingerprint !== "string" || trustedRelease.bom_fingerprint.toLowerCase() !== bomFingerprint || trustedRelease.current !== true || trustedRelease.historical !== false || trustedRelease.synthetic !== false) return failClosed("base_preflight_authoritative_release_mismatch");

    const runtime = input.runtime;
    if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) return failClosed("base_preflight_runtime_missing");
    const unknownRuntimeFields = Object.keys(runtime).filter((field) => !new Set(["binding_version", "source", "runtime_sha256", "run_id", "date_cst", "cursor", "session", "status", "current", "writer_idle", "writer_idle_authority", "terminal_statuses"]).has(field));
    if (unknownRuntimeFields.length > 0) return failClosed("base_preflight_runtime_unknown_field", { fields: unknownRuntimeFields.sort() });
    if (runtime.binding_version !== RUNTIME_BINDING_SCHEMA_VERSION || runtime.source !== BUILD_RUNTIME_SOURCE || !RELEASE_DIGEST_PATTERN.test(typeof runtime.runtime_sha256 === "string" ? runtime.runtime_sha256 : "") || !/^02_Build-\d{8}-\d{6}$/.test(typeof runtime.run_id === "string" ? runtime.run_id : "") || !/^\d{4}-\d{2}-\d{2}$/.test(typeof runtime.date_cst === "string" ? runtime.date_cst : "") || typeof runtime.cursor !== "string" || runtime.cursor.trim() === "") {
      return failClosed("base_preflight_runtime_binding_invalid");
    }
    const authoritativeRuntime = readCurrentBaseRuntimeBinding();
    if (!authoritativeRuntime.writer_idle_authority || authoritativeRuntime.writer_idle !== true) return failClosed("base_preflight_writer_idle_unbound");
    if (runtime.runtime_sha256.toLowerCase() !== authoritativeRuntime.runtime_sha256 || runtime.run_id !== authoritativeRuntime.run_id || runtime.date_cst !== authoritativeRuntime.date_cst || runtime.cursor !== authoritativeRuntime.cursor || authoritativeRuntime.status !== "running") {
      return failClosed("base_preflight_runtime_authority_mismatch");
    }
    const runtimeWriterAuthority = normalizedRuntimeAuthorityRecord(runtime.writer_idle_authority, runtime.runtime_sha256);
    if (!runtimeWriterAuthority || runtime.writer_idle !== true || runtimeWriterAuthority.writer_idle !== true) return failClosed("base_preflight_writer_idle_unbound");
    if (runtime.session !== "02_Build" || runtime.status !== "running" || runtime.current !== true) {
      return failClosed("base_preflight_runtime_status_conflict", { session: runtime.session, status: runtime.status, current: runtime.current, writer_idle: runtime.writer_idle });
    }
    if (!Array.isArray(runtime.terminal_statuses) || runtime.terminal_statuses.length !== 1 || runtime.terminal_statuses[0] !== "complete") {
      return failClosed("base_preflight_terminal_status_vocabulary_invalid", { terminal_statuses: runtime.terminal_statuses });
    }
    const trustedRuntime = authority.current_runtime;
    if (!trustedRuntime || typeof trustedRuntime !== "object" || Array.isArray(trustedRuntime)) return failClosed("base_preflight_authoritative_runtime_missing");
    const unknownTrustedRuntimeFields = Object.keys(trustedRuntime).filter((field) => !new Set(["binding_version", "source", "runtime_sha256", "run_id", "date_cst", "cursor", "writer_idle_authority"]).has(field));
    if (unknownTrustedRuntimeFields.length > 0) return failClosed("base_preflight_authoritative_runtime_unknown_field", { fields: unknownTrustedRuntimeFields.sort() });
    const trustedWriterAuthority = normalizedRuntimeAuthorityRecord(trustedRuntime.writer_idle_authority, runtime.runtime_sha256);
    if (!trustedWriterAuthority || digest(trustedWriterAuthority) !== digest(runtimeWriterAuthority)) return failClosed("base_preflight_writer_idle_unbound");
    if (trustedRuntime.binding_version !== RUNTIME_BINDING_SCHEMA_VERSION || trustedRuntime.source !== runtime.source || typeof trustedRuntime.runtime_sha256 !== "string" || trustedRuntime.runtime_sha256.toLowerCase() !== runtime.runtime_sha256.toLowerCase() || trustedRuntime.run_id !== runtime.run_id || trustedRuntime.date_cst !== runtime.date_cst || trustedRuntime.cursor !== runtime.cursor) return failClosed("base_preflight_authoritative_runtime_mismatch");

    const ownerGate = input.owner_gate;
    if (!ownerGate || typeof ownerGate !== "object" || Array.isArray(ownerGate)) return failClosed("base_preflight_owner_gate_missing");
    if (hasOwn.call(ownerGate, "owner_confirmation")) return failClosed("base_preflight_owner_confirmation_present");
    const unknownOwnerGateFields = Object.keys(ownerGate).filter((field) => !new Set(["status", "current", "observed", "owner_confirmation_status"]).has(field));
    if (unknownOwnerGateFields.length > 0) return failClosed("base_preflight_owner_gate_unknown_field", { fields: unknownOwnerGateFields.sort() });
    if (ownerGate.status !== "not_observed" || ownerGate.current !== true || ownerGate.observed !== false || ownerGate.owner_confirmation_status !== "NOT_GRANTED") {
      return failClosed("base_preflight_owner_gate_not_unobserved", { status: ownerGate.status, current: ownerGate.current, observed: ownerGate.observed, owner_confirmation_status: ownerGate.owner_confirmation_status });
    }

    const receiptFinality = input.receipt_finality;
    if (!receiptFinality || typeof receiptFinality !== "object" || Array.isArray(receiptFinality)) return failClosed("base_preflight_receipt_finality_missing");
    const unknownReceiptFinalityFields = Object.keys(receiptFinality).filter((field) => !new Set(["network", "chain_id", "status", "current", "required_receipt_status", "required_finality_stage", "finality_stages", "reorg_policy"]).has(field));
    if (unknownReceiptFinalityFields.length > 0) return failClosed("base_preflight_receipt_finality_unknown_field", { fields: unknownReceiptFinalityFields.sort() });
    const network = requiredString(receiptFinality.network, "receipt_finality.network");
    if (!NETWORKS[network] || receiptFinality.chain_id !== NETWORKS[network].chainId) return failClosed("base_preflight_receipt_network_invalid");
    if (receiptFinality.status !== "not_observed" || receiptFinality.current !== true || receiptFinality.required_receipt_status !== "0x1" || receiptFinality.required_finality_stage !== "l1_batch_finality" || receiptFinality.reorg_policy !== "reject") {
      return failClosed("base_preflight_receipt_finality_contract_invalid");
    }
    if (!Array.isArray(receiptFinality.finality_stages) || receiptFinality.finality_stages.length !== Object.keys(BASE_FINALITY_STAGES).length || receiptFinality.finality_stages.some((stage, index) => stage !== Object.keys(BASE_FINALITY_STAGES)[index])) {
      return failClosed("base_preflight_finality_vocabulary_invalid", { finality_stages: receiptFinality.finality_stages });
    }

    const erpReadback = input.erp_readback;
    if (!erpReadback || typeof erpReadback !== "object" || Array.isArray(erpReadback)) return failClosed("base_preflight_erp_readback_missing");
    const unknownErpReadbackFields = Object.keys(erpReadback).filter((field) => !new Set(["required", "current", "status", "chain_success_is_not_erp", "binding"]).has(field));
    if (unknownErpReadbackFields.length > 0) return failClosed("base_preflight_erp_readback_unknown_field", { fields: unknownErpReadbackFields.sort() });
    if (erpReadback.required !== true || erpReadback.current !== true || erpReadback.status !== "not_observed" || erpReadback.chain_success_is_not_erp !== true || !Array.isArray(erpReadback.binding) || erpReadback.binding.join("|") !== "caseId|fingerprint|documentId|authoritative|status") {
      return failClosed("base_preflight_erp_readback_contract_invalid");
    }

    const normalizedLists = {};
    for (const [field, value] of [["required_inputs", input.required_inputs], ["required_readbacks", input.required_readbacks], ["stop_conditions", input.stop_conditions], ["recovery", input.recovery]]) {
      if (!Array.isArray(value) || value.length === 0) return failClosed("base_preflight_required_field_missing", { field });
      const normalized = value.map((entry, index) => requiredString(entry, `${field}[${index}]`));
      if (new Set(normalized).size !== normalized.length) return failClosed("base_preflight_required_field_duplicate", { field });
      normalizedLists[field] = normalized;
    }
    for (const field of ["current_release", "base_runtime", "owner_gate", "receipt_finality", "erp_readback"]) {
      if (!normalizedLists.required_inputs.includes(field)) return failClosed("base_preflight_required_input_missing", { field });
    }
    if (normalizedLists.required_inputs.some((field) => !["current_release", "base_runtime", "owner_gate", "receipt_finality", "erp_readback"].includes(field))) return failClosed("base_preflight_required_input_unknown");
    for (const field of ["base_receipt", "base_finality", "wallet_calls_status", "erp_readback", "eight_platform_current_release_receipts"]) {
      if (!normalizedLists.required_readbacks.includes(field)) return failClosed("base_preflight_required_readback_missing", { field });
    }
    if (normalizedLists.required_readbacks.some((field) => !["base_receipt", "base_finality", "wallet_calls_status", "erp_readback", "eight_platform_current_release_receipts"].includes(field))) return failClosed("base_preflight_required_readback_unknown");
    for (const field of ["owner_confirmation_not_observed", "runtime_or_terminal_status_conflict", "receipt_or_finality_missing_or_invalid", "erp_readback_missing_or_mismatched", "historical_partial_or_synthetic_evidence", "release_binding_drift"]) {
      if (!normalizedLists.stop_conditions.includes(field)) return failClosed("base_preflight_stop_condition_missing", { field });
    }
    if (normalizedLists.stop_conditions.some((field) => !["owner_confirmation_not_observed", "runtime_or_terminal_status_conflict", "receipt_or_finality_missing_or_invalid", "erp_readback_missing_or_mismatched", "historical_partial_or_synthetic_evidence", "release_binding_drift"].includes(field))) return failClosed("base_preflight_stop_condition_unknown");
    for (const field of ["do_not_execute_or_retry", "re_read_current_release_and_readbacks", "replay_lock_exact_candidate"]) {
      if (!normalizedLists.recovery.includes(field)) return failClosed("base_preflight_recovery_missing", { field });
    }
    if (normalizedLists.recovery.some((field) => !["do_not_execute_or_retry", "re_read_current_release_and_readbacks", "replay_lock_exact_candidate"].includes(field))) return failClosed("base_preflight_recovery_unknown");

    if (input.executable !== false) return failClosed("base_preflight_executable_not_false");
    if (!hasOwn.call(input, "payload") || input.payload !== null) return failClosed("base_preflight_payload_not_null");

    let atomicOwnerPreflight = null;
    if (input.atomic_owner_preflight !== undefined) {
      atomicOwnerPreflight = validateBaseAtomicOwnerPreflight(input.atomic_owner_preflight);
      if (!atomicOwnerPreflight.ok) return atomicOwnerPreflight;
    }

    let receiptObserved = false;
    let receiptCaseId = null;
    let erpObserved = false;
    let platformReceiptCount = 0;
    if (input.readbacks !== undefined) {
      const readbacks = input.readbacks;
      if (!readbacks || typeof readbacks !== "object" || Array.isArray(readbacks)) return failClosed("base_preflight_readbacks_invalid");
      const readbackFields = ["receipt", "erp", "platforms"];
      const unknownReadbackFields = Object.keys(readbacks).filter((field) => !readbackFields.includes(field));
      if (unknownReadbackFields.length > 0 || readbackFields.some((field) => !hasOwn.call(readbacks, field))) return failClosed("base_preflight_readbacks_shape_invalid");

      const receipt = readbacks.receipt;
      if (receipt !== null) {
        if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return failClosed("base_preflight_receipt_readback_invalid");
        const unknownReceiptFields = Object.keys(receipt).filter((field) => !new Set(["release_id", "release_fingerprint", "bom_fingerprint", "current", "historical", "synthetic", "evidence_origin", "readback_ref", "case_id", "chain_id", "transaction_hash", "receipt_status", "finality_stage", "l1_finalized", "reorged", "state_change", "unique", "wallet_calls_status"]).has(field));
        if (unknownReceiptFields.length > 0) return failClosed("base_preflight_receipt_unknown_field", { fields: unknownReceiptFields.sort() });
        if (receipt.historical === true) return failClosed("base_preflight_historical_evidence");
        if (receipt.synthetic !== false) return failClosed("base_preflight_synthetic_evidence");
        if (receipt.current !== true) return failClosed("base_preflight_stale_readback");
        if (receipt.release_id !== releaseId || typeof receipt.release_fingerprint !== "string" || receipt.release_fingerprint.toLowerCase() !== releaseFingerprint || typeof receipt.bom_fingerprint !== "string" || receipt.bom_fingerprint.toLowerCase() !== bomFingerprint) return failClosed("base_preflight_readback_release_mismatch");
        if (receipt.evidence_origin !== "authorized_base_readback" || typeof receipt.readback_ref !== "string" || receipt.readback_ref.trim() === "") return failClosed("base_preflight_receipt_provenance_invalid");
        if (typeof receipt.case_id !== "string" || receipt.case_id.trim() === "") return failClosed("base_preflight_receipt_case_missing");
        if (receipt.chain_id !== receiptFinality.chain_id || !RELEASE_TRANSACTION_PATTERN.test(typeof receipt.transaction_hash === "string" ? receipt.transaction_hash : "") || receipt.receipt_status !== "0x1" || receipt.finality_stage !== receiptFinality.required_finality_stage || receipt.l1_finalized !== true || receipt.reorged !== false || receipt.state_change !== true || receipt.unique !== true) return failClosed("base_preflight_receipt_finality_invalid");
        const unknownCallsFields = receipt.wallet_calls_status && typeof receipt.wallet_calls_status === "object" ? Object.keys(receipt.wallet_calls_status).filter((field) => !new Set(["version", "chainId", "id", "status", "atomic", "receipts"]).has(field)) : [];
        if (unknownCallsFields.length > 0) return failClosed("base_preflight_wallet_calls_unknown_field", { fields: unknownCallsFields.sort() });
        if (receipt.wallet_calls_status && Array.isArray(receipt.wallet_calls_status.receipts)) {
          for (const callReceipt of receipt.wallet_calls_status.receipts) {
            if (!callReceipt || typeof callReceipt !== "object" || Object.keys(callReceipt).some((field) => !["transactionHash", "status"].includes(field))) return failClosed("base_preflight_wallet_calls_unknown_field");
          }
        }
        const calls = mapWalletCallsStatus(receipt.wallet_calls_status);
        if (!calls.ok || calls.status_code !== 200 || calls.chain_id !== receipt.chain_id) return failClosed(calls.ok && calls.chain_id !== receipt.chain_id ? "base_preflight_wallet_calls_chain_mismatch" : "base_preflight_wallet_calls_readback_invalid", { wallet_calls_reason: calls.reason });
        if (!calls.receipts.some(({ transaction_hash: hash }) => hash === receipt.transaction_hash.toLowerCase())) return failClosed("base_preflight_wallet_calls_readback_invalid", { wallet_calls_reason: calls.reason });
        receiptCaseId = receipt.case_id;
        receiptObserved = true;
      }

      const erp = readbacks.erp;
      if (erp !== null) {
        if (!erp || typeof erp !== "object" || Array.isArray(erp)) return failClosed("base_preflight_erp_readback_invalid");
        const unknownErpFields = Object.keys(erp).filter((field) => !new Set(["release_id", "release_fingerprint", "bom_fingerprint", "current", "historical", "synthetic", "evidence_origin", "readback_ref", "case_id", "documentId", "authoritative", "status"]).has(field));
        if (unknownErpFields.length > 0) return failClosed("base_preflight_erp_readback_unknown_field", { fields: unknownErpFields.sort() });
        if (erp.historical === true) return failClosed("base_preflight_historical_evidence");
        if (erp.synthetic !== false) return failClosed("base_preflight_synthetic_evidence");
        if (erp.current !== true) return failClosed("base_preflight_stale_readback");
        if (erp.release_id !== releaseId || typeof erp.release_fingerprint !== "string" || erp.release_fingerprint.toLowerCase() !== releaseFingerprint || typeof erp.bom_fingerprint !== "string" || erp.bom_fingerprint.toLowerCase() !== bomFingerprint) return failClosed("base_preflight_readback_release_mismatch");
        if (erp.evidence_origin !== "authorized_erp_readback" || typeof erp.readback_ref !== "string" || erp.readback_ref.trim() === "" || erp.authoritative !== true || erp.status !== "posted" || typeof erp.case_id !== "string" || erp.case_id.trim() === "" || typeof erp.documentId !== "string" || erp.documentId.trim() === "") return failClosed("base_preflight_erp_readback_invalid");
        if (receiptCaseId === null) return failClosed("base_preflight_erp_receipt_binding_missing");
        if (receiptCaseId !== null && erp.case_id !== receiptCaseId) return failClosed("base_preflight_readback_case_mismatch", { receipt_case_id: receiptCaseId, erp_case_id: erp.case_id });
        erpObserved = true;
      }

      if (!Array.isArray(readbacks.platforms)) return failClosed("base_preflight_platform_readbacks_invalid");
      if (readbacks.platforms.length !== 0 && readbacks.platforms.length !== RELEASE_PLATFORMS.length) return failClosed("base_preflight_platform_readbacks_incomplete", { count: readbacks.platforms.length });
      const seenPlatforms = new Set();
      const seenReceipts = new Set();
      for (const platform of readbacks.platforms) {
        if (!platform || typeof platform !== "object" || Array.isArray(platform)) return failClosed("base_preflight_platform_readbacks_invalid");
        const unknownPlatformFields = Object.keys(platform).filter((field) => !new Set(["platform", "receipt_id", "release_id", "release_fingerprint", "bom_fingerprint", "current", "historical", "synthetic", "evidence_origin", "independent", "status", "proof_ref"]).has(field));
        if (unknownPlatformFields.length > 0) return failClosed("base_preflight_platform_readback_unknown_field", { fields: unknownPlatformFields.sort() });
        if (platform.historical === true) return failClosed("base_preflight_historical_evidence");
        if (platform.synthetic !== false) return failClosed("base_preflight_synthetic_evidence");
        if (platform.current !== true) return failClosed("base_preflight_stale_readback");
        if (platform.release_id !== releaseId || typeof platform.release_fingerprint !== "string" || platform.release_fingerprint.toLowerCase() !== releaseFingerprint || typeof platform.bom_fingerprint !== "string" || platform.bom_fingerprint.toLowerCase() !== bomFingerprint) return failClosed("base_preflight_readback_release_mismatch");
        if (!RELEASE_PLATFORMS.includes(platform.platform) || seenPlatforms.has(platform.platform)) return failClosed("base_preflight_platform_readbacks_conflict");
        if (platform.evidence_origin !== "official_platform_readback" || platform.independent !== true || platform.status !== "verified" || typeof platform.proof_ref !== "string" || platform.proof_ref.trim() === "") return failClosed("base_preflight_platform_readback_invalid");
        const receiptId = requiredString(platform.receipt_id, "platform.receipt_id");
        if (seenReceipts.has(receiptId)) return failClosed("base_preflight_platform_readbacks_conflict");
        seenPlatforms.add(platform.platform);
        seenReceipts.add(receiptId);
      }
      platformReceiptCount = readbacks.platforms.length;
    }

    return Object.freeze({
      ok: true,
      fail_closed: false,
      gate_id: gateId,
      current_release: { release_id: releaseId, release_fingerprint: releaseFingerprint, bom_fingerprint: bomFingerprint },
      authority_binding: { current_release: "bound", current_runtime: "bound" },
      runtime: { binding_version: RUNTIME_BINDING_SCHEMA_VERSION, source: runtime.source, runtime_sha256: runtime.runtime_sha256.toLowerCase(), run_id: runtime.run_id, date_cst: runtime.date_cst, cursor: runtime.cursor, session: "02_Build", status: "running", current: true, writer_idle: true, writer_idle_authority: runtimeWriterAuthority, terminal_statuses: ["complete"] },
      owner_gate: { status: "not_observed", current: true, observed: false, owner_confirmation_status: "NOT_GRANTED" },
      receipt_finality: { network, chain_id: receiptFinality.chain_id, status: "not_observed", current: true, required_receipt_status: "0x1", required_finality_stage: "l1_batch_finality", reorg_policy: "reject", finality_stages: [...receiptFinality.finality_stages] },
      erp_readback: { required: true, current: true, status: "not_observed", chain_success_is_not_erp: true, binding: [...erpReadback.binding] },
      required_inputs: [...normalizedLists.required_inputs],
      required_readbacks: [...normalizedLists.required_readbacks],
      stop_conditions: [...normalizedLists.stop_conditions],
      recovery: [...normalizedLists.recovery],
      ...(atomicOwnerPreflight ? { atomic_owner_preflight: atomicOwnerPreflight } : {}),
      executable: false,
      payload: null,
      readback_state: { receipt: receiptObserved ? "observed" : "not_observed", erp: erpObserved ? "observed" : "not_observed", platform_receipts: platformReceiptCount === RELEASE_PLATFORMS.length ? "complete" : "not_observed", chain_success_not_erp: true },
    });
  } catch (error) {
    return failClosed("invalid_base_gate_preflight_input", { message: error.message });
  }
}

/** Validate the seven current-release business-closure evidence gaps without inferring close from receipt or ERP posting. */
export function validateBaseBusinessClosureEvidenceGap(input = {}) {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return failClosed("base_business_closure_input_missing");
    const hasOwn = Object.prototype.hasOwnProperty;
    const allowedInputFields = new Set(["preflight", "business_closure_domains", "platform_bindings", "execution_authority"]);
    const unknownInputFields = Object.keys(input).filter((field) => !allowedInputFields.has(field));
    if (unknownInputFields.length > 0) return failClosed("base_business_closure_unknown_field", { fields: unknownInputFields.sort() });

    const preflight = input.preflight;
    if (!preflight || typeof preflight !== "object" || Array.isArray(preflight)) return failClosed("base_business_closure_preflight_missing");
    const preflightResult = validateBaseGatePreflight(preflight);
    if (!preflightResult.ok) return failClosed("base_business_closure_preflight_invalid", { preflight_reason: preflightResult.reason });
    if (input.execution_authority !== "none_until_02_Build_revalidates") return failClosed("base_business_closure_execution_authority_invalid");
    if (preflightResult.owner_gate.status !== "not_observed" || preflightResult.owner_gate.current !== true || preflightResult.owner_gate.observed !== false || preflightResult.owner_gate.owner_confirmation_status !== "NOT_GRANTED") {
      return failClosed("base_business_closure_owner_gate_not_unobserved");
    }
    if (preflightResult.executable !== false) return failClosed("base_business_closure_executable_not_false");
    if (!hasOwn.call(preflightResult, "payload") || preflightResult.payload !== null) return failClosed("base_business_closure_payload_not_null");

    const release = preflightResult.current_release;
    const domains = input.business_closure_domains;
    if (!Array.isArray(domains) || domains.length !== BUSINESS_CLOSURE_RECORD_TYPES.length) {
      return failClosed("base_business_closure_domain_set_mismatch", { expected_count: BUSINESS_CLOSURE_RECORD_TYPES.length, observed_count: Array.isArray(domains) ? domains.length : null });
    }
    const expectedDomains = new Set(BUSINESS_CLOSURE_RECORD_TYPES);
    const seenDomains = new Set();
    const normalizedDomains = [];
    const allowedDomainFields = new Set([
      "record_type",
      "release_id",
      "release_fingerprint",
      "bom_fingerprint",
      "current",
      "historical",
      "partial",
      "synthetic",
      "evidence_status",
      "required_inputs",
      "authoritative_readback",
      "gap_if_missing",
      "stop_condition",
      "owner_confirmation",
    ]);
    for (const domain of domains) {
      if (!domain || typeof domain !== "object" || Array.isArray(domain)) return failClosed("base_business_closure_domain_invalid");
      const unknownDomainFields = Object.keys(domain).filter((field) => !allowedDomainFields.has(field));
      if (unknownDomainFields.length > 0) return failClosed("base_business_closure_domain_unknown_field", { fields: unknownDomainFields.sort() });
      const recordType = typeof domain.record_type === "string" ? domain.record_type.trim() : "";
      if (!expectedDomains.has(recordType)) return failClosed("base_business_closure_domain_name_invalid", { record_type: recordType || null });
      if (seenDomains.has(recordType)) return failClosed("base_business_closure_domain_duplicate", { record_type: recordType });
      seenDomains.add(recordType);
      if (domain.current !== true) return failClosed("base_business_closure_domain_stale", { record_type: recordType });
      if (domain.historical !== false) return failClosed("base_business_closure_historical_evidence", { record_type: recordType });
      if (domain.partial !== false) return failClosed("base_business_closure_partial_evidence", { record_type: recordType, credit: 0 });
      if (domain.synthetic !== false) return failClosed("base_business_closure_synthetic_evidence", { record_type: recordType });
      if (domain.evidence_status !== "not_observed") return failClosed("base_business_closure_domain_gap_not_preserved", { record_type: recordType, evidence_status: domain.evidence_status });
      if (domain.owner_confirmation !== "absent") return failClosed("base_business_closure_owner_confirmation_present", { record_type: recordType });
      if (domain.release_id !== release.release_id || typeof domain.release_fingerprint !== "string" || domain.release_fingerprint.toLowerCase() !== release.release_fingerprint || typeof domain.bom_fingerprint !== "string" || domain.bom_fingerprint.toLowerCase() !== release.bom_fingerprint) {
        return failClosed("base_business_closure_release_binding_mismatch", { record_type: recordType });
      }
      const normalizedLists = {};
      for (const field of ["required_inputs", "authoritative_readback"]) {
        if (!Array.isArray(domain[field]) || domain[field].length === 0) return failClosed("base_business_closure_domain_contract_missing", { record_type: recordType, field });
        const normalized = domain[field].map((entry, index) => requiredString(entry, `${recordType}.${field}[${index}]`));
        if (new Set(normalized).size !== normalized.length) return failClosed("base_business_closure_domain_contract_duplicate", { record_type: recordType, field });
        normalizedLists[field] = normalized;
      }
      const contract = BUSINESS_CLOSURE_CONTRACTS[recordType];
      if (JSON.stringify(normalizedLists.required_inputs) !== JSON.stringify(contract.required_inputs)) return failClosed("base_business_closure_domain_contract_mismatch", { record_type: recordType, field: "required_inputs" });
      if (JSON.stringify(normalizedLists.authoritative_readback) !== JSON.stringify(contract.authoritative_readback)) return failClosed("base_business_closure_domain_contract_mismatch", { record_type: recordType, field: "authoritative_readback" });
      const gapIfMissing = typeof domain.gap_if_missing === "string" ? domain.gap_if_missing.trim() : "";
      const stopCondition = typeof domain.stop_condition === "string" ? domain.stop_condition.trim() : "";
      if (!gapIfMissing || !stopCondition) return failClosed("base_business_closure_domain_contract_missing", { record_type: recordType, field: "gap_if_missing_or_stop_condition" });
      if (gapIfMissing !== contract.gap_if_missing) return failClosed("base_business_closure_domain_contract_mismatch", { record_type: recordType, field: "gap_if_missing" });
      if (stopCondition !== contract.stop_condition) return failClosed("base_business_closure_domain_contract_mismatch", { record_type: recordType, field: "stop_condition" });
      normalizedDomains.push({
        record_type: recordType,
        release_id: release.release_id,
        release_fingerprint: release.release_fingerprint,
        bom_fingerprint: release.bom_fingerprint,
        current: true,
        historical: false,
        partial: false,
        synthetic: false,
        evidence_status: "not_observed",
        required_inputs: normalizedLists.required_inputs,
        authoritative_readback: normalizedLists.authoritative_readback,
        gap_if_missing: gapIfMissing,
        stop_condition: stopCondition,
        owner_confirmation: "absent",
      });
    }
    const missingDomains = BUSINESS_CLOSURE_RECORD_TYPES.filter((recordType) => !seenDomains.has(recordType));
    if (missingDomains.length > 0) return failClosed("base_business_closure_domain_set_mismatch", { missing_domains: missingDomains, observed_count: domains.length });

    const platforms = input.platform_bindings;
    if (!Array.isArray(platforms) || platforms.length !== RELEASE_PLATFORMS.length) {
      return failClosed("base_business_closure_platform_set_mismatch", { expected_count: RELEASE_PLATFORMS.length, observed_count: Array.isArray(platforms) ? platforms.length : null });
    }
    const expectedPlatforms = new Set(RELEASE_PLATFORMS);
    const seenPlatforms = new Set();
    const normalizedPlatforms = [];
    const allowedPlatformFields = new Set([
      "platform",
      "release_id",
      "release_fingerprint",
      "bom_fingerprint",
      "current",
      "historical",
      "partial",
      "synthetic",
      "evidence_status",
      "historical_credit",
      "partial_credit",
    ]);
    for (const platform of platforms) {
      if (!platform || typeof platform !== "object" || Array.isArray(platform)) return failClosed("base_business_closure_platform_invalid");
      const unknownPlatformFields = Object.keys(platform).filter((field) => !allowedPlatformFields.has(field));
      if (unknownPlatformFields.length > 0) return failClosed("base_business_closure_platform_unknown_field", { fields: unknownPlatformFields.sort() });
      if (!expectedPlatforms.has(platform.platform)) return failClosed("base_business_closure_platform_name_invalid", { platform: platform.platform ?? null });
      if (seenPlatforms.has(platform.platform)) return failClosed("base_business_closure_platform_duplicate", { platform: platform.platform });
      seenPlatforms.add(platform.platform);
      if (platform.current !== true) return failClosed("base_business_closure_platform_stale", { platform: platform.platform });
      if (platform.historical !== false) return failClosed("base_business_closure_historical_platform_evidence", { platform: platform.platform, credit: 0 });
      if (platform.partial !== false) return failClosed("base_business_closure_partial_platform_evidence", { platform: platform.platform, credit: 0 });
      if (platform.synthetic !== false) return failClosed("base_business_closure_synthetic_platform_evidence", { platform: platform.platform });
      if (platform.evidence_status !== "not_observed") return failClosed("base_business_closure_platform_gap_not_preserved", { platform: platform.platform, evidence_status: platform.evidence_status });
      if (platform.historical_credit !== 0 || platform.partial_credit !== 0) return failClosed("base_business_closure_platform_credit_nonzero", { platform: platform.platform, historical_credit: platform.historical_credit, partial_credit: platform.partial_credit });
      if (platform.release_id !== release.release_id || typeof platform.release_fingerprint !== "string" || platform.release_fingerprint.toLowerCase() !== release.release_fingerprint || typeof platform.bom_fingerprint !== "string" || platform.bom_fingerprint.toLowerCase() !== release.bom_fingerprint) {
        return failClosed("base_business_closure_platform_release_binding_mismatch", { platform: platform.platform });
      }
      normalizedPlatforms.push({
        platform: platform.platform,
        release_id: release.release_id,
        release_fingerprint: release.release_fingerprint,
        bom_fingerprint: release.bom_fingerprint,
        current: true,
        historical: false,
        partial: false,
        synthetic: false,
        evidence_status: "not_observed",
        historical_credit: 0,
        partial_credit: 0,
      });
    }
    const missingPlatforms = RELEASE_PLATFORMS.filter((platform) => !seenPlatforms.has(platform));
    if (missingPlatforms.length > 0) return failClosed("base_business_closure_platform_set_mismatch", { missing_platforms: missingPlatforms, observed_count: platforms.length });

    return Object.freeze({
      ok: true,
      fail_closed: false,
      batch_id: BUSINESS_CLOSURE_BATCH_ID,
      current_release: { ...release },
      business_closure_domains: normalizedDomains,
      domain_count: normalizedDomains.length,
      platform_bindings: normalizedPlatforms,
      platform_count: normalizedPlatforms.length,
      historical_credit: 0,
      partial_credit: 0,
      independent_evidence: {
        receipt: preflightResult.readback_state.receipt,
        erp_posting: preflightResult.readback_state.erp,
        business_close: "not_observed",
        chain_success_not_erp: true,
        receipt_does_not_prove_erp_posting: true,
        receipt_does_not_prove_business_close: true,
        erp_posting_does_not_prove_business_close: true,
      },
      readback_state: {
        receipt: preflightResult.readback_state.receipt,
        erp_posting: preflightResult.readback_state.erp,
        business_close: "not_observed",
        platform_evidence: "not_observed",
        chain_success_not_erp: true,
      },
      owner_gate: { ...preflightResult.owner_gate },
      owner_confirmation: "absent",
      evidence_gap: true,
      business_close_complete: false,
      execution_authority: "none_until_02_Build_revalidates",
      executable: false,
      payload: null,
      external_actions: 0,
    });
  } catch (error) {
    return failClosed("invalid_base_business_closure_input", { message: error.message });
  }
}

function publicEvidenceValuePresent(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim() !== "";
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function samePublicOrigin(left, right) {
  try {
    const leftUrl = new URL(left);
    const rightUrl = new URL(right);
    return leftUrl.protocol === "https:" && rightUrl.protocol === "https:" && leftUrl.hostname.toLowerCase() === rightUrl.hostname.toLowerCase() && (leftUrl.port || "443") === (rightUrl.port || "443");
  } catch {
    return false;
  }
}

/** Validate the eight current-release public-surface rows from the v2 product-owner contract. */
export function validateEightSurfacePublicEvidence({ surfaces, releaseId, releaseFingerprint, bomFingerprint, immutableBomSha256 } = {}) {
  try {
    if (!surfaces || typeof surfaces !== "object" || Array.isArray(surfaces)) return failClosed("eight_platform_gate_incomplete");
    const receiptIds = new Set();
    const outcomeDigests = new Set();
    const normalized = {};
    for (const platform of RELEASE_PLATFORMS) {
      const evidence = surfaces[platform];
      const rule = PUBLIC_SURFACE_RULES[platform];
      if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return failClosed("eight_platform_gate_incomplete", { platform });
      if (evidence.release_id !== releaseId || evidence.release_fingerprint !== releaseFingerprint || evidence.bom_fingerprint !== bomFingerprint || (evidence.immutable_bom_sha256 ?? null) !== (immutableBomSha256 ?? null)) {
        return failClosed("historical_receipt_guard", { platform });
      }
      if (evidence.current !== true || evidence.historical !== false || evidence.synthetic !== false || evidence.independent !== true || evidence.status !== "verified") {
        return failClosed("platform_receipt_not_independent", { platform });
      }
      if (evidence.evidence_origin !== "official_platform_readback") return failClosed("platform_evidence_provenance_missing", { platform });
      const receiptId = requiredString(evidence.receipt_id, `${platform}.receipt_id`);
      if (receiptIds.has(receiptId)) return failClosed("platform_receipt_not_independent", { platform });
      receiptIds.add(receiptId);
      const outcomeDigest = requiredString(evidence.material_outcome_digest, `${platform}.material_outcome_digest`).toLowerCase();
      if (!RELEASE_DIGEST_PATTERN.test(outcomeDigest)) return failClosed("platform_outcome_digest_invalid", { platform });
      outcomeDigests.add(outcomeDigest);

      const proofRef = requiredString(evidence.proof_ref, `${platform}.proof_ref`);
      if (!/^https:\/\//i.test(proofRef)) return failClosed("platform_public_url_invalid", { platform });
      const lowerProofRef = proofRef.toLowerCase();
      if (rule.forbidden_fragments.some((fragment) => lowerProofRef.includes(fragment.toLowerCase()))) return failClosed("platform_public_url_forbidden", { platform });
      const canonicalIndex = rule.canonical_urls.findIndex((pattern) => pattern.test(proofRef));
      if (canonicalIndex < 0) return failClosed("platform_public_url_noncanonical", { platform });
      if (!Array.isArray(evidence.public_urls) || evidence.public_urls.length === 0 || evidence.public_urls.some((url) => typeof url !== "string" || !/^https:\/\//i.test(url) || rule.forbidden_fragments.some((fragment) => url.toLowerCase().includes(fragment.toLowerCase())))) {
        return failClosed("platform_public_urls_invalid", { platform });
      }
      if (!evidence.public_urls.includes(proofRef)) return failClosed("platform_public_urls_missing_proof_ref", { platform });
      if (evidence.public_access !== "unauthenticated_public") return failClosed("platform_public_access_invalid", { platform });
      if (typeof evidence.observed_at !== "string" || Number.isNaN(Date.parse(evidence.observed_at))) return failClosed("platform_observed_at_invalid", { platform });
      if (!evidence.public_fields || typeof evidence.public_fields !== "object" || Array.isArray(evidence.public_fields)) return failClosed("platform_public_fields_missing", { platform });
      for (const field of rule.required_public_fields) {
        if (!Object.prototype.hasOwnProperty.call(evidence.public_fields, field) || !publicEvidenceValuePresent(evidence.public_fields[field])) return failClosed("platform_public_field_missing", { platform, field });
      }
      if (platform === "base_app" && canonicalIndex === 1 && (evidence.public_fields.material_outcome_type !== "token" || !publicEvidenceValuePresent(evidence.public_fields.token_address))) {
        return failClosed("platform_public_url_semantics_invalid", { platform });
      }
      if (platform === "base_app" && canonicalIndex === 1) {
        const tokenMatch = proofRef.match(/\/coin\/base-mainnet\/(0x[0-9a-f]{40})$/i);
        if (!tokenMatch || evidence.public_fields.token_address.toLowerCase() !== tokenMatch[1].toLowerCase()) return failClosed("platform_public_url_semantics_invalid", { platform });
      }
      if (platform === "base_app" && canonicalIndex === 2 && !samePublicOrigin(proofRef, evidence.public_fields.primary_url)) return failClosed("platform_public_url_semantics_invalid", { platform });
      if (platform === "render" && !samePublicOrigin(proofRef, evidence.public_fields.service_url)) return failClosed("platform_public_url_semantics_invalid", { platform });
      if (platform === "base_dashboard" && canonicalIndex === 1 && (!samePublicOrigin(proofRef, evidence.public_fields.registered_app_url) || !samePublicOrigin(proofRef, evidence.public_fields.primary_url))) return failClosed("platform_public_url_semantics_invalid", { platform });
      if (evidence.public_fields.release_id !== releaseId || evidence.public_fields.release_fingerprint !== releaseFingerprint || evidence.public_fields.bom_fingerprint !== bomFingerprint || evidence.public_fields.material_outcome_digest.toLowerCase() !== outcomeDigest) {
        return failClosed("platform_public_field_binding_mismatch", { platform });
      }
      normalized[platform] = Object.freeze({ proof_ref: proofRef, public_urls: Object.freeze([...evidence.public_urls]), public_fields: Object.freeze({ ...evidence.public_fields }) });
    }
    if (outcomeDigests.size !== 1) return failClosed("platform_outcome_mismatch");
    if (normalized.github.public_fields.commit_sha !== normalized.render.public_fields.commit_sha || normalized.github.public_fields.render_commit_sha !== normalized.render.public_fields.commit_sha) {
      return failClosed("platform_commit_sha_mismatch", { platforms: ["github", "render"] });
    }
    const baseDev = normalized.base_dev;
    const baseDashboard = normalized.base_dashboard;
    if (baseDev.proof_ref === baseDashboard.proof_ref || baseDev.public_urls.some((url) => baseDashboard.public_urls.includes(url)) || digest(baseDev.public_fields) === digest(baseDashboard.public_fields)) {
      return failClosed("platform_alias_collision", { platforms: ["base_dev", "base_dashboard"] });
    }
    const baseAppFields = normalized.base_app.public_fields;
    const baseDashboardFields = baseDashboard.public_fields;
    const baseDevFields = baseDev.public_fields;
    if (baseAppFields.primary_url !== baseDashboardFields.registered_app_url || baseAppFields.primary_url !== baseDashboardFields.primary_url || baseAppFields.primary_url !== baseDevFields.primary_url) {
      return failClosed("platform_primary_url_mismatch", { platforms: ["base_app", "base_dashboard", "base_dev"] });
    }
    if (normalizeAddress(baseAppFields.wallet_address, "base_app.public_fields.wallet_address") !== PRIMARY_BASE_ACCOUNT) {
      return failClosed("platform_wallet_identity_mismatch", { platform: "base_app" });
    }
    const basenameFields = normalized.basename_base_org.public_fields;
    if (normalizeAddress(basenameFields.primary_base_account, "basename.public_fields.primary_base_account") !== PRIMARY_BASE_ACCOUNT || normalizeAddress(basenameFields.resolved_address, "basename.public_fields.resolved_address") !== PRIMARY_BASE_ACCOUNT) {
      return failClosed("platform_wallet_identity_mismatch", { platform: "basename_base_org" });
    }
    return Object.freeze({ ok: true, fail_closed: false, contract_id: BASE_EIGHT_SURFACE_CONTRACT_ID, platform_count: RELEASE_PLATFORMS.length, receipt_count: receiptIds.size, outcome_digest: [...outcomeDigests][0] });
  } catch (error) {
    return failClosed("invalid_eight_surface_public_evidence", { message: error.message });
  }
}

/** Validate one current release without inferring ERP or publication from chain success. */
export function validateReleaseIntegrity({ currentRelease, chainEvidence, erpReadback } = {}) {
  try {
    if (!currentRelease || typeof currentRelease !== "object" || Array.isArray(currentRelease)) {
      return releaseFailure("current_release_missing");
    }
    const releaseId = requiredString(currentRelease.release_id, "currentRelease.release_id");
    const delta = currentRelease.current_release_delta;
    const interactionEvidence = currentRelease.interaction_evidence;
    const acceptanceState = currentRelease.acceptance_state;
    if (!delta || typeof delta !== "object" || Array.isArray(delta)) return releaseFailure("current_release_delta_missing");
    if (!interactionEvidence || typeof interactionEvidence !== "object" || Array.isArray(interactionEvidence)) return releaseFailure("interaction_evidence_missing");
    if (!acceptanceState || typeof acceptanceState !== "object" || Array.isArray(acceptanceState)) return releaseFailure("acceptance_state_missing");
    const runtimeBindingResult = validateReleaseRuntimeBinding(currentRelease.runtime_binding);
    if (!runtimeBindingResult.ok) return releaseFailure(runtimeBindingResult.reason, runtimeBindingResult);
    const bom = currentRelease.immutable_release_bom;
    if (!Array.isArray(bom) || bom.length === 0) return releaseFailure("immutable_release_bom_missing");
    const seenBomPaths = new Set();
    const normalizedBom = bom.map((entry) => {
      const path = requiredString(entry?.path, "immutable_release_bom.path");
      const entryDigest = requiredString(entry?.digest, `immutable_release_bom.${path}.digest`).toLowerCase();
      if (!RELEASE_DIGEST_PATTERN.test(entryDigest)) throw new TypeError(`immutable_release_bom.${path}.digest must be a 32-byte digest`);
      if (seenBomPaths.has(path)) throw new TypeError("immutable_release_bom contains duplicate paths");
      seenBomPaths.add(path);
      return { path, digest: entryDigest };
    }).sort((left, right) => left.path.localeCompare(right.path));
    const computedBomManifestDigest = digest(normalizedBom);
    const bomFingerprint = currentRelease.bom_fingerprint;
    if (!RELEASE_DIGEST_PATTERN.test(typeof bomFingerprint === "string" ? bomFingerprint : "") || bomFingerprint.toLowerCase() !== computedBomManifestDigest) {
      return releaseFailure("bom_fingerprint_mismatch", { computed_bom_fingerprint: computedBomManifestDigest });
    }
    const bomFileHashes = {};
    for (const entry of normalizedBom) {
      const actualDigest = readReleaseBomFileDigest(entry.path);
      if (actualDigest === null) return releaseFailure("bom_file_missing", { path: entry.path });
      bomFileHashes[entry.path] = actualDigest;
      if (actualDigest !== entry.digest) {
        return releaseFailure("bom_file_hash_mismatch", { path: entry.path, expected_digest: entry.digest, actual_digest: actualDigest });
      }
    }
    const immutableBomSha256 = currentRelease.immutable_bom_sha256;
    if (immutableBomSha256 !== undefined) {
      if (!RELEASE_DIGEST_PATTERN.test(typeof immutableBomSha256 === "string" ? immutableBomSha256 : "")) {
        return releaseFailure("immutable_bom_sha256_invalid", { computed_bom_fingerprint: computedBomManifestDigest });
      }
    }
    const releaseFingerprintBasis = currentRelease.release_fingerprint_basis;
    let computedReleaseFingerprint;
    let releaseFingerprintAlgorithm = "sha256(canonical_current_release_fields)";
    let normalizedReleaseFingerprintBasis = null;
    if (releaseFingerprintBasis !== undefined) {
      const basisAlgorithm = Array.isArray(releaseFingerprintBasis) ? RELEASE_FINGERPRINT_BASIS_ALGORITHMS[releaseFingerprintBasis.length] : undefined;
      if (!basisAlgorithm) {
        return releaseFailure("release_fingerprint_basis_invalid");
      }
      const normalizedBasis = releaseFingerprintBasis.map((entry, index) => {
        const value = requiredString(entry, `release_fingerprint_basis[${index}]`).toLowerCase();
        if (!RELEASE_DIGEST_PATTERN.test(value)) throw new TypeError(`release_fingerprint_basis[${index}] must be a 32-byte digest`);
        return value;
      }).sort();
      if (new Set(normalizedBasis).size !== normalizedBasis.length) return releaseFailure("release_fingerprint_basis_invalid");
      normalizedReleaseFingerprintBasis = normalizedBasis;
      computedReleaseFingerprint = digest(normalizedBasis);
      releaseFingerprintAlgorithm = basisAlgorithm;
    } else {
      computedReleaseFingerprint = digest({
        release_id: releaseId,
        current_release_delta: delta,
        immutable_release_bom: normalizedBom,
        interaction_evidence: interactionEvidence,
        acceptance_state: acceptanceState,
      });
    }
    if (immutableBomSha256 !== undefined && (!normalizedReleaseFingerprintBasis || !normalizedReleaseFingerprintBasis.includes(immutableBomSha256.toLowerCase()))) {
      return releaseFailure("immutable_bom_basis_mismatch");
    }
    if (currentRelease.release_fingerprint !== computedReleaseFingerprint) return releaseFailure("release_fingerprint_mismatch", { computed_release_fingerprint: computedReleaseFingerprint });
    const resultBase = {
      release_identity_valid: true,
      release_id: releaseId,
      release_fingerprint: currentRelease.release_fingerprint,
      release_fingerprint_algorithm: releaseFingerprintAlgorithm,
      bom_fingerprint: bomFingerprint,
      immutable_bom_sha256: immutableBomSha256 ?? null,
      bom_manifest_digest: computedBomManifestDigest,
      bom_file_hashes: Object.freeze({ ...bomFileHashes }),
      bom_files_verified: true,
      chain_valid: false,
      erp_complete: false,
      platform_complete: false,
      publication_complete: false,
    };

    if (!chainEvidence || typeof chainEvidence !== "object" || Array.isArray(chainEvidence)) return releaseFailure("chain_evidence_missing", resultBase);
    if (chainEvidence.release_id !== releaseId || chainEvidence.release_fingerprint !== currentRelease.release_fingerprint || chainEvidence.bom_fingerprint !== currentRelease.bom_fingerprint || (chainEvidence.immutable_bom_sha256 ?? null) !== (immutableBomSha256 ?? null)) {
      return releaseFailure("historical_receipt_guard", resultBase);
    }
    if (chainEvidence.synthetic !== false || chainEvidence.evidence_origin !== "authorized_base_readback" || typeof chainEvidence.readback_ref !== "string" || chainEvidence.readback_ref.trim() === "") {
      return releaseFailure("chain_evidence_provenance_missing", resultBase);
    }
    const chainCaseId = requiredString(chainEvidence.case_id, "chainEvidence.case_id");
    if (chainEvidence.chain_id !== 8453) return releaseFailure("chain_network_not_base_mainnet", resultBase);
    if (requiredString(chainEvidence.sender, "chainEvidence.sender").toLowerCase() !== PRIMARY_BASE_ACCOUNT) return releaseFailure("chain_sender_not_primary_base_account", resultBase);
    const transactionHash = requiredString(chainEvidence.transaction_hash, "chainEvidence.transaction_hash").toLowerCase();
    if (!RELEASE_TRANSACTION_PATTERN.test(transactionHash)) return releaseFailure("chain_transaction_hash_invalid", resultBase);
    if (!/^0x[0-9a-f]{40}$/i.test(requiredString(chainEvidence.target, "chainEvidence.target"))) return releaseFailure("chain_target_invalid", resultBase);
    if (typeof chainEvidence.target_semantics !== "string" || chainEvidence.target_semantics.trim() === "") return releaseFailure("chain_target_semantics_missing", resultBase);
    if (!RELEASE_DIGEST_PATTERN.test(requiredString(chainEvidence.calldata_hash, "chainEvidence.calldata_hash"))) return releaseFailure("chain_calldata_hash_invalid", resultBase);
    if (chainEvidence.state_change !== true || chainEvidence.unique !== true || chainEvidence.reorged !== false || chainEvidence.dedup_verified !== true || chainEvidence.replay_locked !== true) {
      return releaseFailure("chain_dedup_or_state_change_not_proven", resultBase);
    }
    const finality = mapBaseFinality({
      stage: chainEvidence.finality_stage,
      receiptStatus: chainEvidence.receipt_status,
      reorged: chainEvidence.reorged,
      stateChange: chainEvidence.state_change,
      l1Finalized: chainEvidence.l1_finalized,
      claimedFinality: chainEvidence.finality,
    });
    if (!finality.ok) return releaseFailure("chain_finality_rejected", { ...resultBase, finality_reason: finality.reason });
    const calls = mapWalletCallsStatus(chainEvidence.wallet_calls_status);
    if (!calls.ok) return releaseFailure("wallet_calls_status_rejected", { ...resultBase, wallet_calls_reason: calls.reason });
    const callReceiptHashes = calls.receipts.map(({ transaction_hash: hash }) => hash);
    if (callReceiptHashes.length === 1 && callReceiptHashes[0] !== transactionHash) {
      return releaseFailure("wallet_calls_receipts_transaction_mismatch", resultBase);
    }
    if (callReceiptHashes.length > 1) {
      const declaredReceiptHashes = chainEvidence.receipt_transaction_hashes;
      if (!Array.isArray(declaredReceiptHashes) || declaredReceiptHashes.length !== callReceiptHashes.length || declaredReceiptHashes.some((hash) => typeof hash !== "string" || !RELEASE_TRANSACTION_PATTERN.test(hash))) {
        return releaseFailure("wallet_calls_receipts_transaction_mismatch", resultBase);
      }
      const actual = [...callReceiptHashes].sort();
      const declared = declaredReceiptHashes.map((hash) => hash.toLowerCase()).sort();
      if (new Set(actual).size !== actual.length || new Set(declared).size !== declared.length || !declared.includes(transactionHash) || actual.some((hash, index) => hash !== declared[index])) {
        return releaseFailure("wallet_calls_receipts_transaction_mismatch", resultBase);
      }
    }
    const chainResult = { ...resultBase, chain_valid: true, finality, wallet_calls_status: calls };

    if (!erpReadback || typeof erpReadback !== "object" || Array.isArray(erpReadback)) return releaseFailure("erp_readback_missing", chainResult);
    if (erpReadback.release_id !== releaseId || erpReadback.release_fingerprint !== currentRelease.release_fingerprint || erpReadback.bom_fingerprint !== currentRelease.bom_fingerprint || (erpReadback.immutable_bom_sha256 ?? null) !== (immutableBomSha256 ?? null)) {
      return releaseFailure("historical_receipt_guard", chainResult);
    }
    if (erpReadback.synthetic !== false || erpReadback.evidence_origin !== "authorized_erp_readback" || typeof erpReadback.readback_ref !== "string" || erpReadback.readback_ref.trim() === "") {
      return releaseFailure("erp_readback_provenance_missing", chainResult);
    }
    if (erpReadback.case_id !== chainCaseId) return releaseFailure("erp_case_identity_mismatch", chainResult);
    if (erpReadback.authoritative !== true || erpReadback.status !== "posted" || typeof erpReadback.case_id !== "string" || erpReadback.case_id.trim() === "") {
      return releaseFailure("erp_readback_not_authoritative", chainResult);
    }
    const erpResult = { ...chainResult, erp_complete: true, erp_case_id: erpReadback.case_id };
    const surfaces = currentRelease.eight_surface_evidence_map;
    if (!surfaces || typeof surfaces !== "object" || Array.isArray(surfaces)) return releaseFailure("eight_platform_gate_incomplete", erpResult);
    const receiptIds = new Set();
    const outcomeDigests = new Set();
    for (const platform of RELEASE_PLATFORMS) {
      const evidence = surfaces[platform];
      if (!evidence || typeof evidence !== "object") return releaseFailure("eight_platform_gate_incomplete", { ...erpResult, missing_platform: platform });
      if (evidence.release_id !== releaseId || evidence.release_fingerprint !== currentRelease.release_fingerprint || evidence.bom_fingerprint !== currentRelease.bom_fingerprint || (evidence.immutable_bom_sha256 ?? null) !== (immutableBomSha256 ?? null) || evidence.historical === true) {
        return releaseFailure("historical_receipt_guard", erpResult);
      }
      if (evidence.synthetic !== false || evidence.evidence_origin !== "official_platform_readback" || typeof evidence.proof_ref !== "string" || evidence.proof_ref.trim() === "") {
        return releaseFailure("platform_evidence_provenance_missing", { ...erpResult, platform });
      }
      if (evidence.platform !== platform || evidence.current !== true || evidence.independent !== true || evidence.status !== "verified") return releaseFailure("platform_receipt_not_independent", { ...erpResult, platform });
      const receiptId = requiredString(evidence.receipt_id, `${platform}.receipt_id`);
      if (receiptIds.has(receiptId)) return releaseFailure("platform_receipt_not_independent", { ...erpResult, platform });
      receiptIds.add(receiptId);
      const outcomeDigest = requiredString(evidence.material_outcome_digest, `${platform}.material_outcome_digest`).toLowerCase();
      if (!RELEASE_DIGEST_PATTERN.test(outcomeDigest)) return releaseFailure("platform_outcome_digest_invalid", { ...erpResult, platform });
      outcomeDigests.add(outcomeDigest);
    }
    if (outcomeDigests.size !== 1) return releaseFailure("platform_outcome_mismatch", erpResult);
    const publicEvidenceResult = validateEightSurfacePublicEvidence({
      surfaces,
      releaseId,
      releaseFingerprint: currentRelease.release_fingerprint,
      bomFingerprint: currentRelease.bom_fingerprint,
      immutableBomSha256,
    });
    if (!publicEvidenceResult.ok) return releaseFailure(publicEvidenceResult.reason, { ...erpResult, platform: publicEvidenceResult.platform, field: publicEvidenceResult.field });
    const platformResult = { ...erpResult, platform_complete: true, platform_count: RELEASE_PLATFORMS.length, public_surface_contract_id: publicEvidenceResult.contract_id };
    if (acceptanceState.independent_sol_medium !== "pass") return releaseFailure("independent_review_pending", platformResult);
    if (acceptanceState.owner_gate !== "owner_visible") return releaseFailure("owner_gate_missing", platformResult);
    return Object.freeze({ ...platformResult, ok: true, fail_closed: false, publication_complete: true });
  } catch (error) {
    return releaseFailure("invalid_release_integrity_input", { message: error.message });
  }
}

export function buildSettlementCase(input) {
  if (!input || typeof input !== "object") throw new TypeError("input must be an object");
  const source = requiredString(input.source, "source");
  const direction = requiredString(input.direction, "direction");
  const network = requiredString(input.network, "network");
  if (!SOURCES.has(source)) throw new RangeError(`unsupported source: ${source}`);
  if (!DIRECTIONS.has(direction)) throw new RangeError(`unsupported direction: ${direction}`);
  if (!NETWORKS[network]) throw new RangeError(`unsupported network: ${network}`);
  if (!SOURCE_NETWORKS[source].includes(network)) {
    if (source === "b20") throw new RangeError("B20 experimental cases must start on Base Vibenet");
    if (source === "swap") throw new RangeError("swap cases require Base Mainnet; testnet swaps are unsupported");
    if (source === "x402") throw new RangeError("x402 cases require Base Mainnet or Base Sepolia");
    throw new RangeError(`${source} cases are unsupported on ${network}`);
  }

  const wallet = normalizeAddress(input.wallet, "wallet");
  const amount = requiredString(input.amount, "amount");
  const asset = requiredString(input.asset, "asset");
  const businessReference = input.businessReference ? requiredString(input.businessReference, "businessReference") : null;
  const scenario = routeScenario(source, direction);
  const fingerprintInput = JSON.stringify({ source, direction, network, wallet, amount, asset, businessReference });
  const fingerprint = createHash("sha256").update(fingerprintInput).digest("hex");

  return {
    caseId: `base-erp-${fingerprint.slice(0, 16)}`,
    fingerprint,
    scenario,
    source,
    direction,
    network,
    chainId: NETWORKS[network].chainId,
    wallet,
    amount,
    asset,
    businessReference,
    identityStatus: wallet === PRIMARY_BASE_ACCOUNT ? "primary_base_account" : "non_primary_wallet",
    experimental: network === "base_vibenet",
    evidenceLevel: "L0",
    chainStatus: "unverified",
    erpStatus: "unmatched",
    dailyCountEligible: false,
  };
}

export function applyReceipt(caseRecord, receipt) {
  if (!caseRecord || typeof caseRecord !== "object") throw new TypeError("caseRecord must be an object");
  if (!receipt || typeof receipt !== "object") throw new TypeError("receipt must be an object");
  const transactionHash = requiredString(receipt.transactionHash, "transactionHash").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(transactionHash)) throw new TypeError("transactionHash must be 32-byte hex");
  if (receipt.chainId !== caseRecord.chainId) throw new RangeError("receipt chain does not match case network");
  if (receipt.status !== "success") throw new RangeError("only successful receipts can advance evidence");
  if (receipt.unique !== true) throw new RangeError("receipt uniqueness must be proven");
  if (receipt.finality !== "final") throw new RangeError("receipt finality must be final");
  if (receipt.reorged === true) throw new RangeError("reorged receipts cannot advance evidence");
  if (receipt.stateChange !== true) throw new RangeError("receipt must prove a state-changing execution");

  let receiptEvidenceDigest;
  let finalityMapping;
  if (receipt.finalityStage !== undefined) {
    finalityMapping = mapBaseFinality({
      stage: receipt.finalityStage,
      receiptStatus: receipt.receiptStatus,
      reorged: receipt.reorged,
      stateChange: receipt.stateChange,
      l1Finalized: receipt.l1Finalized,
      claimedFinality: receipt.finality,
    });
    if (!finalityMapping.ok) throw new RangeError(`Base finality rejected: ${finalityMapping.reason}`);
  }
  let walletCallsMapping;
  if (receipt.walletCallsStatus !== undefined) {
    walletCallsMapping = mapWalletCallsStatus(receipt.walletCallsStatus);
    if (!walletCallsMapping.ok) throw new RangeError(`wallet_getCallsStatus rejected: ${walletCallsMapping.reason}`);
  }
  if (receipt.controlEvidence !== undefined) {
    const evidence = validateReceiptEvidence({
      evidence: receipt.controlEvidence,
      expected: { chainId: caseRecord.chainId, caseId: caseRecord.caseId },
    });
    if (!evidence.ok) throw new RangeError(`receipt control evidence rejected: ${evidence.reason}`);
    receiptEvidenceDigest = evidence.evidence_digest;
  }

  const mainnetPrimary = caseRecord.network === "base_mainnet" && caseRecord.wallet === PRIMARY_BASE_ACCOUNT;
  return {
    ...caseRecord,
    transactionHash,
    receiptFinality: receipt.finality,
    stateChange: receipt.stateChange,
    ...(receiptEvidenceDigest ? { receiptEvidenceDigest } : {}),
    ...(finalityMapping ? { baseFinality: finalityMapping } : {}),
    ...(walletCallsMapping ? { walletCallsStatus: walletCallsMapping } : {}),
    chainStatus: "confirmed_unique",
    evidenceLevel: "L2",
    dailyCountEligible: mainnetPrimary,
  };
}

export function applyErpReadback(caseRecord, readback) {
  if (!caseRecord || caseRecord.chainStatus !== "confirmed_unique") {
    throw new RangeError("ERP evidence requires a confirmed unique chain receipt");
  }
  if (!caseRecord.businessReference) throw new RangeError("ERP posting requires an explicit business reference");
  if (!readback || readback.authoritative !== true || readback.status !== "posted") {
    throw new RangeError("ERP readback must be authoritative and posted");
  }
  if (readback.caseId !== caseRecord.caseId) throw new RangeError("ERP readback case does not match settlement case");
  if (readback.fingerprint !== caseRecord.fingerprint) throw new RangeError("ERP readback fingerprint does not match settlement case");
  const documentId = requiredString(readback.documentId, "documentId");
  return {
    ...caseRecord,
    erpStatus: "posted_readback_verified",
    erpDocumentId: documentId,
    evidenceLevel: caseRecord.dailyCountEligible ? "L3" : "L2",
  };
}
