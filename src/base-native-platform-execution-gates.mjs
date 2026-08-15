import { createHash } from "node:crypto";

/**
 * H217 is deliberately a read-only product/evidence contract.  It models the
 * remaining owner/platform gates without creating wallet requests, receipts,
 * deployments, queue work, or a second eight-platform publication unit.
 */
export const SCHEMA_VERSION = "base-erp-h217-platform-execution-gates-v1";
export const READBACK_SCHEMA_VERSION = "base-erp-h217-platform-execution-gates-readback-v1";
export const H217_PACKET_ID = "base-erp-h217-remaining-platform-execution-gates-20260815";
export const H217_BATCH_ID = "BASE_ERP_H217_REMAINING_PLATFORM_EXECUTION_GATES_20260815";
export const EXECUTION_AUTHORITY = "none_until_02_Build_revalidates";
export const AUTHORITY_NONE = EXECUTION_AUTHORITY;

export const H217_SOURCE_HASHES = Object.freeze({
  manifest_sha256: "dbd6b5257aa5472a8e4621ec1ecd0c9a8ea2270c37b821912d86a9229f82b4a8",
  artifact_sha256: "a886f3d35ddff84852448de5ca5832087bf879c7d840b70bc9e6719e7e92acc8",
  handoff_sha256: "853970cc363c22a1d366ea0c6b217f9fe73fd70c01da1e1e4c595f3c0bc32124",
});

export const RELEASE_JOIN_FIELDS = Object.freeze(["release_id", "release_fingerprint", "bom_fingerprint"]);
export const H217_RELEASE_ENVELOPE = Object.freeze({
  release_id: "base-erp-public-product-20260815-v7",
  release_fingerprint: "bfd8e57684b0c43bb92dbc9ac3bcd7426b226dc816541c008c7085b7cc6ae5ae",
  bom_fingerprint: "3b856d0a18fc996b47e5bb4bb0b4c06a73e28ff2f5a0ce13e08612b27ad3529c",
  commit_sha: "5459eaf3b8000b5a85197516d0b72a5cc46e03a5",
  github_release_url: "https://github.com/gaysonloser/base-erp-settlement-workbench/releases/tag/base-erp-public-product-20260815-v7",
  render_service_id: "srv-d9t0bsafngtc7387gqo0",
  render_deployment_id: "dep-da00nk1t0dsc738jpuv0",
  render_release_url: "https://base-erp-settlement-workbench.onrender.com/release.json",
  render_health_url: "https://base-erp-settlement-workbench.onrender.com/healthz",
  render_http_status: 200,
  render_ready: true,
  render_status: "ok",
  render_git_commit: "5459eaf3b8000b5a85197516d0b72a5cc46e03a5",
  canonical_dashboard_app_id: "6a7a0717e209a55163497d2d",
  canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com",
});
export const H217_RELEASE_JOIN = Object.freeze(Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, H217_RELEASE_ENVELOPE[field]])));
export const RELEASE_ENVELOPE = H217_RELEASE_ENVELOPE;

export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_SEPOLIA_CHAIN_ID_HEX = "0x14a34";
export const BASE_SEPOLIA_NETWORK = "base-sepolia";
export const BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org";
export const BASE_SEPOLIA_EXPLORER_URL = "https://sepolia.basescan.org";
export const BASE_SEPOLIA_DESCRIPTOR = Object.freeze({
  network: BASE_SEPOLIA_NETWORK,
  chain_id: BASE_SEPOLIA_CHAIN_ID,
  chain_id_hex: BASE_SEPOLIA_CHAIN_ID_HEX,
  rpc_url: BASE_SEPOLIA_RPC_URL,
  explorer_url: BASE_SEPOLIA_EXPLORER_URL,
  rehearsal_only: true,
});
export const BASE_SEPOLIA = BASE_SEPOLIA_DESCRIPTOR;
export const FINALITY_STAGES = Object.freeze(["flashblock", "l2_block", "l1_batch", "l1_batch_finality"]);

export const H217_PLATFORM_ROW_IDS = Object.freeze([
  "base_sepolia_rehearsal",
  "talent_native_domain",
  "guild_native_domain",
  "basename_base_org_identity",
]);
export const PLATFORM_ROW_IDS = H217_PLATFORM_ROW_IDS;
export const H217_PLATFORM_ROWS = H217_PLATFORM_ROW_IDS;
export const PLATFORM_ROWS = H217_PLATFORM_ROW_IDS;

const ROW_CONTRACTS = {
  base_sepolia_rehearsal: {
    label: "Base Sepolia descriptor/receipt/finality rehearsal",
    evidence_class: "rehearsal_descriptor_receipt_finality",
  },
  talent_native_domain: {
    label: "Talent native-domain project/profile outcome",
    evidence_class: "native_domain_profile_project_reputation",
  },
  guild_native_domain: {
    label: "Guild native-domain community outcome",
    evidence_class: "native_domain_community_roles_requirements_rewards",
  },
  basename_base_org_identity: {
    label: "Basename/base.org account-level identity outcome",
    evidence_class: "account_level_singleton_identity",
  },
};
export const PLATFORM_CONTRACTS = Object.freeze({
  base_sepolia_rehearsal: Object.freeze({ ...ROW_CONTRACTS.base_sepolia_rehearsal, descriptor: BASE_SEPOLIA_DESCRIPTOR, release_receipt: false }),
  talent_native_domain: Object.freeze({ ...ROW_CONTRACTS.talent_native_domain, release_receipt: false }),
  guild_native_domain: Object.freeze({ ...ROW_CONTRACTS.guild_native_domain, release_receipt: false }),
  basename_base_org_identity: Object.freeze({ ...ROW_CONTRACTS.basename_base_org_identity, release_receipt: false }),
});

const VECTOR_DEFINITIONS = [
  ["H217-01", "Base Sepolia descriptor", "chain_id=84532 and current official URLs", "descriptor_valid; credit=0"],
  ["H217-02", "Base Sepolia wrong descriptor", "wrong chain id or non-official explorer", "fail_closed; credit=0"],
  ["H217-03", "Sepolia receipt missing", "transaction_hash=null or receipt=null", "rehearsal_pending; no receipt; credit=0"],
  ["H217-04", "Sepolia finality missing", "receipt success without explicit finality_stage", "finality_missing; credit=0"],
  ["H217-05", "Sepolia explicit finality", "receipt plus one of flashblock/l2_block/l1_batch/l1_batch_finality", "rehearsal_readback_valid; still credit=0"],
  ["H217-06", "v7 release join", "v7 release_id, release_fingerprint and bom_fingerprint all match GitHub/Render", "current_release_join_valid"],
  ["H217-07", "Talent exact search empty", "Talent exact title search returns projects_found=0", "owner_gate; native outcome absent; credit=0"],
  ["H217-08", "Talent project readback", "Talent owner readback supplies exact project URL/id and current release mapping", "native_domain_readback; no release receipt unless documented schema exists"],
  ["H217-09", "Talent authentication gate", "Talent API key or sign-in required", "stop; no auth/write; credit=0"],
  ["H217-10", "Guild generic page", "generic Guild Base page with member count and Join Guild", "context_only; no project outcome; credit=0"],
  ["H217-11", "Guild project readback", "Guild exact project URL plus owner/admin or visitor roles/requirements/rewards readback", "native_domain_readback; no release receipt"],
  ["H217-12", "Basename singleton", "Basename primary/resolver readback with account_level_singleton=true", "identity_only; release_join=null; credit=0"],
  ["H217-13", "Basename release misuse", "Basename registration or profile page proposed as project receipt", "reject; identity_receipt_not_release_receipt"],
  ["H217-14", "Receipt duplication", "four H217 rows aggregated as eight publication receipts", "reject duplication; aggregate credit=0"],
  ["H217-15", "CIRCLE collision", "any BASE target equals a CIRCLE repo/service/app/domain/release/receipt", "fail_closed; no read/write"],
  ["H217-16", "Stale/write invalidation", "stale official URL, missing release field or external write request", "invalidated; stop; no mutation"],
];
export const H217_TEST_VECTORS = Object.freeze(VECTOR_DEFINITIONS.map(([id, name, input, expected]) => Object.freeze({ id, name, input, expected })));
export const TEST_VECTOR_IDS = Object.freeze(H217_TEST_VECTORS.map((item) => item.id));
export const H217_VECTOR_IDS = TEST_VECTOR_IDS;

const FAILURE_DEFINITIONS = [
  ["F01", "stale_or_mismatched_v7_release_id", "stop"],
  ["F02", "release_fingerprint_or_bom_mismatch", "stop"],
  ["F03", "base_sepolia_descriptor_mismatch", "stop"],
  ["F04", "sepolia_receipt_missing_or_invalid", "stop"],
  ["F05", "sepolia_finality_inferred_or_missing", "stop"],
  ["F06", "talent_project_absent_or_inferred", "stop"],
  ["F07", "talent_authentication_or_api_key_gate", "owner_gate"],
  ["F08", "talent_profile_promoted_to_release_receipt", "stop"],
  ["F09", "guild_generic_or_sign_in_gate", "stop"],
  ["F10", "guild_dynamic_fields_without_project_readback", "owner_gate"],
  ["F11", "basename_identity_used_as_project_release", "stop"],
  ["F12", "basename_owner_or_resolver_unverified", "owner_gate"],
  ["F13", "dashboard_basedev_alias_duplication", "stop"],
  ["F14", "circle_target_collision", "fail_closed"],
  ["F15", "unsupported_or_duplicated_receipts", "reject"],
  ["F16", "external_write_or_queue_mutation_attempt", "forbidden"],
];
export const H217_FAILURE_MODES = Object.freeze(FAILURE_DEFINITIONS.map(([source_id, code, default_state]) => Object.freeze({
  id: `H217-${source_id}`,
  source_id,
  name: code,
  code,
  default_state,
  fail_closed: true,
  credit: 0,
})));
export const FAILURE_MODE_IDS = Object.freeze(H217_FAILURE_MODES.map((item) => item.id));
export const H217_FAILURE_MODE_RECORDS = H217_FAILURE_MODES;
export const FAILURE_MODES = H217_FAILURE_MODES;

export const CIRCLE_DENYLIST = Object.freeze([
  "gaysonloser/arc-payment-receipt",
  "srv-d9cumml8nd3s73c9nehg",
  "arc-payment-receipt.onrender.com",
  "programme-final-20260810",
]);

const HASH_RE = /^[0-9a-f]{64}$/i;
const TX_HASH_RE = /^0x[0-9a-f]{64}$/i;
const CIRCLE_WORD_RE = /(^|[^a-z])(circle|arc-payment-receipt|arc[_ -]?payment[_ -]?receipt)([^a-z]|$)/i;
const FINALITY_ALIASES = new Map([
  ["flashblock", "flashblock"],
  ["flashblock_preconfirmation", "flashblock"],
  ["l2_block", "l2_block"],
  ["l2_block_inclusion", "l2_block"],
  ["l1_batch", "l1_batch"],
  ["l1_batch_inclusion", "l1_batch"],
  ["l1_batch_finality", "l1_batch_finality"],
]);

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}

export function digest(value) {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

function text(value) {
  return typeof value === "string" ? value.trim() : value === null || value === undefined ? "" : String(value).trim();
}

function nonEmpty(value) {
  return text(value).length > 0;
}

function hash(value) {
  return HASH_RE.test(text(value));
}

function chainId(value) {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^0x[0-9a-f]+$/i.test(value)) return Number.parseInt(value, 16);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return null;
}

function txHash(value) {
  return TX_HASH_RE.test(text(value));
}

function normalizeFinality(value) {
  return FINALITY_ALIASES.get(text(value).toLowerCase()) ?? null;
}

function containsCircle(value) {
  if (typeof value === "string") return CIRCLE_DENYLIST.some((entry) => value.toLowerCase().includes(entry.toLowerCase())) || CIRCLE_WORD_RE.test(value);
  if (Array.isArray(value)) return value.some(containsCircle);
  if (value && typeof value === "object") return Object.values(value).some(containsCircle);
  return false;
}

function baseRow(platform_row_id, overrides = {}) {
  const contract = ROW_CONTRACTS[platform_row_id] ?? { label: platform_row_id, evidence_class: "unknown" };
  return {
    platform_row_id,
    platform: platform_row_id,
    label: contract.label,
    evidence_class: contract.evidence_class,
    target_identity: null,
    owner_readback: null,
    native_receipt: null,
    release_join: null,
    release_receipt: false,
    failure_state: { id: "H217-F16", code: "not_observed" },
    status: "not_accepted",
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    ...overrides,
  };
}

function failRow(id, reason, failureId, details = {}) {
  return baseRow(id, {
    status: "owner_platform_gate",
    state: "owner_platform_gate",
    reason,
    failure_state: { id: failureId, code: failureId.replace(/^H217-/, "") },
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    ...details,
  });
}

function safeReadback(value) {
  if (value === true) return { present: true };
  if (!value || typeof value !== "object" || Array.isArray(value)) return value ? { present: true } : null;
  const safe = {};
  for (const key of ["project_id", "project_url", "title", "profile_id", "guild_slug", "roles", "requirements", "rewards", "visitor_page", "owner_admin_readback", "current_release_join"]) {
    if (value[key] !== undefined) safe[key] = clone(value[key]);
  }
  return Object.keys(safe).length ? safe : { present: true };
}

export function validateBaseCircleIsolation(value, { platform = null } = {}) {
  const collision = containsCircle(value);
  return {
    schema_version: SCHEMA_VERSION,
    ok: !collision,
    fail_closed: collision,
    state: collision ? "owner_platform_gate_no_overwrite" : "base_identity_isolated",
    reason: collision ? "base_circle_identity_collision" : "base_target_isolated",
    failure_id: collision ? "H217-F14" : null,
    platform,
    circle_collision: collision,
    circle_target_absent: !collision,
    action_enabled: false,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
  };
}

export const checkBaseCircleIsolation = (value = {}) => validateBaseCircleIsolation(value);
export const CIRCLE_ISOLATION_DENYLIST = CIRCLE_DENYLIST;

function releaseJoinFrom(value = {}) {
  const source = value.release_join ?? value.releaseJoin ?? value;
  return Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, source?.[field] ?? null]));
}

function completeReleaseJoin(join) {
  return nonEmpty(join?.release_id) && hash(join?.release_fingerprint) && hash(join?.bom_fingerprint);
}

export function compareReleaseJoin(left = {}, right = {}, expected = null) {
  const a = releaseJoinFrom(left);
  const b = releaseJoinFrom(right);
  const e = expected ? releaseJoinFrom(expected) : null;
  const mismatch_fields = RELEASE_JOIN_FIELDS.filter((field) => a[field] !== b[field] || (e && a[field] !== e[field]));
  return { same_release: mismatch_fields.length === 0 && completeReleaseJoin(a), release_join: a, compared_fields: RELEASE_JOIN_FIELDS, mismatch_fields, credit: 0 };
}

export const joinReleaseEnvelope = compareReleaseJoin;

export function validateH217ReleaseEnvelope(value = {}, expected = H217_RELEASE_ENVELOPE) {
  const actual = value.release_join ?? value;
  // A row-level release_join intentionally carries only the three immutable
  // join fields.  The full public envelope may additionally carry commit_sha;
  // require that field only when the caller supplied it.
  const fields = [...RELEASE_JOIN_FIELDS, ...(actual?.commit_sha !== undefined ? ["commit_sha"] : [])];
  const mismatch_fields = fields.filter((field) => actual?.[field] !== expected?.[field]);
  const ok = mismatch_fields.length === 0 && completeReleaseJoin(actual);
  return {
    schema_version: SCHEMA_VERSION,
    ok,
    fail_closed: !ok,
    state: ok ? "current_release_join_valid" : "owner_platform_gate",
    reason: ok ? "current_v7_release_envelope" : mismatch_fields.some((field) => field.includes("fingerprint") || field === "bom_fingerprint") ? "release_fingerprint_or_bom_mismatch" : "stale_or_mismatched_v7_release_id",
    failure_id: ok ? null : mismatch_fields.some((field) => field.includes("fingerprint") || field === "bom_fingerprint") ? "H217-F02" : "H217-F01",
    release_join: releaseJoinFrom(actual),
    mismatch_fields,
    credit: 0,
    external_actions: 0,
  };
}

export const validateCurrentV7Release = validateH217ReleaseEnvelope;

export function validateH217PublicEnvelope({ release = null, github = null, render = null, dashboard = null } = {}) {
  const releaseCheck = validateH217ReleaseEnvelope(release ?? {});
  // A release hash alone is not a public receipt.  All three independent
  // readbacks are mandatory: GitHub source, Render deployment/health, and the
  // canonical Dashboard/Base.dev identity.
  const githubOk = Boolean(github) && github.repo === "gaysonloser/base-erp-settlement-workbench" && github.branch === "main" && github.commit_sha === H217_RELEASE_ENVELOPE.commit_sha && validateH217ReleaseEnvelope(github).ok;
  const renderOk = Boolean(render) && render.service_id === H217_RELEASE_ENVELOPE.render_service_id && render.deployment_id === H217_RELEASE_ENVELOPE.render_deployment_id && render.commit_sha === H217_RELEASE_ENVELOPE.commit_sha && render.health_ready === true && render.health_status === "ok" && validateH217ReleaseEnvelope(render).ok;
  const dashboardOk = Boolean(dashboard) && dashboard.app_id === H217_RELEASE_ENVELOPE.canonical_dashboard_app_id && dashboard.primary_url === H217_RELEASE_ENVELOPE.canonical_primary_url;
  const isolation = validateBaseCircleIsolation({ release, github, render, dashboard }, { platform: "h217_public_envelope" });
  const ok = releaseCheck.ok && githubOk && renderOk && dashboardOk && isolation.ok;
  return {
    schema_version: SCHEMA_VERSION,
    ok,
    fail_closed: !ok,
    state: ok ? "current_v7_public_envelope_valid" : "owner_platform_gate",
    reason: ok ? "v7_github_render_dashboard_join_valid" : !isolation.ok ? "circle_target_collision" : !releaseCheck.ok ? releaseCheck.reason : "public_target_readback_mismatch",
    failure_id: ok ? null : !isolation.ok ? "H217-F14" : !releaseCheck.ok ? releaseCheck.failure_id : "H217-F01",
    release: releaseCheck,
    legs: { github: githubOk, render: renderOk, dashboard: dashboardOk },
    circle_target_absent: isolation.ok,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
  };
}

export const validateV7PublicEnvelope = validateH217PublicEnvelope;

export function evaluateBaseSepoliaRehearsal(input = {}) {
  const descriptor = { ...BASE_SEPOLIA_DESCRIPTOR, ...(input.descriptor ?? {}) };
  const isolation = validateBaseCircleIsolation({ descriptor, target: input.target }, { platform: "base_sepolia_rehearsal" });
  if (!isolation.ok) return { ...failRow("base_sepolia_rehearsal", "circle_target_collision", "H217-F14"), ...isolation };
  const descriptorValid = descriptor.network === BASE_SEPOLIA_NETWORK && chainId(descriptor.chain_id) === BASE_SEPOLIA_CHAIN_ID && descriptor.chain_id_hex === BASE_SEPOLIA_CHAIN_ID_HEX && descriptor.rpc_url === BASE_SEPOLIA_RPC_URL && descriptor.explorer_url === BASE_SEPOLIA_EXPLORER_URL && descriptor.rehearsal_only === true;
  if (!descriptorValid) return failRow("base_sepolia_rehearsal", "descriptor_mismatch", "H217-F03", { target_identity: descriptor });
  const receipt = input.receipt ?? input.native_receipt ?? null;
  const common = { target_identity: clone(descriptor), owner_readback: safeReadback(input.owner_readback), release_join: null, native_receipt: clone(receipt) };
  if (!receipt) return baseRow("base_sepolia_rehearsal", { ...common, status: "rehearsal_pending", state: "rehearsal_pending", reason: "descriptor_valid_receipt_missing", failure_state: { id: "H217-F04", code: "sepolia_receipt_missing_or_invalid" }, finality_stage: null });
  const receiptChain = chainId(receipt.chain_id ?? receipt.chainId);
  const transactionHash = receipt.transaction_hash ?? receipt.transactionHash;
  const blockHash = receipt.block_hash ?? receipt.blockHash;
  const blockNumber = receipt.block_number ?? receipt.blockNumber;
  const status = text(receipt.status).toLowerCase();
  const receiptValid = receiptChain === BASE_SEPOLIA_CHAIN_ID && txHash(transactionHash) && txHash(blockHash) && blockNumber !== undefined && blockNumber !== null && Array.isArray(receipt.logs) && ["0x1", "1", "success", "succeeded"].includes(status);
  if (!receiptValid) return baseRow("base_sepolia_rehearsal", { ...common, status: "rehearsal_pending", state: "rehearsal_pending", reason: "receipt_missing_or_invalid", failure_state: { id: "H217-F04", code: "sepolia_receipt_missing_or_invalid" }, finality_stage: null });
  const finality_stage = normalizeFinality(input.finality_stage ?? input.finalityStage);
  const normalizedReceipt = { ...clone(receipt), transaction_hash: transactionHash, block_hash: blockHash, block_number: blockNumber };
  if (!finality_stage) return baseRow("base_sepolia_rehearsal", { ...common, native_receipt: normalizedReceipt, status: "finality_missing", state: "finality_missing", reason: "receipt_success_without_explicit_finality", failure_state: { id: "H217-F05", code: "sepolia_finality_inferred_or_missing" }, finality_stage: null });
  return baseRow("base_sepolia_rehearsal", { ...common, native_receipt: normalizedReceipt, status: "rehearsal_readback_valid", state: "rehearsal_readback_valid", reason: "receipt_and_explicit_finality_observed", failure_state: null, finality_stage, release_receipt: false });
}

export const evaluateBaseSepolia = evaluateBaseSepoliaRehearsal;

function hasAuthOrWrite(input) {
  return input.external_write === true || input.write_requested === true || input.write_gate === true || input.api_key_required === true || input.api_key || input.x_api_key || input.login_required === true || input.auth_required === true || input.requires_auth === true || input.wallet || input.signature || input.credential;
}

function currentJoin(input) {
  return input.current_release_join ?? input.release_join ?? input.currentReleaseJoin ?? null;
}

export function evaluateTalentNativeDomain(input = {}) {
  const isolation = validateBaseCircleIsolation(input, { platform: "talent_native_domain" });
  if (!isolation.ok) return { ...failRow("talent_native_domain", "circle_target_collision", "H217-F14"), ...isolation };
  if (input.external_write === true || input.write_requested === true || input.write_gate === true) return failRow("talent_native_domain", "external_write_attempt_rejected", "H217-F16", { owner_gate: true, write_authorized: false });
  if (hasAuthOrWrite(input)) return failRow("talent_native_domain", "talent_authentication_or_api_key_gate", "H217-F07", { owner_gate: true, write_authorized: false });
  if (input.http_status === 429 || input.security_checkpoint === 429) return failRow("talent_native_domain", "talent_authentication_or_api_key_gate", "H217-F07", { status: "unavailable", state: "unavailable", owner_gate: true });
  if (input.projects_found === 0) return failRow("talent_native_domain", "talent_exact_project_absent", "H217-F06", { status: "owner_gate", owner_gate: true, project_identity_observed: false });
  const project_id = input.project_id ?? input.projectId ?? null;
  const project_url = input.project_url ?? input.projectUrl ?? null;
  const ownerReadback = input.owner_readback ?? input.ownerReadback ?? input.owner_controlled_readback;
  if (!nonEmpty(project_id) && !nonEmpty(project_url)) return failRow("talent_native_domain", "talent_exact_project_absent_or_inferred", "H217-F06", { owner_gate: true });
  if (ownerReadback !== true && (!ownerReadback || typeof ownerReadback !== "object")) return failRow("talent_native_domain", "talent_owner_readback_missing", "H217-F06", { owner_gate: true, target_identity: { project_id, project_url } });
  const join = currentJoin(input);
  if (join) {
    const releaseCheck = validateH217ReleaseEnvelope(join);
    if (!releaseCheck.ok) return failRow("talent_native_domain", releaseCheck.reason, releaseCheck.failure_id, { target_identity: { project_id, project_url }, release_join: releaseJoinFrom(join) });
  }
  return baseRow("talent_native_domain", { status: "native_domain_readback", state: "native_domain_readback", reason: "exact_project_owner_readback", target_identity: { project_id, project_url }, owner_readback: safeReadback(ownerReadback), release_join: join ? releaseJoinFrom(join) : null, release_receipt: false, native_receipt: null, failure_state: null });
}

export const evaluateTalentDomain = evaluateTalentNativeDomain;
export const evaluateTalentEvidence = evaluateTalentNativeDomain;

export function evaluateGuildNativeDomain(input = {}) {
  const isolation = validateBaseCircleIsolation(input, { platform: "guild_native_domain" });
  if (!isolation.ok) return { ...failRow("guild_native_domain", "circle_target_collision", "H217-F14"), ...isolation };
  if (input.external_write === true || input.write_requested === true || input.write_gate === true || input.login_required === true || input.auth_required === true || input.credential) return failRow("guild_native_domain", "external_write_attempt_rejected", "H217-F16", { owner_gate: true, write_authorized: false });
  const project_url = input.project_url ?? input.projectUrl ?? null;
  const guild_slug = input.guild_slug ?? input.slug ?? null;
  if (input.generic_base_page === true || (!nonEmpty(project_url) && !nonEmpty(guild_slug))) return baseRow("guild_native_domain", { status: "context_only", state: "context_only", reason: "generic_base_guild_or_sign_in_gate", target_identity: { project_url, guild_slug }, failure_state: { id: "H217-F09", code: "guild_generic_or_sign_in_gate" } });
  const visitor = input.visitor_readback ?? input.visitor_fields;
  const admin = input.owner_admin_readback ?? input.admin_readback;
  const readback = visitor ?? admin;
  const hasFields = readback && typeof readback === "object" && ["roles", "requirements", "rewards"].every((key) => readback[key] !== undefined);
  if (!hasFields) return failRow("guild_native_domain", "guild_project_readback_incomplete", "H217-F10", { owner_gate: true, target_identity: { project_url, guild_slug } });
  const join = currentJoin(input);
  if (join) {
    const releaseCheck = validateH217ReleaseEnvelope(join);
    if (!releaseCheck.ok) return failRow("guild_native_domain", releaseCheck.reason, releaseCheck.failure_id, { target_identity: { project_url, guild_slug }, release_join: releaseJoinFrom(join) });
  }
  return baseRow("guild_native_domain", { status: "native_domain_readback", state: "native_domain_readback", reason: "exact_project_visitor_or_admin_readback", target_identity: { project_url, guild_slug }, owner_readback: safeReadback(readback), release_join: join ? releaseJoinFrom(join) : null, release_receipt: false, native_receipt: null, failure_state: null });
}

export const evaluateGuildDomain = evaluateGuildNativeDomain;
export const evaluateGuildEvidence = evaluateGuildNativeDomain;

export function evaluateBasenameIdentity(input = {}) {
  const isolation = validateBaseCircleIsolation(input, { platform: "basename_base_org_identity" });
  if (!isolation.ok) return { ...failRow("basename_base_org_identity", "circle_target_collision", "H217-F14"), ...isolation };
  if (input.external_write === true || input.write_requested === true || input.signature || input.wallet) return failRow("basename_base_org_identity", "external_write_attempt_rejected", "H217-F16", { owner_gate: true, write_authorized: false, release_join: null });
  if (input.as_project_receipt === true || input.project_receipt === true || input.registration_receipt_as_release === true || input.profile_page_as_release === true) return baseRow("basename_base_org_identity", { status: "rejected", state: "rejected", reason: "identity_receipt_not_release_receipt", failure_state: { id: "H217-F11", code: "basename_identity_used_as_project_release" }, release_join: null, release_receipt: false });
  if (input.account_level_singleton !== true) return failRow("basename_base_org_identity", "basename_singleton_not_confirmed", "H217-F12", { owner_gate: true, release_join: null });
  const ownerReadback = input.owner_readback ?? input.ownerReadback ?? input.resolver_readback ?? input.primary_name_readback;
  if (!ownerReadback) return failRow("basename_base_org_identity", "basename_owner_or_resolver_unverified", "H217-F12", { owner_gate: true, target_identity: { account_level_singleton: true }, release_join: null });
  return baseRow("basename_base_org_identity", { status: "identity_only", state: "identity_only", reason: "account_level_singleton_identity", target_identity: { account_level_singleton: true }, owner_readback: { present: true }, release_join: null, release_receipt: false, native_receipt: null, failure_state: null });
}

export const evaluateBasenameBaseOrg = evaluateBasenameIdentity;
export const evaluateBaseOrgBasename = evaluateBasenameIdentity;

export function evaluateH217Row(input = {}) {
  const id = input.platform_row_id ?? input.platform ?? input.id;
  switch (id) {
    case "base_sepolia":
    case "base_sepolia_rehearsal": return evaluateBaseSepoliaRehearsal(input);
    case "talent":
    case "talent_native_domain": return evaluateTalentNativeDomain(input);
    case "guild":
    case "guild_native_domain": return evaluateGuildNativeDomain(input);
    case "basename":
    case "basename_base_org":
    case "basename_base_org_identity": return evaluateBasenameIdentity(input);
    default: return failRow(String(id ?? "unknown"), "unsupported_platform", "H217-F16");
  }
}

export const evaluatePlatformExecutionGate = evaluateH217Row;

function defaultRows() {
  return H217_PLATFORM_ROW_IDS.map((id) => baseRow(id));
}

export function createH217EvidenceEnvelope({ packet_id = H217_PACKET_ID, rows = [], release_join = null, owner_readback = null, packet_revalidation = null } = {}) {
  const supplied = new Map((Array.isArray(rows) ? rows : Object.values(rows ?? {})).map((row) => [row.platform_row_id ?? row.platform ?? row.id, row]));
  const platform_rows = H217_PLATFORM_ROW_IDS.map((id) => {
    const row = supplied.get(id);
    return row ? { ...baseRow(id), ...clone(row), platform_row_id: id, platform: id, credit: 0, publication_unit_credit: 0, external_actions: 0, release_receipt: false } : baseRow(id);
  });
  const isolation = validateBaseCircleIsolation({ packet_id, platform_rows, release_join }, { platform: "h217_envelope" });
  const envelope = {
    schema_version: SCHEMA_VERSION,
    packet_id,
    execution_authority: EXECUTION_AUTHORITY,
    platform_rows,
    platform_rows_by_id: Object.fromEntries(platform_rows.map((row) => [row.platform_row_id, row])),
    owner_readback: clone(owner_readback),
    packet_revalidation: clone(packet_revalidation),
    native_receipt: null,
    release_join: release_join ? releaseJoinFrom(release_join) : null,
    failure_state: isolation.ok ? null : { id: "H217-F14", code: "circle_target_collision" },
    credit: 0,
    publication_unit_credit: 0,
    aggregate_publication_unit_credit: 0,
    external_actions: 0,
    wallet_authority: false,
    public_write_authority: false,
    deployment_authority: false,
    circle_target_absent: isolation.ok,
    isolation,
  };
  return envelope;
}

export const buildH217EvidenceEnvelope = createH217EvidenceEnvelope;
export const createPlatformExecutionEnvelope = createH217EvidenceEnvelope;

export function validateH217Envelope(envelope = {}) {
  if (!envelope || envelope.schema_version !== SCHEMA_VERSION) return { schema_version: SCHEMA_VERSION, ok: false, fail_closed: true, reason: "unsupported_schema", failure_id: "H217-F16", credit: 0, publication_unit_credit: 0, external_actions: 0 };
  const rows = Array.isArray(envelope.platform_rows) ? envelope.platform_rows : [];
  const exactRows = rows.length === H217_PLATFORM_ROW_IDS.length && H217_PLATFORM_ROW_IDS.every((id, index) => rows[index]?.platform_row_id === id);
  const zero = rows.every((row) => row.credit === 0 && (row.publication_unit_credit ?? 0) === 0 && row.external_actions === 0 && row.release_receipt === false);
  const safe = envelope.credit === 0 && (envelope.publication_unit_credit ?? 0) === 0 && (envelope.aggregate_publication_unit_credit ?? 0) === 0 && envelope.external_actions === 0 && envelope.wallet_authority === false && envelope.public_write_authority === false && envelope.deployment_authority === false && envelope.execution_authority === EXECUTION_AUTHORITY;
  const isolation = validateBaseCircleIsolation(envelope, { platform: "h217_envelope" });
  const release = envelope.release_join ? validateH217ReleaseEnvelope(envelope.release_join) : { ok: true, credit: 0 };
  const ok = exactRows && zero && safe && isolation.ok && release.ok;
  return {
    schema_version: SCHEMA_VERSION,
    ok,
    fail_closed: !ok,
    state: ok ? "h217_envelope_valid" : "owner_platform_gate",
    reason: ok ? "h217_envelope_valid" : !exactRows ? "platform_rows_mismatch" : !zero ? "credit_or_receipt_nonzero" : !safe ? "authority_present" : !isolation.ok ? "circle_target_collision" : "release_join_mismatch",
    failure_id: ok ? null : !isolation.ok ? "H217-F14" : !release.ok ? release.failure_id : "H217-F15",
    platform_rows: rows.length,
    expected_platform_rows: H217_PLATFORM_ROW_IDS.length,
    test_vectors: H217_TEST_VECTORS.length,
    failure_modes: H217_FAILURE_MODES.length,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    circle_target_absent: isolation.ok,
  };
}

export const validatePlatformExecutionEnvelope = validateH217Envelope;
export const validateH217EvidenceEnvelope = validateH217Envelope;

export function validateH217PacketRevalidation({ manifest_sha256, artifact_sha256, handoff_sha256, exchange_sha256 = null, exchange_mode = "0444", exchange_occurrences = 1, exchange_packet = null } = {}) {
  const packet = exchange_packet ?? {};
  const acceptance = packet.acceptance ?? {};
  const severity = acceptance.severity ?? {};
  const statusOk = packet.status === "accepted_for_02_Build_bounded_pending_revalidation_non_executable";
  const reviewOk = acceptance.review_status === "reviewed" && acceptance.review_verdict === "pass" && acceptance.reviewer === "independent fresh root gpt-5.6-sol/medium" && severity.p0 === 0 && severity.p1 === 0 && severity.p2 === 0;
  const hashesOk = manifest_sha256 === H217_SOURCE_HASHES.manifest_sha256 && artifact_sha256 === H217_SOURCE_HASHES.artifact_sha256 && handoff_sha256 === H217_SOURCE_HASHES.handoff_sha256;
  const occurrenceOk = exchange_occurrences === 1 && packet.batch_id === H217_BATCH_ID;
  const ok = hashesOk && occurrenceOk && statusOk && reviewOk && exchange_mode === "0444";
  return {
    schema_version: SCHEMA_VERSION,
    ok,
    fail_closed: !ok,
    state: ok ? "accepted_once_revalidated" : "needs_review",
    reason: ok ? "fresh_sol_medium_pass_and_exact_hash_closure" : !hashesOk ? "source_hash_mismatch" : !occurrenceOk ? "exchange_occurrence_or_batch_mismatch" : !reviewOk ? "independent_review_not_pass" : "exchange_mode_not_0444",
    failure_id: ok ? null : "H217-F16",
    accepted_once: occurrenceOk,
    occurrence: exchange_occurrences,
    execution_authority: EXECUTION_AUTHORITY,
    source_hashes: clone(H217_SOURCE_HASHES),
    exchange_sha256,
    exchange_mode,
    review: { status: acceptance.review_status ?? null, verdict: acceptance.review_verdict ?? null, reviewer: acceptance.reviewer ?? null, severity: { p0: severity.p0 ?? null, p1: severity.p1 ?? null, p2: severity.p2 ?? null } },
    credit: 0,
    external_actions: 0,
  };
}

export const revalidateH217Packet = validateH217PacketRevalidation;

export function getH217Contract() {
  return Object.freeze({
    schema_version: SCHEMA_VERSION,
    packet_id: H217_PACKET_ID,
    batch_id: H217_BATCH_ID,
    execution_authority: EXECUTION_AUTHORITY,
    source_hashes: clone(H217_SOURCE_HASHES),
    platform_rows: H217_PLATFORM_ROW_IDS.map((id) => ({ id, ...clone(PLATFORM_CONTRACTS[id]), default_credit: 0 })),
    base_sepolia: clone(BASE_SEPOLIA_DESCRIPTOR),
    native_domains: { talent: "project/profile owner readback only", guild: "project roles/requirements/rewards readback only", basename: "account-level singleton identity only", release_receipts: false },
    release_join: clone(H217_RELEASE_JOIN),
    release_envelope: clone(H217_RELEASE_ENVELOPE),
    test_vectors: clone(H217_TEST_VECTORS),
    failure_modes: clone(H217_FAILURE_MODES),
    default_credit: 0,
    aggregate_publication_unit_credit: 0,
    external_actions: 0,
    wallet_authority: false,
    public_write_authority: false,
    deployment_authority: false,
    circle_target_absent: true,
  });
}

export const H217_CONTRACT = getH217Contract();
export const CONTRACT = H217_CONTRACT;

export function aggregateCredit(rows = []) {
  return (Array.isArray(rows) ? rows : Object.values(rows ?? {})).reduce((sum, row) => sum + (Number(row?.credit) || 0), 0);
}

export function buildH217Readback({
  source_hashes = H217_SOURCE_HASHES,
  exchange_sha256 = null,
  exchange_mode = "0444",
  exchange_occurrences = 1,
  exchange_packet = null,
  implementation = {},
  runtime = {},
  runtime_authority = {},
  tests = {},
  public_envelope = {},
  observed_at_cst = "2026-08-15T15:03:56+08:00",
} = {}) {
  const packet_revalidation = validateH217PacketRevalidation({ ...source_hashes, exchange_sha256, exchange_mode, exchange_occurrences, exchange_packet });
  const supplied_public_envelope = {
    release: public_envelope.release ?? H217_RELEASE_ENVELOPE,
    github: public_envelope.github ?? { repo: "gaysonloser/base-erp-settlement-workbench", branch: "main", commit_sha: H217_RELEASE_ENVELOPE.commit_sha, ...H217_RELEASE_ENVELOPE },
    render: public_envelope.render ?? { service_id: H217_RELEASE_ENVELOPE.render_service_id, deployment_id: H217_RELEASE_ENVELOPE.render_deployment_id, commit_sha: H217_RELEASE_ENVELOPE.commit_sha, health_ready: true, health_status: "ok", ...H217_RELEASE_ENVELOPE },
    dashboard: public_envelope.dashboard ?? { app_id: H217_RELEASE_ENVELOPE.canonical_dashboard_app_id, primary_url: H217_RELEASE_ENVELOPE.canonical_primary_url },
  };
  const public_check = validateH217PublicEnvelope(supplied_public_envelope);
  const envelope = createH217EvidenceEnvelope({ release_join: public_check.ok ? H217_RELEASE_JOIN : null, packet_revalidation });
  return {
    schema_version: READBACK_SCHEMA_VERSION,
    readback_id: "h217-remaining-platform-readback-20260815-v7",
    packet_id: H217_PACKET_ID,
    batch_id: H217_BATCH_ID,
    observed_at_cst,
    execution_authority: EXECUTION_AUTHORITY,
    packet_revalidation,
    implementation: {
      exact_write_set: [
        "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-native-platform-execution-gates.mjs",
        "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-native-platform-execution-gates.test.mjs",
        "projects/2026-08_Base_ERP_Settlement_Workbench/runtime/h217_remaining_platform_readback_2026-08-15.json",
      ],
      source: "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-native-platform-execution-gates.mjs",
      source_sha256: implementation.source_sha256 ?? null,
      test: "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-native-platform-execution-gates.test.mjs",
      test_sha256: implementation.test_sha256 ?? null,
      runtime_readback: "projects/2026-08_Base_ERP_Settlement_Workbench/runtime/h217_remaining_platform_readback_2026-08-15.json",
      product_bom_mutated: false,
      external_actions: 0,
    },
    contract_counts: { platform_rows: 4, test_vectors: 16, failure_modes: 16, default_row_credit: 0, aggregate_publication_unit_credit: 0 },
    controls: [
      "Base Sepolia descriptor-only chain_id=84532/0x14a34 with basescan descriptor; receipt/finality remain separate",
      "Talent, Guild and Basename remain native-domain/identity owner gates with no release receipt",
      "v7 release_id+release_fingerprint+bom_fingerprint joins GitHub/Render and canonical Dashboard/Base.dev identity",
      "Base App readiness is not a release receipt and H217 never creates eight publication receipts",
      "strict BASE/CIRCLE isolation is fail-closed; all credits and actions remain zero",
      "no wallet, credential, approval, signature, transaction, deployment or public-write authority",
    ],
    public_envelope: { ...public_check, expected: clone(H217_RELEASE_ENVELOPE) },
    evidence_envelope: envelope,
    owner_gate_observations: {
      base_sepolia_rehearsal: { descriptor_valid: true, transaction_hash_observed: false, receipt_observed: false, finality_stage: null, credit: 0 },
      talent_native_domain: { exact_project_search: "Base ERP Settlement Workbench", projects_found: 0, project_identity_observed: false, owner_auth_required: true, credit: 0 },
      guild_native_domain: { generic_base_page_visible: true, project_identity_observed: false, release_mapping_observed: false, owner_auth_required: true, credit: 0 },
      basename_base_org_identity: { account_level_singleton: true, project_release_mapping_observed: false, identity_only: true, credit: 0 },
    },
    release_join: { ...clone(H217_RELEASE_JOIN), status: public_check.ok ? "current_v7_github_render_dashboard_join" : "owner_platform_gate", credit: 0, separate_dashboard_basedev_receipt: false, base_app_readiness_only: true },
    runtime: clone(runtime),
    runtime_authority: clone(runtime_authority),
    tests: clone(tests),
    isolation: { matrix: "projects/2026-08_Base_ERP_Settlement_Workbench/config/base_circle_platform_isolation_matrix_v1.json", matrix_sha256: "c538e47c4b7951f341b36e351858bf3e1c28dd772d7d3f9c3588f1f0093f19de", circle_target_absent: true, circle_files_or_external_targets_touched: false },
    queue_cursor_counters: { changed: false, external_trace_units: 0, public_update_units: 0, note: "H217 is bounded non-executable evidence work and does not increment 0/30 or 0/10." },
    self_hash: "H217_READBACK_SELF_HASH_PLACEHOLDER",
    self_hash_rule: { mode: "explicit_placeholder_allowed", value: "H217_READBACK_SELF_HASH_PLACEHOLDER", reason: "The readback is excluded from the immutable v7 BOM; a self-referential SHA is intentionally not materialized under the exact H217 Build write-set contract." },
  };
}

export const createH217Readback = buildH217Readback;
