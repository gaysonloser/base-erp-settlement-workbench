import { createHash } from "node:crypto";

export const SCHEMA_VERSION = "base-erp-h216-native-platform-evidence-v1";
export const H216_PACKET_ID = "base-erp-h216-base-native-platform-evidence-access-contract-20260815";
export const EXECUTION_AUTHORITY = "none_until_02_Build_revalidates";
export const AUTHORITY_NONE = EXECUTION_AUTHORITY;
export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_SEPOLIA_CHAIN_ID_HEX = "0x14a34";
export const BASE_SEPOLIA_NETWORK = "base-sepolia";
export const BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org";
export const BASE_SEPOLIA_EXPLORER_URL = "https://sepolia.basescan.org";
export const BASE_MAINNET_CHAIN_ID = 8453;
export const RELEASE_JOIN_FIELDS = Object.freeze(["release_id", "release_fingerprint", "bom_fingerprint"]);
export const CANONICAL_APP_LABELS = Object.freeze(["Base Dashboard", "Base.dev"]);
export const CANONICAL_APP_ID = "6a7a0717e209a55163497d2d";
export const CANONICAL_PRIMARY_URL = "https://base-erp-settlement-workbench.onrender.com";

export const PLATFORM_ROW_IDS = Object.freeze([
  "base_sepolia_rehearsal",
  "base_dashboard_base_dev",
  "base_app_readiness",
  "basename_base_org_identity",
  "talent_native_domain",
  "guild_native_domain",
  "github_current_release",
  "render_current_release",
]);
export const H216_PLATFORM_ROWS = PLATFORM_ROW_IDS;
export const PLATFORM_ROWS = H216_PLATFORM_ROWS;

export const PLATFORM_CONTRACTS = {
  base_sepolia_rehearsal: {
    label: "Base Sepolia rehearsal descriptor/receipt/finality",
    evidence_class: "rehearsal_chain_evidence",
    target_identity: {
      network: BASE_SEPOLIA_NETWORK,
      chain_id: BASE_SEPOLIA_CHAIN_ID,
      chain_id_hex: BASE_SEPOLIA_CHAIN_ID_HEX,
      rpc_url: BASE_SEPOLIA_RPC_URL,
      explorer_url: BASE_SEPOLIA_EXPLORER_URL,
      rehearsal_only: true,
    },
  },
  base_dashboard_base_dev: {
    label: "Base Dashboard + Base.dev canonical app identity",
    evidence_class: "canonical_owner_app_identity",
    target_identity: { canonical_key: "app_id+primary_url", labels: CANONICAL_APP_LABELS, duplicate_rows: false },
  },
  base_app_readiness: {
    label: "Base App readiness metadata",
    evidence_class: "consumer_readiness_and_discovery",
    target_identity: { inherits: "base_dashboard_base_dev.app_id+primary_url", separate_release_row: false },
  },
  basename_base_org_identity: {
    label: "Base.org/Basename identity outcome",
    evidence_class: "onchain_identity",
    target_identity: { candidate_name: "gaysonloser.base.eth", identity_only: true },
  },
  talent_native_domain: {
    label: "Talent native-domain outcome",
    evidence_class: "reputation_profile_read_surface",
    target_identity: { accepted_forms: ["profile_id", "account_id", "documented_project_object"], personal_profile_as_release: false },
  },
  guild_native_domain: {
    label: "Guild native-domain outcome",
    evidence_class: "community_roles_requirements_rewards",
    target_identity: { accepted_forms: ["owner-controlled permanent_guild_url", "admin_object"], generic_base_page_as_release: false },
  },
  github_current_release: {
    label: "GitHub current release join",
    evidence_class: "source_release_identity",
    target_identity: { repo: "gaysonloser/base-erp-settlement-workbench", branch: "main" },
  },
  render_current_release: {
    label: "Render current release join",
    evidence_class: "deployed_service_identity",
    target_identity: { service_name: "base-erp-settlement-workbench", domain: "base-erp-settlement-workbench.onrender.com" },
  },
};

export const H216_FAILURE_MODES = Object.freeze([
  ["H216-F01", "descriptor_present_receipt_missing", "Base Sepolia descriptor without a mined receipt stays rehearsal_only and credit=0."],
  ["H216-F02", "receipt_chain_mismatch", "A receipt on a different chain stops and cannot join the release."],
  ["H216-F03", "finality_inferred", "Finality must be an explicit documented stage; never infer it."],
  ["H216-F04", "alias_duplication", "Dashboard and Base.dev collapse to one canonical app_id plus primary_url row."],
  ["H216-F05", "readiness_as_receipt", "Base App readiness, manifests and CDN assets are not release receipts."],
  ["H216-F06", "basename_identity_as_release", "Basename identity evidence is not deployment or publication evidence."],
  ["H216-F07", "talent_gate", "Missing API key, wallet auth, 429 or undocumented write keeps Talent at its owner gate."],
  ["H216-F08", "guild_gate", "Community pages without owner/admin/current release readback remain community_only."],
  ["H216-F09", "github_placeholder", "Placeholder, stale or unverified GitHub commit cannot join the current release."],
  ["H216-F10", "render_stale", "A Render URL without current deploy and commit readback cannot join the release."],
  ["H216-F11", "release_join_mismatch", "Any release_id, release_fingerprint or BOM mismatch rejects the aggregate."],
  ["H216-F12", "circle_collision", "Any CIRCLE/Arc target collision fails closed with no overwrite and credit=0."],
  ["H216-F13", "external_write_attempt", "Wallet, login, deployment or platform write is outside this non-executable contract."],
  ["H216-F14", "stale_source", "Source drift before revalidation invalidates the packet and exchange append."],
].map(([id, name, policy]) => Object.freeze({ id, name, code: name, policy, fail_closed: true })));
export const FAILURE_MODE_IDS = Object.freeze(H216_FAILURE_MODES.map((item) => item.id));
export const FAILURE_MODES = H216_FAILURE_MODES;
export const H216_FAILURE_MODE_RECORDS = H216_FAILURE_MODES;

const TEST_VECTOR_DEFINITIONS = [
  ["Base Sepolia descriptor", "chain_id=84532 and rpc=https://sepolia.base.org", "rehearsal_descriptor; receipt and finality remain separate; credit=0"],
  ["receipt before mining", "eth_getTransactionReceipt returns null", "not_mined; no receipt; credit=0"],
  ["receipt success", "status=0x1 with transactionHash/blockHash/blockNumber/logs", "receipt_observed; require finality stage and current release join"],
  ["receipt revert", "status=0x0", "receipt_failed; stop; credit=0"],
  ["four finality stages", "Flashblock/L2/L1 batch/L1 batch finality", "stage explicit; no stage inference"],
  ["withdrawal boundary", "Base-to-Ethereum withdrawal", "separate seven-day path; not regular Base receipt"],
  ["wallet_sendCalls descriptor", "version/from/chainId/atomicRequired/calls", "descriptor_only; no wallet call"],
  ["calls status atomic", "status=200, atomic=true, receipts[]", "owner readback evidence; still require finality/release join"],
  ["Dashboard canonical identity", "same app_id and primary_url read back under Dashboard/Base.dev labels", "one canonical row"],
  ["Dashboard generic redirect", "base.dev redirects without app_id", "owner_platform_gate; credit=0"],
  ["metadata complete", "name/icon/tagline/description/screenshots/category/primary_url/builder_code", "readiness candidate; not release receipt"],
  ["Base App old manifest", "Farcaster manifest or CDN only", "deprecated/non-receipt; credit=0"],
  ["Base App readiness", "mobile/in-app browser + wallet-ready + canonical metadata", "readiness_only; release_receipt=null"],
  ["Basename resolver", "name resolves with owner/primary/text record readback", "identity_only; release fields null"],
  ["Basename profile page", "public profile page without resolver/owner receipt", "insufficient; credit=0"],
  ["Talent profile read", "documented profile/account/project API response", "native-domain observation; no release receipt"],
  ["Talent write gate", "API key/wallet nonce/signature/JWT required", "owner_platform_gate; no write"],
  ["Talent 429", "security checkpoint 429", "unavailable; credit=0"],
  ["Guild permanent URL", "owner-created URL and visitor/admin readback", "community evidence; no release receipt"],
  ["Guild verification", "complete roles/requirements/rewards + public launch + verification", "community verification; release fields null"],
  ["Guild generic Base page", "guild.xyz/base member count only", "not project identity; credit=0"],
  ["GitHub current join", "repo/main/commit and release envelope match", "current source-release leg observed"],
  ["GitHub placeholder", "PENDING_OWNER_PUBLIC_COMMIT", "owner gate; credit=0"],
  ["Render deploy join", "service/deploy/commit/current URL and release envelope match", "current deployed leg observed"],
  ["Render URL only", "onrender.com page without deploy/commit readback", "insufficient; credit=0"],
  ["release mismatch", "GitHub release_fingerprint differs from Render", "aggregate reject; credit=0"],
  ["all rows current", "every required platform has exact owner receipt and same release join", "eligible for independent Build/owner gate; H216 still does not increment credit"],
  ["CIRCLE collision", "target/service/app/domain/release matches CIRCLE denylist", "fail_closed_no_overwrite; credit=0"],
  ["external write attempt", "wallet/login/platform/public write is proposed", "stop; 03_Base authority absent"],
  ["stale official source", "source changes before review", "invalidate and request fresh review"],
];
export const H216_TEST_VECTORS = Object.freeze(TEST_VECTOR_DEFINITIONS.map(([name, input, expected], index) => Object.freeze({
  id: `H216-${String(index + 1).padStart(2, "0")}`,
  name,
  input,
  expected,
})));
export const TEST_VECTOR_IDS = Object.freeze(H216_TEST_VECTORS.map((item) => item.id));

export const BASE_SEPOLIA_DESCRIPTOR = Object.freeze({
  network: BASE_SEPOLIA_NETWORK,
  chain_id: BASE_SEPOLIA_CHAIN_ID,
  chain_id_hex: BASE_SEPOLIA_CHAIN_ID_HEX,
  rpc_url: BASE_SEPOLIA_RPC_URL,
  explorer_url: BASE_SEPOLIA_EXPLORER_URL,
  rehearsal_only: true,
});
export const BASE_SEPOLIA = BASE_SEPOLIA_DESCRIPTOR;
export const CIRCLE_DENYLIST = Object.freeze([
  "gaysonloser/arc-payment-receipt",
  "srv-d9cumml8nd3s73c9nehg",
  "arc-payment-receipt.onrender.com",
  "programme-final-20260810",
]);

const FINALITY_STAGES = new Set(["flashblock_preconfirmation", "l2_block_inclusion", "l1_batch_inclusion", "l1_batch_finality"]);
const HASH_RE = /^[0-9a-f]{64}$/i;
const TX_HASH_RE = /^0x[0-9a-f]{64}$/i;
const CIRCLE_WORD_RE = /(^|[^a-z])(circle|arc)([^a-z]|$)/i;
const REQUIRED_METADATA = ["name", "icon", "tagline", "description", "screenshots", "category", "primary_url", "builder_code"];

function clone(value) {
  if (value === undefined) return undefined;
  return structuredClone(value);
}

function freeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) freeze(item);
  return Object.freeze(value);
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(value, (_key, item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return item;
    return Object.fromEntries(Object.keys(item).sort().map((key) => [key, item[key]]));
  })).digest("hex");
}

function failClosed(reason, failure_id, details = {}) {
  return {
    schema_version: SCHEMA_VERSION,
    ok: false,
    fail_closed: true,
    state: "owner_platform_gate",
    reason,
    failure_id,
    credit: 0,
    release_receipt: null,
    publication_unit_credit: 0,
    external_actions: 0,
    circle_target_absent: false,
    ...details,
  };
}

function success(state, details = {}) {
  return {
    schema_version: SCHEMA_VERSION,
    ok: true,
    fail_closed: false,
    state,
    credit: 0,
    publication_unit_credit: 0,
    release_receipt: null,
    external_actions: 0,
    circle_target_absent: true,
    ...details,
  };
}

function asChainId(value) {
  if (Number.isInteger(value)) return value;
  if (typeof value === "string" && /^0x[0-9a-f]+$/i.test(value)) return Number.parseInt(value.slice(2), 16);
  return Number(value) || null;
}

function asNonEmpty(value) {
  return typeof value === "string" && value.trim() !== "";
}

function isHash(value) {
  return typeof value === "string" && HASH_RE.test(value.replace(/^0x/i, ""));
}

function isTxHash(value) {
  return typeof value === "string" && TX_HASH_RE.test(value);
}

function hasCircleCollision(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return CIRCLE_WORD_RE.test(value);
  if (typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(hasCircleCollision);
  // Field names such as `circle_target_absent` are contract metadata, not a
  // target identity. Only values are inspected for a CIRCLE/Arc collision.
  const serialized = JSON.stringify(value);
  if (CIRCLE_DENYLIST.some((entry) => serialized.includes(entry))) return true;
  return Object.values(value).some(hasCircleCollision);
}

export function validateBaseCircleIsolation(value, { platform } = {}) {
  if (hasCircleCollision(value)) return failClosed("circle_target_collision", "H216-F12", { platform, target: clone(value) });
  return success("isolation_verified", { platform, target: clone(value) });
}

export function checkBaseCircleIsolation(input = {}) {
  const collision = hasCircleCollision(input);
  const isolated = !collision;
  return {
    schema_version: SCHEMA_VERSION,
    state: isolated ? "base_identity_isolated" : "owner_platform_gate_no_overwrite",
    ok: isolated,
    fail_closed: !isolated,
    circle_collision: collision,
    action_enabled: false,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    circle_target_absent: isolated,
    reason: isolated ? "base_target_isolated" : "base_circle_identity_collision",
  };
}

function releaseJoinFrom(value = {}) {
  const source = value.release_join ?? value.releaseJoin ?? value;
  return Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, source?.[field] ?? null]));
}

function releaseJoinComplete(join) {
  return asNonEmpty(join?.release_id) && isHash(join?.release_fingerprint) && isHash(join?.bom_fingerprint);
}

export function compareReleaseJoin(left = {}, right = {}, expected = null) {
  const a = releaseJoinFrom(left);
  const b = releaseJoinFrom(right);
  const expectedJoin = expected ? releaseJoinFrom(expected) : null;
  const same = RELEASE_JOIN_FIELDS.every((field) => asNonEmpty(a[field]) && a[field] === b[field] && (!expectedJoin || a[field] === expectedJoin[field]));
  return {
    same_release: same,
    release_join: a,
    compared_fields: RELEASE_JOIN_FIELDS,
    mismatch_fields: RELEASE_JOIN_FIELDS.filter((field) => a[field] !== b[field] || (expectedJoin && a[field] !== expectedJoin[field])),
    credit: 0,
  };
}

export const joinReleaseEnvelope = compareReleaseJoin;

function baseRow(rowId, overrides = {}) {
  const contract = PLATFORM_CONTRACTS[rowId];
  return {
    platform_row_id: rowId,
    platform: rowId,
    label: contract?.label ?? rowId,
    evidence_class: contract?.evidence_class ?? "unknown",
    target_identity: clone(contract?.target_identity ?? null),
    owner_readback: null,
    native_receipt: null,
    release_join: Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, null])),
    failure_state: { id: "H216-F14", code: "not_observed" },
    status: "not_accepted",
    credit: 0,
    release_receipt: null,
    external_actions: 0,
    circle_target_absent: true,
    ...overrides,
  };
}

export function evaluateBaseSepolia(input = {}) {
  const descriptor = { ...BASE_SEPOLIA_DESCRIPTOR, ...(input.descriptor ?? {}) };
  const targetCheck = validateBaseCircleIsolation({ descriptor, target: input.target }, { platform: "base_sepolia_rehearsal" });
  if (!targetCheck.ok) return { ...baseRow("base_sepolia_rehearsal"), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  const chainId = asChainId(input.chain_id ?? input.chainId ?? descriptor.chain_id);
  if (chainId !== BASE_SEPOLIA_CHAIN_ID || descriptor.network !== BASE_SEPOLIA_NETWORK || descriptor.rpc_url !== BASE_SEPOLIA_RPC_URL || descriptor.explorer_url !== BASE_SEPOLIA_EXPLORER_URL) {
    return { ...baseRow("base_sepolia_rehearsal"), status: "owner_platform_gate", reason: "descriptor_mismatch", failure_state: { id: "H216-F02", code: "receipt_chain_mismatch" }, target_identity: descriptor };
  }
  const receipt = input.receipt ?? input.native_receipt ?? null;
  const finalityStage = input.finality_stage ?? input.finalityStage ?? "not_observed";
  const common = { target_identity: descriptor, owner_readback: clone(input.owner_readback ?? null), native_receipt: clone(receipt), finality_stage: finalityStage, release_join: releaseJoinFrom(input) };
  if (!receipt) return { ...baseRow("base_sepolia_rehearsal", common), status: "rehearsal_only", reason: "descriptor_present_receipt_missing", failure_state: { id: "H216-F01", code: "descriptor_present_receipt_missing" } };
  const receiptChain = asChainId(receipt.chainId ?? receipt.chain_id);
  if (receiptChain !== BASE_SEPOLIA_CHAIN_ID) return { ...baseRow("base_sepolia_rehearsal", common), status: "owner_platform_gate", reason: "receipt_chain_mismatch", failure_state: { id: "H216-F02", code: "receipt_chain_mismatch" } };
  if (receipt.transactionHash && !isTxHash(receipt.transactionHash)) return { ...baseRow("base_sepolia_rehearsal", common), status: "owner_platform_gate", reason: "receipt_invalid", failure_state: { id: "H216-F02", code: "receipt_chain_mismatch" } };
  if (String(receipt.status ?? "").toLowerCase() === "0x0" || receipt.status === 0 || receipt.status === "failed") return { ...baseRow("base_sepolia_rehearsal", common), status: "receipt_failed", reason: "receipt_failed", failure_state: { id: "H216-F02", code: "receipt_chain_mismatch" } };
  if (!FINALITY_STAGES.has(finalityStage)) return { ...baseRow("base_sepolia_rehearsal", common), status: "receipt_observed", reason: "finality_inferred", failure_state: { id: "H216-F03", code: "finality_inferred" } };
  return { ...baseRow("base_sepolia_rehearsal", common), status: "receipt_observed", reason: "rehearsal_receipt_observed", failure_state: null, finality_stage: finalityStage };
}

function metadataComplete(metadata = {}) {
  return REQUIRED_METADATA.every((key) => metadata[key] !== undefined && metadata[key] !== null && metadata[key] !== "" && (!Array.isArray(metadata[key]) || metadata[key].length > 0));
}

export function evaluateCanonicalApp(input = {}) {
  const app_id = input.app_id ?? input.appId ?? null;
  const primary_url = input.primary_url ?? input.primaryUrl ?? null;
  const target = { app_id, primary_url, labels: input.labels ?? CANONICAL_APP_LABELS };
  const targetCheck = validateBaseCircleIsolation({ target, metadata: input.metadata }, { platform: "base_dashboard_base_dev" });
  if (!targetCheck.ok) return { ...baseRow("base_dashboard_base_dev"), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  if (!asNonEmpty(app_id)) return { ...baseRow("base_dashboard_base_dev"), status: "owner_platform_gate", reason: "missing_app_id", failure_state: { id: "H216-F04", code: "alias_duplication" }, target_identity: target };
  if (!asNonEmpty(primary_url) || !/^https?:\/\//i.test(primary_url)) return { ...baseRow("base_dashboard_base_dev"), status: "owner_platform_gate", reason: "generic_base_dev_redirect", failure_state: { id: "H216-F04", code: "alias_duplication" }, target_identity: target };
  if (input.base_dev_redirect === true || input.generic_redirect === true) return { ...baseRow("base_dashboard_base_dev"), status: "owner_platform_gate", reason: "generic_base_dev_redirect", failure_state: { id: "H216-F04", code: "alias_duplication" }, target_identity: target };
  const complete = input.metadata_complete ?? (input.metadata && Object.keys(input.metadata).length ? metadataComplete(input.metadata) : true);
  const ownerVerified = input.ownership_verified === true || input.owner_verified === true;
  if (complete !== true || !ownerVerified) return { ...baseRow("base_dashboard_base_dev"), status: "owner_platform_gate", reason: complete !== true ? "incomplete_metadata" : "unverified_ownership", failure_state: { id: "H216-F04", code: "alias_duplication" }, target_identity: target, owner_readback: clone(input.owner_readback ?? null) };
  return { ...baseRow("base_dashboard_base_dev"), status: "canonical_route_verified", state: "canonical_route_verified", canonical_state: "canonical_identity_verified", canonical_key: `${app_id}|${primary_url}`, duplicate_rows: false, release_receipt: false, reason: "one_canonical_app_route", failure_state: null, target_identity: { app_id, primary_url, labels: CANONICAL_APP_LABELS, canonical_key: `${app_id}|${primary_url}`, duplicate_rows: false }, owner_readback: clone(input.owner_readback ?? { app_id, primary_url, metadata_complete: true, ownership_verified: true, builder_code: input.builder_code ?? null }) };
}

export const evaluateDashboardBaseDev = evaluateCanonicalApp;

export function evaluateBaseAppReadiness(input = {}) {
  const canonical_app_id = input.canonical_app_id ?? input.app_id ?? input.appId ?? null;
  const primary_url = input.primary_url ?? input.primaryUrl ?? null;
  const target = { canonical_app_id, primary_url };
  const targetCheck = validateBaseCircleIsolation(target, { platform: "base_app_readiness" });
  if (!targetCheck.ok) return { ...baseRow("base_app_readiness"), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  const complete = input.metadata_complete === true || metadataComplete(input.metadata);
  if (!asNonEmpty(canonical_app_id) || !asNonEmpty(primary_url)) return { ...baseRow("base_app_readiness"), status: "readiness_gate", reason: "readiness_claimed_without_canonical_app_id", failure_state: { id: "H216-F05", code: "readiness_as_receipt" }, target_identity: target };
  if (input.farcaster_manifest_only === true || input.cdn_asset_only === true || input.continue_on_web_only === true) return { ...baseRow("base_app_readiness"), status: "deprecated_non_receipt", state: "deprecated_non_receipt", reason: "deprecated_readiness_surface", failure_state: { id: "H216-F05", code: "readiness_as_receipt" }, target_identity: target };
  if (!complete) return { ...baseRow("base_app_readiness"), status: "readiness_gate", reason: "readiness_inputs_incomplete", failure_state: { id: "H216-F05", code: "readiness_as_receipt" }, target_identity: target };
  const primaryUrlResolves = input.primary_url_resolves ?? true;
  const mobileReady = input.mobile_ready === true;
  const walletReady = input.wallet_ready === true;
  if (!mobileReady || !walletReady || primaryUrlResolves !== true) return { ...baseRow("base_app_readiness"), status: "readiness_candidate", state: "readiness_candidate", reason: "readiness_candidate_not_release", failure_state: { id: "H216-F05", code: "readiness_as_receipt" }, target_identity: target, owner_readback: clone(input.owner_readback ?? input) };
  return { ...baseRow("base_app_readiness"), status: "readiness_only", state: "readiness_only", reason: "base_app_readiness_observed", failure_state: null, target_identity: target, owner_readback: clone(input.owner_readback ?? input), release_receipt: null };
}

export function evaluateBasenameIdentity(input = {}) {
  const name = input.name ?? input.candidate_name ?? null;
  const targetCheck = validateBaseCircleIsolation({ name, target: input.target }, { platform: "basename_base_org_identity" });
  if (!targetCheck.ok) return { ...baseRow("basename_base_org_identity"), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  if (!asNonEmpty(name) || input.resolved_owner === undefined || input.primary_name === undefined) return { ...baseRow("basename_base_org_identity"), status: "identity_gate", reason: "profile_page_without_resolver_readback", failure_state: { id: "H216-F06", code: "basename_identity_as_release" }, target_identity: { candidate_name: name, identity_only: true } };
  return { ...baseRow("basename_base_org_identity"), status: "identity_only", reason: "identity_observed_no_release_receipt", failure_state: null, target_identity: { name, identity_only: true }, owner_readback: clone(input), release_join: Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, null])) };
}

export const evaluateBaseOrgBasename = evaluateBasenameIdentity;

export function evaluateTalentDomain(input = {}) {
  const targetCheck = validateBaseCircleIsolation(input, { platform: "talent_native_domain" });
  if (!targetCheck.ok) return { ...baseRow("talent_native_domain"), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  if (input.http_status === 429 || input.security_checkpoint_429 === true) return { ...baseRow("talent_native_domain"), status: "talent_unavailable", reason: "429_security_checkpoint", failure_state: { id: "H216-F07", code: "talent_gate" } };
  const id = input.profile_id_or_account_id ?? input.profile_id ?? input.account_id ?? null;
  if (!asNonEmpty(id) || input.documented_fields === undefined || !asNonEmpty(input.source_timestamp ?? input.readback_at)) return { ...baseRow("talent_native_domain"), status: "talent_platform_gate", reason: "owner_readback_missing", failure_state: { id: "H216-F07", code: "talent_gate" } };
  return { ...baseRow("talent_native_domain"), status: "native_domain_observed", reason: "profile_reputation_read_surface_only", failure_state: null, target_identity: { profile_id_or_account_id: id }, owner_readback: clone(input), release_join: Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, null])) };
}

export const evaluateTalentEvidence = evaluateTalentDomain;

export function evaluateGuildDomain(input = {}) {
  const targetCheck = validateBaseCircleIsolation(input, { platform: "guild_native_domain" });
  if (!targetCheck.ok) return { ...baseRow("guild_native_domain"), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  const guildUrl = input.guild_url ?? input.permanent_guild_url ?? null;
  if (input.generic_base_page === true || guildUrl === "https://guild.xyz/base") return { ...baseRow("guild_native_domain"), status: "community_only", reason: "generic_guild_xyz_base_page", failure_state: { id: "H216-F08", code: "guild_gate" } };
  if (!asNonEmpty(guildUrl) || input.visitor_readback === undefined || input.admin_readback === undefined) return { ...baseRow("guild_native_domain"), status: "community_only", reason: "sign_in_no_release_mapping", failure_state: { id: "H216-F08", code: "guild_gate" } };
  return { ...baseRow("guild_native_domain"), status: "community_only", reason: "community_roles_requirements_rewards_only", failure_state: null, target_identity: { guild_url: guildUrl }, owner_readback: clone(input), release_join: Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, null])) };
}

export const evaluateGuildEvidence = evaluateGuildDomain;

function evaluateReleaseLeg(rowId, input = {}) {
  const contract = PLATFORM_CONTRACTS[rowId];
  const targetCheck = validateBaseCircleIsolation(input, { platform: rowId });
  if (!targetCheck.ok) return { ...baseRow(rowId), ...targetCheck, failure_state: { id: "H216-F12", code: "circle_collision" } };
  const join = releaseJoinFrom(input);
  if (!releaseJoinComplete(join)) return { ...baseRow(rowId), status: "owner_platform_gate", reason: rowId === "github_current_release" ? "github_placeholder" : "render_stale", failure_state: { id: rowId === "github_current_release" ? "H216-F09" : "H216-F10", code: rowId === "github_current_release" ? "github_placeholder" : "render_stale" }, target_identity: clone(contract.target_identity), release_join: join };
  if (rowId === "github_current_release") {
    const repo = input.repo ?? input.repository;
    const branch = input.branch;
    const commit = input.commit_sha ?? input.commit;
    if (repo !== contract.target_identity.repo || branch !== contract.target_identity.branch || !asNonEmpty(commit) || commit === "PENDING_OWNER_PUBLIC_COMMIT") return { ...baseRow(rowId), status: "owner_platform_gate", reason: "github_placeholder", failure_state: { id: "H216-F09", code: "github_placeholder" }, target_identity: clone(contract.target_identity), release_join: join };
  } else {
    const service = input.service_name ?? input.service;
    const domain = input.domain ?? input.render_url ?? input.url;
    const deploy = input.deploy_id ?? input.deployment_id;
    if (service !== contract.target_identity.service_name || domain !== `https://${contract.target_identity.domain}` && domain !== contract.target_identity.domain || !asNonEmpty(deploy) || !asNonEmpty(input.commit_sha ?? input.commit) || (input.commit_sha ?? input.commit) === "PENDING_OWNER_PUBLIC_COMMIT") return { ...baseRow(rowId), status: "owner_platform_gate", reason: "render_stale", failure_state: { id: "H216-F10", code: "render_stale" }, target_identity: clone(contract.target_identity), release_join: join };
  }
  return { ...baseRow(rowId), status: "current_release_leg_observed", reason: "owner_readback_required_for_credit", failure_state: null, target_identity: clone(contract.target_identity), owner_readback: clone(input.owner_readback ?? input), release_join: join };
}

export const evaluateGithubRelease = (input = {}) => evaluateReleaseLeg("github_current_release", input);
export const evaluateRenderRelease = (input = {}) => evaluateReleaseLeg("render_current_release", input);

export function joinGithubRenderRelease({ github = {}, render = {}, expected_release = null, expectedRelease = null } = {}) {
  const left = evaluateGithubRelease(github);
  const right = evaluateRenderRelease(render);
  const comparison = compareReleaseJoin(left.release_join, right.release_join, expected_release ?? expectedRelease);
  const targetCheck = validateBaseCircleIsolation({ github: github.target ?? github.repo, render: render.target ?? render.domain }, { platform: "github_render_release_join" });
  const ok = targetCheck.ok && left.status === "current_release_leg_observed" && right.status === "current_release_leg_observed" && comparison.same_release;
  return {
    schema_version: SCHEMA_VERSION,
    ok,
    fail_closed: !ok,
    state: ok ? "current_release_join_observed" : "owner_platform_gate",
    reason: ok ? "same_current_release_envelope" : comparison.mismatch_fields.length ? "release_join_mismatch" : "owner_readback_missing",
    failure_id: ok ? null : comparison.mismatch_fields.length ? "H216-F11" : "H216-F10",
    github: left,
    render: right,
    same_release: comparison.same_release,
    release_join: comparison.release_join,
    mismatch_fields: comparison.mismatch_fields,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    circle_target_absent: targetCheck.ok,
  };
}

export const evaluateGithubRenderJoin = joinGithubRenderRelease;

export function evaluatePlatformEvidence(input = {}) {
  const id = input.platform_row_id ?? input.platform ?? input.id;
  switch (id) {
    case "base_sepolia":
    case "base_sepolia_rehearsal": return evaluateBaseSepolia(input);
    case "base_dashboard":
    case "base.dev":
    case "base_dashboard_base_dev": return evaluateCanonicalApp(input);
    case "base_app":
    case "base_app_readiness": return evaluateBaseAppReadiness(input);
    case "basename":
    case "basename_base_org":
    case "basename_base_org_identity": return evaluateBasenameIdentity(input);
    case "talent":
    case "talent_native_domain": return evaluateTalentDomain(input);
    case "guild":
    case "guild_native_domain": return evaluateGuildDomain(input);
    case "github":
    case "github_current_release": return evaluateGithubRelease(input);
    case "render":
    case "render_current_release": return evaluateRenderRelease(input);
    default: return { ...baseRow(String(id ?? "unknown")), status: "owner_platform_gate", reason: "unsupported_platform", failure_state: { id: "H216-F14", code: "stale_source" } };
  }
}

export function createPlatformEvidenceEnvelope({ packet_id = H216_PACKET_ID, rows = [], release_join = null, owner_readback = null } = {}) {
  const supplied = new Map((Array.isArray(rows) ? rows : Object.values(rows ?? {})).map((row) => [row.platform_row_id ?? row.platform ?? row.id, row]));
  const platform_rows = PLATFORM_ROW_IDS.map((id) => {
    const row = supplied.get(id);
    return row ? { ...baseRow(id), ...clone(row), platform_row_id: id, platform: id, credit: 0, publication_unit_credit: 0, external_actions: 0 } : baseRow(id);
  });
  const isolation = validateBaseCircleIsolation({ packet_id, platform_rows }, { platform: "h216_envelope" });
  const envelope = {
    schema_version: SCHEMA_VERSION,
    packet_id,
    execution_authority: EXECUTION_AUTHORITY,
    platform_rows,
    platform_rows_by_id: Object.fromEntries(platform_rows.map((row) => [row.platform_row_id, row])),
    owner_readback: clone(owner_readback),
    native_receipt: null,
    release_join: releaseJoinFrom(release_join ?? {}),
    failure_state: null,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    wallet_authority: false,
    public_write_authority: false,
    deployment_authority: false,
    circle_target_absent: isolation.ok,
    isolation,
  };
  if (!isolation.ok) envelope.failure_state = { id: "H216-F12", code: "circle_collision" };
  return envelope;
}

export const buildPlatformEvidenceEnvelope = createPlatformEvidenceEnvelope;
export const createH216EvidenceEnvelope = createPlatformEvidenceEnvelope;

export function validatePlatformEvidenceEnvelope(envelope = {}) {
  if (!envelope || envelope.schema_version !== SCHEMA_VERSION) return failClosed("unsupported_schema", "H216-F14");
  const rows = Array.isArray(envelope.platform_rows) ? envelope.platform_rows : [];
  const ids = rows.map((row) => row.platform_row_id);
  const exactRows = ids.length === PLATFORM_ROW_IDS.length && PLATFORM_ROW_IDS.every((id, index) => ids[index] === id);
  const creditsZero = rows.every((row) => row.credit === 0 && (row.publication_unit_credit ?? 0) === 0);
  const authoritySafe = envelope.external_actions === 0 && envelope.wallet_authority === false && envelope.public_write_authority === false && envelope.deployment_authority === false;
  const isolation = validateBaseCircleIsolation(envelope, { platform: "h216_envelope" });
  const ok = exactRows && creditsZero && authoritySafe && isolation.ok;
  return {
    schema_version: SCHEMA_VERSION,
    ok,
    fail_closed: !ok,
    reason: ok ? "h216_envelope_valid" : !exactRows ? "platform_rows_mismatch" : !creditsZero ? "credit_nonzero" : !authoritySafe ? "authority_present" : "circle_target_collision",
    platform_rows: rows.length,
    expected_platform_rows: PLATFORM_ROW_IDS.length,
    test_vectors: H216_TEST_VECTORS.length,
    failure_modes: H216_FAILURE_MODES.length,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    circle_target_absent: isolation.ok,
  };
}

export const validateH216Envelope = validatePlatformEvidenceEnvelope;

export function getH216Contract() {
  return freeze({
    schema_version: SCHEMA_VERSION,
    packet_id: H216_PACKET_ID,
    platform_rows: PLATFORM_ROW_IDS.map((id) => ({ id, ...clone(PLATFORM_CONTRACTS[id]), default_credit: 0 })),
    base_sepolia: clone(BASE_SEPOLIA_DESCRIPTOR),
    canonical_app: { route: "Base Dashboard + Base.dev", identity_key: "one owner-verified app_id + primary_url", duplicate_rows: false, credit: 0 },
    base_app: { role: "readiness/discovery metadata only", release_receipt: null, credit: 0 },
    native_domains: { basename: "identity-only", talent: "profile/reputation read surface only", guild: "community/roles/requirements/rewards surface only", release_receipts: false, credit: 0 },
    release_join: { required_fields: RELEASE_JOIN_FIELDS, github_render_rule: "same current release envelope plus owner-visible commit/deploy readbacks and exact BASE/CIRCLE target comparison", credit: 0 },
    failure_modes: H216_FAILURE_MODES,
    test_vectors: H216_TEST_VECTORS,
    default_credit: 0,
    aggregate_publication_unit_credit: 0,
    execution_authority: EXECUTION_AUTHORITY,
    external_actions: 0,
    circle_target_absent: true,
  });
}

export const H216_CONTRACT = getH216Contract();
export const CONTRACT = H216_CONTRACT;
// Compatibility surface used by deterministic H216 acceptance vectors. These
// adapters are read-only and always keep credit at zero.
export function evaluateRehearsalEvidence(input = {}) {
  if (input.withdrawal) return { schema_version: SCHEMA_VERSION, state: "withdrawal_boundary", seven_day_path: true, credit: 0, wallet_request: null, external_actions: 0 };
  if (input.wallet_send_calls || input.walletSendCalls) return { schema_version: SCHEMA_VERSION, state: "descriptor_only", descriptor_only: true, rehearsal_only: true, wallet_request: null, tx_hash: null, receipt: null, finality_stage: "not_observed", credit: 0, external_actions: 0 };
  if (input.calls_status || input.callsStatus) return { schema_version: SCHEMA_VERSION, state: "calls_status_owner_readback", finality_required: true, release_join_required: true, wallet_request: null, credit: 0, external_actions: 0 };
  const descriptorInput = input.descriptor ?? {};
  const descriptorChain = asChainId(descriptorInput.chainId ?? descriptorInput.chain_id ?? input.chain_id ?? input.chainId);
  const chainId = descriptorChain ?? BASE_SEPOLIA_CHAIN_ID;
  if (chainId !== BASE_SEPOLIA_CHAIN_ID) return { schema_version: SCHEMA_VERSION, state: "receipt_chain_mismatch", stop: true, descriptor_only: true, rehearsal_only: true, tx_hash: null, receipt: null, finality_stage: "not_observed", credit: 0, external_actions: 0 };
  const descriptor = { ...BASE_SEPOLIA_DESCRIPTOR, chain_id: chainId, chain_id_hex: BASE_SEPOLIA_CHAIN_ID_HEX, rpc_url: input.rpc ?? input.rpc_url ?? descriptorInput.rpc_url ?? BASE_SEPOLIA_RPC_URL };
  const receipt = input.receipt ?? null;
  const finalityInput = input.finality_stage ?? input.finalityStage ?? "not_observed";
  const validFinality = new Set(["flashblock", "l2_included", "l1_batch_included", "l1_batch_final", ...FINALITY_STAGES]);
  const finality_stage = validFinality.has(finalityInput) ? finalityInput : "not_observed";
  if (!receipt) return { schema_version: SCHEMA_VERSION, state: "not_mined", descriptor_only: true, rehearsal_only: true, descriptor, tx_hash: null, receipt: null, finality_stage: "not_observed", credit: 0, external_actions: 0 };
  const receiptChain = asChainId(receipt.chainId ?? receipt.chain_id);
  if (receiptChain !== null && receiptChain !== BASE_SEPOLIA_CHAIN_ID) return { schema_version: SCHEMA_VERSION, state: "receipt_chain_mismatch", stop: true, descriptor, tx_hash: null, receipt: clone(receipt), finality_stage: "not_observed", credit: 0, external_actions: 0 };
  const status = String(receipt.status ?? "").toLowerCase();
  const tx_hash = receipt.transaction_hash ?? receipt.transactionHash ?? null;
  if (status === "0x0" || status === "0" || status === "failed" || receipt.success === false) return { schema_version: SCHEMA_VERSION, state: "receipt_failed", stop: true, descriptor, tx_hash, receipt: clone(receipt), finality_stage, credit: 0, external_actions: 0 };
  return { schema_version: SCHEMA_VERSION, state: "receipt_observed", descriptor, descriptor_only: false, rehearsal_only: true, tx_hash, receipt: clone(receipt), finality_stage, release_join_required: true, credit: 0, external_actions: 0 };
}

export function evaluateNativeDomainRow(rowId, input = {}) {
  if (rowId === "basename_base_org_identity") {
    if (input.profile_page_only) return { schema_version: SCHEMA_VERSION, state: "insufficient", release_fields_null: true, release_receipt: null, credit: 0, external_actions: 0 };
    const result = evaluateBasenameIdentity(input);
    return { ...result, state: result.status === "identity_only" ? "identity_only" : result.status === "identity_gate" ? "insufficient" : result.state, release_fields_null: true, release_receipt: null };
  }
  if (rowId === "talent_native_domain") {
    if (input.security_checkpoint === 429) return { schema_version: SCHEMA_VERSION, state: "unavailable", release_receipt: null, credit: 0, external_actions: 0 };
    if (input.write_gate) return { schema_version: SCHEMA_VERSION, state: "owner_platform_gate", write_authorized: false, release_receipt: null, credit: 0, external_actions: 0 };
    const result = evaluateTalentDomain({ ...input, http_status: input.http_status ?? input.security_checkpoint, profile_id_or_account_id: input.profile_id_or_account_id ?? input.profile_id, source_timestamp: input.source_timestamp });
    return { ...result, state: result.status === "native_domain_observed" ? "native_domain_observation" : result.status === "talent_unavailable" ? "unavailable" : result.state, release_receipt: null };
  }
  if (rowId === "guild_native_domain") {
    if (input.generic_base_page) return { schema_version: SCHEMA_VERSION, state: "not_project_identity", release_receipt: null, release_fields_null: true, credit: 0, external_actions: 0 };
    if (input.roles && input.requirements && input.rewards && input.verification) return { schema_version: SCHEMA_VERSION, state: "community_verification", release_receipt: null, release_fields_null: true, credit: 0, external_actions: 0 };
    const result = evaluateGuildDomain(input);
    return { ...result, state: result.status === "community_only" && result.failure_state === null ? "community_evidence" : result.state, release_receipt: null, release_fields_null: true };
  }
  return { schema_version: SCHEMA_VERSION, state: "owner_platform_gate", release_receipt: null, credit: 0, external_actions: 0, write_authorized: false };
}

export function evaluateReleaseJoin({ github = null, render = null, release = null } = {}) {
  const expected = release ? releaseJoinFrom(release) : null;
  if (github && render) {
    const left = evaluateGithubRelease(github);
    const right = evaluateRenderRelease(render);
    if (left.status === "owner_platform_gate" && left.failure_state?.id === "H216-F09") return { schema_version: SCHEMA_VERSION, state: "owner_gate", joined: false, credit: 0, external_actions: 0 };
    if (right.status === "owner_platform_gate" && right.failure_state?.id === "H216-F10") return { schema_version: SCHEMA_VERSION, state: "insufficient", joined: false, credit: 0, external_actions: 0 };
    const comparison = compareReleaseJoin(github, render, expected);
    if (!comparison.same_release) return { schema_version: SCHEMA_VERSION, state: "aggregate_rejected", joined: false, same_release: false, mismatch_fields: comparison.mismatch_fields, credit: 0, external_actions: 0 };
    return { schema_version: SCHEMA_VERSION, state: "current_release_join_observed", joined: true, same_release: true, release_join: comparison.release_join, credit: 0, external_actions: 0 };
  }
  if (github) {
    const result = evaluateGithubRelease(github);
    if (!releaseJoinComplete(releaseJoinFrom(github))) return { schema_version: SCHEMA_VERSION, state: "release_join_missing", joined: false, credit: 0, external_actions: 0 };
    if (result.status === "owner_platform_gate") return { schema_version: SCHEMA_VERSION, state: "owner_gate", joined: false, credit: 0, external_actions: 0 };
    if (expected && !compareReleaseJoin(github, github, expected).same_release) return { schema_version: SCHEMA_VERSION, state: "aggregate_rejected", joined: false, credit: 0, external_actions: 0 };
    return { schema_version: SCHEMA_VERSION, state: "current_source_release_leg_observed", joined: true, credit: 0, external_actions: 0 };
  }
  if (render) {
    const result = evaluateRenderRelease(render);
    if (!releaseJoinComplete(releaseJoinFrom(render))) return { schema_version: SCHEMA_VERSION, state: "insufficient", joined: false, credit: 0, external_actions: 0 };
    if (result.status === "owner_platform_gate") return { schema_version: SCHEMA_VERSION, state: "insufficient", joined: false, credit: 0, external_actions: 0 };
    if (expected && !compareReleaseJoin(render, render, expected).same_release) return { schema_version: SCHEMA_VERSION, state: "aggregate_rejected", joined: false, credit: 0, external_actions: 0 };
    return { schema_version: SCHEMA_VERSION, state: "current_deployed_leg_observed", joined: true, credit: 0, external_actions: 0 };
  }
  return { schema_version: SCHEMA_VERSION, state: "release_join_missing", joined: false, credit: 0, external_actions: 0 };
}

function defaultRowsObject() {
  return Object.fromEntries(PLATFORM_ROW_IDS.map((id) => [id, baseRow(id)]));
}

export function defaultEvidenceEnvelope() {
  return {
    schema_version: SCHEMA_VERSION,
    state: "not_accepted",
    platform_rows: defaultRowsObject(),
    owner_readback: null,
    native_receipt: null,
    release_join: Object.fromEntries(RELEASE_JOIN_FIELDS.map((field) => [field, null])),
    failure_state: null,
    credit: 0,
    publication_unit_credit: 0,
    external_actions: 0,
    execution_authority: AUTHORITY_NONE,
    wallet_request: null,
    public_write: false,
    deployment_request: null,
    circle_target_absent: true,
  };
}

export function aggregateCredit(rows = []) {
  const values = Array.isArray(rows) ? rows : Object.values(rows ?? {});
  return values.reduce((sum, row) => sum + (Number(row?.credit) || 0), 0);
}

export function evaluateSourceState(input = {}) {
  if (input.source_hash_mismatch || input.stale_source) return { schema_version: SCHEMA_VERSION, state: "invalidated_require_fresh_review", append_exchange: false, credit: 0, external_actions: 0 };
  return { schema_version: SCHEMA_VERSION, state: "source_revalidated", append_exchange: false, credit: 0, external_actions: 0 };
}

export function buildEvidenceEnvelope({ evidence = null, release = null, wallet_request = null, source_hash_mismatch = false, stale_source = false } = {}) {
  const envelope = defaultEvidenceEnvelope();
  if (source_hash_mismatch || stale_source) return { ...envelope, ...evaluateSourceState({ source_hash_mismatch, stale_source }) };
  if (wallet_request) return { ...envelope, state: "external_write_attempt_rejected", failure_state: { id: "H216-F13", code: "external_write_attempt" }, wallet_request: null, external_actions: 0 };
  if (evidence && Object.keys(evidence).length > 0) {
    const rows = Object.fromEntries(PLATFORM_ROW_IDS.map((id) => [id, evaluatePlatformEvidence({ platform_row_id: id, ...(evidence[id] ?? {}) })]));
    const complete = PLATFORM_ROW_IDS.every((id) => rows[id].failure_state === null || ["rehearsal_only", "receipt_observed", "canonical_route_verified", "readiness_only", "identity_only", "native_domain_observed", "community_only", "current_release_leg_observed"].includes(rows[id].status));
    return { ...envelope, state: complete ? "eligible_for_independent_build_owner_gate" : "not_accepted", platform_rows: rows, release_join: releaseJoinFrom(release ?? {}), publication_unit_credit: 0, credit: 0 };
  }
  return envelope;
}

export { digest };
