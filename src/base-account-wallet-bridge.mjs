import { createHash } from "node:crypto";

/**
 * Base Account browser bridge.
 *
 * This module is deliberately a pure, dependency-free control plane. It does
 * not import an SDK, create a provider, persist wallet material, or perform a
 * request by itself. The browser adapter receives an injected SDK factory and
 * only calls it from an explicit method invocation (normally a button event).
 */

export const BASE_ACCOUNT_CHAIN_ID = "0x2105";
export const BASE_ACCOUNT_CHAIN_ID_DECIMAL = 8453;
export const BASE_ACCOUNT_METHODS = Object.freeze({
  connect: "wallet_connect",
  capabilities: "wallet_getCapabilities",
  sendCalls: "wallet_sendCalls",
  callsStatus: "wallet_getCallsStatus",
});
export const BASE_ACCOUNT_SEND_CALLS_VERSION = "2.0.0";
export const BASE_ACCOUNT_RELEASE_SCHEMA_VERSION = "base-erp-v9-release-identity-v1";
export const BASE_ACCOUNT_V11_RELEASE_SCHEMA_VERSION = "base-erp-v11-release-identity-v1";
export const BASE_ACCOUNT_PHASES = Object.freeze([
  "disconnected",
  "connected",
  "capabilities_checked",
  "review_ready",
  "owner_review_pending",
  "submitted",
  "pending",
  "confirmed",
  "failed",
  "partial",
  "erp_readback_pending",
  "erp_ready",
]);

const PHASE_SET = new Set(BASE_ACCOUNT_PHASES);
const DIGEST = /^[0-9a-f]{64}$/i;
const COMMIT = /^[0-9a-f]{40}$/i;
const ACCOUNT = /^0x[0-9a-f]{40}$/i;
const TARGET = /^0x[0-9a-f]{40}$/i;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const BYTES = /^0x(?:[0-9a-f]{2})*$/i;
const COMMIT_PLACEHOLDER = "PENDING_OWNER_PUBLIC_COMMIT";
const BASE_TARGET_FIELDS = new Set(["github_repo", "render_service_id", "render_domain", "dashboard_app_id", "canonical_primary_url"]);
const CIRCLE_MARKER = /(circle|arc)/i;

function fail(code, details = {}) {
  const error = new Error(code);
  error.code = code;
  Object.assign(error, details);
  throw error;
}

function plainObject(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  return value;
}

function exactFields(value, allowed, code) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(code, { field: key });
}

function requiredString(value, code) {
  if (typeof value !== "string" || value.trim() === "") fail(code);
  return value.trim();
}

function normalizeDigest(value, code) {
  const normalized = requiredString(value, code).toLowerCase();
  if (!DIGEST.test(normalized) || /^v9-f99$/i.test(normalized)) fail(code);
  return normalized;
}

function canonicalize(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("BRIDGE_CANONICAL_VALUE_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"));
    if (new Set(keys).size !== keys.length) fail("BRIDGE_CANONICAL_KEY_DUPLICATE");
    keys.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  fail("BRIDGE_CANONICAL_VALUE_INVALID");
}

function digest(value) {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function normalizeBaseTarget(value) {
  const source = plainObject(value, "BRIDGE_BASE_TARGET_REQUIRED");
  exactFields(source, BASE_TARGET_FIELDS, "BRIDGE_BASE_TARGET_UNKNOWN_FIELD");
  const target = {};
  for (const field of BASE_TARGET_FIELDS) target[field] = requiredString(source[field], "BRIDGE_BASE_TARGET_FIELD_REQUIRED");
  if (CIRCLE_MARKER.test(JSON.stringify(target))) fail("BRIDGE_BASE_TARGET_CIRCLE_COLLISION");
  return deepFreeze(target);
}

export function canonicalBridgeReleaseFingerprintBasis({ release_id, bom_fingerprint, base_target, commit_sha, source_catalog_fingerprint } = {}) {
  const schema_version = releaseIdentitySchema(release_id);
  return {
    schema_version,
    release_id,
    bom_fingerprint,
    base_target,
    commit_sha,
    source_catalog_fingerprint,
  };
}

function releaseIdentitySchema(releaseId) {
  if (typeof releaseId !== "string") fail("BRIDGE_RELEASE_SCHEMA_INVALID");
  if (/^base-erp-public-product-\d{8}-v11$/i.test(releaseId)) return BASE_ACCOUNT_V11_RELEASE_SCHEMA_VERSION;
  // v10 is a local successor of the v9 identity contract.
  if (/^base-erp-public-product-\d{8}-v(?:9|10)$/i.test(releaseId)) return BASE_ACCOUNT_RELEASE_SCHEMA_VERSION;
  fail("BRIDGE_RELEASE_SCHEMA_INVALID");
}

export function computeBridgeReleaseFingerprint(identity) {
  return digest(canonicalBridgeReleaseFingerprintBasis(identity));
}

function normalizeReleaseBinding(release, { requireCommit = true } = {}) {
  const source = plainObject(release, "BRIDGE_RELEASE_REQUIRED");
  exactFields(source, new Set([
    "release_id",
    "release_fingerprint",
    "bom_fingerprint",
    "commit_sha",
    "source_catalog_fingerprint",
    "base_target",
    "current",
    "historical",
    "synthetic",
  ]), "BRIDGE_RELEASE_UNKNOWN_FIELD");
  const normalized = {
    release_id: requiredString(source.release_id, "BRIDGE_RELEASE_ID_REQUIRED"),
    release_fingerprint: normalizeDigest(source.release_fingerprint, "BRIDGE_RELEASE_FINGERPRINT_INVALID"),
    bom_fingerprint: normalizeDigest(source.bom_fingerprint, "BRIDGE_BOM_FINGERPRINT_INVALID"),
  };
  if (requireCommit && typeof source.commit_sha !== "string") fail("BRIDGE_COMMIT_REQUIRED");
  if (source.commit_sha !== undefined) {
    const commit = source.commit_sha.trim();
    if (commit !== COMMIT_PLACEHOLDER && !COMMIT.test(commit)) fail("BRIDGE_COMMIT_INVALID");
    normalized.commit_sha = commit === COMMIT_PLACEHOLDER ? COMMIT_PLACEHOLDER : commit.toLowerCase();
  }
  if (typeof source.source_catalog_fingerprint !== "string") fail("BRIDGE_SOURCE_CATALOG_REQUIRED");
  normalized.source_catalog_fingerprint = normalizeDigest(source.source_catalog_fingerprint, "BRIDGE_SOURCE_CATALOG_INVALID");
  normalized.base_target = normalizeBaseTarget(source.base_target);
  if (source.current !== undefined && source.current !== true) fail("BRIDGE_RELEASE_NOT_CURRENT");
  if (source.historical !== undefined && source.historical !== false) fail("BRIDGE_RELEASE_HISTORICAL");
  if (source.synthetic !== undefined && source.synthetic !== false) fail("BRIDGE_RELEASE_SYNTHETIC");
  if (computeBridgeReleaseFingerprint(normalized) !== normalized.release_fingerprint) fail("BRIDGE_RELEASE_FINGERPRINT_MISMATCH");
  return deepFreeze(normalized);
}

function normalizeAccount(value, code = "BRIDGE_ACCOUNT_INVALID") {
  const account = requiredString(value, code);
  if (!ACCOUNT.test(account)) fail(code);
  return account.toLowerCase();
}

function normalizeCallTemplate(callTemplate) {
  const source = plainObject(callTemplate, "BRIDGE_CALL_TEMPLATE_REQUIRED");
  exactFields(source, new Set(["to", "value", "data", "capabilities"]), "BRIDGE_CALL_TEMPLATE_UNKNOWN_FIELD");
  const to = requiredString(source.to, "BRIDGE_CALL_TARGET_REQUIRED").toLowerCase();
  if (!TARGET.test(to)) fail("BRIDGE_CALL_TARGET_INVALID");
  const value = requiredString(source.value, "BRIDGE_CALL_VALUE_REQUIRED").toLowerCase();
  if (!QUANTITY.test(value)) fail("BRIDGE_CALL_VALUE_INVALID");
  const normalized = { to, value };
  if (source.data !== undefined) {
    const data = requiredString(source.data, "BRIDGE_CALL_DATA_REQUIRED").toLowerCase();
    if (!BYTES.test(data)) fail("BRIDGE_CALL_DATA_INVALID");
    normalized.data = data;
  }
  if (source.capabilities !== undefined) {
    const capabilities = plainObject(source.capabilities, "BRIDGE_CALL_CAPABILITIES_INVALID");
    normalized.capabilities = structuredClone(capabilities);
  }
  return deepFreeze(normalized);
}

function normalizedReleaseEqual(left, right) {
  return canonicalize(left) === canonicalize(right);
}

/** Validate and freeze a server-owned, release-bound call plan. */
export function buildReleaseBoundUnsignedCallPlan({ release, action_plan = null, call_template } = {}) {
  const binding = normalizeReleaseBinding(release);
  const actionPlan = action_plan === null ? null : plainObject(action_plan, "BRIDGE_ACTION_PLAN_INVALID");
  if (actionPlan) {
    if (actionPlan.action_enabled === true) fail("BRIDGE_ACTION_PLAN_EXECUTABLE");
    if (actionPlan.execution_authority !== "owner_review_required") fail("BRIDGE_ACTION_PLAN_AUTHORITY_INVALID");
    if (actionPlan.wallet?.wallet_method !== "wallet_sendCalls" || actionPlan.wallet?.account_bound !== true) fail("BRIDGE_ACTION_PLAN_WALLET_INVALID");
    const actionRelease = normalizeReleaseBinding({
      release_id: actionPlan.release?.release_id,
      release_fingerprint: actionPlan.release?.release_fingerprint,
      bom_fingerprint: actionPlan.release?.bom_fingerprint,
      commit_sha: binding.commit_sha,
      source_catalog_fingerprint: binding.source_catalog_fingerprint,
      base_target: binding.base_target,
    });
    if (!normalizedReleaseEqual({ ...actionRelease, commit_sha: binding.commit_sha }, binding)) fail("BRIDGE_ACTION_PLAN_RELEASE_MISMATCH");
  }
  const calls = normalizeCallTemplate(call_template);
  const callTemplateDigest = digest(calls);
  const plan = {
    schema_version: "base-account-wallet-bridge-plan-v1",
    release: binding,
    protocol: {
      chain_id: BASE_ACCOUNT_CHAIN_ID,
      version: BASE_ACCOUNT_SEND_CALLS_VERSION,
      capability_method: BASE_ACCOUNT_METHODS.capabilities,
      send_method: BASE_ACCOUNT_METHODS.sendCalls,
      status_method: BASE_ACCOUNT_METHODS.callsStatus,
      atomic_required: true,
    },
    from_binding: "connected_account",
    call_template: calls,
    call_template_digest: callTemplateDigest,
    review: {
      chain: "Base Mainnet",
      chain_id: BASE_ACCOUNT_CHAIN_ID,
      target: calls.to,
      value: calls.value,
      calldata: calls.data ?? "0x",
      release_id: binding.release_id,
      release_fingerprint: binding.release_fingerprint,
      bom_fingerprint: binding.bom_fingerprint,
      commit_sha: binding.commit_sha,
    },
    owner_review: {
      required: true,
      final_click_owner: "owner",
      status: "not_started",
    },
    execution: {
      unsigned: true,
      signed: false,
      broadcast: false,
      action_enabled: false,
      execution_ready: binding.commit_sha !== COMMIT_PLACEHOLDER,
      calls_id: null,
      receipt: null,
      finality: null,
      erp_readback: "not_observed",
    },
  };
  return deepFreeze(plan);
}

/** Strictly validate a previously-generated plan before any provider call. */
export function validateReleaseBoundUnsignedCallPlan({ plan, release } = {}) {
  try {
    const source = plainObject(plan, "BRIDGE_PLAN_REQUIRED");
    exactFields(source, new Set(["schema_version", "release", "protocol", "from_binding", "call_template", "call_template_digest", "review", "owner_review", "execution"]), "BRIDGE_PLAN_UNKNOWN_FIELD");
    if (source.schema_version !== "base-account-wallet-bridge-plan-v1") fail("BRIDGE_PLAN_SCHEMA_INVALID");
    const binding = normalizeReleaseBinding(source.release);
    if (release !== undefined && !normalizedReleaseEqual(binding, normalizeReleaseBinding(release))) fail("BRIDGE_PLAN_RELEASE_DRIFT");
    if (source.from_binding !== "connected_account") fail("BRIDGE_PLAN_FROM_BINDING_INVALID");
    const protocol = plainObject(source.protocol, "BRIDGE_PROTOCOL_REQUIRED");
    exactFields(protocol, new Set(["chain_id", "version", "capability_method", "send_method", "status_method", "atomic_required"]), "BRIDGE_PROTOCOL_UNKNOWN_FIELD");
    if (protocol.chain_id !== BASE_ACCOUNT_CHAIN_ID || protocol.version !== BASE_ACCOUNT_SEND_CALLS_VERSION || protocol.capability_method !== BASE_ACCOUNT_METHODS.capabilities || protocol.send_method !== BASE_ACCOUNT_METHODS.sendCalls || protocol.status_method !== BASE_ACCOUNT_METHODS.callsStatus || protocol.atomic_required !== true) fail("BRIDGE_PROTOCOL_DRIFT");
    const calls = normalizeCallTemplate(source.call_template);
    if (source.call_template_digest !== digest(calls)) fail("BRIDGE_CALL_TEMPLATE_DIGEST_MISMATCH");
    const execution = plainObject(source.execution, "BRIDGE_EXECUTION_REQUIRED");
    exactFields(execution, new Set(["unsigned", "signed", "broadcast", "action_enabled", "execution_ready", "calls_id", "receipt", "finality", "erp_readback"]), "BRIDGE_EXECUTION_UNKNOWN_FIELD");
    if (execution.unsigned !== true || execution.signed !== false || execution.broadcast !== false || execution.action_enabled !== false) fail("BRIDGE_PLAN_EXECUTION_ENABLED");
    if (execution.calls_id !== null || execution.receipt !== null || execution.finality !== null || execution.erp_readback !== "not_observed") fail("BRIDGE_PLAN_SENSITIVE_STATE_PRESENT");
    const ownerReview = plainObject(source.owner_review, "BRIDGE_OWNER_REVIEW_REQUIRED");
    exactFields(ownerReview, new Set(["required", "final_click_owner", "status"]), "BRIDGE_OWNER_REVIEW_UNKNOWN_FIELD");
    if (ownerReview.required !== true || ownerReview.final_click_owner !== "owner" || ownerReview.status !== "not_started") fail("BRIDGE_OWNER_REVIEW_INVALID");
    const expectedReview = {
      chain: "Base Mainnet",
      chain_id: BASE_ACCOUNT_CHAIN_ID,
      target: calls.to,
      value: calls.value,
      calldata: calls.data ?? "0x",
      release_id: binding.release_id,
      release_fingerprint: binding.release_fingerprint,
      bom_fingerprint: binding.bom_fingerprint,
      commit_sha: binding.commit_sha,
    };
    if (canonicalize(source.review) !== canonicalize(expectedReview)) fail("BRIDGE_REVIEW_BINDING_MISMATCH");
    return deepFreeze({ ok: true, plan: source, execution_ready: binding.commit_sha !== COMMIT_PLACEHOLDER });
  } catch (error) {
    return Object.freeze({ ok: false, fail_closed: true, code: error.code ?? "BRIDGE_PLAN_INVALID" });
  }
}

/** Build the only accepted wallet_sendCalls request from a trusted plan. */
export function buildWalletSendCallsRequest({ plan, account } = {}) {
  const valid = validateReleaseBoundUnsignedCallPlan({ plan });
  if (!valid.ok) fail(valid.code);
  if (!valid.execution_ready) fail("BRIDGE_COMMIT_UNBOUND");
  const from = normalizeAccount(account);
  const request = {
    version: BASE_ACCOUNT_SEND_CALLS_VERSION,
    from,
    chainId: BASE_ACCOUNT_CHAIN_ID,
    atomicRequired: true,
    calls: [structuredClone(valid.plan.call_template)],
  };
  return deepFreeze(request);
}

/** Verify a provider request is exactly the trusted server plan. */
export function verifyReleaseBoundSendCalls({ plan, account, request } = {}) {
  try {
    const expected = buildWalletSendCallsRequest({ plan, account });
    const source = plainObject(request, "BRIDGE_SEND_REQUEST_INVALID");
    exactFields(source, new Set(["version", "from", "chainId", "atomicRequired", "calls"]), "BRIDGE_SEND_REQUEST_UNKNOWN_FIELD");
    if (canonicalize(source) !== canonicalize(expected)) fail("BRIDGE_SEND_REQUEST_DRIFT");
    return Object.freeze({ ok: true, request: expected });
  } catch (error) {
    return Object.freeze({ ok: false, fail_closed: true, code: error.code ?? "BRIDGE_SEND_REQUEST_INVALID" });
  }
}

function capabilityStatus(value) {
  // The current Base Docs contract explicitly permits both `supported` and
  // `ready` for this preflight. Unknown/unsupported/missing values remain
  // fail-closed; no implicit upgrade or approval is inferred here.
  if (value === "supported" || value === "ready") return value;
  fail("BRIDGE_CAPABILITY_ATOMIC_UNSUPPORTED");
}

/** Validate the exact Base chain capability observation. */
export function validateWalletCapabilities(response) {
  try {
    const source = plainObject(response, "BRIDGE_CAPABILITIES_RESPONSE_INVALID");
    const keys = Object.keys(source);
    if (keys.length !== 1 || keys[0] !== BASE_ACCOUNT_CHAIN_ID) fail("BRIDGE_CAPABILITY_CHAIN_MISSING");
    const chain = plainObject(source[BASE_ACCOUNT_CHAIN_ID], "BRIDGE_CAPABILITY_CHAIN_INVALID");
    exactFields(chain, new Set(["atomic"]), "BRIDGE_CAPABILITY_UNKNOWN_FIELD");
    return deepFreeze({ ok: true, chain_id: BASE_ACCOUNT_CHAIN_ID, atomic: capabilityStatus(chain.atomic) });
  } catch (error) {
    return Object.freeze({ ok: false, fail_closed: true, code: error.code ?? "BRIDGE_CAPABILITY_INVALID" });
  }
}

function normalizedStatus(value) {
  const status = typeof value === "number" && Number.isInteger(value) ? value : NaN;
  if (![100, 200, 400, 500, 600].includes(status)) fail("BRIDGE_CALLS_STATUS_UNKNOWN");
  return status;
}

function validateReceipts(receipts, { allowEmpty = false, allowMissing = false } = {}) {
  if (receipts === undefined && allowMissing) return [];
  if (!Array.isArray(receipts) || (!allowEmpty && receipts.length === 0)) fail("BRIDGE_RECEIPTS_INVALID");
  return receipts.map((receipt) => {
    const source = plainObject(receipt, "BRIDGE_RECEIPT_INVALID");
    exactFields(source, new Set(["transactionHash", "status"]), "BRIDGE_RECEIPT_UNKNOWN_FIELD");
    if (source.status !== "0x1" && source.status !== "0x0") fail("BRIDGE_RECEIPT_STATUS_INVALID");
    const transactionHash = requiredString(source.transactionHash, "BRIDGE_RECEIPT_TRANSACTION_HASH_REQUIRED").toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(transactionHash)) fail("BRIDGE_RECEIPT_TRANSACTION_HASH_INVALID");
    return { transactionHash, status: source.status };
  });
}

function validateFinality(finality) {
  if (finality === undefined || finality === null) return null;
  const source = plainObject(finality, "BRIDGE_FINALITY_INVALID");
  exactFields(source, new Set(["stage", "final", "reorged", "evidence_ref"]), "BRIDGE_FINALITY_UNKNOWN_FIELD");
  if (source.stage !== "l1_batch_finality" || source.final !== true || source.reorged !== false || typeof source.evidence_ref !== "string" || source.evidence_ref.trim() === "") fail("BRIDGE_FINALITY_NOT_PROVEN");
  return { stage: source.stage, final: true, reorged: false, evidence_ref: source.evidence_ref.trim() };
}

/** Map wallet_getCallsStatus with atomic and receipt checks, never status alone. */
export function mapWalletCallsStatus(response, { finality = null, expectedCallsId = undefined } = {}) {
  try {
    const source = plainObject(response, "BRIDGE_CALLS_STATUS_RESPONSE_INVALID");
    exactFields(source, new Set(["version", "chainId", "id", "status", "atomic", "receipts"]), "BRIDGE_CALLS_STATUS_UNKNOWN_FIELD");
    if (source.version !== BASE_ACCOUNT_SEND_CALLS_VERSION) fail("BRIDGE_CALLS_VERSION_INVALID");
    if (source.chainId !== BASE_ACCOUNT_CHAIN_ID) fail("BRIDGE_CALLS_CHAIN_INVALID");
    if (typeof source.id !== "string" || source.id.trim() === "") fail("BRIDGE_CALLS_ID_MISSING");
    if (expectedCallsId !== undefined && source.id.trim() !== String(expectedCallsId).trim()) fail("BRIDGE_CALLS_ID_MISMATCH");
    const status = normalizedStatus(source.status);
    if (typeof source.atomic !== "boolean") fail("BRIDGE_CALLS_ATOMIC_MISSING");
    if (status === 100) {
      const receipts = validateReceipts(source.receipts, { allowEmpty: true, allowMissing: true });
      if (receipts.length > 0) fail("BRIDGE_PENDING_RECEIPTS_PRESENT");
      return deepFreeze({ ok: true, phase: "pending", status, atomic: source.atomic, receipt_success: false, finality: null });
    }
    if (status === 600) {
      const receipts = validateReceipts(source.receipts);
      return deepFreeze({ ok: true, phase: "partial", status, atomic: source.atomic, receipt_success: false, receipt_count: receipts.length, recovery_required: true, finality: null });
    }
    if (status === 400) {
      validateReceipts(source.receipts, { allowEmpty: true, allowMissing: true });
      if (source.receipts?.length) fail("BRIDGE_FAILED_RECEIPTS_PRESENT");
      return deepFreeze({ ok: true, phase: "failed", status, atomic: source.atomic, receipt_success: false, finality: null });
    }
    if (status === 500) {
      validateReceipts(source.receipts, { allowEmpty: true, allowMissing: true });
      if (source.receipts?.length) fail("BRIDGE_FAILED_RECEIPTS_PRESENT");
      return deepFreeze({ ok: true, phase: "failed", status, atomic: source.atomic, receipt_success: false, finality: null });
    }
    const receipts = validateReceipts(source.receipts);
    if (source.atomic !== true || receipts.some((receipt) => receipt.status !== "0x1")) fail("BRIDGE_ATOMIC_RECEIPT_NOT_SUCCESS");
    if (source.atomic === true && receipts.length !== 1) fail("BRIDGE_ATOMIC_RECEIPT_CARDINALITY");
    const provenFinality = validateFinality(finality);
    return deepFreeze({ ok: true, phase: provenFinality ? "erp_readback_pending" : "confirmed", status, atomic: true, receipt_success: true, receipt_count: receipts.length, finality: provenFinality });
  } catch (error) {
    return Object.freeze({ ok: false, fail_closed: true, phase: "failed", code: error.code ?? "BRIDGE_CALLS_STATUS_INVALID" });
  }
}

export function classifyBaseProviderError(error) {
  const code = Number(error?.code);
  const state = code === 4001 ? "rejected"
    : code === 4100 ? "auth_required"
      : code === 5700 || code === 4200 ? "capability_missing"
        : code === -32602 ? "invalid_request"
          : "provider_error";
  return Object.freeze({ ok: false, fail_closed: true, state, code: Number.isFinite(code) ? code : "provider_error" });
}

function connectionAccounts(result) {
  if (!Array.isArray(result) || result.length !== 1) fail("BRIDGE_CONNECT_RESULT_INVALID");
  return normalizeAccount(result[0], "BRIDGE_CONNECT_ACCOUNT_INVALID");
}

function redactedError(error) {
  const mapped = classifyBaseProviderError(error);
  return { state: mapped.state, code: mapped.code };
}

/**
 * Create an explicit-event browser controller. No SDK factory or provider
 * method is touched until connect(), checkCapabilities(), submit() or poll().
 */
export function createBaseAccountWalletBridge({ sdkFactory, sdkOptions = {}, fetchPlan, release } = {}) {
  if (typeof sdkFactory !== "function") fail("BRIDGE_SDK_FACTORY_REQUIRED");
  if (typeof fetchPlan !== "function" && (!fetchPlan || typeof fetchPlan !== "object")) fail("BRIDGE_PLAN_LOADER_REQUIRED");
  const trustedRelease = normalizeReleaseBinding(release);
  let provider = null;
  let account = null;
  let callsId = null;
  let plan = null;
  let capabilities = null;
  let statusReadback = null;
  let finality = null;
  let errorState = null;
  let providerCallCount = 0;
  let phase = "disconnected";
  let submitUsed = false;

  const callProvider = async (request) => {
    providerCallCount += 1;
    return provider.request(request);
  };
  const snapshot = () => deepFreeze({
    phase,
    connected: account !== null,
    capabilities_checked: capabilities !== null,
    review_ready: plan !== null,
    owner_review_pending: phase === "owner_review_pending",
    submitted: callsId !== null,
    calls_id_present: callsId !== null,
    provider_call_count: providerCallCount,
    error: errorState ? { ...errorState } : null,
    review: plan ? { ...plan.review } : null,
  });
  const requirePhase = (...allowed) => {
    if (!allowed.includes(phase)) fail("BRIDGE_PHASE_INVALID", { phase, allowed });
  };

  return Object.freeze({
    snapshot,
    async connect() {
      requirePhase("disconnected");
      try {
        const sdk = sdkFactory(sdkOptions);
        if (!sdk || typeof sdk.getProvider !== "function") fail("BRIDGE_PROVIDER_MISSING");
        provider = sdk.getProvider();
        if (!provider || typeof provider.request !== "function") fail("BRIDGE_PROVIDER_INVALID");
        const result = await callProvider({ method: BASE_ACCOUNT_METHODS.connect });
        account = connectionAccounts(result);
        phase = "connected";
        return snapshot();
      } catch (caught) {
        errorState = redactedError(caught);
        phase = "failed";
        return snapshot();
      }
    },
    async checkCapabilities() {
      requirePhase("connected");
      try {
        const result = await callProvider({ method: BASE_ACCOUNT_METHODS.capabilities, params: [account] });
        const validated = validateWalletCapabilities(result);
        if (!validated.ok) fail(validated.code);
        capabilities = validated;
        phase = "capabilities_checked";
        return snapshot();
      } catch (caught) {
        errorState = caught?.code ? { state: "capability_missing", code: caught.code } : redactedError(caught);
        phase = "failed";
        return snapshot();
      }
    },
    async prepareReview() {
      requirePhase("capabilities_checked");
      try {
        const rawPlan = typeof fetchPlan === "function" ? await fetchPlan() : structuredClone(fetchPlan);
        const validated = validateReleaseBoundUnsignedCallPlan({ plan: rawPlan, release: trustedRelease });
        if (!validated.ok) fail(validated.code);
        if (!validated.execution_ready) fail("BRIDGE_COMMIT_UNBOUND");
        plan = validated.plan;
        phase = "review_ready";
        return snapshot();
      } catch (caught) {
        errorState = { state: "plan_invalid", code: caught?.code ?? "BRIDGE_PLAN_INVALID" };
        phase = "failed";
        return snapshot();
      }
    },
    requestOwnerReview() {
      requirePhase("review_ready");
      phase = "owner_review_pending";
      return snapshot();
    },
    async submit() {
      requirePhase("owner_review_pending");
      if (submitUsed) fail("BRIDGE_SUBMIT_ALREADY_USED");
      submitUsed = true;
      try {
        const request = buildWalletSendCallsRequest({ plan, account });
        const result = await callProvider({ method: BASE_ACCOUNT_METHODS.sendCalls, params: [request] });
        if (typeof result !== "string" || result.trim() === "") fail("BRIDGE_CALLS_ID_INVALID");
        callsId = result.trim();
        phase = "submitted";
        return snapshot();
      } catch (caught) {
        errorState = caught?.code ? { state: "send_failed", code: caught.code } : redactedError(caught);
        phase = "failed";
        return snapshot();
      }
    },
    async pollStatus({ finality: finalityInput = null } = {}) {
      requirePhase("submitted", "pending", "confirmed");
      if (!callsId) fail("BRIDGE_CALLS_ID_REQUIRED");
      try {
        const result = await callProvider({ method: BASE_ACCOUNT_METHODS.callsStatus, params: [callsId] });
        const mapped = mapWalletCallsStatus(result, { finality: finalityInput, expectedCallsId: callsId });
        if (!mapped.ok) fail(mapped.code);
        statusReadback = mapped;
        finality = mapped.finality;
        phase = mapped.phase;
        return snapshot();
      } catch (caught) {
        errorState = caught?.code ? { state: "status_invalid", code: caught.code } : redactedError(caught);
        phase = "failed";
        return snapshot();
      }
    },
    markErpReadback(readback) {
      requirePhase("erp_readback_pending");
      const source = plainObject(readback, "BRIDGE_ERP_READBACK_INVALID");
      exactFields(source, new Set(["release_id", "release_fingerprint", "bom_fingerprint", "authoritative", "status", "evidence_ref"]), "BRIDGE_ERP_READBACK_UNKNOWN_FIELD");
      if (source.release_id !== trustedRelease.release_id || source.release_fingerprint !== trustedRelease.release_fingerprint || source.bom_fingerprint !== trustedRelease.bom_fingerprint || source.authoritative !== true || source.status !== "ready" || typeof source.evidence_ref !== "string" || source.evidence_ref.trim() === "") fail("BRIDGE_ERP_READBACK_MISMATCH");
      phase = "erp_ready";
      return snapshot();
    },
    /** Test-only introspection that intentionally excludes all wallet values. */
    _unsafeForTests: Object.freeze({
      getProviderCallCount: () => providerCallCount,
      getLastStatusPhase: () => statusReadback?.phase ?? null,
      getFinalityObserved: () => finality !== null,
    }),
  });
}

/** A static script for the operator page; it only binds an explicit click. */
export function renderWalletBridgeBrowserScript({ planUrl = "/wallet-action-bridge.json" } = {}) {
  const escapedPlanUrl = JSON.stringify(String(planUrl));
  return `<script data-base-account-bridge="v1">(() => {
  const button = document.querySelector('[data-wallet-bridge="connect"]');
  const sendButton = document.querySelector('[data-wallet-bridge="send"]');
  const pollButton = document.querySelector('[data-wallet-bridge="poll"]');
  const status = document.querySelector('[data-wallet-bridge-status]');
  if (!button || !status) return;
  const setStatus = (text) => { status.textContent = text; };
  let provider = null;
  let account = null;
  let plan = null;
  let currentRelease = null;
  let callsId = null;
  const CHAIN_ID = "0x2105";
  const VERSION = "2.0.0";
  const COMMIT_PLACEHOLDER = "PENDING_OWNER_PUBLIC_COMMIT";
  const digestPattern = /^[0-9a-f]{64}$/i;
  const commitPattern = /^[0-9a-f]{40}$/i;
  const validAccount = (value) => typeof value === "string" && /^0x[0-9a-f]{40}$/i.test(value);
  const sortedKeys = (value) => Object.keys(value).map((key) => key.normalize("NFC")).sort((left, right) => {
    const a = new TextEncoder().encode(left); const b = new TextEncoder().encode(right);
    for (let i = 0; i < Math.min(a.length, b.length); i += 1) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  });
  const canonical = (value) => {
    if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
    if (value === null || typeof value === "boolean") return JSON.stringify(value);
    if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error("canonical_value_invalid"); return JSON.stringify(value); }
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    if (value && typeof value === "object") return "{" + sortedKeys(value).map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
    throw new Error("canonical_value_invalid");
  };
  const sha256Hex = async (value) => {
    const bytes = new TextEncoder().encode(value);
    const digestBytes = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digestBytes)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  };
  const exactKeys = (value, allowed) => Object.keys(value).every((key) => allowed.includes(key)) && Object.keys(value).length === allowed.length;
  const targetValid = (target) => target && typeof target === "object" && !Array.isArray(target)
    && exactKeys(target, ["github_repo", "render_service_id", "render_domain", "dashboard_app_id", "canonical_primary_url"])
    && Object.values(target).every((value) => typeof value === "string" && value.trim() !== "")
    // Keep the embedded legacy page validator in lockstep with the canonical
    // bridge validator: concatenated identities such as circlepayments are
    // denylisted too.
    && !/(circle|arc)/i.test(JSON.stringify(target));
  const bindingFromRelease = (release) => ({
    release_id: release?.release_id,
    release_fingerprint: release?.release_fingerprint,
    bom_fingerprint: release?.bom_fingerprint,
    commit_sha: release?.git_commit ?? release?.commit_sha,
    source_catalog_fingerprint: release?.source_catalog_fingerprint,
    base_target: release?.base_target,
  });
  const validateBinding = async (binding) => {
    if (!binding || typeof binding !== "object" || !exactKeys(binding, ["release_id", "release_fingerprint", "bom_fingerprint", "commit_sha", "source_catalog_fingerprint", "base_target"])) throw new Error("release_binding_invalid");
    if (typeof binding.release_id !== "string" || !digestPattern.test(binding.release_fingerprint ?? "") || !digestPattern.test(binding.bom_fingerprint ?? "") || !digestPattern.test(binding.source_catalog_fingerprint ?? "") || !targetValid(binding.base_target)) throw new Error("release_binding_invalid");
    if (binding.commit_sha !== COMMIT_PLACEHOLDER && !commitPattern.test(binding.commit_sha ?? "")) throw new Error("commit_binding_invalid");
    const basis = { schema_version: releaseIdentitySchema(binding.release_id), release_id: binding.release_id, bom_fingerprint: binding.bom_fingerprint.toLowerCase(), base_target: binding.base_target, commit_sha: binding.commit_sha, source_catalog_fingerprint: binding.source_catalog_fingerprint.toLowerCase() };
    if ((await sha256Hex(canonical(basis))) !== binding.release_fingerprint.toLowerCase()) throw new Error("release_fingerprint_mismatch");
  };
  const validateCallTemplate = async (template) => {
    if (!template || typeof template !== "object" || !["to", "value", "data", "capabilities"].every((key) => Object.prototype.hasOwnProperty.call(template, key) || key === "data" || key === "capabilities") || Object.keys(template).some((key) => !["to", "value", "data", "capabilities"].includes(key))) throw new Error("call_template_invalid");
    if (!/^0x[0-9a-f]{40}$/i.test(template.to ?? "") || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(template.value ?? "")) throw new Error("call_template_invalid");
    if (template.data !== undefined && !/^0x(?:[0-9a-f]{2})*$/i.test(template.data)) throw new Error("call_template_invalid");
    if (template.capabilities !== undefined && (!template.capabilities || typeof template.capabilities !== "object" || Array.isArray(template.capabilities))) throw new Error("call_template_invalid");
  };
  const validatePlan = async (candidate, releaseDocument) => {
    if (!candidate || typeof candidate !== "object") throw new Error("plan_shape_invalid");
    // An authenticated owner route may wrap the strict plan with public
    // readiness flags. The visitor route never returns this wrapper, so it
    // remains fail-closed without exposing a call template.
    const envelope = Object.prototype.hasOwnProperty.call(candidate, "plan");
    if (envelope) {
      if (!exactKeys(candidate, ["bridge_available", "execution_ready", "plan"]) || candidate.bridge_available !== true || candidate.execution_ready !== true) throw new Error("plan_not_ready");
      candidate = candidate.plan;
    }
    if (!candidate || typeof candidate !== "object" || !exactKeys(candidate, ["schema_version", "release", "protocol", "from_binding", "call_template", "call_template_digest", "review", "owner_review", "execution"])) throw new Error("plan_shape_invalid");
    if (candidate.schema_version !== "base-account-wallet-bridge-plan-v1" || candidate.from_binding !== "connected_account") throw new Error("plan_shape_invalid");
    const expectedBinding = bindingFromRelease(releaseDocument);
    await validateBinding(expectedBinding); await validateBinding(candidate.release);
    if (canonical(candidate.release) !== canonical(expectedBinding)) throw new Error("plan_release_drift");
    const protocol = candidate.protocol;
    if (!protocol || typeof protocol !== "object" || !exactKeys(protocol, ["chain_id", "version", "capability_method", "send_method", "status_method", "atomic_required"]) || protocol.chain_id !== CHAIN_ID || protocol.version !== VERSION || protocol.capability_method !== "wallet_getCapabilities" || protocol.send_method !== "wallet_sendCalls" || protocol.status_method !== "wallet_getCallsStatus" || protocol.atomic_required !== true) throw new Error("protocol_drift");
    await validateCallTemplate(candidate.call_template);
    if (!digestPattern.test(candidate.call_template_digest ?? "") || (await sha256Hex(canonical({ to: candidate.call_template.to.toLowerCase(), value: candidate.call_template.value.toLowerCase(), ...(candidate.call_template.data === undefined ? {} : { data: candidate.call_template.data.toLowerCase() }), ...(candidate.call_template.capabilities === undefined ? {} : { capabilities: candidate.call_template.capabilities }) }))) !== candidate.call_template_digest.toLowerCase()) throw new Error("call_template_digest_mismatch");
    const expectedReview = { chain: "Base Mainnet", chain_id: CHAIN_ID, target: candidate.call_template.to.toLowerCase(), value: candidate.call_template.value.toLowerCase(), calldata: candidate.call_template.data?.toLowerCase() ?? "0x", release_id: candidate.release.release_id, release_fingerprint: candidate.release.release_fingerprint, bom_fingerprint: candidate.release.bom_fingerprint, commit_sha: candidate.release.commit_sha };
    if (!candidate.review || canonical(candidate.review) !== canonical(expectedReview)) throw new Error("review_binding_mismatch");
    if (!candidate.owner_review || !exactKeys(candidate.owner_review, ["required", "final_click_owner", "status"]) || candidate.owner_review.required !== true || candidate.owner_review.final_click_owner !== "owner" || candidate.owner_review.status !== "not_started") throw new Error("owner_review_invalid");
    const execution = candidate.execution;
    if (!execution || !exactKeys(execution, ["unsigned", "signed", "broadcast", "action_enabled", "execution_ready", "calls_id", "receipt", "finality", "erp_readback"]) || execution.unsigned !== true || execution.signed !== false || execution.broadcast !== false || execution.action_enabled !== false || execution.calls_id !== null || execution.receipt !== null || execution.finality !== null || execution.erp_readback !== "not_observed") throw new Error("execution_state_invalid");
    if (candidate.execution.execution_ready !== true) throw new Error("plan_not_ready");
    return candidate;
  };
  const loadAndValidatePlan = async () => {
    const response = await fetch(${escapedPlanUrl}, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error("plan_unavailable");
    const candidate = await response.json();
    const releaseResponse = await fetch("/release.json", { headers: { accept: "application/json" } });
    if (!releaseResponse.ok) throw new Error("release_unavailable");
    const releaseDocument = await releaseResponse.json();
    const validatedPlan = await validatePlan(candidate, releaseDocument);
    return { candidate: validatedPlan, releaseDocument };
  };
  const validateStatus = (result) => {
    if (!result || typeof result !== "object" || Object.keys(result).some((key) => !["version", "chainId", "id", "status", "atomic", "receipts"].includes(key)) || result.version !== VERSION || result.chainId !== CHAIN_ID || typeof result.id !== "string" || result.id.trim() === "" || typeof result.atomic !== "boolean") throw new Error("status_envelope_invalid");
    const statusCode = result.status; const receipts = result.receipts;
    if (!Number.isInteger(statusCode)) throw new Error("status_unknown");
    if (![100, 200, 400, 500, 600].includes(statusCode)) throw new Error("status_unknown");
    if (statusCode === 100) { if (receipts !== undefined && (!Array.isArray(receipts) || receipts.length !== 0)) throw new Error("pending_receipts_invalid"); return statusCode; }
    if (statusCode === 400 || statusCode === 500) { if (receipts !== undefined && (!Array.isArray(receipts) || receipts.length !== 0)) throw new Error("failed_receipts_invalid"); return statusCode; }
    if (!Array.isArray(receipts) || receipts.length === 0 || (statusCode === 200 && result.atomic !== true) || (statusCode === 200 && receipts.length !== 1) || receipts.some((receipt) => !receipt || Object.keys(receipt).some((key) => !["transactionHash", "status"].includes(key)) || !/^0x[0-9a-f]{64}$/i.test(receipt.transactionHash ?? "") || (receipt.status !== "0x1" && receipt.status !== "0x0")) || (statusCode === 200 && receipts.some((receipt) => receipt.status !== "0x1"))) throw new Error("receipt_or_atomic_invalid");
    return statusCode;
  };
  const failClosed = () => {
    setStatus("Wallet action unavailable; owner review remains required");
    button.disabled = true;
    if (sendButton) sendButton.disabled = true;
    if (pollButton) pollButton.disabled = true;
  };
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const loaded = await loadAndValidatePlan();
      plan = loaded.candidate; currentRelease = loaded.releaseDocument;
      const factory = window.createBaseAccountSDK;
      if (typeof factory !== "function") throw new Error("sdk_missing");
      provider = factory({}).getProvider();
      if (!provider || typeof provider.request !== "function") throw new Error("provider_missing");
      const accounts = await provider.request({ method: "wallet_connect" });
      if (!Array.isArray(accounts) || accounts.length !== 1 || !validAccount(accounts[0])) throw new Error("connect_invalid");
      account = accounts[0].toLowerCase();
      const capabilities = await provider.request({ method: "wallet_getCapabilities", params: [account] });
      if (!capabilities || Object.keys(capabilities).length !== 1 || !capabilities["0x2105"] || !["supported", "ready"].includes(capabilities["0x2105"].atomic)) throw new Error("capability_missing");
      setStatus("Connected; review target, value, calldata and release, then click Send");
      if (sendButton) { sendButton.disabled = false; sendButton.removeAttribute("aria-disabled"); }
    } catch (error) {
      failClosed();
    }
  }, { once: true });
  sendButton?.addEventListener("click", async () => {
    sendButton.disabled = true;
    try {
      if (!provider || !account || !plan || callsId) throw new Error("review_or_calls_id_invalid");
      const loaded = await loadAndValidatePlan();
      if (canonical(loaded.candidate) !== canonical(plan) || canonical(bindingFromRelease(loaded.releaseDocument)) !== canonical(bindingFromRelease(currentRelease))) throw new Error("plan_drift_before_send");
      const template = plan.call_template;
      const request = { version: "2.0.0", from: account, chainId: "0x2105", atomicRequired: true, calls: [{ to: template.to.toLowerCase(), value: template.value.toLowerCase(), ...(template.data === undefined ? {} : { data: template.data.toLowerCase() }), ...(template.capabilities === undefined ? {} : { capabilities: template.capabilities }) }] };
      const result = await provider.request({ method: "wallet_sendCalls", params: [request] });
      if (typeof result !== "string" || result.trim() === "") throw new Error("calls_id_invalid");
      callsId = result.trim();
      setStatus("Owner review submitted; status and finality remain pending");
      if (pollButton) { pollButton.disabled = false; pollButton.removeAttribute("aria-disabled"); }
    } catch (error) {
      failClosed();
    }
  }, { once: true });
  pollButton?.addEventListener("click", async () => {
    pollButton.disabled = true;
    try {
      if (!provider || !callsId) throw new Error("calls_id_required");
      const result = await provider.request({ method: "wallet_getCallsStatus", params: [callsId] });
      const statusCode = validateStatus(result);
      if (typeof result.id !== "string" || result.id.trim() !== callsId) throw new Error("status_id_mismatch");
      if (statusCode === 100) { setStatus("Wallet batch pending; no ERP readback"); pollButton.disabled = false; return; }
      if (statusCode === 600) { setStatus("Wallet batch partial; recovery required"); return; }
      if (statusCode === 400 || statusCode === 500) { setStatus("Wallet batch failed; no ERP readback"); return; }
      setStatus("Receipt success; L1 finality and ERP readback are still required");
    } catch (error) {
      failClosed();
    }
  });
})();</script>`;
}
