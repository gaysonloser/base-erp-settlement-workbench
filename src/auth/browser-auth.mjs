export const BASE_ACCOUNT_CHAIN_ID = "0x2105";
export const BASE_ACCOUNT_METHODS = Object.freeze({
  capabilities: "wallet_getCapabilities",
  sendCalls: "wallet_sendCalls",
});

export const AUTH_WALLET_CONNECT_METHOD = "wallet_connect";
export const AUTH_WALLET_CONNECT_VERSION = "1";
const DIGEST = /^[0-9a-f]{64}$/i;
const COMMIT = /^[0-9a-f]{40}$/i;
const COMMIT_PLACEHOLDER = "PENDING_OWNER_PUBLIC_COMMIT";
const ACCOUNT = /^0x[0-9a-f]{40}$/i;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const BYTES = /^0x(?:[0-9a-f]{2})*$/i;
const BASE_TARGET_FIELDS = ["github_repo", "render_service_id", "render_domain", "dashboard_app_id", "canonical_primary_url"];
const DEFAULT_SDK_OPTIONS = Object.freeze({
  appName: "Base ERP Settlement Workbench",
  appLogoUrl: "",
  appChainIds: Object.freeze([8453]),
  preference: Object.freeze({ telemetry: false }),
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function requiredString(value, code) {
  if (typeof value !== "string" || value.trim() === "") fail(code);
  return value.trim();
}

function exactFields(value, allowed, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(code);
}

function canonicalize(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("auth_canonical_value_invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"));
    if (new Set(keys).size !== keys.length) fail("auth_canonical_key_duplicate");
    keys.sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  fail("auth_canonical_value_invalid");
}

async function digestValue(value) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) fail("auth_crypto_unavailable");
  const bytes = new TextEncoder().encode(canonicalize(value));
  const digestBuffer = await subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digestBuffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function noCircle(value) {
  // The browser route is an independent BASE/CIRCLE boundary.  Do not rely
  // on word boundaries: concatenated identities such as `circlepayments`
  // must be denied just as surely as a slash-delimited repo name.
  return !/(circle|arc)/i.test(JSON.stringify(value));
}

function releaseIdentitySchema(releaseId) {
  if (typeof releaseId !== "string") fail("auth_owner_plan_release_schema_invalid");
  if (/^base-erp-public-product-\d{8}-v11$/i.test(releaseId)) return "base-erp-v11-release-identity-v1";
  // v10 intentionally retains the accepted v9 canonical identity basis.
  if (/^base-erp-public-product-\d{8}-v(?:9|10)$/i.test(releaseId)) return "base-erp-v9-release-identity-v1";
  fail("auth_owner_plan_release_schema_invalid");
}

function validateWalletCapabilities(response) {
  const chain = response && typeof response === "object" && !Array.isArray(response) ? response[BASE_ACCOUNT_CHAIN_ID] : null;
  if (!response || typeof response !== "object" || Array.isArray(response) || Object.keys(response).length !== 1 || !chain || typeof chain !== "object" || Array.isArray(chain) || Object.keys(chain).some((key) => key !== "atomic") || (chain.atomic !== "supported" && chain.atomic !== "ready")) return { ok: false, code: "auth_capability_missing" };
  return { ok: true, atomic: chain.atomic };
}

async function validateOwnerPlan(plan, release) {
  const source = plan && typeof plan === "object" && !Array.isArray(plan) ? plan : null;
  const binding = source?.release;
  const calls = source?.call_template;
  const protocol = source?.protocol;
  const review = source?.review;
  const ownerReview = source?.owner_review;
  const execution = source?.execution;
  try {
    if (!source || source.schema_version !== "base-account-wallet-bridge-plan-v1" || !binding || !calls || !protocol || !review || !ownerReview || !execution) fail("auth_owner_plan_invalid");
    exactFields(source, new Set(["schema_version", "release", "protocol", "from_binding", "call_template", "call_template_digest", "review", "owner_review", "execution"]), "auth_owner_plan_unknown_field");
    exactFields(binding, new Set(["release_id", "release_fingerprint", "bom_fingerprint", "commit_sha", "source_catalog_fingerprint", "base_target"]), "auth_owner_plan_release_shape");
    exactFields(binding.base_target, new Set(BASE_TARGET_FIELDS), "auth_owner_plan_target_shape");
    if (!BASE_TARGET_FIELDS.every((field) => typeof binding.base_target[field] === "string" && binding.base_target[field].trim() !== "") || !noCircle(binding.base_target)) fail("auth_owner_plan_target_invalid");
    if (!DIGEST.test(binding.release_fingerprint) || !DIGEST.test(binding.bom_fingerprint) || !DIGEST.test(binding.source_catalog_fingerprint)) fail("auth_owner_plan_release_digest_invalid");
    if (binding.commit_sha !== COMMIT_PLACEHOLDER && !COMMIT.test(binding.commit_sha)) fail("auth_owner_plan_commit_invalid");
    if (release && (binding.release_id !== release.release_id || binding.release_fingerprint !== release.release_fingerprint || binding.bom_fingerprint !== release.bom_fingerprint || binding.commit_sha !== release.git_commit || binding.source_catalog_fingerprint !== release.source_catalog_fingerprint)) fail("auth_owner_plan_release_drift");
    const identitySchema = releaseIdentitySchema(binding.release_id);
    const expectedFingerprint = await digestValue({ schema_version: identitySchema, release_id: binding.release_id, bom_fingerprint: binding.bom_fingerprint, base_target: binding.base_target, commit_sha: binding.commit_sha, source_catalog_fingerprint: binding.source_catalog_fingerprint });
    if (binding.release_fingerprint !== expectedFingerprint) fail("auth_owner_plan_release_fingerprint_invalid");
    exactFields(protocol, new Set(["chain_id", "version", "capability_method", "send_method", "status_method", "atomic_required"]), "auth_owner_plan_protocol_shape");
    if (protocol.chain_id !== BASE_ACCOUNT_CHAIN_ID || protocol.version !== "2.0.0" || protocol.capability_method !== BASE_ACCOUNT_METHODS.capabilities || protocol.send_method !== BASE_ACCOUNT_METHODS.sendCalls || protocol.status_method !== "wallet_getCallsStatus" || protocol.atomic_required !== true) fail("auth_owner_plan_protocol_invalid");
    if (source.from_binding !== "connected_account") fail("auth_owner_plan_from_binding_invalid");
    exactFields(calls, new Set(["to", "value", "data", "capabilities"]), "auth_owner_plan_call_shape");
    if (!/^0x[0-9a-f]{40}$/i.test(String(calls.to ?? "")) || !QUANTITY.test(String(calls.value ?? "")) || (calls.data !== undefined && !BYTES.test(String(calls.data)))) fail("auth_owner_plan_call_invalid");
    if (calls.capabilities !== undefined && (!calls.capabilities || typeof calls.capabilities !== "object" || Array.isArray(calls.capabilities) || !noCircle(calls.capabilities))) fail("auth_owner_plan_call_capabilities_invalid");
    if (source.call_template_digest !== await digestValue(calls)) fail("auth_owner_plan_call_digest_invalid");
    const expectedReview = { chain: "Base Mainnet", chain_id: BASE_ACCOUNT_CHAIN_ID, target: calls.to.toLowerCase(), value: calls.value.toLowerCase(), calldata: calls.data ?? "0x", release_id: binding.release_id, release_fingerprint: binding.release_fingerprint, bom_fingerprint: binding.bom_fingerprint, commit_sha: binding.commit_sha };
    if (canonicalize(review) !== canonicalize(expectedReview)) fail("auth_owner_plan_review_invalid");
    exactFields(ownerReview, new Set(["required", "final_click_owner", "status"]), "auth_owner_plan_owner_review_shape");
    if (ownerReview.required !== true || ownerReview.final_click_owner !== "owner" || ownerReview.status !== "not_started") fail("auth_owner_plan_owner_review_invalid");
    exactFields(execution, new Set(["unsigned", "signed", "broadcast", "action_enabled", "execution_ready", "calls_id", "receipt", "finality", "erp_readback"]), "auth_owner_plan_execution_shape");
    if (execution.unsigned !== true || execution.signed !== false || execution.broadcast !== false || execution.action_enabled !== false || execution.execution_ready !== true || execution.calls_id !== null || execution.receipt !== null || execution.finality !== null || execution.erp_readback !== "not_observed") fail("auth_owner_plan_execution_invalid");
    if (binding.commit_sha === COMMIT_PLACEHOLDER) fail("auth_owner_plan_commit_unbound");
    return { ok: true, plan: source, execution_ready: true };
  } catch (error) {
    return { ok: false, code: error.code ?? "auth_owner_plan_invalid" };
  }
}

function buildWalletSendCallsRequest({ plan, account }) {
  const callTemplate = plan?.call_template;
  if (!callTemplate || !/^0x[0-9a-f]{40}$/i.test(String(account ?? ""))) fail("auth_send_request_invalid");
  return Object.freeze({ version: "2.0.0", from: account.toLowerCase(), chainId: BASE_ACCOUNT_CHAIN_ID, atomicRequired: true, calls: [structuredClone(callTemplate)] });
}

export function mapCallsStatus(response, { expectedCallsId, finality = null } = {}) {
  const source = response && typeof response === "object" && !Array.isArray(response) ? response : null;
  if (!source || Object.keys(source).some((key) => !["version", "chainId", "id", "status", "atomic", "receipts"].includes(key)) || source.version !== "2.0.0" || source.chainId !== BASE_ACCOUNT_CHAIN_ID || source.id !== expectedCallsId || !Number.isInteger(source.status) || ![100, 200, 400, 500, 600].includes(source.status) || typeof source.atomic !== "boolean") fail("auth_calls_status_invalid");
  const status = source.status;
  const receipts = source.receipts;
  if (receipts !== undefined) {
    if (!Array.isArray(receipts)) fail("auth_receipts_invalid");
    for (const receipt of receipts) {
      if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) || Object.keys(receipt).some((key) => !["transactionHash", "status"].includes(key)) || typeof receipt.transactionHash !== "string" || !/^0x[0-9a-f]{64}$/i.test(receipt.transactionHash) || !["0x0", "0x1"].includes(receipt.status)) fail("auth_receipt_shape_invalid");
    }
  }
  if (status === 100) {
    if (receipts !== undefined && receipts.length > 0) fail("auth_pending_receipts_invalid");
    return { phase: "pending" };
  }
  if (status === 400 || status === 500) {
    if (receipts !== undefined && receipts.length > 0) fail("auth_failed_receipts_invalid");
    return { phase: "failed" };
  }
  if (!Array.isArray(receipts) || receipts.length === 0) fail("auth_receipts_invalid");
  if (status === 600) return { phase: "partial" };
  if (source.atomic !== true || receipts.length !== 1 || receipts.some((receipt) => receipt.status !== "0x1" || typeof receipt.transactionHash !== "string" || !/^0x[0-9a-f]{64}$/i.test(receipt.transactionHash))) fail("auth_atomic_receipt_invalid");
  if (finality !== null) {
    if (!finality || finality.stage !== "l1_batch_finality" || finality.final !== true || finality.reorged !== false || typeof finality.evidence_ref !== "string" || finality.evidence_ref.trim() === "") fail("auth_finality_invalid");
    return { phase: "erp_readback_pending" };
  }
  return { phase: "confirmed" };
}

export function buildWalletConnectSignInRequest(nonce) {
  const source = typeof nonce === "string" ? { nonce } : object(nonce);
  const signIn = {
    nonce: requiredString(source?.nonce, "auth_nonce_invalid"),
    chainId: BASE_ACCOUNT_CHAIN_ID,
  };
  // The two required fields above preserve the Base contract. When the
  // server supplies its strict SIWE envelope, pass the optional EIP-4361
  // fields too so the wallet signs exactly the server-issued message.
  for (const [key, value] of [["version", source?.version], ["domain", source?.domain], ["uri", source?.uri], ["statement", source?.statement], ["issuedAt", source?.issued_at], ["expirationTime", source?.expiration_time]]) {
    if (value !== undefined) signIn[key] = requiredString(value, `auth_${key}_invalid`);
  }
  if (source?.resources !== undefined) {
    if (!Array.isArray(source.resources) || source.resources.some((entry) => typeof entry !== "string" || entry.trim() === "")) fail("auth_resources_invalid");
    signIn.resources = [...source.resources];
  }
  return Object.freeze({
    method: AUTH_WALLET_CONNECT_METHOD,
    params: [{ version: AUTH_WALLET_CONNECT_VERSION, capabilities: { signInWithEthereum: signIn } }],
  });
}

function parseConnectResponse(result) {
  const source = object(result);
  const account = Array.isArray(source?.accounts) && source.accounts.length === 1 ? object(source.accounts[0]) : null;
  if (!account || typeof account.address !== "string") fail("auth_wallet_connect_response_invalid");
  const capability = object(account.capabilities)?.signInWithEthereum;
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) fail("auth_signin_capability_missing");
  if (Object.keys(capability).some((key) => !["message", "signature"].includes(key))) fail("auth_signin_capability_shape_invalid");
  return Object.freeze({
    address: requiredString(account.address, "auth_address_invalid"),
    message: requiredString(capability.message, "auth_message_invalid"),
    signature: requiredString(capability.signature, "auth_signature_invalid"),
  });
}

function redactedProviderError(error) {
  const code = Number(error?.code);
  const state = code === 4001 ? "rejected" : code === 4100 ? "auth_required" : code === 5700 || code === 4200 ? "capability_missing" : "provider_error";
  return Object.freeze({ state, code: Number.isFinite(code) ? code : "provider_error" });
}

function classifyError(error, fallbackState) {
  if (Number.isFinite(Number(error?.code))) return redactedProviderError(error);
  return Object.freeze({ state: fallbackState, code: error?.code ?? "auth_failed" });
}

/**
 * Browser auth controller. It has no constructor side effects: SDK/provider
 * creation and every provider request are reachable only from explicit
 * signIn() or sendCalls() calls.
 */
export function createBaseAuthBrowserController({ sdkFactory, fetcher = globalThis.fetch, release, sdkOptions = DEFAULT_SDK_OPTIONS } = {}) {
  if (typeof fetcher !== "function") fail("auth_fetcher_required");
  // Telemetry is disabled through the supported SDK preference.  Do not let a
  // caller accidentally re-enable it while retaining other SDK options.
  const effectiveSdkOptions = Object.freeze({
    ...sdkOptions,
    appChainIds: [...(Array.isArray(sdkOptions?.appChainIds) ? sdkOptions.appChainIds : DEFAULT_SDK_OPTIONS.appChainIds)],
    preference: Object.freeze({ ...(sdkOptions?.preference ?? {}), telemetry: false }),
  });
  let phase = "disconnected";
  let provider = null;
  let account = null;
  let csrfToken = null;
  let plan = null;
  let callsId = null;
  let sendUsed = false;
  let capabilities = null;
  let error = null;
  let fetchCount = 0;
  let providerCallCount = 0;
  const state = () => Object.freeze({
    phase,
    authenticated: csrfToken !== null,
    review_ready: plan !== null,
    submitted: callsId !== null,
    calls_id_present: callsId !== null,
    provider_call_count: providerCallCount,
    fetch_count: fetchCount,
    error: error ? { ...error } : null,
    review: plan ? { chain: plan.review.chain, chain_id: plan.review.chain_id, target: plan.review.target, value: plan.review.value, calldata: plan.review.calldata, release_id: plan.review.release_id, release_fingerprint: plan.review.release_fingerprint, bom_fingerprint: plan.review.bom_fingerprint } : null,
  });
  const fetchJson = async (url, options = {}) => {
    fetchCount += 1;
    const response = await fetcher(url, { credentials: "include", ...options });
    const body = await response.json();
    if (!response.ok) fail(body?.error ?? "auth_request_failed");
    return body;
  };
  const sameOriginHeader = () => {
    const origin = globalThis.location?.origin;
    return typeof origin === "string" && origin.startsWith("https://") ? { "x-base-auth-origin": origin } : {};
  };
  const call = async (request) => {
    providerCallCount += 1;
    return provider.request(request);
  };
  return Object.freeze({
    snapshot: state,
    async prefetch() {
      // Session/nonce prefetch is permitted and never creates a provider.
      await fetchJson("/auth/session");
      return state();
    },
    async signIn() {
      if (phase !== "disconnected") fail("auth_phase_invalid");
      try {
        const nonce = await fetchJson("/auth/nonce");
        if (!nonce?.nonce) fail("auth_nonce_invalid");
        const factory = sdkFactory ?? globalThis.BaseAuthSDK?.createBaseAccountSDK ?? globalThis.createBaseAccountSDK;
        if (typeof factory !== "function") fail("auth_sdk_unavailable");
        const sdk = factory(effectiveSdkOptions);
        if (!sdk || typeof sdk.getProvider !== "function") fail("auth_provider_missing");
        provider = sdk.getProvider();
        if (!provider || typeof provider.request !== "function") fail("auth_provider_invalid");
        const connected = parseConnectResponse(await call(buildWalletConnectSignInRequest(nonce)));
        account = connected.address;
        const verified = await fetchJson("/auth/verify", {
          method: "POST",
          headers: { "content-type": "application/json", ...sameOriginHeader() },
          body: JSON.stringify({ address: connected.address, message: connected.message, signature: connected.signature }),
        });
        csrfToken = requiredString(verified.csrf_token, "auth_csrf_missing");
        phase = "authenticated";
        capabilities = validateWalletCapabilities(await call({ method: BASE_ACCOUNT_METHODS.capabilities, params: [account] }));
        if (!capabilities.ok) fail(capabilities.code);
        const ownerPlan = await fetchJson("/owner/wallet-action-bridge.json", { headers: { "x-csrf-token": csrfToken, ...sameOriginHeader() } });
        const validPlan = await validateOwnerPlan(ownerPlan.plan ?? ownerPlan, release);
        if (!validPlan.ok || !validPlan.execution_ready) fail(validPlan.code ?? "auth_owner_plan_invalid");
        plan = validPlan.plan;
        phase = "owner_review_ready";
        return state();
      } catch (caught) {
        error = classifyError(caught, "auth_failed");
        phase = "failed";
        return state();
      }
    },
    async sendCalls() {
      if (sendUsed) fail("auth_send_already_used");
      if (phase !== "owner_review_ready" || !provider || !account || !plan) fail("auth_owner_review_required");
      sendUsed = true;
      try {
        const request = buildWalletSendCallsRequest({ plan, account });
        const result = await call({ method: BASE_ACCOUNT_METHODS.sendCalls, params: [request] });
        if (typeof result !== "string" || result.trim() === "") fail("auth_calls_id_invalid");
        callsId = result.trim();
        phase = "submitted";
        return state();
      } catch (caught) {
        error = classifyError(caught, "send_failed");
        phase = "failed";
        return state();
      }
    },
    async pollStatus({ finality = null } = {}) {
      if (!callsId || !provider || !["submitted", "pending", "confirmed"].includes(phase)) fail("auth_calls_status_unavailable");
      try {
        const mapped = mapCallsStatus(await call({ method: "wallet_getCallsStatus", params: [callsId] }), { expectedCallsId: callsId, finality });
        phase = mapped.phase;
        return state();
      } catch (caught) {
        error = classifyError(caught, "status_invalid");
        phase = "failed";
        return state();
      }
    },
    markErpReadback(readback) {
      if (phase !== "erp_readback_pending") fail("auth_erp_readback_early");
      if (!readback || readback.release_id !== release?.release_id || readback.release_fingerprint !== release?.release_fingerprint || readback.bom_fingerprint !== release?.bom_fingerprint || readback.authoritative !== true || readback.status !== "ready") fail("auth_erp_readback_invalid");
      phase = "erp_ready";
      return state();
    },
  });
}

/** Inline page adapter; only button events call the controller. */
export function renderBaseAuthBrowserScript({ bundlePath = "/assets/base-auth-sdk.bundle.js", release = null } = {}) {
  const path = String(bundlePath).replace(/[\"']/g, "");
  const releaseJson = JSON.stringify({
    release_id: release?.release_id ?? null,
    release_fingerprint: release?.release_fingerprint ?? null,
    bom_fingerprint: release?.bom_fingerprint ?? null,
    git_commit: release?.git_commit ?? null,
  }).replaceAll("<", "\\u003c");
  return `<script>globalThis.__BASE_AUTH_RELEASE__=${releaseJson};</script><script>
(() => {
  const signIn = document.querySelector('[data-base-auth="signin"]');
  const send = document.querySelector('[data-base-auth="send"]');
  const poll = document.querySelector('[data-base-auth="poll"]');
  const status = document.querySelector('[data-base-auth-status]');
  const review = document.querySelector('[data-base-auth-review]');
  if (!signIn || !status) return;
  let controller;
  const write = (value) => { status.textContent = value; };
  const loadSdkBundle = () => new Promise((resolve, reject) => {
    if (globalThis.BaseAuthControllerFactory && globalThis.BaseAuthSDK) return resolve();
    const script = document.createElement("script");
    script.src = "${path}";
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("auth_sdk_bundle_unavailable"));
    document.head.appendChild(script);
  });
  const make = () => {
    if (controller) return controller;
    controller = globalThis.BaseAuthControllerFactory ? globalThis.BaseAuthControllerFactory({ release: globalThis.__BASE_AUTH_RELEASE__ }) : null;
    return controller;
  };
  signIn.addEventListener("click", async () => {
    signIn.disabled = true;
    write("Owner sign-in in progress; review remains required.");
    try {
      await loadSdkBundle();
      const current = make();
      if (!current) throw new Error("auth_sdk_unavailable");
      const next = await current.signIn();
      if (next.review_ready) {
        write("Authenticated owner review ready. Inspect chain, target, value, calldata and release before sending.");
        if (review && next.review) {
          review.hidden = false;
          review.textContent = "Owner review · " + next.review.chain + " · " + next.review.target + " · value " + next.review.value + " · calldata " + next.review.calldata + " · release " + next.review.release_id + " · BOM " + next.review.bom_fingerprint;
        }
        if (send) send.disabled = false;
      } else write("Owner sign-in did not produce a reviewable plan.");
    } catch { write("Owner sign-in unavailable; no wallet action was sent."); }
  });
  send?.addEventListener("click", async () => {
    send.disabled = true;
    try {
      const next = await controller?.sendCalls();
      write(next?.submitted ? "Owner review submitted; status and ERP gates remain pending." : "Wallet action remains unavailable.");
      if (poll) poll.disabled = !next?.submitted;
    } catch { write("Wallet action rejected or unavailable; no retry was performed."); }
  });
  poll?.addEventListener("click", async () => {
    poll.disabled = true;
    try {
      const next = await controller?.pollStatus();
      write(next?.phase === "pending" ? "Wallet status pending; no ERP readback yet." : next?.phase === "confirmed" ? "Confirmed receipt observed; finality and ERP readback remain pending." : "Wallet status is fail-closed; recovery is required.");
      if (next?.phase === "pending" || next?.phase === "confirmed") poll.disabled = false;
    } catch { write("Wallet status unavailable; no retry was performed."); }
  });
})();
</script>`;
}

export { parseConnectResponse, redactedProviderError, validateOwnerPlan };
