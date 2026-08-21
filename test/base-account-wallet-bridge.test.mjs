import test from "node:test";
import assert from "node:assert/strict";

import {
  BASE_ACCOUNT_CHAIN_ID,
  BASE_ACCOUNT_METHODS,
  BASE_ACCOUNT_SEND_CALLS_VERSION,
  buildReleaseBoundUnsignedCallPlan,
  buildWalletSendCallsRequest,
  classifyBaseProviderError,
  computeBridgeReleaseFingerprint,
  createBaseAccountWalletBridge,
  mapWalletCallsStatus,
  renderWalletBridgeBrowserScript,
  validateReleaseBoundUnsignedCallPlan,
  validateWalletCapabilities,
  verifyReleaseBoundSendCalls,
} from "../src/base-account-wallet-bridge.mjs";

const baseTarget = {
  github_repo: "gaysonloser/base-erp-settlement-workbench",
  render_service_id: "srv-d9t0bsafngtc7387gqo0",
  render_domain: "base-erp-settlement-workbench.onrender.com",
  dashboard_app_id: "6a7a0717e209a55163497d2d",
  canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com",
};

const release = {
  release_id: "base-erp-public-product-20260816-v9",
  bom_fingerprint: "b".repeat(64),
  commit_sha: "71964b167c5462d8633344781c2f2b532354b3c1",
  source_catalog_fingerprint: "c".repeat(64),
  base_target: baseTarget,
};
release.release_fingerprint = computeBridgeReleaseFingerprint(release);

const actionPlan = {
  action_enabled: false,
  execution_authority: "owner_review_required",
  wallet: { wallet_method: "wallet_sendCalls", account_bound: true },
  release: {
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
  },
};

const callTemplate = {
  to: "0x1111111111111111111111111111111111111111",
  value: "0x0",
  data: "0x",
};
const txHash = `0x${"a".repeat(64)}`;
const statusBase = { version: "2.0.0", chainId: "0x2105", id: "calls-fixture-id", atomic: true };

function plan() {
  return buildReleaseBoundUnsignedCallPlan({ release, action_plan: actionPlan, call_template: callTemplate });
}

test("builds a deterministic v2 release-bound unsigned call plan", () => {
  const first = plan();
  const second = plan();
  assert.deepEqual(first, second);
  assert.equal(first.protocol.chain_id, BASE_ACCOUNT_CHAIN_ID);
  assert.equal(first.protocol.version, BASE_ACCOUNT_SEND_CALLS_VERSION);
  assert.equal(first.from_binding, "connected_account");
  assert.equal(first.execution.action_enabled, false);
  assert.equal(first.execution.signed, false);
  assert.equal(first.execution.broadcast, false);
  assert.equal(first.review.target, callTemplate.to);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.call_template), true);
});

test("rejects placeholder and arbitrary non-40-hex commit bindings before send", () => {
  const placeholderRelease = {
    ...release,
    commit_sha: "PENDING_OWNER_PUBLIC_COMMIT",
  };
  placeholderRelease.release_fingerprint = computeBridgeReleaseFingerprint(placeholderRelease);
  const placeholder = buildReleaseBoundUnsignedCallPlan({
    release: placeholderRelease,
    call_template: callTemplate,
  });
  assert.equal(placeholder.execution.execution_ready, false);
  assert.throws(() => buildWalletSendCallsRequest({ plan: placeholder, account: "0x2222222222222222222222222222222222222222" }), /BRIDGE_COMMIT_UNBOUND/);
  assert.throws(() => buildReleaseBoundUnsignedCallPlan({ release: { ...release, commit_sha: "d".repeat(64) }, call_template: callTemplate }), /BRIDGE_COMMIT_INVALID/);
  assert.throws(() => buildReleaseBoundUnsignedCallPlan({ release: { ...release, release_fingerprint: "V9-F99" }, call_template: callTemplate }), /BRIDGE_RELEASE_FINGERPRINT_INVALID/);
  assert.throws(() => buildReleaseBoundUnsignedCallPlan({ release: { ...release, release_fingerprint: "d".repeat(64) }, call_template: callTemplate }), /BRIDGE_RELEASE_FINGERPRINT_MISMATCH/);
});

test("release-bound plans fail closed on BASE/CIRCLE target collision and action-plan drift", () => {
  const circleRelease = {
    ...release,
    base_target: { ...baseTarget, github_repo: "circle/arc-settlement-workbench" },
  };
  circleRelease.release_fingerprint = computeBridgeReleaseFingerprint(circleRelease);
  assert.throws(() => buildReleaseBoundUnsignedCallPlan({ release: circleRelease, call_template: callTemplate }), /BRIDGE_BASE_TARGET_CIRCLE_COLLISION/);
  assert.throws(() => buildReleaseBoundUnsignedCallPlan({ release, action_plan: { ...actionPlan, release: { ...actionPlan.release, bom_fingerprint: "d".repeat(64) } }, call_template: callTemplate }), /BRIDGE_RELEASE_FINGERPRINT_MISMATCH/);
});

test("builds only the canonical wallet_sendCalls v2 request and rejects client drift", () => {
  const request = buildWalletSendCallsRequest({ plan: plan(), account: "0x2222222222222222222222222222222222222222" });
  assert.deepEqual(request, {
    version: "2.0.0",
    from: "0x2222222222222222222222222222222222222222",
    chainId: "0x2105",
    atomicRequired: true,
    calls: [callTemplate],
  });
  assert.equal(verifyReleaseBoundSendCalls({ plan: plan(), account: request.from, request }).ok, true);
  assert.equal(verifyReleaseBoundSendCalls({ plan: plan(), account: request.from, request: { ...request, chainId: "0x8453" } }).ok, false);
  assert.equal(verifyReleaseBoundSendCalls({ plan: plan(), account: request.from, request: { ...request, calls: [{ ...callTemplate, to: "0x3333333333333333333333333333333333333333" }] } }).ok, false);
});

test("capability validation is Base-chain exact and fail-closed", () => {
  assert.equal(validateWalletCapabilities({ "0x2105": { atomic: "supported" } }).ok, true);
  assert.equal(validateWalletCapabilities({ "0x2105": { atomic: "ready" } }).atomic, "ready");
  for (const candidate of [
    {},
    { "0x8453": { atomic: "supported" } },
    { "0x2105": {} },
    { "0x2105": { atomic: "unsupported" } },
    { "0x2105": { atomic: "unknown" } },
    { "0x2105": { atomic: "supported", extra: true } },
  ]) assert.equal(validateWalletCapabilities(candidate).ok, false);
});

test("status mapping checks atomic, receipts and finality independently", () => {
  assert.equal(mapWalletCallsStatus({ ...statusBase, status: 100 }).phase, "pending");
  assert.equal(mapWalletCallsStatus({ ...statusBase, status: 600, receipts: [{ transactionHash: txHash, status: "0x1" }, { transactionHash: `0x${"b".repeat(64)}`, status: "0x0" }] }).phase, "partial");
  assert.equal(mapWalletCallsStatus({ ...statusBase, status: 400, atomic: false, receipts: [] }).phase, "failed");
  assert.equal(mapWalletCallsStatus({ ...statusBase, status: 500, receipts: [] }).phase, "failed");
  const confirmed = mapWalletCallsStatus({ ...statusBase, status: 200, receipts: [{ transactionHash: txHash, status: "0x1" }] });
  assert.equal(confirmed.phase, "confirmed");
  const ready = mapWalletCallsStatus(
    { ...statusBase, status: 200, receipts: [{ transactionHash: txHash, status: "0x1" }] },
    { finality: { stage: "l1_batch_finality", final: true, reorged: false, evidence_ref: "finality-fixture-1" } },
  );
  assert.equal(ready.phase, "erp_readback_pending");
  assert.equal(mapWalletCallsStatus({ ...statusBase, id: "different-calls-id", status: 200, receipts: [{ transactionHash: txHash, status: "0x1" }] }, { expectedCallsId: statusBase.id }).ok, false);
  for (const invalid of [
    { ...statusBase, status: 200, atomic: false, receipts: [{ transactionHash: txHash, status: "0x1" }] },
    { ...statusBase, status: 200, receipts: [{ transactionHash: txHash, status: "0x0" }] },
    { ...statusBase, status: 200, receipts: [{ transactionHash: txHash, status: "0x1", tx_hash: "forbidden" }] },
    { ...statusBase, status: 200, receipts: [{ transactionHash: "0x1", status: "0x1" }] },
    { ...statusBase, status: 999, receipts: [{ transactionHash: txHash, status: "0x1" }] },
    { ...statusBase, status: 200, chainId: "0x8453", receipts: [{ transactionHash: txHash, status: "0x1" }] },
    { ...statusBase, status: 200, version: "1.0", receipts: [{ transactionHash: txHash, status: "0x1" }] },
  ]) assert.equal(mapWalletCallsStatus(invalid).ok, false);
});

test("controller makes no provider call on construction and sends once only after explicit review", async () => {
  const calls = [];
  let statusRead = false;
  const provider = {
    async request(request) {
      calls.push(request);
      if (request.method === BASE_ACCOUNT_METHODS.connect) return ["0x2222222222222222222222222222222222222222"];
      if (request.method === BASE_ACCOUNT_METHODS.capabilities) return { "0x2105": { atomic: "supported" } };
      if (request.method === BASE_ACCOUNT_METHODS.sendCalls) return "calls-fixture-id";
      if (request.method === BASE_ACCOUNT_METHODS.callsStatus) {
        statusRead = true;
        return { ...statusBase, status: 200, receipts: [{ transactionHash: txHash, status: "0x1" }] };
      }
      throw new Error("unexpected provider method");
    },
  };
  let sdkFactoryCalls = 0;
  const bridge = createBaseAccountWalletBridge({
    sdkFactory: () => { sdkFactoryCalls += 1; return { getProvider: () => provider }; },
    fetchPlan: plan(),
    release,
  });
  assert.equal(sdkFactoryCalls, 0);
  assert.equal(bridge.snapshot().phase, "disconnected");
  assert.equal(calls.length, 0);
  await bridge.connect();
  await bridge.checkCapabilities();
  await bridge.prepareReview();
  assert.equal(bridge.snapshot().phase, "review_ready");
  bridge.requestOwnerReview();
  await bridge.submit();
  assert.equal(bridge.snapshot().phase, "submitted");
  assert.equal(bridge.snapshot().calls_id_present, true);
  await bridge.pollStatus();
  assert.equal(statusRead, true);
  assert.equal(bridge.snapshot().phase, "confirmed");
  assert.equal(calls.filter(({ method }) => method === BASE_ACCOUNT_METHODS.sendCalls).length, 1);
  assert.equal(JSON.stringify(bridge.snapshot()).includes("calls-fixture-id"), false);
  assert.equal(JSON.stringify(bridge.snapshot()).includes("0x222222"), false);
});

test("finality and ERP readback are separate gates; mismatches fail closed", async () => {
  const provider = {
    async request({ method }) {
      if (method === BASE_ACCOUNT_METHODS.connect) return ["0x2222222222222222222222222222222222222222"];
      if (method === BASE_ACCOUNT_METHODS.capabilities) return { "0x2105": { atomic: "ready" } };
      if (method === BASE_ACCOUNT_METHODS.sendCalls) return "calls-fixture-id";
      return { ...statusBase, status: 200, receipts: [{ transactionHash: txHash, status: "0x1" }] };
    },
  };
  const bridge = createBaseAccountWalletBridge({ sdkFactory: () => ({ getProvider: () => provider }), fetchPlan: plan(), release });
  await bridge.connect();
  await bridge.checkCapabilities();
  await bridge.prepareReview();
  bridge.requestOwnerReview();
  await bridge.submit();
  await bridge.pollStatus({ finality: { stage: "l1_batch_finality", final: true, reorged: false, evidence_ref: "finality-fixture-1" } });
  assert.equal(bridge.snapshot().phase, "erp_readback_pending");
  bridge.markErpReadback({ release_id: release.release_id, release_fingerprint: release.release_fingerprint, bom_fingerprint: release.bom_fingerprint, authoritative: true, status: "ready", evidence_ref: "erp-fixture-1" });
  assert.equal(bridge.snapshot().phase, "erp_ready");
});

test("provider error classes are explicit and never retried", () => {
  assert.deepEqual(classifyBaseProviderError({ code: 4001 }), { ok: false, fail_closed: true, state: "rejected", code: 4001 });
  assert.deepEqual(classifyBaseProviderError({ code: 4100 }), { ok: false, fail_closed: true, state: "auth_required", code: 4100 });
  assert.deepEqual(classifyBaseProviderError({ code: 5700 }), { ok: false, fail_closed: true, state: "capability_missing", code: 5700 });
  assert.equal(classifyBaseProviderError({ code: 4200 }).state, "capability_missing");
  assert.equal(classifyBaseProviderError({ code: -32602 }).state, "invalid_request");
  assert.equal(classifyBaseProviderError({ code: 4999 }).state, "provider_error");
});

test("browser script binds connect only to an explicit click and does not expose sensitive state", () => {
  const script = renderWalletBridgeBrowserScript();
  assert.match(script, /addEventListener\("click"/);
  assert.match(script, /wallet_connect/);
  assert.match(script, /release_fingerprint_mismatch/);
  assert.match(script, /status_envelope_invalid/);
  assert.equal(script.includes("console.log"), false);
  assert.equal(script.includes("localStorage"), false);
  assert.equal(script.includes("sessionStorage"), false);
  assert.equal(script.includes("tx_hash"), false);
  assert.match(script, /status\.textContent/);
});
