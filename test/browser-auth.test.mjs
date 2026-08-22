import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  buildWalletConnectSignInRequest,
  createBaseAuthBrowserController,
  mapCallsStatus,
  renderBaseAuthBrowserScript,
  validateOwnerPlan,
} from "../src/auth/browser-auth.mjs";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const BASE_TARGET = Object.freeze({ github_repo: "gaysonloser/base-erp-settlement-workbench", render_service_id: "srv-d9t0bsafngtc7387gqo0", render_domain: "base-erp-settlement-workbench.onrender.com", dashboard_app_id: "6a7a0717e209a55163497d2d", canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com" });
const SOURCE_CATALOG = "d".repeat(64);
function canonical(value) {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function digest(value) { return createHash("sha256").update(canonical(value)).digest("hex"); }
const RELEASE_BASE = { release_id: "base-erp-public-product-20260822-v11", bom_fingerprint: "b".repeat(64), git_commit: "c".repeat(40), source_catalog_fingerprint: SOURCE_CATALOG, base_target: BASE_TARGET };
const RELEASE = Object.freeze({ ...RELEASE_BASE, release_fingerprint: digest({ schema_version: "base-erp-v11-release-identity-v1", release_id: RELEASE_BASE.release_id, bom_fingerprint: RELEASE_BASE.bom_fingerprint, base_target: RELEASE_BASE.base_target, commit_sha: RELEASE_BASE.git_commit, source_catalog_fingerprint: RELEASE_BASE.source_catalog_fingerprint }) });
const PLAN = Object.freeze({
  schema_version: "base-account-wallet-bridge-plan-v1",
  release: { release_id: RELEASE.release_id, release_fingerprint: RELEASE.release_fingerprint, bom_fingerprint: RELEASE.bom_fingerprint, commit_sha: RELEASE.git_commit, source_catalog_fingerprint: RELEASE.source_catalog_fingerprint, base_target: RELEASE.base_target },
  protocol: { chain_id: "0x2105", version: "2.0.0", capability_method: "wallet_getCapabilities", send_method: "wallet_sendCalls", status_method: "wallet_getCallsStatus", atomic_required: true },
  from_binding: "connected_account",
  call_template: { to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x" },
  call_template_digest: digest({ data: "0x", to: "0x2222222222222222222222222222222222222222", value: "0x0" }),
  review: { chain: "Base Mainnet", chain_id: "0x2105", target: "0x2222222222222222222222222222222222222222", value: "0x0", calldata: "0x", release_id: RELEASE.release_id, release_fingerprint: RELEASE.release_fingerprint, bom_fingerprint: RELEASE.bom_fingerprint, commit_sha: RELEASE.git_commit },
  owner_review: { required: true, final_click_owner: "owner", status: "not_started" },
  execution: { unsigned: true, signed: false, broadcast: false, action_enabled: false, execution_ready: true, calls_id: null, receipt: null, finality: null, erp_readback: "not_observed" },
});

function response(body, ok = true, status = ok ? 200 : 400) {
  return { ok, status, async json() { return body; } };
}

test("wallet_connect SIWE request is exact and provider is untouched until signIn", async () => {
  assert.deepEqual(buildWalletConnectSignInRequest("nonce-123"), {
    method: "wallet_connect",
    params: [{ version: "1", capabilities: { signInWithEthereum: { nonce: "nonce-123", chainId: "0x2105" } } }],
  });
  assert.deepEqual(buildWalletConnectSignInRequest({
    nonce: "nonce-123",
    version: "1",
    domain: "base.example",
    uri: "https://base.example",
    statement: "Sign in to Base ERP Settlement Workbench.",
    issued_at: "2026-08-22T00:00:00.000Z",
    expiration_time: "2026-08-22T00:05:00.000Z",
    resources: ["https://base.example/auth/session"],
  }), {
    method: "wallet_connect",
    params: [{ version: "1", capabilities: { signInWithEthereum: {
      nonce: "nonce-123",
      chainId: "0x2105",
      version: "1",
      domain: "base.example",
      uri: "https://base.example",
      statement: "Sign in to Base ERP Settlement Workbench.",
      issuedAt: "2026-08-22T00:00:00.000Z",
      expirationTime: "2026-08-22T00:05:00.000Z",
      resources: ["https://base.example/auth/session"],
    } } }],
  });
  const calls = [];
  const sdkOptionsSeen = [];
  const provider = { async request(request) { calls.push(request); if (request.method === "wallet_connect") return { accounts: [{ address: ACCOUNT, capabilities: { signInWithEthereum: { message: "siwe", signature: "0xsig" } } }] }; if (request.method === "wallet_getCapabilities") return { "0x2105": { atomic: "ready" } }; if (request.method === "wallet_sendCalls") return "calls-v11"; if (request.method === "wallet_getCallsStatus") return { version: "2.0.0", chainId: "0x2105", id: "calls-v11", status: 200, atomic: true, receipts: [{ transactionHash: `0x${"a".repeat(64)}`, status: "0x1" }] }; throw new Error("unexpected"); } };
  const fetchCalls = [];
  const controller = createBaseAuthBrowserController({
    sdkFactory: (options) => { sdkOptionsSeen.push(options); return { getProvider: () => provider }; },
    release: RELEASE,
    fetcher: async (url, options = {}) => {
      fetchCalls.push({ url, options });
      if (url === "/auth/session") return response({ authenticated: false, auth_enabled: true });
      if (url === "/auth/nonce") return response({ nonce: "nonce-123" });
      if (url === "/auth/verify") return response({ authenticated: true, csrf_token: "csrf-token" });
      if (url === "/owner/wallet-action-bridge.json") return response({ plan: PLAN });
      throw new Error("unexpected fetch");
    },
  });
  assert.equal(calls.length, 0);
  assert.equal(controller.snapshot().provider_call_count, 0);
  await controller.prefetch();
  assert.equal(calls.length, 0);
  const signed = await controller.signIn();
  assert.equal(signed.review_ready, true);
  assert.equal(sdkOptionsSeen.length, 1);
  assert.equal(sdkOptionsSeen[0].preference.telemetry, false);
  assert.deepEqual(sdkOptionsSeen[0].appChainIds, [8453]);
  assert.deepEqual(calls.map((entry) => entry.method), ["wallet_connect", "wallet_getCapabilities"]);
  const submitted = await controller.sendCalls();
  assert.equal(submitted.submitted, true);
  assert.equal(calls.at(-1).method, "wallet_sendCalls");
  const confirmed = await controller.pollStatus();
  assert.equal(confirmed.phase, "confirmed");
  const pendingErp = await controller.pollStatus({ finality: { stage: "l1_batch_finality", final: true, reorged: false, evidence_ref: "finality-v11" } });
  assert.equal(pendingErp.phase, "erp_readback_pending");
  assert.throws(() => controller.markErpReadback({ release_id: RELEASE.release_id, release_fingerprint: RELEASE.release_fingerprint, bom_fingerprint: RELEASE.bom_fingerprint, authoritative: false, status: "ready" }), (error) => error.code === "auth_erp_readback_invalid");
  assert.equal(controller.markErpReadback({ release_id: RELEASE.release_id, release_fingerprint: RELEASE.release_fingerprint, bom_fingerprint: RELEASE.bom_fingerprint, authoritative: true, status: "ready" }).phase, "erp_ready");
  await assert.rejects(() => controller.sendCalls(), (error) => error.code === "auth_send_already_used");
  assert.equal(JSON.stringify(controller.snapshot()).includes(ACCOUNT), false);
  assert.equal(fetchCalls.some(({ options }) => String(options.body ?? "").includes("csrf-token")), false);
});

test("browser adapter fails closed for unknown capability and never retries provider errors", async () => {
  const provider = { async request({ method }) { if (method === "wallet_connect") return { accounts: [{ address: ACCOUNT, capabilities: { signInWithEthereum: { message: "siwe", signature: "0xsig" } } }] }; if (method === "wallet_getCapabilities") return { "0x2105": { atomic: "unknown" } }; throw new Error("unexpected"); } };
  const controller = createBaseAuthBrowserController({
    sdkFactory: () => ({ getProvider: () => provider }), release: RELEASE,
    fetcher: async (url) => url === "/auth/nonce" ? response({ nonce: "n" }) : url === "/auth/verify" ? response({ csrf_token: "c" }) : response({ plan: PLAN }),
  });
  const result = await controller.signIn();
  assert.equal(result.phase, "failed");
  assert.equal(result.provider_call_count, 2);
  assert.equal(result.error.code, "auth_capability_missing");
});

test("provider rejection codes are mapped without exposing provider payloads", async () => {
  const provider = { async request() { throw Object.assign(new Error("user rejected"), { code: 4001, data: ACCOUNT }); } };
  const controller = createBaseAuthBrowserController({ sdkFactory: () => ({ getProvider: () => provider }), release: RELEASE, fetcher: async (url) => url === "/auth/nonce" ? response({ nonce: "n" }) : response({ plan: PLAN }) });
  const result = await controller.signIn();
  assert.equal(result.phase, "failed");
  assert.deepEqual(result.error, { state: "rejected", code: 4001 });
  assert.equal(JSON.stringify(result).includes(ACCOUNT), false);
});

test("wallet status unknown shapes and premature ERP readback remain fail-closed", async () => {
  const provider = { async request({ method }) { if (method === "wallet_connect") return { accounts: [{ address: ACCOUNT, capabilities: { signInWithEthereum: { message: "siwe", signature: "0xsig" } } }] }; if (method === "wallet_getCapabilities") return { "0x2105": { atomic: "ready" } }; if (method === "wallet_sendCalls") return "calls-v11"; return { version: "2.0.0", chainId: "0x2105", id: "calls-v11", status: 999, atomic: true, receipts: [] }; } };
  const controller = createBaseAuthBrowserController({ sdkFactory: () => ({ getProvider: () => provider }), release: RELEASE, fetcher: async (url) => url === "/auth/nonce" ? response({ nonce: "n" }) : url === "/auth/verify" ? response({ csrf_token: "c" }) : response({ plan: PLAN }) });
  await controller.signIn();
  await controller.sendCalls();
  const failed = await controller.pollStatus();
  assert.equal(failed.phase, "failed");
  assert.equal(failed.error.code, "auth_calls_status_invalid");
  assert.throws(() => controller.markErpReadback({ release_id: RELEASE.release_id, release_fingerprint: RELEASE.release_fingerprint, bom_fingerprint: RELEASE.bom_fingerprint, authoritative: true, status: "ready" }), (error) => error.code === "auth_erp_readback_early");
});

test("wallet status envelope is exact, numeric, and pending receipts stay empty", async () => {
  const valid = { version: "2.0.0", chainId: "0x2105", id: "calls-v11", status: 200, atomic: true, receipts: [{ transactionHash: `0x${"a".repeat(64)}`, status: "0x1" }] };
  assert.equal(mapCallsStatus(valid, { expectedCallsId: "calls-v11" }).phase, "confirmed");
  assert.throws(() => mapCallsStatus({ ...valid, status: "200" }, { expectedCallsId: "calls-v11" }), (error) => error.code === "auth_calls_status_invalid");
  assert.throws(() => mapCallsStatus({ ...valid, injected: true }, { expectedCallsId: "calls-v11" }), (error) => error.code === "auth_calls_status_invalid");
  assert.equal(mapCallsStatus({ ...valid, status: 100, receipts: [] }, { expectedCallsId: "calls-v11" }).phase, "pending");
  assert.throws(() => mapCallsStatus({ ...valid, status: 100, receipts: [{ transactionHash: `0x${"a".repeat(64)}`, status: "0x1" }] }, { expectedCallsId: "calls-v11" }), (error) => error.code === "auth_pending_receipts_invalid");
});

test("unknown release suffixes and concatenated CIRCLE identities fail closed", async () => {
  const unknownRelease = { ...RELEASE, release_id: "base-erp-public-product-20260822-v13" };
  const unknownPlan = { ...PLAN, release: { ...PLAN.release, release_id: unknownRelease.release_id }, review: { ...PLAN.review, release_id: unknownRelease.release_id } };
  const unknown = await validateOwnerPlan(unknownPlan, unknownRelease);
  assert.equal(unknown.ok, false);
  assert.equal(unknown.code, "auth_owner_plan_release_schema_invalid");
  const circleTarget = { ...BASE_TARGET, github_repo: "circlepayments/base-erp-settlement-workbench" };
  const circleRelease = { ...RELEASE, base_target: circleTarget };
  const circlePlan = { ...PLAN, release: { ...PLAN.release, base_target: circleTarget }, review: { ...PLAN.review, release_id: circleRelease.release_id } };
  const circle = await validateOwnerPlan(circlePlan, circleRelease);
  assert.equal(circle.ok, false);
  assert.equal(circle.code, "auth_owner_plan_target_invalid");
});

test("inline auth script is self-hosted, explicit-event only and has no browser storage/logging", () => {
  const script = renderBaseAuthBrowserScript({ release: RELEASE });
  assert.match(script, /base-auth-sdk-v12\.bundle\.js/);
  assert.match(script, /addEventListener\("click"/);
  assert.match(script, /createElement\("script"\)/);
  assert.doesNotMatch(script, /<script\s+src=/i);
  assert.match(script, /wallet action remains unavailable/i);
  assert.doesNotMatch(script, /localStorage|sessionStorage|console\./);
  assert.doesNotMatch(script, /wallet_connect\(/);
});
