import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { V9_SOURCE_CATALOG_FINGERPRINT, computeV9ReleaseFingerprint, createAppServer, readReleaseDocument } from "../src/server.mjs";
import { buildSiweMessage, createAuthService } from "../src/auth/auth-core.mjs";
import { digest as h220Digest } from "../src/base-release-evidence-integrity-seal.mjs";
import { buildWalletErpActionPlanProjection } from "../src/base-erp-workbench.mjs";
import { buildReleaseBoundUnsignedCallPlan } from "../src/base-account-wallet-bridge.mjs";

const ORIGIN = "https://base.example";
const HOST = "base.example";
const ADDRESS = "0x1111111111111111111111111111111111111111";
const SECRET = "auth-server-secret-012345678901234567890123";

const PROJECT_PREFIX = "projects/2026-08_Base_ERP_Settlement_Workbench/";
const TEST_COMMIT = "a".repeat(40);

function readCurrentV9Candidate() {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_v9_local_2026-08-16.json", "utf8"));
  candidate.immutable_release_bom = candidate.immutable_release_bom.map((entry) => ({
    path: entry.path,
    digest: createHash("sha256").update(readFileSync(entry.path.slice(PROJECT_PREFIX.length))).digest("hex"),
  }));
  candidate.bom_fingerprint = h220Digest(candidate.immutable_release_bom);
  candidate.immutable_bom_sha256 = candidate.bom_fingerprint;
  candidate.commit_sha = TEST_COMMIT;
  candidate.commit_placeholder = false;
  candidate.commit_gate = { state: "bound_owner_public_commit_for_test", required: "test-only", placeholder: "PENDING_OWNER_PUBLIC_COMMIT", failure_code: null };
  candidate.release_fingerprint = computeV9ReleaseFingerprint({
    release_id: candidate.release_id,
    bom_fingerprint: candidate.bom_fingerprint,
    base_target: candidate.base_target,
    commit_sha: candidate.commit_sha,
    source_catalog_fingerprint: candidate.source_catalog_fingerprint,
  });
  const { self_hash: _ignoredSelfHash, ...withoutSelfHash } = candidate;
  candidate.self_hash = h220Digest(withoutSelfHash);
  assert.equal(candidate.source_catalog_fingerprint, V9_SOURCE_CATALOG_FINGERPRINT);
  return candidate;
}

async function withTempV9Candidate(run) {
  const directory = mkdtempSync(join(tmpdir(), "base-erp-auth-v9-candidate-"));
  const releasePath = join(directory, "release.json");
  writeFileSync(releasePath, JSON.stringify(readCurrentV9Candidate(), null, 2));
  try { return await run(releasePath); }
  finally { rmSync(directory, { recursive: true, force: true }); }
}

async function withServer(run, { enabled = true, releasePath = undefined, authCallTemplate = null } = {}) {
  const ownerDigest = createHmac("sha256", SECRET).update(ADDRESS).digest("hex");
  let counter = 0;
  const authService = createAuthService({
    env: enabled ? { BASE_AUTH_ENABLED: "true", BASE_AUTH_ORIGIN: ORIGIN, BASE_AUTH_HMAC_SECRET: SECRET, BASE_AUTH_OWNER_DIGESTS: ownerDigest, BASE_AUTH_SINGLE_INSTANCE: "true" } : {},
    verifier: async () => true,
    randomBytesFn: (size) => Buffer.alloc(size, ++counter),
  });
  const server = createAppServer({ authService, releasePath, authCallTemplate, env: { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT } });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  try { return await run(`http://127.0.0.1:${address.port}`, authService); }
  finally { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}

const authHeaders = { origin: ORIGIN, host: HOST };

function request(baseUrl, pathname, { method = "GET", headers = {}, body = null } = {}) {
  const url = new URL(pathname, baseUrl);
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method, headers: { ...headers, ...(body !== null ? { "content-length": Buffer.byteLength(body) } : {}) } }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: response.statusCode, headers: response.headers, text, json: () => JSON.parse(text) });
      });
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

test("auth routes are disabled safely without production configuration", async () => {
  await withServer(async (baseUrl) => {
    const nonce = await request(baseUrl, "/auth/nonce", { headers: authHeaders });
    assert.equal(nonce.status, 503);
    assert.deepEqual(nonce.json(), { error: "auth_disabled" });
    const session = await request(baseUrl, "/auth/session", { headers: authHeaders });
    assert.equal(session.status, 503);
    const health = await request(baseUrl, "/healthz");
    const body = health.json();
    assert.equal(body.auth.ready, false);
    assert.equal(body.auth.owner_allowlist, "unavailable");
  }, { enabled: false });
});

test("nonce/verify/session/logout are explicit, same-origin and redacted", async () => {
  await withServer(async (baseUrl) => {
    const nonceResponse = await request(baseUrl, "/auth/nonce", { headers: authHeaders });
    assert.equal(nonceResponse.status, 200);
    const nonce = nonceResponse.json();
    assert.equal(nonce.chain_id, "0x2105");
    const message = buildSiweMessage({ domain: nonce.domain, uri: nonce.uri, address: ADDRESS, nonce: nonce.nonce, issuedAt: nonce.issued_at, expirationTime: nonce.expiration_time, statement: nonce.statement, resources: nonce.resources, chainId: 8453, version: "1" });
    const verifyResponse = await request(baseUrl, "/auth/verify", { method: "POST", headers: { ...authHeaders, "content-type": "application/json" }, body: JSON.stringify({ address: ADDRESS, message, signature: "0x1234" }) });
    assert.equal(verifyResponse.status, 200);
    const verified = verifyResponse.json();
    assert.equal(verified.authenticated, true);
    assert.equal(JSON.stringify(verified).includes(ADDRESS), false);
    assert.equal(JSON.stringify(verified).includes(message), false);
    const setCookie = verifyResponse.headers["set-cookie"]?.[0];
    assert.match(setCookie, /^__Host-base_erp_session=/);
    const sessionResponse = await request(baseUrl, "/auth/session", { headers: { ...authHeaders, cookie: setCookie } });
    assert.deepEqual(sessionResponse.json(), { authenticated: true, auth_enabled: true });
    const ownerNoCsrf = await request(baseUrl, "/owner/wallet-action-bridge.json", { headers: { ...authHeaders, cookie: setCookie } });
    assert.equal(ownerNoCsrf.status, 403);
    const ownerNoSession = await request(baseUrl, "/owner/wallet-action-bridge.json", { headers: authHeaders });
    assert.equal(ownerNoSession.status, 401);
    const logout = await request(baseUrl, "/auth/logout", { method: "POST", headers: { ...authHeaders, cookie: setCookie, "x-csrf-token": verified.csrf_token, "content-type": "application/json" }, body: "{}" });
    assert.equal(logout.status, 200);
    const loggedOut = await request(baseUrl, "/auth/session", { headers: { ...authHeaders, cookie: setCookie } });
    assert.deepEqual(loggedOut.json(), { authenticated: false, auth_enabled: true });
  });
});

test("authenticated owner route returns only a release-bound plan with CSRF and same-origin", async () => {
  await withTempV9Candidate(async (releasePath) => withServer(async (baseUrl) => {
    const localRelease = readReleaseDocument({ releasePath, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
    assert.equal(localRelease.v9_release_ready, true, JSON.stringify(localRelease.v9_candidate_gate));
    const localActionPlan = buildWalletErpActionPlanProjection({ release: localRelease });
    const localBinding = { release_id: localRelease.release_id, release_fingerprint: localRelease.release_fingerprint, bom_fingerprint: localRelease.bom_fingerprint, commit_sha: localRelease.git_commit, source_catalog_fingerprint: localRelease.source_catalog_fingerprint, base_target: localRelease.base_target };
    assert.doesNotThrow(() => buildReleaseBoundUnsignedCallPlan({ release: localBinding, action_plan: localActionPlan, call_template: { to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x" } }));
    const nonceResponse = await request(baseUrl, "/auth/nonce", { headers: authHeaders });
    const nonce = nonceResponse.json();
    const message = buildSiweMessage({ domain: nonce.domain, uri: nonce.uri, address: ADDRESS, nonce: nonce.nonce, issuedAt: nonce.issued_at, expirationTime: nonce.expiration_time, statement: nonce.statement, resources: nonce.resources, chainId: 8453, version: "1" });
    const verified = await request(baseUrl, "/auth/verify", {
      method: "POST",
      headers: { ...authHeaders, "content-type": "application/json" },
      body: JSON.stringify({ address: ADDRESS, message, signature: "0x1234" }),
    });
    assert.equal(verified.status, 200);
    const setCookie = verified.headers["set-cookie"]?.[0];
    const owner = await request(baseUrl, "/owner/wallet-action-bridge.json", {
      headers: { ...authHeaders, cookie: setCookie, "x-csrf-token": verified.json().csrf_token },
    });
    assert.equal(owner.status, 200, owner.text);
    const body = owner.json();
    assert.equal(body.schema_version, "base-account-wallet-bridge-owner-v1");
    assert.equal(body.owner_auth_required, false);
    assert.equal(body.plan.release.commit_sha, TEST_COMMIT);
    assert.equal(body.plan.execution.execution_ready, true);
    assert.equal(body.plan.call_template.to, "0x2222222222222222222222222222222222222222");
    assert.equal(JSON.stringify(body).includes(ADDRESS), false);
  }, {
    releasePath,
    authCallTemplate: { to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x" },
  }));
});

test("auth POST whitelist does not widen the read-only surface", async () => {
  await withServer(async (baseUrl) => {
    const response = await request(baseUrl, "/healthz", { method: "POST", headers: authHeaders });
    assert.equal(response.status, 405);
    assert.deepEqual(response.json(), { error: "method_not_allowed", allowed: ["GET", "HEAD"] });
    const head = await request(baseUrl, "/auth/nonce", { method: "HEAD", headers: authHeaders });
    assert.equal(head.status, 200);
    assert.equal(head.text, "");
  });
});

test("self-hosted auth SDK asset is served locally and the visitor surface stays redacted", async () => {
  await withServer(async (baseUrl) => {
    const asset = await request(baseUrl, "/assets/base-auth-sdk.bundle.js");
    assert.equal(asset.status, 200);
    assert.match(asset.headers["content-type"], /javascript/);
    assert.match(asset.text, /BaseAuthControllerFactory/);
    assert.doesNotMatch(asset.text, /<script\s+src=/i);
    const bridge = await request(baseUrl, "/wallet-action-bridge.json");
    assert.equal(bridge.status, 503);
    assert.equal(bridge.text.includes("call_template"), false);
    assert.equal(bridge.text.includes("calldata"), false);
  }, { enabled: false });
});
