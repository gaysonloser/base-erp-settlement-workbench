import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import {
  AUTH_CHAIN_ID,
  AUTH_STATEMENT,
  buildSiweMessage,
  createAuthService,
  createProductionMessageVerifier,
  redactedAuthError,
  validateSiweMessage,
} from "../src/auth/auth-core.mjs";

const ADDRESS = "0x1111111111111111111111111111111111111111";
const OTHER_ADDRESS = "0x2222222222222222222222222222222222222222";
const SECRET = "auth-test-secret-012345678901234567890123";
const ORIGIN = "https://base.example";
const HOST = "base.example";

function authFixture({ verifier = async () => true, limits, nowRef = { value: Date.parse("2026-08-22T00:00:00.000Z") } } = {}) {
  const ownerDigest = createHmac("sha256", SECRET).update(ADDRESS).digest("hex");
  let randomCounter = 0;
  const auth = createAuthService({
    env: {
      BASE_AUTH_ENABLED: "true",
      BASE_AUTH_ORIGIN: ORIGIN,
      BASE_AUTH_HMAC_SECRET: SECRET,
      BASE_AUTH_OWNER_DIGESTS: ownerDigest,
      BASE_AUTH_SINGLE_INSTANCE: "true",
    },
    verifier,
    now: () => nowRef.value,
    randomBytesFn: (size) => Buffer.alloc(size, ++randomCounter),
    options: limits ? { limits } : {},
  });
  return { auth, nowRef };
}

function siweFromNonce(nonce, address = ADDRESS, mutate = {}) {
  return buildSiweMessage({
    domain: mutate.domain ?? nonce.domain,
    uri: mutate.uri ?? nonce.uri,
    address,
    nonce: mutate.nonce ?? nonce.nonce,
    issuedAt: mutate.issuedAt ?? nonce.issued_at,
    expirationTime: mutate.expirationTime ?? nonce.expiration_time,
    statement: mutate.statement ?? nonce.statement,
    resources: mutate.resources ?? nonce.resources,
    chainId: mutate.chainId ?? 8453,
    version: mutate.version ?? "1",
  });
}

function issue(auth, clientKey = "client-a") {
  return auth.issueNonce({ clientKey, origin: ORIGIN, host: HOST });
}

test("auth disables fail-closed when production configuration is incomplete", () => {
  const auth = createAuthService({ env: {} });
  assert.deepEqual(auth.readiness(), {
    enabled: false,
    ready: false,
    single_instance: false,
    nonce_store: "unavailable",
    verifier: "unavailable",
    owner_allowlist: "unavailable",
    reason: "disabled_by_configuration",
  });
  assert.throws(() => auth.issueNonce({ origin: ORIGIN, host: HOST }), (error) => error.code === "auth_disabled");
});

test("nonce is strict, expires in five minutes and is atomically one-time", async () => {
  const { auth, nowRef } = authFixture();
  const nonce = issue(auth);
  assert.equal(nonce.chain_id, AUTH_CHAIN_ID);
  assert.equal(nonce.statement, AUTH_STATEMENT);
  assert.equal(nonce.uri, ORIGIN);
  const message = siweFromNonce(nonce);
  const result = await auth.verify({ address: ADDRESS, message, signature: "0x1234", origin: ORIGIN, host: HOST });
  assert.equal(result.session.authenticated, true);
  await assert.rejects(() => auth.verify({ address: ADDRESS, message, signature: "0x1234", origin: ORIGIN, host: HOST }), (error) => error.code === "auth_nonce_replay_or_expired");
  nowRef.value += 5 * 60 * 1000 + 1;
  const expired = issue(auth, "client-b");
  nowRef.value += 5 * 60 * 1000 + 1;
  await assert.rejects(() => auth.verify({ address: ADDRESS, message: siweFromNonce(expired), signature: "0x1234", origin: ORIGIN, host: HOST }), (error) => error.code === "auth_nonce_replay_or_expired");
});

test("concurrent verification consumes a nonce once and mock ERC-1271/6492 verifier results are honored", async () => {
  const seen = [];
  const { auth } = authFixture({ verifier: async ({ signature }) => { seen.push(signature); return signature === "0x1271" || signature === "0x6492"; } });
  const nonce = issue(auth, "concurrent");
  const message = siweFromNonce(nonce);
  const results = await Promise.allSettled([
    auth.verify({ address: ADDRESS, message, signature: "0x1271", origin: ORIGIN, host: HOST }),
    auth.verify({ address: ADDRESS, message, signature: "0x1271", origin: ORIGIN, host: HOST }),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected" && result.reason.code === "auth_nonce_replay_or_expired").length, 1);
  const second = issue(auth, "erc6492");
  await auth.verify({ address: ADDRESS, message: siweFromNonce(second), signature: "0x6492", origin: ORIGIN, host: HOST });
  assert.deepEqual(seen, ["0x1271", "0x6492"]);
});

test("verification binds the nonce to the server-derived client key when supplied", async () => {
  const { auth } = authFixture();
  const nonce = issue(auth, "bound-client");
  const message = siweFromNonce(nonce);
  await assert.rejects(() => auth.verify({ address: ADDRESS, message, signature: "0x1234", clientKey: "other-client", origin: ORIGIN, host: HOST }), (error) => error.code === "auth_nonce_client_mismatch");
  await auth.verify({ address: ADDRESS, message, signature: "0x1234", clientKey: "bound-client", origin: ORIGIN, host: HOST });
});

test("nonce capacity and rate gates fail closed per client and globally", () => {
  const { auth } = authFixture({ limits: { maxNoncesPerClient: 2, maxOutstandingNonces: 3, nonceRateLimit: 3 } });
  issue(auth, "same");
  issue(auth, "same");
  assert.throws(() => issue(auth, "same"), (error) => error.code === "auth_nonce_capacity");
  issue(auth, "other");
  assert.throws(() => issue(auth, "third"), (error) => error.code === "auth_nonce_capacity");
});

test("SIWE domain, URI, version, chain, statement and resources are exact", () => {
  const { auth } = authFixture();
  const nonce = issue(auth);
  const valid = validateSiweMessage(siweFromNonce(nonce), {
    domain: nonce.domain,
    uri: nonce.uri,
    address: ADDRESS,
    nonce: nonce.nonce,
    issuedAt: nonce.issued_at,
    expirationTime: nonce.expiration_time,
    statement: nonce.statement,
    resources: nonce.resources,
    chainId: 8453,
    version: "1",
  });
  assert.equal(valid.ok, true);
  for (const mutate of [
    { domain: "evil.example" },
    { uri: "https://evil.example/auth/verify" },
    { version: "2" },
    { chainId: 1 },
    { statement: "different" },
    { resources: ["/other"] },
  ]) {
    let mutated;
    try { mutated = siweFromNonce(nonce, ADDRESS, mutate); } catch { continue; }
    assert.equal(validateSiweMessage(mutated, {
      domain: nonce.domain,
      uri: nonce.uri,
      address: ADDRESS,
      nonce: nonce.nonce,
      issuedAt: nonce.issued_at,
      expirationTime: nonce.expiration_time,
      statement: nonce.statement,
      resources: nonce.resources,
      chainId: 8453,
      version: "1",
    }).ok, false, JSON.stringify(mutate));
  }
});

test("origin/host checks ignore forwarded headers and owner mismatch is redacted", async () => {
  const logs = [];
  const { auth } = authFixture({ verifier: async () => true });
  const nonce = auth.issueNonce({ origin: ORIGIN, host: HOST, clientKey: "direct" });
  const message = siweFromNonce(nonce);
  await assert.rejects(() => auth.verify({ address: ADDRESS, message, signature: "0x1234", origin: "https://evil.example", host: HOST }), (error) => error.code === "auth_origin_invalid");
  await assert.rejects(() => auth.verify({ address: ADDRESS, message, signature: "0x1234", host: HOST }), (error) => error.code === "auth_origin_invalid");
  const wrongNonce = auth.issueNonce({ origin: ORIGIN, host: HOST, clientKey: "other" });
  await assert.rejects(() => auth.verify({ address: OTHER_ADDRESS, message: siweFromNonce(wrongNonce, OTHER_ADDRESS), signature: "0x1234", origin: ORIGIN, host: HOST }), (error) => error.code === "auth_owner_mismatch");
  const redacted = redactedAuthError(Object.assign(new Error("auth_owner_mismatch"), { code: "auth_owner_mismatch", status: 403 }));
  assert.deepEqual(redacted.body, { error: "authentication_failed" });
  assert.equal(JSON.stringify(logs).includes(ADDRESS), false);
});

test("session cookie flags, CSRF binding, rotation and idempotent logout are strict", async () => {
  const { auth, nowRef } = authFixture();
  const nonce = issue(auth);
  const result = await auth.verify({ address: ADDRESS, message: siweFromNonce(nonce), signature: "0x1234", origin: ORIGIN, host: HOST });
  assert.match(result.set_cookie, /^__Host-base_erp_session=/);
  assert.match(result.set_cookie, /Path=\//);
  assert.match(result.set_cookie, /HttpOnly/);
  assert.match(result.set_cookie, /Secure/);
  assert.match(result.set_cookie, /SameSite=Strict/);
  assert.doesNotMatch(result.set_cookie, /Domain=/);
  const token = auth.sessionFromCookie(result.set_cookie);
  assert.equal(token, result.token);
  assert.throws(() => auth.requireSession({ token, csrfToken: "wrong", origin: ORIGIN, host: HOST }), (error) => error.code === "auth_csrf_invalid");
  assert.equal(auth.requireSession({ token, csrfToken: result.csrf_token, origin: ORIGIN, host: HOST }).authenticated, true);
  nowRef.value += 29 * 60 * 1000;
  assert.equal(auth.requireSession({ token, csrfToken: result.csrf_token, origin: ORIGIN, host: HOST }).authenticated, true);
  nowRef.value += 31 * 60 * 1000;
  assert.throws(() => auth.requireSession({ token, csrfToken: result.csrf_token, origin: ORIGIN, host: HOST }), (error) => error.code === "auth_session_required");
  assert.deepEqual(auth.logout({ token, csrfToken: result.csrf_token, origin: ORIGIN, host: HOST }).authenticated, false);
  assert.deepEqual(auth.logout({ token: null, origin: ORIGIN, host: HOST }).authenticated, false);
});

test("session re-authentication rotates the opaque token and logs only salted digests", async () => {
  const logs = [];
  const ownerDigest = createHmac("sha256", SECRET).update(ADDRESS).digest("hex");
  const auth = createAuthService({
    env: { BASE_AUTH_ENABLED: "true", BASE_AUTH_ORIGIN: ORIGIN, BASE_AUTH_HMAC_SECRET: SECRET, BASE_AUTH_OWNER_DIGESTS: ownerDigest, BASE_AUTH_SINGLE_INSTANCE: "true" },
    verifier: async () => true,
    logger: (event) => logs.push(event),
  });
  const first = issue(auth, "rotation");
  const firstSession = await auth.verify({ address: ADDRESS, message: siweFromNonce(first), signature: "0x1234", clientKey: "rotation", origin: ORIGIN, host: HOST });
  const second = issue(auth, "rotation");
  const secondSession = await auth.verify({ address: ADDRESS, message: siweFromNonce(second), signature: "0x1234", clientKey: "rotation", origin: ORIGIN, host: HOST, existingToken: firstSession.token });
  assert.notEqual(secondSession.token, firstSession.token);
  assert.throws(() => auth.requireSession({ token: firstSession.token, csrfToken: firstSession.csrf_token, origin: ORIGIN, host: HOST }), (error) => error.code === "auth_session_required");
  assert.equal(auth.requireSession({ token: secondSession.token, csrfToken: secondSession.csrf_token, origin: ORIGIN, host: HOST }).authenticated, true);
  assert.ok(logs.length >= 2);
  assert.equal(JSON.stringify(logs).includes(ADDRESS), false);
  assert.equal(JSON.stringify(logs).includes(firstSession.token), false);
});

test("production verifier requires an HTTPS RPC URL and delegates to viem public client", async () => {
  assert.throws(() => createProductionMessageVerifier({ rpcUrl: "http://localhost" }), (error) => error.code === "auth_verifier_rpc_invalid");
  let called = 0;
  const verifier = createProductionMessageVerifier({ rpcUrl: "https://rpc.example", publicClient: { verifyMessage: async (value) => { called += 1; return value.address === ADDRESS; } } });
  assert.equal(await verifier({ address: ADDRESS, message: "m", signature: "0xs" }), true);
  assert.equal(called, 1);
});
