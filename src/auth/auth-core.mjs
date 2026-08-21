import {
  createHmac,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export const AUTH_CHAIN_ID = "0x2105";
export const AUTH_CHAIN_ID_DECIMAL = 8453;
export const AUTH_SIWE_VERSION = "1";
export const AUTH_STATEMENT = "Sign in to Base ERP Settlement Workbench.";
export const AUTH_RESOURCE = "/auth/session";
export const AUTH_COOKIE_NAME = "__Host-base_erp_session";
export const AUTH_DEFAULTS = Object.freeze({
  nonceTtlMs: 5 * 60 * 1000,
  maxNoncesPerClient: 3,
  maxOutstandingNonces: 1024,
  nonceRateWindowMs: 60 * 1000,
  nonceRateLimit: 10,
  requestRateWindowMs: 60 * 1000,
  requestRateLimit: 60,
  idleSessionMs: 30 * 60 * 1000,
  absoluteSessionMs: 8 * 60 * 60 * 1000,
});

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/i;
const HEX_SIGNATURE_PATTERN = /^0x[0-9a-f]+$/i;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,256}$/;

function fail(code, status = 400) {
  const error = new Error(code);
  error.code = code;
  error.status = status;
  throw error;
}

function plainObject(value, code = "invalid_object") {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  return value;
}

function requiredString(value, code) {
  if (typeof value !== "string" || value.trim() === "") fail(code);
  return value.trim();
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function iso(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) fail("auth_time_invalid");
  return date.toISOString();
}

function nowMs(now) {
  const value = typeof now === "function" ? now() : now;
  const number = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(number)) fail("auth_clock_invalid", 503);
  return number;
}

function normalizeAddress(value) {
  const address = requiredString(value, "auth_address_invalid");
  if (!ADDRESS_PATTERN.test(address)) fail("auth_address_invalid");
  return address.toLowerCase();
}

function digestText(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex");
}

function hmac(secret, value) {
  return createHmac("sha256", secret).update(String(value), "utf8").digest("hex");
}

function equalSecret(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function normalizeResources(resources) {
  if (!Array.isArray(resources) || resources.length !== 1 || resources[0] !== AUTH_RESOURCE) fail("auth_resources_invalid");
  return [AUTH_RESOURCE];
}

/** Build the exact SIWE message the provider must return for this nonce. */
export function buildSiweMessage({ domain, uri, address, nonce, issuedAt, expirationTime, statement = AUTH_STATEMENT, resources = [AUTH_RESOURCE], chainId = AUTH_CHAIN_ID_DECIMAL, version = AUTH_SIWE_VERSION } = {}) {
  const normalizedDomain = requiredString(domain, "auth_domain_invalid");
  const normalizedUri = requiredString(uri, "auth_uri_invalid");
  const normalizedAddress = requiredString(address, "auth_address_invalid");
  const normalizedNonce = requiredString(nonce, "auth_nonce_invalid");
  const normalizedIssuedAt = iso(issuedAt);
  const normalizedExpiration = iso(expirationTime);
  if (version !== AUTH_SIWE_VERSION) fail("auth_siwe_version_invalid");
  if (String(chainId) !== String(AUTH_CHAIN_ID_DECIMAL) && String(chainId) !== AUTH_CHAIN_ID) fail("auth_chain_invalid");
  if (statement !== AUTH_STATEMENT) fail("auth_statement_invalid");
  normalizeResources(resources);
  if (!ADDRESS_PATTERN.test(normalizedAddress)) fail("auth_address_invalid");
  if (!/^https:\/\//.test(normalizedUri)) fail("auth_uri_invalid");
  if (new Date(normalizedExpiration).getTime() <= new Date(normalizedIssuedAt).getTime()) fail("auth_expiration_invalid");
  return `${normalizedDomain} wants you to sign in with your Ethereum account:\n${normalizedAddress}\n\n${AUTH_STATEMENT}\n\nURI: ${normalizedUri}\nVersion: 1\nChain ID: 8453\nNonce: ${normalizedNonce}\nIssued At: ${normalizedIssuedAt}\nExpiration Time: ${normalizedExpiration}\nResources:\n- ${AUTH_RESOURCE}`;
}

/** Strictly compare a submitted SIWE message to a server-issued nonce. */
export function validateSiweMessage(message, expected) {
  try {
    const source = requiredString(message, "auth_message_invalid");
    const config = plainObject(expected, "auth_siwe_expectation_invalid");
    const address = requiredString(config.address, "auth_address_invalid");
    const canonical = buildSiweMessage({
      domain: config.domain,
      uri: config.uri,
      address,
      nonce: config.nonce,
      issuedAt: config.issuedAt,
      expirationTime: config.expirationTime,
      statement: config.statement,
      resources: config.resources,
      chainId: config.chainId,
      version: config.version,
    });
    if (source !== canonical) fail("auth_message_drift");
    return Object.freeze({ ok: true, address: normalizeAddress(address), message: canonical });
  } catch (error) {
    return Object.freeze({ ok: false, fail_closed: true, code: error.code ?? "auth_message_invalid" });
  }
}

class MemoryAuthStore {
  constructor() {
    this.nonces = new Map();
    this.clientNonces = new Map();
    this.nonceAttempts = new Map();
    this.requestAttempts = new Map();
    this.sessions = new Map();
  }

  prune(now) {
    for (const [key, value] of this.nonces) if (value.expiresAt <= now) {
      this.nonces.delete(key);
      const set = this.clientNonces.get(value.clientKey);
      set?.delete(key);
      if (set?.size === 0) this.clientNonces.delete(value.clientKey);
    }
    for (const [key, value] of this.sessions) if (value.absoluteExpiresAt <= now || value.idleExpiresAt <= now) this.sessions.delete(key);
    for (const [key, value] of this.nonceAttempts) if (value.resetAt <= now) this.nonceAttempts.delete(key);
    for (const [key, value] of this.requestAttempts) if (value.resetAt <= now) this.requestAttempts.delete(key);
  }

  countOutstanding(clientKey) {
    return this.clientNonces.get(clientKey)?.size ?? 0;
  }

  countOutstandingTotal() {
    return this.nonces.size;
  }

  countAttempts(clientKey, now, windowMs) {
    const current = this.nonceAttempts.get(clientKey);
    if (!current || current.resetAt <= now) return 0;
    return current.count;
  }

  noteAttempt(clientKey, now, windowMs) {
    const current = this.nonceAttempts.get(clientKey);
    if (!current || current.resetAt <= now) this.nonceAttempts.set(clientKey, { count: 1, resetAt: now + windowMs });
    else current.count += 1;
  }

  countRequestAttempts(clientKey, now, windowMs) {
    const current = this.requestAttempts.get(clientKey);
    if (!current || current.resetAt <= now) return 0;
    return current.count;
  }

  noteRequestAttempt(clientKey, now, windowMs) {
    const current = this.requestAttempts.get(clientKey);
    if (!current || current.resetAt <= now) this.requestAttempts.set(clientKey, { count: 1, resetAt: now + windowMs });
    else current.count += 1;
  }

  putNonce(value) {
    this.nonces.set(value.nonce, value);
    if (!this.clientNonces.has(value.clientKey)) this.clientNonces.set(value.clientKey, new Set());
    this.clientNonces.get(value.clientKey).add(value.nonce);
  }

  peekNonce(nonce) {
    return this.nonces.get(nonce) ?? null;
  }

  consumeNonce(nonce, now) {
    const value = this.nonces.get(nonce);
    if (!value || value.expiresAt <= now) return null;
    this.nonces.delete(nonce);
    const set = this.clientNonces.get(value.clientKey);
    set?.delete(nonce);
    if (set?.size === 0) this.clientNonces.delete(value.clientKey);
    return value;
  }

  putSession(key, value) {
    this.sessions.set(key, value);
  }

  getSession(key) {
    return this.sessions.get(key) ?? null;
  }

  deleteSession(key) {
    this.sessions.delete(key);
  }
}

function parseOwnerDigests(value) {
  if (typeof value !== "string" || value.trim() === "") return [];
  let values;
  try {
    values = value.trim().startsWith("[") ? JSON.parse(value) : value.split(",");
  } catch {
    return [];
  }
  if (!Array.isArray(values) || values.length === 0) return [];
  const normalized = values.map((entry) => typeof entry === "string" ? entry.trim().toLowerCase() : "");
  if (normalized.some((entry) => !DIGEST_PATTERN.test(entry))) return [];
  return [...new Set(normalized)];
}

function deriveConfig(env, verifier, options) {
  const origin = typeof env.BASE_AUTH_ORIGIN === "string" ? env.BASE_AUTH_ORIGIN.trim() : "";
  let originUrl = null;
  try {
    originUrl = new URL(origin);
  } catch {
    originUrl = null;
  }
  const secret = typeof env.BASE_AUTH_HMAC_SECRET === "string" ? env.BASE_AUTH_HMAC_SECRET : "";
  const ownerDigests = parseOwnerDigests(env.BASE_AUTH_OWNER_DIGESTS);
  const enabledRequested = env.BASE_AUTH_ENABLED === "true" || options.enabled === true;
  const singleInstance = options.singleInstance === true || env.BASE_AUTH_SINGLE_INSTANCE === "true";
  const config = {
    enabled: false,
    ready: false,
    origin: originUrl?.protocol === "https:" ? originUrl.origin : null,
    domain: originUrl?.protocol === "https:" ? originUrl.host : null,
    siweUri: null,
    secret,
    ownerDigests,
    verifier: typeof verifier === "function" ? verifier : null,
    singleInstance,
    disabledReason: "configuration_missing",
  };
  if (!enabledRequested) {
    config.disabledReason = "disabled_by_configuration";
    return config;
  }
  if (!config.origin || !config.domain) {
    config.disabledReason = "origin_invalid";
    return config;
  }
  if (originUrl.pathname !== "/" || originUrl.search || originUrl.hash) {
    config.disabledReason = "origin_invalid";
    return config;
  }
  const configuredSiweUri = typeof env.BASE_AUTH_SIWE_URI === "string" && env.BASE_AUTH_SIWE_URI.trim() !== ""
    ? env.BASE_AUTH_SIWE_URI.trim()
    : config.origin;
  try {
    const siweUri = new URL(configuredSiweUri);
    if (siweUri.protocol !== "https:" || siweUri.origin !== config.origin || siweUri.search || siweUri.hash) {
      config.disabledReason = "siwe_uri_invalid";
      return config;
    }
    config.siweUri = siweUri.toString().replace(/\/$/, "") || siweUri.origin;
  } catch {
    config.disabledReason = "siwe_uri_invalid";
    return config;
  }
  if (secret.length < 32 || ownerDigests.length === 0) {
    config.disabledReason = "owner_configuration_missing";
    return config;
  }
  if (!singleInstance && !options.store) {
    config.disabledReason = "shared_store_required";
    return config;
  }
  if (typeof verifier !== "function" && !env.BASE_AUTH_VERIFY_RPC_URL) {
    config.disabledReason = "verifier_configuration_missing";
    return config;
  }
  config.enabled = true;
  config.ready = true;
  config.disabledReason = null;
  return config;
}

function sameOrigin({ origin, host }, config, { requireOrigin = false } = {}) {
  if (typeof host !== "string" || host.trim() !== config.domain) return false;
  if (requireOrigin && (typeof origin !== "string" || origin.trim() === "")) return false;
  if (origin !== undefined && origin !== null && String(origin).trim() !== config.origin) return false;
  return true;
}

function cookie(token, maxAge = AUTH_DEFAULTS.absoluteSessionMs / 1000) {
  return `${AUTH_COOKIE_NAME}=${token}; Path=/; Max-Age=${Math.max(0, Math.floor(maxAge))}; HttpOnly; Secure; SameSite=Strict`;
}

function tokenFromCookie(header) {
  if (typeof header !== "string") return null;
  for (const item of header.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === AUTH_COOKIE_NAME) {
      const token = rest.join("=").trim();
      return TOKEN_PATTERN.test(token) ? token : null;
    }
  }
  return null;
}

export function createProductionMessageVerifier({ rpcUrl, chain, publicClient } = {}) {
  if (typeof rpcUrl !== "string" || !/^https:\/\//.test(rpcUrl)) fail("auth_verifier_rpc_invalid", 503);
  if (publicClient && typeof publicClient.verifyMessage === "function") {
    return ({ address, message, signature }) => publicClient.verifyMessage({ address, message, signature });
  }
  let clientPromise;
  return async ({ address, message, signature }) => {
    clientPromise ??= (async () => {
      const { createPublicClient, http } = await import("viem");
      const { base } = await import("viem/chains");
      return createPublicClient({ chain: chain ?? base, transport: http(rpcUrl) });
    })();
    const client = await clientPromise;
    // Public-client verifyMessage is the smart-account aware viem action and
    // supports ERC-6492/1271. The root viem export is the EOA utility.
    return client.verifyMessage({ address, message, signature });
  };
}

/**
 * Auth service. The default memory store is only enabled with an explicit
 * BASE_AUTH_SINGLE_INSTANCE=true (or singleInstance:true in tests). A
 * shared store can be supplied by production without changing the API.
 */
export function createAuthService({ env = process.env, now = () => Date.now(), randomBytesFn = randomBytes, verifier = null, store = null, logger = () => {}, options = {} } = {}) {
  const memoryStore = store ?? new MemoryAuthStore();
  const config = deriveConfig(env, verifier, { ...options, store });
  const activeVerifier = typeof verifier === "function"
    ? verifier
    : config.ready && typeof env.BASE_AUTH_VERIFY_RPC_URL === "string"
      ? createProductionMessageVerifier({ rpcUrl: env.BASE_AUTH_VERIFY_RPC_URL })
      : null;
  const limits = { ...AUTH_DEFAULTS, ...(options.limits ?? {}) };
  const hmacSecret = config.secret;
  const log = (event) => {
    try {
      logger(Object.freeze({
        request_id: event.request_id ?? null,
        route: event.route ?? null,
        code: event.code ?? null,
        success: event.success === true,
        duration_ms: Number.isFinite(event.duration_ms) ? event.duration_ms : null,
        digest: event.digest ? digestText(event.digest).slice(0, 16) : null,
      }));
    } catch {
      // Logging must never change an auth decision.
    }
  };
  const guardRequestRate = (clientKey, nowValue) => {
    const key = digestText(clientKey ?? "anonymous");
    memoryStore.prune(nowValue);
    const attempts = memoryStore.countRequestAttempts(key, nowValue, limits.requestRateWindowMs);
    if (attempts >= limits.requestRateLimit) fail("auth_request_rate_limited", 429);
    memoryStore.noteRequestAttempt(key, nowValue, limits.requestRateWindowMs);
    return key;
  };
  const issueNonce = ({ clientKey = "anonymous", nowValue = nowMs(now), origin, host } = {}) => {
    if (!config.ready) fail("auth_disabled", 503);
    if (!sameOrigin({ origin, host }, config)) fail("auth_origin_invalid", 403);
    memoryStore.prune(nowValue);
    const key = digestText(clientKey);
    const attempts = memoryStore.countAttempts(key, nowValue, limits.nonceRateWindowMs);
    if (attempts >= limits.nonceRateLimit) fail("auth_nonce_rate_limited", 429);
    memoryStore.noteAttempt(key, nowValue, limits.nonceRateWindowMs);
    if (memoryStore.countOutstanding(key) >= limits.maxNoncesPerClient || memoryStore.countOutstandingTotal() >= limits.maxOutstandingNonces) fail("auth_nonce_capacity", 429);
    const nonce = randomBytesFn(16).toString("hex");
    const issuedAt = new Date(nowValue).toISOString();
    const expirationTime = new Date(nowValue + limits.nonceTtlMs).toISOString();
    memoryStore.putNonce({ nonce, clientKey: key, issuedAt, expirationTime, expiresAt: nowValue + limits.nonceTtlMs });
    const result = { nonce, issued_at: issuedAt, expiration_time: expirationTime, domain: config.domain, uri: config.siweUri, chain_id: AUTH_CHAIN_ID, version: AUTH_SIWE_VERSION, statement: AUTH_STATEMENT, resources: [AUTH_RESOURCE] };
    log({ route: "/auth/nonce", code: "issued", success: true, digest: nonce });
    return Object.freeze(result);
  };
  const sessionForToken = (token, nowValue = nowMs(now)) => {
    if (!TOKEN_PATTERN.test(String(token ?? ""))) return null;
    memoryStore.prune(nowValue);
    const key = hmac(hmacSecret || "disabled", token);
    const session = memoryStore.getSession(key);
    if (!session || session.absoluteExpiresAt <= nowValue || session.idleExpiresAt <= nowValue) {
      if (session) memoryStore.deleteSession(key);
      return null;
    }
    session.idleExpiresAt = Math.min(nowValue + limits.idleSessionMs, session.absoluteExpiresAt);
    return { key, session };
  };
  const verify = async ({ address, message, signature, clientKey = null, origin, host, existingToken = null, requestId = null } = {}) => {
    const started = nowMs(now);
    if (!config.ready) fail("auth_disabled", 503);
    if (!sameOrigin({ origin, host }, config, { requireOrigin: true })) fail("auth_origin_invalid", 403);
    const clientDigest = guardRequestRate(clientKey ?? "anonymous", started);
    const normalizedAddress = normalizeAddress(address);
    if (typeof signature !== "string" || !HEX_SIGNATURE_PATTERN.test(signature)) fail("auth_signature_invalid");
    const nonceMatch = /^.*\nNonce: ([A-Za-z0-9]+)\nIssued At: ([^\n]+)\nExpiration Time: ([^\n]+)\nResources:/s.exec(String(message ?? ""));
    const nonce = nonceMatch?.[1];
    if (!nonce) fail("auth_nonce_invalid");
    const record = memoryStore.peekNonce(nonce);
    if (!record || record.expiresAt <= started) fail("auth_nonce_replay_or_expired", 409);
    if (clientKey !== null && record.clientKey !== clientDigest) fail("auth_nonce_client_mismatch", 409);
    const messageCheck = validateSiweMessage(message, { domain: config.domain, uri: config.siweUri, address, nonce: record.nonce, issuedAt: record.issuedAt, expirationTime: record.expirationTime, statement: AUTH_STATEMENT, resources: [AUTH_RESOURCE], chainId: AUTH_CHAIN_ID_DECIMAL, version: AUTH_SIWE_VERSION });
    if (!messageCheck.ok) fail(messageCheck.code);
    const consumed = memoryStore.consumeNonce(record.nonce, started);
    if (!consumed) fail("auth_nonce_replay_or_expired", 409);
    const verified = typeof activeVerifier === "function" ? await activeVerifier({ address: normalizedAddress, message, signature }) : false;
    if (verified !== true) fail("auth_signature_invalid", 401);
    const ownerDigest = hmac(hmacSecret, normalizedAddress);
    if (!config.ownerDigests.some((candidate) => equalSecret(candidate, ownerDigest))) fail("auth_owner_mismatch", 403);
    if (existingToken) {
      const existing = sessionForToken(existingToken, started);
      if (existing) memoryStore.deleteSession(existing.key);
    }
    const token = randomBytesFn(32).toString("base64url");
    const csrfToken = randomBytesFn(32).toString("base64url");
    const createdAt = started;
    const session = { ownerDigest, createdAt, idleExpiresAt: started + limits.idleSessionMs, absoluteExpiresAt: started + limits.absoluteSessionMs, csrfDigest: hmac(hmacSecret, csrfToken), rotation: 1 };
    memoryStore.putSession(hmac(hmacSecret, token), session);
    log({ request_id: requestId, route: "/auth/verify", code: "authenticated", success: true, duration_ms: nowMs(now) - started, digest: ownerDigest });
    return Object.freeze({ token, csrf_token: csrfToken, set_cookie: cookie(token), session: Object.freeze({ authenticated: true, expires_at: new Date(session.absoluteExpiresAt).toISOString() }) });
  };
  const requireSession = ({ token, csrfToken = null, origin, host, clientKey = null, requireCsrf = true, requireOrigin = true } = {}) => {
    if (!config.ready) fail("auth_disabled", 503);
    guardRequestRate(clientKey ?? "anonymous", nowMs(now));
    if (!sameOrigin({ origin, host }, config, { requireOrigin })) fail("auth_origin_invalid", 403);
    const current = sessionForToken(token);
    if (!current) fail("auth_session_required", 401);
    if (requireCsrf) {
      const expected = current.session.csrfDigest;
      const provided = typeof csrfToken === "string" ? hmac(hmacSecret, csrfToken) : "";
      if (!equalSecret(expected, provided)) fail("auth_csrf_invalid", 403);
    }
    return Object.freeze({ authenticated: true, session: current.session, key: current.key });
  };
  const logout = ({ token = null, csrfToken = null, origin, host, clientKey = null } = {}) => {
    if (!config.ready) fail("auth_disabled", 503);
    if (!sameOrigin({ origin, host }, config, { requireOrigin: true })) fail("auth_origin_invalid", 403);
    guardRequestRate(clientKey ?? "anonymous", nowMs(now));
    if (!token) return Object.freeze({ authenticated: false, clear_cookie: cookie("", 0) });
    const current = sessionForToken(token);
    if (!current) return Object.freeze({ authenticated: false, clear_cookie: cookie("", 0) });
    requireSession({ token, csrfToken, origin, host, requireCsrf: true });
    memoryStore.deleteSession(current.key);
    return Object.freeze({ authenticated: false, clear_cookie: cookie("", 0) });
  };
    return Object.freeze({
    config: Object.freeze({ enabled: config.enabled, ready: config.ready, origin: config.origin, domain: config.domain, single_instance: config.singleInstance, disabled_reason: config.disabledReason }),
    readiness: () => Object.freeze({ enabled: config.enabled, ready: config.ready, single_instance: config.singleInstance, nonce_store: config.ready ? "available" : "unavailable", verifier: config.ready ? "configured" : "unavailable", owner_allowlist: config.ownerDigests.length > 0 ? "configured" : "unavailable", reason: config.disabledReason }),
    issueNonce,
    verify,
    requireSession,
    sessionFromCookie: (header) => tokenFromCookie(header),
    logout,
    buildOwnerSession: ({ token, csrfToken, origin, host, clientKey = null } = {}) => requireSession({ token, csrfToken, origin, host, clientKey, requireCsrf: true }),
  });
}

export function redactedAuthError(error) {
  const code = error?.code ?? "auth_failed";
  const authenticationFailure = new Set(["auth_owner_mismatch", "auth_signature_invalid", "auth_nonce_invalid", "auth_nonce_replay_or_expired", "auth_nonce_client_mismatch", "auth_message_drift"]);
  const status = authenticationFailure.has(code) ? 401 : Number.isInteger(error?.status) ? error.status : code === "auth_session_required" ? 401 : code === "auth_csrf_invalid" || code === "auth_origin_invalid" ? 403 : code === "auth_nonce_capacity" || code === "auth_nonce_rate_limited" || code === "auth_request_rate_limited" ? 429 : code === "auth_disabled" ? 503 : 400;
  const publicCode = authenticationFailure.has(code) ? "authentication_failed" : code === "auth_disabled" ? "auth_disabled" : code === "auth_session_required" ? "auth_required" : code === "auth_csrf_invalid" ? "csrf_invalid" : code === "auth_origin_invalid" ? "origin_invalid" : code === "auth_nonce_capacity" || code === "auth_nonce_rate_limited" || code === "auth_request_rate_limited" ? "rate_limited" : "auth_request_invalid";
  return Object.freeze({ status, body: { error: publicCode } });
}

export function authRequestIdentity(request) {
  const forwarded = request?.headers?.["x-forwarded-for"];
  const remote = request?.socket?.remoteAddress ?? "unknown";
  // Forwarded headers are intentionally not trusted for origin/host checks.
  return `${remote}|${forwarded ? "forwarded-present" : "direct"}`;
}

export { MemoryAuthStore, tokenFromCookie };
