import { createHash } from "node:crypto";

/**
 * H220/v9 is a read-only integrity contract. It joins claim bytes, public-route
 * readbacks, native-platform evidence and the Build runtime binding without
 * creating a receipt, credit, wallet request, deployment or external write.
 */
export const SCHEMA_VERSION = "base-erp-v9-release-evidence-integrity-seal-v1";
export const H220_PACKET_ID = "base-erp-h220-release-evidence-integrity-seal-20260816";
export const H220_BATCH_ID = "BASE_ERP_H220_RELEASE_EVIDENCE_INTEGRITY_SEAL_20260816";
export const EXECUTION_AUTHORITY = "none_until_02_Build_revalidates";
export const AUTHORITY_NONE = EXECUTION_AUTHORITY;

export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const FINALITY_STAGES = Object.freeze([
  "flashblock_preconfirmation",
  "l2_block_inclusion",
  "l1_batch_inclusion",
  "l1_batch_finality",
]);

export const REQUIRED_ROUTE_PATHS = Object.freeze([
  "/release.json",
  "/healthz",
  "/platform-gates.json",
  "/workbench.json",
  "/workbench",
  "/workbench/",
  "/evidence.json",
  "/recurring-settlement.json",
  "/refund-preview.json",
  "/app.json",
]);

export const REQUIRED_PLATFORM_IDS = Object.freeze([
  "base_sepolia_rehearsal",
  "github",
  "render",
  "base_app",
  "base_dashboard",
  "base_dev",
  "talent",
  "guild",
  "basename_base_org",
]);

export const PLATFORM_STATES = Object.freeze([
  "absent",
  "not_observed",
  "owner_gate_pending",
  "observed",
  "current",
  "historical",
  "synthetic",
]);

export const CIRCLE_DENYLIST = Object.freeze([
  "gaysonloser/arc-payment-receipt",
  "srv-d9cumml8nd3s73c9nehg",
  "arc-payment-receipt.onrender.com",
  "programme-final-20260810",
]);

const HASH_RE = /^[0-9a-f]{64}$/i;
const TX_HASH_RE = /^0x[0-9a-f]{64}$/i;
const COMMIT_RE = /^[0-9a-f]{40}$/i;
const CIRCLE_WORD_RE = /(^|[^a-z])(circle|arc)([^a-z]|$)/i;
const RECEIPT_CLASSES = new Set(["chain_receipt", "native_platform_receipt", "attribution_metadata"]);
const PLATFORM_STATE_SET = new Set(PLATFORM_STATES);

export const ZERO_CREDIT_DEFAULTS = Object.freeze({
  native_receipt: null,
  release_receipt: false,
  rehearsal_receipt: null,
  attribution_observed: false,
  credit: 0,
  publication_unit_credit: 0,
  mainnet_30_credit: 0,
});

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return value.normalize("NFC");
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort((a, b) => Buffer.from(a).compare(Buffer.from(b)))
      .map((key) => [key, canonicalize(value[key])]));
  }
  throw new TypeError("unsupported value");
}

export function digest(value) {
  return createHash("sha256").update(JSON.stringify(canonicalize(value)), "utf8").digest("hex");
}

function nonEmpty(value, field) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${field} must be non-empty`);
  return value.trim();
}

function hash(value, field) {
  const normalized = nonEmpty(value, field).toLowerCase();
  if (!HASH_RE.test(normalized)) throw new TypeError(`${field} must be a 64-hex digest`);
  return normalized;
}

function commit(value, field) {
  const normalized = nonEmpty(value, field).toLowerCase();
  if (!COMMIT_RE.test(normalized)) throw new TypeError(`${field} must be a 40-hex commit`);
  return normalized;
}

function timestamp(value, field) {
  const normalized = nonEmpty(value, field);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed)) throw new TypeError(`${field} must be an ISO timestamp`);
  return { value: normalized, epoch: parsed };
}

function failClosed(reason, failure_codes = [], details = {}) {
  return Object.freeze({
    schema_version: SCHEMA_VERSION,
    ok: false,
    fail_closed: true,
    state: "integrity_gate",
    reason,
    failure_codes,
    ...ZERO_CREDIT_DEFAULTS,
    build_credit_eligible: false,
    execution_authority: EXECUTION_AUTHORITY,
    external_actions: 0,
    ...details,
  });
}

function circleCollision(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") {
    return CIRCLE_DENYLIST.some((entry) => value.includes(entry)) || CIRCLE_WORD_RE.test(value);
  }
  if (Array.isArray(value)) return value.some(circleCollision);
  if (typeof value === "object") return Object.values(value).some(circleCollision);
  return false;
}

function releaseIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("release_identity must be an object");
  return {
    release_id: nonEmpty(value.release_id, "release_identity.release_id"),
    release_fingerprint: hash(value.release_fingerprint, "release_identity.release_fingerprint"),
    bom_fingerprint: hash(value.bom_fingerprint, "release_identity.bom_fingerprint"),
    commit_sha: commit(value.commit_sha, "release_identity.commit_sha"),
    source_catalog_fingerprint: hash(value.source_catalog_fingerprint, "release_identity.source_catalog_fingerprint"),
  };
}

function sameRelease(candidate, expected) {
  return candidate?.release_id === expected.release_id
    && candidate?.release_fingerprint === expected.release_fingerprint
    && candidate?.bom_fingerprint === expected.bom_fingerprint
    && candidate?.commit_sha === expected.commit_sha
    && candidate?.source_catalog_fingerprint === expected.source_catalog_fingerprint;
}

function sourceDigestCatalog(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return failClosed("source_digest_catalog_missing", ["V9-F43"]);
  }
  const entries = Object.entries(value);
  if (entries.length === 0) return failClosed("source_digest_catalog_empty", ["V9-F43"]);
  const normalized = {};
  for (const [sourcePath, sourceDigest] of entries) {
    const path = nonEmpty(sourcePath, "source_digests.path");
    normalized[path] = hash(sourceDigest, `source_digests[${path}]`);
  }
  return normalized;
}

function routeReadbacks(value, release, evaluationEpoch, maxAgeSeconds) {
  if (!Array.isArray(value)) throw new TypeError("route_readbacks must be an array");
  const byPath = new Map();
  for (const route of value) {
    const path = nonEmpty(route?.path, "route_readbacks.path");
    if (byPath.has(path)) return failClosed("route_duplicate", ["V9-F03"], { path });
    const observed = timestamp(route?.observed_at, `route_readbacks[${path}].observed_at`);
    if (observed.epoch > evaluationEpoch) return failClosed("route_observed_in_future", ["V9-F04"], { path });
    if ((evaluationEpoch - observed.epoch) > maxAgeSeconds * 1000) return failClosed("evidence_stale", ["V9-F05"], { path, age_seconds: (evaluationEpoch - observed.epoch) / 1000 });
    if (!REQUIRED_ROUTE_PATHS.includes(path)) return failClosed("route_not_allowlisted", ["V9-F06"], { path });
    const routeIdentity = route.release_identity;
    if (!sameRelease(routeIdentity, release)) return failClosed("route_release_binding_mismatch", ["V9-F07"], { path });
    if (typeof route.response_sha256 !== "string" || !HASH_RE.test(route.response_sha256)) return failClosed("route_response_digest_missing", ["V9-F08"], { path });
    if (!Array.isArray(route.generated_by)
      || route.generated_by.length === 0
      || !route.generated_by.includes("code_test_contract")) {
      return failClosed("route_not_code_generated", ["V9-F09"], { path });
    }
    if (route.http_status !== 200 || route.claim_state !== "current") {
      return failClosed("route_not_current", ["V9-F42"], {
        path,
        http_status: route.http_status,
        claim_state: route.claim_state,
      });
    }
    const ready = route.http_status === 200 && route.claim_state === "current";
    byPath.set(path, {
      path,
      method: route.method ?? "GET",
      http_status: route.http_status,
      response_sha256: route.response_sha256.toLowerCase(),
      release_identity: clone(routeIdentity),
      observed_at: observed.value,
      claim_state: route.claim_state,
      generated_by: clone(route.generated_by),
      ready,
    });
  }
  const missing = REQUIRED_ROUTE_PATHS.filter((path) => !byPath.has(path));
  if (missing.length) return failClosed("route_set_incomplete", ["V9-F10"], { missing_routes: missing });
  return Object.fromEntries(REQUIRED_ROUTE_PATHS.map((path) => [path, byPath.get(path)]));
}

function claimBindings(value, routeMap, release, sourceDigests, evaluationEpoch, maxAgeSeconds) {
  if (!Array.isArray(value)) throw new TypeError("claim_bindings must be an array");
  const seen = new Set();
  const seenRoutes = new Set();
  const normalized = [];
  for (const claim of value) {
    const claimId = nonEmpty(claim?.claim_id, "claim_bindings.claim_id");
    if (seen.has(claimId)) return failClosed("claim_duplicate", ["V9-F11"], { claim_id: claimId });
    seen.add(claimId);
    const sourcePath = nonEmpty(claim?.source_path, `${claimId}.source_path`);
    const routePath = nonEmpty(claim?.route_path, `${claimId}.route_path`);
    const route = routeMap[routePath];
    if (!route) return failClosed("claim_route_missing", ["V9-F12"], { claim_id: claimId, route_path: routePath });
    if (seenRoutes.has(routePath)) return failClosed("claim_route_duplicate", ["V9-F44"], { claim_id: claimId, route_path: routePath });
    seenRoutes.add(routePath);
    const observed = timestamp(claim?.observed_at, `${claimId}.observed_at`);
    if (observed.epoch > evaluationEpoch || (evaluationEpoch - observed.epoch) > maxAgeSeconds * 1000) return failClosed("claim_stale", ["V9-F13"], { claim_id: claimId });
    if (!sameRelease(claim.release_identity, release)) return failClosed("claim_release_binding_mismatch", ["V9-F14"], { claim_id: claimId });
    const sourceDigest = hash(claim.source_sha256, `${claimId}.source_sha256`);
    if (!sourceDigests[sourcePath]) return failClosed("claim_source_digest_unbound", ["V9-F45"], { claim_id: claimId, source_path: sourcePath });
    if (sourceDigest !== sourceDigests[sourcePath]) return failClosed("claim_source_digest_mismatch", ["V9-F46"], { claim_id: claimId, source_path: sourcePath });
    if (claim.route_response_sha256 !== route.response_sha256) return failClosed("claim_route_digest_mismatch", ["V9-F16"], { claim_id: claimId, route_path: routePath });
    if (claim.generated_by !== "code_test_contract") return failClosed("claim_not_code_test_generated", ["V9-F17"], { claim_id: claimId });
    normalized.push({
      claim_id: claimId,
      source_path: sourcePath,
      source_sha256: sourceDigest,
      route_path: routePath,
      route_response_sha256: claim.route_response_sha256.toLowerCase(),
      release_identity: clone(claim.release_identity),
      observed_at: observed.value,
      generated_by: claim.generated_by,
    });
  }
  if (normalized.length === 0) return failClosed("claim_set_empty", ["V9-F18"]);
  const missingRoutes = REQUIRED_ROUTE_PATHS.filter((path) => !seenRoutes.has(path));
  if (missingRoutes.length) return failClosed("claim_set_incomplete", ["V9-F47"], { missing_routes: missingRoutes });
  return normalized;
}

function platformEvidence(value, release, evaluationEpoch, maxAgeSeconds) {
  if (!Array.isArray(value)) throw new TypeError("platform_evidence must be an array");
  const byPlatform = new Map();
  for (const evidence of value) {
    const platform = nonEmpty(evidence?.platform, "platform_evidence.platform");
    if (!REQUIRED_PLATFORM_IDS.includes(platform)) return failClosed("platform_not_allowlisted", ["V9-F19"], { platform });
    if (byPlatform.has(platform)) return failClosed("platform_duplicate", ["V9-F20"], { platform });
    if (!RECEIPT_CLASSES.has(evidence?.evidence_class)) return failClosed("platform_evidence_class_invalid", ["V9-F21"], { platform });
    const state = nonEmpty(evidence?.state, `${platform}.state`);
    if (!PLATFORM_STATE_SET.has(state)) return failClosed("platform_state_invalid", ["V9-F48"], { platform, state });
    if (!["current", "historical", "synthetic"].every((field) => typeof evidence[field] === "boolean")) {
      return failClosed("platform_freshness_flags_invalid", ["V9-F49"], { platform });
    }
    const current = evidence.current === true;
    const historical = evidence.historical === true;
    const synthetic = evidence.synthetic === true;
    if ([current, historical, synthetic].filter(Boolean).length > 1) {
      return failClosed("platform_freshness_flags_conflict", ["V9-F49"], { platform });
    }
    if (historical || synthetic) return failClosed("platform_historical_or_synthetic", ["V9-F50"], { platform, state });
    if ((state === "current" && !current) || (current && state !== "current")) {
      return failClosed("platform_current_state_mismatch", ["V9-F51"], { platform, state, current });
    }
    if ((state === "historical" && !historical) || (state === "synthetic" && !synthetic)) {
      return failClosed("platform_state_flag_mismatch", ["V9-F51"], { platform, state, historical, synthetic });
    }
    const observed = timestamp(evidence?.observed_at, `${platform}.observed_at`);
    if (observed.epoch > evaluationEpoch) return failClosed("platform_observed_in_future", ["V9-F22"], { platform });
    if ((evaluationEpoch - observed.epoch) > maxAgeSeconds * 1000) return failClosed("platform_evidence_stale", ["V9-F23"], { platform });
    if (!sameRelease(evidence.release_identity, release)) return failClosed("platform_release_binding_mismatch", ["V9-F24"], { platform });
    if (platform === "base_app" && evidence.evidence_class !== "attribution_metadata") {
      return failClosed("base_app_attribution_class_invalid", ["V9-F53"], { platform });
    }
    if (evidence.evidence_class === "chain_receipt" && platform !== "base_sepolia_rehearsal") {
      return failClosed("chain_receipt_platform_invalid", ["V9-F54"], { platform });
    }
    if (platform === "base_sepolia_rehearsal" && evidence.new_rehearsal === true) {
      return failClosed("new_rehearsal_forbidden", ["V9-F27"], { platform });
    }
    const record = {
      platform,
      evidence_class: evidence.evidence_class,
      state,
      current,
      historical,
      synthetic,
      observed_at: observed.value,
      release_identity: clone(evidence.release_identity),
      is_receipt: evidence.is_receipt === true,
      receipt_ref: evidence.receipt_ref ?? null,
      attribution_observed: evidence.attribution_observed === true,
      credit: 0,
    };
    if (record.evidence_class === "attribution_metadata" && record.is_receipt) return failClosed("attribution_claimed_as_receipt", ["V9-F25"], { platform });
    if (record.is_receipt) {
      if (!current) return failClosed("receipt_not_current", ["V9-F52"], { platform });
      if (typeof record.receipt_ref !== "string" || record.receipt_ref.trim() === "") return failClosed("receipt_reference_missing", ["V9-F26"], { platform });
      if (platform === "base_sepolia_rehearsal") {
        if (Number(evidence.chain_id) !== BASE_SEPOLIA_CHAIN_ID || evidence.receipt_status !== "0x1" || !FINALITY_STAGES.includes(evidence.finality_stage)) {
          return failClosed("sepolia_receipt_finality_invalid", ["V9-F28"], { platform });
        }
        if (typeof evidence.transaction_hash !== "string" || !TX_HASH_RE.test(evidence.transaction_hash)) return failClosed("sepolia_transaction_hash_invalid", ["V9-F29"], { platform });
      }
    }
    byPlatform.set(platform, record);
  }
  const missing = REQUIRED_PLATFORM_IDS.filter((platform) => !byPlatform.has(platform));
  if (missing.length) return failClosed("platform_set_incomplete", ["V9-F30"], { missing_platforms: missing });
  return Object.fromEntries(REQUIRED_PLATFORM_IDS.map((platform) => [platform, byPlatform.get(platform)]));
}

function runtimeBinding(value, release, evaluationEpoch, maxAgeSeconds) {
  if (!value || typeof value !== "object") return failClosed("runtime_binding_missing", ["V9-F31"]);
  const observed = timestamp(value.observed_at, "runtime.observed_at");
  if (observed.epoch > evaluationEpoch || (evaluationEpoch - observed.epoch) > maxAgeSeconds * 1000) return failClosed("runtime_binding_stale", ["V9-F32"]);
  if (value.release_id !== release.release_id
    || value.release_fingerprint !== release.release_fingerprint
    || value.bom_fingerprint !== release.bom_fingerprint
    || value.commit_sha !== release.commit_sha
    || value.source_catalog_fingerprint !== release.source_catalog_fingerprint) return failClosed("runtime_release_binding_mismatch", ["V9-F33"]);
  if (typeof value.runtime_sha256 !== "string" || !HASH_RE.test(value.runtime_sha256)) return failClosed("runtime_hash_invalid", ["V9-F34"]);
  if (typeof value.run_id !== "string" || value.run_id.trim() === "") return failClosed("runtime_run_id_missing", ["V9-F35"]);
  if (!value.cursor || typeof value.cursor !== "object" || typeof value.cursor.active_item_id !== "string" || value.cursor.active_item_id !== "") return failClosed("runtime_cursor_not_idle", ["V9-F36"]);
  if (value.writer_idle !== true) return failClosed("runtime_writer_not_idle", ["V9-F37"]);
  return {
    runtime_sha256: value.runtime_sha256.toLowerCase(),
    run_id: value.run_id,
    cursor: clone(value.cursor),
    writer_idle: true,
    observed_at: observed.value,
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    commit_sha: release.commit_sha,
    source_catalog_fingerprint: release.source_catalog_fingerprint,
  };
}

/**
 * Evaluate the v9 seal. The result is deterministic for a fixed `evaluation_time`.
 * It never turns local readiness or attribution into credit; Build must revalidate.
 */
export function evaluateReleaseEvidenceSeal(input = {}) {
  try {
    if (circleCollision(input)) return failClosed("circle_target_collision", ["V9-F01"]);
    const release = releaseIdentity(input.release_identity);
    const evaluation = timestamp(input.evaluation_time, "evaluation_time");
    const maxAgeSeconds = Number(input.max_age_seconds ?? 900);
    if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds <= 0) return failClosed("freshness_policy_invalid", ["V9-F02"]);
    const sourceDigests = sourceDigestCatalog(input.source_digests);
    if (!sourceDigests || sourceDigests.ok === false) return sourceDigests;
    if (digest(sourceDigests) !== release.source_catalog_fingerprint) {
      return failClosed("source_catalog_fingerprint_mismatch", ["V9-F56"]);
    }
    const routes = routeReadbacks(input.route_readbacks, release, evaluation.epoch, maxAgeSeconds);
    if (!routes || routes.ok === false) return routes;
    const claims = claimBindings(input.claim_bindings, routes, release, sourceDigests, evaluation.epoch, maxAgeSeconds);
    if (!claims || claims.ok === false) return claims;
    const platforms = platformEvidence(input.platform_evidence, release, evaluation.epoch, maxAgeSeconds);
    if (!platforms || platforms.ok === false) return platforms;
    const runtime = runtimeBinding(input.runtime_binding, release, evaluation.epoch, maxAgeSeconds);
    if (!runtime || runtime.ok === false) return runtime;
    const sealPayload = {
      schema_version: SCHEMA_VERSION,
      packet_id: H220_PACKET_ID,
      release_identity: release,
      source_digests: sourceDigests,
      route_readbacks: routes,
      claim_bindings: claims,
      platform_evidence: platforms,
      runtime_binding: runtime,
      evaluation_time: evaluation.value,
      max_age_seconds: maxAgeSeconds,
      state: "integrity_seal_candidate_ready",
      fail_closed: false,
      native_receipt: null,
      release_receipt: false,
      rehearsal_receipt: null,
      attribution_observed: false,
      credit: 0,
      publication_unit_credit: 0,
      mainnet_30_credit: 0,
      build_credit_eligible: false,
      execution_authority: EXECUTION_AUTHORITY,
      external_actions: 0,
    };
    return Object.freeze({
      ...sealPayload,
      seal_digest: digest(sealPayload),
      ok: true,
      fail_closed: false,
      state: "integrity_seal_candidate_ready",
      failure_codes: [],
      ...ZERO_CREDIT_DEFAULTS,
      build_credit_eligible: false,
      execution_authority: EXECUTION_AUTHORITY,
      external_actions: 0,
    });
  } catch (error) {
    return failClosed("invalid_integrity_seal_input", ["V9-F99"], { message: error.message });
  }
}

export function verifyReleaseEvidenceSeal(seal) {
  try {
    if (!seal || seal.schema_version !== SCHEMA_VERSION || seal.ok !== true || typeof seal.seal_digest !== "string") return failClosed("unsupported_integrity_seal");
    const payload = {
      schema_version: seal.schema_version,
      packet_id: seal.packet_id,
      release_identity: seal.release_identity,
      source_digests: seal.source_digests,
      route_readbacks: seal.route_readbacks,
      claim_bindings: seal.claim_bindings,
      platform_evidence: seal.platform_evidence,
      runtime_binding: seal.runtime_binding,
      evaluation_time: seal.evaluation_time,
      max_age_seconds: seal.max_age_seconds,
      state: seal.state,
      fail_closed: seal.fail_closed,
      native_receipt: seal.native_receipt,
      release_receipt: seal.release_receipt,
      rehearsal_receipt: seal.rehearsal_receipt,
      attribution_observed: seal.attribution_observed,
      credit: seal.credit,
      publication_unit_credit: seal.publication_unit_credit,
      mainnet_30_credit: seal.mainnet_30_credit,
      build_credit_eligible: seal.build_credit_eligible,
      execution_authority: seal.execution_authority,
      external_actions: seal.external_actions,
    };
    const expectedBoundary = {
      state: "integrity_seal_candidate_ready",
      fail_closed: false,
      native_receipt: null,
      release_receipt: false,
      rehearsal_receipt: null,
      attribution_observed: false,
      credit: 0,
      publication_unit_credit: 0,
      mainnet_30_credit: 0,
      build_credit_eligible: false,
      execution_authority: EXECUTION_AUTHORITY,
      external_actions: 0,
    };
    if (JSON.stringify({
      state: seal.state,
      fail_closed: seal.fail_closed,
      native_receipt: seal.native_receipt,
      release_receipt: seal.release_receipt,
      rehearsal_receipt: seal.rehearsal_receipt,
      attribution_observed: seal.attribution_observed,
      credit: seal.credit,
      publication_unit_credit: seal.publication_unit_credit,
      mainnet_30_credit: seal.mainnet_30_credit,
      build_credit_eligible: seal.build_credit_eligible,
      execution_authority: seal.execution_authority,
      external_actions: seal.external_actions,
    }) !== JSON.stringify(expectedBoundary)) {
      return failClosed("integrity_seal_security_boundary_mismatch", ["V9-F55"]);
    }
    if (digest(payload) !== seal.seal_digest) return failClosed("integrity_seal_digest_mismatch", ["V9-F40"]);
    return Object.freeze({ ok: true, fail_closed: false, seal_digest: seal.seal_digest, credit: 0, publication_unit_credit: 0, build_credit_eligible: false });
  } catch (error) {
    return failClosed("invalid_integrity_seal", ["V9-F41"], { message: error.message });
  }
}
