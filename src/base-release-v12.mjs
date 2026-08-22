import { createHash } from "node:crypto";

export const V12_MANIFEST_SCHEMA_VERSION = "base-erp-v12-deployment-manifest-v1";
export const V12_PUBLIC_SCHEMA_VERSION = "base-erp-v12-public-release-v1";
export const V12_RELEASE_SCHEMA_VERSION = "base-erp-v12-release-identity-v1";
export const V12_CANDIDATE_SCHEMA_VERSION = "base-erp-v12-release-candidate-v1";
export const V12_RELEASE_FINGERPRINT_ALGORITHM = "sha256(base-erp-v12-deterministic-release-identity-v1)";
export const V12_MANIFEST_SELF_HASH_ALGORITHM = "sha256(base-erp-v12-manifest-self-hash-v1)";
export const V12_BOM_SCHEMA_VERSION = "base-erp-v12-bom-v1";
export const V12_RELEASE_ID_PATTERN = /^base-erp-public-product-\d{8}-v12$/i;
export const V12_COMMIT_PLACEHOLDER = "PENDING_OWNER_PUBLIC_COMMIT";
export const V12_COMMIT_ENV_NAMES = Object.freeze([
  "RENDER_GIT_COMMIT",
  "RENDER_GIT_COMMIT_SHA",
  "GIT_COMMIT_SHA",
  "SOURCE_VERSION",
]);

const DIGEST = /^[0-9a-f]{64}$/i;
const COMMIT = /^[0-9a-f]{40}$/i;
const RELATIVE_PATH = /^(?!\/)(?!.*\\)(?!.*(?:^|\/)\.\.?(?:\/|$))(?!runtime(?:\/|$))(?!shared(?:\/|$))(?!upstream(?:\/|$))(?!\.base-memory(?:\/|$))(?!progress\.md$)(?!AGENTS\.md$)[A-Za-z0-9._/-]+$/;
const BASE_TARGET_FIELDS = new Set(["github_repo", "render_service_id", "render_domain", "dashboard_app_id", "canonical_primary_url"]);
const MANIFEST_BOM_IDENTITY_FIELDS = new Set([
  "release_fingerprint",
  "release_fingerprint_basis",
  "bom_fingerprint",
  "immutable_bom_sha256",
  "immutable_release_bom",
  "source_catalog_fingerprint",
  "manifest_self_hash",
  "self_hash",
]);
const FORBIDDEN_MANIFEST_KEYS = /^(?:owner_digest|owner_allowlist|wallet_address|wallet_account|primary_base_account|account_address|call_template|calldata|call_data|calls|auth_hmac_secret|auth_secret|hmac_secret|hmac|rpc_url|rpc_secret|rpc|private_key|privatekey|signature|mnemonic|seed|password|passwd|token|access_token|authorization|cookie|api_key|apikey|client_secret|secret|credentials)$/i;
const V12_SEAL_SCHEMA_VERSION = "base-erp-v12-release-integrity-seal-v1";
const V12_SEAL_EXECUTION_AUTHORITY = "none_until_02_Build_revalidates";
const V12_SEAL_KEYS = new Set([
  "schema_version", "ok", "fail_closed", "state", "observed_at", "release_identity", "public_routes", "auth",
  "native_receipt", "release_receipt", "credit", "publication_unit_credit", "mainnet_30_credit", "build_credit_eligible",
  "execution_authority", "external_actions", "seal_digest",
]);
const V12_SEAL_IDENTITY_KEYS = new Set([
  "release_schema_version", "release_id", "release_fingerprint", "bom_fingerprint", "commit_sha", "source_catalog_fingerprint",
  "commit_binding", "base_target",
]);
const V12_SEAL_ROUTE_KEYS = new Set(["healthz", "release", "integrity_seal", "workbench", "wallet_action_plan", "wallet_action_bridge"]);
const V12_SEAL_AUTH_KEYS = new Set(["enabled", "ready", "owner_routes_fail_closed"]);

function fail(code, details = {}) {
  const error = new Error(code);
  error.code = code;
  Object.assign(error, details);
  throw error;
}

function plainObject(value, code = "V12_OBJECT_REQUIRED") {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  return value;
}

function requiredString(value, code) {
  if (typeof value !== "string" || value.trim() === "") fail(code);
  return value.trim();
}

function digestValue(value) {
  return createHash("sha256").update(canonicalizeV12(value), "utf8").digest("hex");
}

export function canonicalizeV12(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("V12_CANONICAL_VALUE_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeV12).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"));
    if (new Set(keys).size !== keys.length) fail("V12_CANONICAL_KEY_DUPLICATE");
    keys.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizeV12(value[key])}`).join(",")}}`;
  }
  fail("V12_CANONICAL_VALUE_INVALID");
}

export function digestV12(value) {
  return digestValue(value);
}

function exactKeys(value, allowed, code) {
  const source = plainObject(value, code);
  if (Object.keys(source).some((key) => !allowed.has(key))) fail(code);
  return source;
}

export function normalizeV12CommitBinding(value) {
  const source = exactKeys(value, new Set(["mode", "env_names", "expected_commit", "require_full_40_hex", "require_consistent_values", "placeholder"]), "V12_COMMIT_BINDING_SHAPE_INVALID");
  if (source.mode !== "runtime_commit_env") fail("V12_COMMIT_BINDING_MODE_INVALID");
  if (!Array.isArray(source.env_names) || source.env_names.length === 0 || source.env_names.some((name) => typeof name !== "string" || !V12_COMMIT_ENV_NAMES.includes(name))) fail("V12_COMMIT_BINDING_ENV_INVALID");
  const envNames = [...new Set(source.env_names)].sort();
  if (envNames.length !== source.env_names.length) fail("V12_COMMIT_BINDING_ENV_DUPLICATE");
  if (source.expected_commit !== null && source.expected_commit !== undefined && (typeof source.expected_commit !== "string" || !COMMIT.test(source.expected_commit.trim()))) fail("V12_COMMIT_BINDING_EXPECTED_COMMIT_INVALID");
  if (source.require_full_40_hex !== true || source.require_consistent_values !== true) fail("V12_COMMIT_BINDING_STRICTNESS_INVALID");
  if (source.placeholder !== V12_COMMIT_PLACEHOLDER) fail("V12_COMMIT_BINDING_PLACEHOLDER_INVALID");
  return Object.freeze({
    mode: source.mode,
    env_names: Object.freeze(envNames),
    expected_commit: source.expected_commit == null ? null : source.expected_commit.trim().toLowerCase(),
    require_full_40_hex: true,
    require_consistent_values: true,
    placeholder: V12_COMMIT_PLACEHOLDER,
  });
}

/**
 * Resolve only the deployment-provided commit. Any non-empty value in the
 * allowlist must be a full 40-hex value, and all supplied values must agree.
 * A missing or invalid observation is deliberately represented by the
 * placeholder so callers can expose a bounded, not-ready document.
 */
export function resolveV12Commit({ commit_binding, env = {} } = {}) {
  let binding;
  try {
    binding = normalizeV12CommitBinding(commit_binding);
  } catch (error) {
    return Object.freeze({ value: V12_COMMIT_PLACEHOLDER, placeholder: true, source: "manifest_commit_binding_invalid", reason: error.code ?? "V12_COMMIT_BINDING_INVALID" });
  }
  const observed = [];
  for (const name of binding.env_names) {
    const raw = env?.[name];
    if (raw === undefined || raw === null || String(raw).trim() === "") continue;
    const value = String(raw).trim().toLowerCase();
    if (!COMMIT.test(value)) return Object.freeze({ value: V12_COMMIT_PLACEHOLDER, placeholder: true, source: "environment_invalid", reason: "V12_COMMIT_NOT_FULL_40_HEX", observed_env_names: [name] });
    observed.push({ name, value });
  }
  if (observed.length === 0) return Object.freeze({ value: V12_COMMIT_PLACEHOLDER, placeholder: true, source: "owner_public_commit_pending", reason: "V12_COMMIT_MISSING", observed_env_names: [] });
  const values = [...new Set(observed.map((entry) => entry.value))];
  if (values.length !== 1) return Object.freeze({ value: V12_COMMIT_PLACEHOLDER, placeholder: true, source: "environment_conflict", reason: "V12_COMMIT_CONFLICT", observed_env_names: observed.map((entry) => entry.name) });
  const value = values[0];
  if (binding.expected_commit !== null && binding.expected_commit !== value) return Object.freeze({ value: V12_COMMIT_PLACEHOLDER, placeholder: true, source: "environment_drift", reason: "V12_COMMIT_EXPECTED_MISMATCH", observed_env_names: observed.map((entry) => entry.name) });
  return Object.freeze({ value, placeholder: false, source: observed.map((entry) => entry.name).join(","), reason: null, observed_env_names: observed.map((entry) => entry.name) });
}

function normalizeBaseTarget(value) {
  const source = exactKeys(value, BASE_TARGET_FIELDS, "V12_BASE_TARGET_SHAPE_INVALID");
  const target = {};
  for (const field of BASE_TARGET_FIELDS) target[field] = requiredString(source[field], "V12_BASE_TARGET_FIELD_INVALID");
  return Object.freeze(target);
}

export function canonicalV12ReleaseFingerprintBasis({ release_id, bom_fingerprint, base_target, commit_binding, source_catalog_fingerprint } = {}) {
  const normalizedReleaseId = requiredString(release_id, "V12_RELEASE_ID_REQUIRED");
  if (!V12_RELEASE_ID_PATTERN.test(normalizedReleaseId)) fail("V12_RELEASE_ID_INVALID");
  const normalizedBom = requiredString(bom_fingerprint, "V12_BOM_FINGERPRINT_REQUIRED").toLowerCase();
  const normalizedSource = requiredString(source_catalog_fingerprint, "V12_SOURCE_CATALOG_REQUIRED").toLowerCase();
  if (!DIGEST.test(normalizedBom) || !DIGEST.test(normalizedSource)) fail("V12_RELEASE_DIGEST_INVALID");
  return {
    schema_version: V12_RELEASE_SCHEMA_VERSION,
    release_id: normalizedReleaseId,
    bom_fingerprint: normalizedBom,
    base_target: normalizeBaseTarget(base_target),
    commit_binding: normalizeV12CommitBinding(commit_binding),
    source_catalog_fingerprint: normalizedSource,
  };
}

export function computeV12ReleaseFingerprint(identity) {
  return digestValue(canonicalV12ReleaseFingerprintBasis(identity));
}

export function canonicalV12ManifestProjection(manifest) {
  const source = plainObject(manifest, "V12_MANIFEST_REQUIRED");
  const projection = {};
  for (const [key, value] of Object.entries(source)) {
    if (!MANIFEST_BOM_IDENTITY_FIELDS.has(key)) projection[key] = structuredClone(value);
  }
  return projection;
}

export function digestV12ManifestForBom(manifest) {
  return digestValue(canonicalV12ManifestProjection(manifest));
}

export function digestV12ManifestSelfHash(manifest) {
  const source = plainObject(manifest, "V12_MANIFEST_REQUIRED");
  const { manifest_self_hash: _manifestSelfHash, self_hash: _selfHash, ...withoutSelfHash } = source;
  return digestValue(withoutSelfHash);
}

function scanForbiddenKeys(value, path = "manifest") {
  if (!value || typeof value !== "object") return null;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const result = scanForbiddenKeys(value[index], `${path}[${index}]`);
      if (result) return result;
    }
    return null;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_MANIFEST_KEYS.test(key)) return `${path}.${key}`;
    if (typeof child === "string" && /^0x[0-9a-f]{40}$/i.test(child.trim())) return `${path}.${key}`;
    const result = scanForbiddenKeys(child, `${path}.${key}`);
    if (result) return result;
  }
  return null;
}

function normalizedDigest(value, code) {
  if (typeof value !== "string" || !DIGEST.test(value) || value !== value.toLowerCase()) fail(code);
  return value;
}

function normalizeV12SealIdentity(value) {
  const source = exactKeys(value, V12_SEAL_IDENTITY_KEYS, "V12_SEAL_RELEASE_IDENTITY_SHAPE_INVALID");
  if (source.release_schema_version !== V12_RELEASE_SCHEMA_VERSION) fail("V12_SEAL_RELEASE_SCHEMA_INVALID");
  if (typeof source.release_id !== "string" || !V12_RELEASE_ID_PATTERN.test(source.release_id)) fail("V12_SEAL_RELEASE_ID_INVALID");
  const commit = typeof source.commit_sha === "string" ? source.commit_sha.trim().toLowerCase() : "";
  if (!COMMIT.test(commit)) fail("V12_SEAL_COMMIT_INVALID");
  return Object.freeze({
    release_schema_version: source.release_schema_version,
    release_id: source.release_id,
    release_fingerprint: normalizedDigest(source.release_fingerprint, "V12_SEAL_RELEASE_FINGERPRINT_INVALID"),
    bom_fingerprint: normalizedDigest(source.bom_fingerprint, "V12_SEAL_BOM_FINGERPRINT_INVALID"),
    commit_sha: commit,
    source_catalog_fingerprint: normalizedDigest(source.source_catalog_fingerprint, "V12_SEAL_SOURCE_FINGERPRINT_INVALID"),
    commit_binding: normalizeV12CommitBinding(source.commit_binding),
    base_target: normalizeBaseTarget(source.base_target),
  });
}

function expectedV12SealIdentity(release) {
  const source = plainObject(release, "V12_SEAL_EXPECTED_RELEASE_REQUIRED");
  if (source.v12_release_ready !== true) fail("V12_SEAL_EXPECTED_RELEASE_UNREADY");
  return normalizeV12SealIdentity({
    release_schema_version: source.release_schema_version,
    release_id: source.release_id,
    release_fingerprint: source.release_fingerprint,
    bom_fingerprint: source.bom_fingerprint,
    commit_sha: source.git_commit,
    source_catalog_fingerprint: source.source_catalog_fingerprint,
    commit_binding: source.commit_binding,
    base_target: source.base_target,
  });
}

function validRelativePath(value) {
  return typeof value === "string" && RELATIVE_PATH.test(value) && !value.startsWith("projects/");
}

export function validateV12Manifest(manifest) {
  try {
    const source = plainObject(manifest, "V12_MANIFEST_REQUIRED");
    const forbidden = scanForbiddenKeys(source);
    if (forbidden) fail("V12_MANIFEST_FORBIDDEN_FIELD", { field: forbidden });
    const allowed = new Set([
      "schema_version", "release_id", "release_fingerprint_algorithm", "release_fingerprint_basis", "release_fingerprint",
      "bom_schema_version", "bom_fingerprint", "immutable_bom_sha256", "bom_file_count", "immutable_release_bom",
      "source_files", "source_catalog_fingerprint", "commit_binding", "project_name", "material_outcome", "generated_at_cst",
      "network", "base_target", "public_identity", "evidence_level", "deployment", "receipt", "external_actions",
      "public_write_authorized", "credits", "execution_authority", "circle_isolation", "limitations", "state", "manifest_self_hash",
    ]);
    if (Object.keys(source).some((key) => !allowed.has(key))) fail("V12_MANIFEST_UNKNOWN_FIELD");
    if (source.schema_version !== V12_MANIFEST_SCHEMA_VERSION || !V12_RELEASE_ID_PATTERN.test(String(source.release_id ?? ""))) fail("V12_MANIFEST_IDENTITY_INVALID");
    if (source.release_fingerprint_algorithm !== V12_RELEASE_FINGERPRINT_ALGORITHM || source.bom_schema_version !== V12_BOM_SCHEMA_VERSION || source.execution_authority !== "none_until_02_Build_revalidates") fail("V12_MANIFEST_ALGORITHM_INVALID");
    if (!DIGEST.test(String(source.release_fingerprint ?? "")) || !DIGEST.test(String(source.bom_fingerprint ?? "")) || source.immutable_bom_sha256 !== source.bom_fingerprint || !DIGEST.test(String(source.source_catalog_fingerprint ?? "")) || !DIGEST.test(String(source.manifest_self_hash ?? ""))) fail("V12_MANIFEST_DIGEST_INVALID");
    if (!Array.isArray(source.immutable_release_bom) || source.immutable_release_bom.length === 0 || source.bom_file_count !== source.immutable_release_bom.length) fail("V12_MANIFEST_BOM_SHAPE_INVALID");
    const paths = source.immutable_release_bom.map((entry) => {
      const item = exactKeys(entry, new Set(["path", "digest"]), "V12_MANIFEST_BOM_ENTRY_INVALID");
      if (typeof item.path !== "string" || !item.path.startsWith("projects/2026-08_Base_ERP_Settlement_Workbench/") || !validRelativePath(item.path.slice("projects/2026-08_Base_ERP_Settlement_Workbench/".length)) || !DIGEST.test(String(item.digest ?? ""))) fail("V12_MANIFEST_BOM_ENTRY_INVALID");
      return item.path;
    });
    const sortedPaths = [...paths].sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    if (JSON.stringify(paths) !== JSON.stringify(sortedPaths) || new Set(paths).size !== paths.length) fail("V12_MANIFEST_BOM_ORDER_INVALID");
    if (!Array.isArray(source.source_files) || source.source_files.length === 0 || source.source_files.some((path) => !validRelativePath(path))) fail("V12_MANIFEST_SOURCE_FILES_INVALID");
    const sortedSourceFiles = [...source.source_files].sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    if (JSON.stringify(source.source_files) !== JSON.stringify(sortedSourceFiles) || new Set(source.source_files).size !== source.source_files.length) fail("V12_MANIFEST_SOURCE_FILES_ORDER_INVALID");
    const target = normalizeBaseTarget(source.base_target);
    const commitBinding = normalizeV12CommitBinding(source.commit_binding);
    if (digestValue(source.release_fingerprint_basis) !== digestValue(canonicalV12ReleaseFingerprintBasis({ release_id: source.release_id, bom_fingerprint: source.bom_fingerprint, base_target: target, commit_binding: commitBinding, source_catalog_fingerprint: source.source_catalog_fingerprint }))) fail("V12_MANIFEST_FINGERPRINT_BASIS_INVALID");
    if (source.release_fingerprint !== computeV12ReleaseFingerprint({ release_id: source.release_id, bom_fingerprint: source.bom_fingerprint, base_target: target, commit_binding: commitBinding, source_catalog_fingerprint: source.source_catalog_fingerprint })) fail("V12_MANIFEST_FINGERPRINT_INVALID");
    const identity = exactKeys(source.public_identity, new Set(["basename"]), "V12_MANIFEST_PUBLIC_IDENTITY_INVALID");
    if (typeof identity.basename !== "string" || identity.basename.trim() === "") fail("V12_MANIFEST_PUBLIC_IDENTITY_INVALID");
    if (source.state !== "tracked_deployment_manifest_v12" || source.deployment !== false || source.receipt !== null || source.public_write_authorized !== false || source.external_actions !== 0) fail("V12_MANIFEST_EXECUTION_STATE_INVALID");
    const credits = exactKeys(source.credits, new Set(["mainnet_transaction_credit", "publication_unit_credit"]), "V12_MANIFEST_CREDITS_INVALID");
    if (credits.mainnet_transaction_credit !== 0 || credits.publication_unit_credit !== 0) fail("V12_MANIFEST_CREDITS_INVALID");
    const isolation = exactKeys(source.circle_isolation, new Set(["checked", "collision", "target_reuse", "external_actions"]), "V12_MANIFEST_ISOLATION_INVALID");
    if (isolation.checked !== true || isolation.collision !== false || isolation.target_reuse !== false || isolation.external_actions !== 0) fail("V12_MANIFEST_ISOLATION_INVALID");
    if (!Array.isArray(source.limitations) || source.limitations.some((value) => typeof value !== "string" || value.trim() === "")) fail("V12_MANIFEST_LIMITATIONS_INVALID");
    return Object.freeze({ ok: true, target, commit_binding: commitBinding, source: source });
  } catch (error) {
    return Object.freeze({ ok: false, fail_closed: true, reason: error.code ?? "V12_MANIFEST_INVALID", failure_codes: [error.code ?? "V12-F99"], field: error.field ?? null });
  }
}

export function buildV12IntegritySeal({ release, authReadiness = null, observedAt = new Date().toISOString() } = {}) {
  const payload = {
    schema_version: V12_SEAL_SCHEMA_VERSION,
    ok: true,
    fail_closed: false,
    state: "v12_manifest_ready",
    observed_at: observedAt,
    release_identity: {
      release_schema_version: release.release_schema_version,
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      commit_sha: release.git_commit,
      source_catalog_fingerprint: release.source_catalog_fingerprint,
      commit_binding: release.commit_binding,
      base_target: release.base_target,
    },
    public_routes: {
      healthz: true,
      release: true,
      integrity_seal: true,
      workbench: true,
      wallet_action_plan: true,
      wallet_action_bridge: true,
    },
    auth: {
      enabled: authReadiness?.enabled === true,
      ready: authReadiness?.ready === true,
      owner_routes_fail_closed: authReadiness?.ready !== true,
    },
    native_receipt: null,
    release_receipt: false,
    credit: 0,
    publication_unit_credit: 0,
    mainnet_30_credit: 0,
    build_credit_eligible: false,
    execution_authority: V12_SEAL_EXECUTION_AUTHORITY,
    external_actions: 0,
  };
  return Object.freeze({ ...payload, seal_digest: digestValue(payload) });
}

export function verifyV12IntegritySeal(seal, { expectedRelease = null } = {}) {
  try {
    if (expectedRelease === null) fail("V12_SEAL_EXPECTED_RELEASE_REQUIRED");
    const source = exactKeys(seal, V12_SEAL_KEYS, "V12_SEAL_SHAPE_INVALID");
    const { seal_digest: _ignored, ...payload } = source;
    if (source.schema_version !== V12_SEAL_SCHEMA_VERSION || source.ok !== true || source.fail_closed !== false || source.state !== "v12_manifest_ready") fail("V12_SEAL_STATE_INVALID");
    if (typeof source.observed_at !== "string" || Number.isNaN(Date.parse(source.observed_at)) || new Date(source.observed_at).toISOString() !== source.observed_at) fail("V12_SEAL_OBSERVED_AT_INVALID");
    const identity = normalizeV12SealIdentity(source.release_identity);
    const expectedIdentity = expectedV12SealIdentity(expectedRelease);
    if (digestValue(identity) !== digestValue(expectedIdentity)) fail("V12_SEAL_RELEASE_IDENTITY_MISMATCH");
    const routes = exactKeys(source.public_routes, V12_SEAL_ROUTE_KEYS, "V12_SEAL_ROUTES_SHAPE_INVALID");
    if (Object.keys(routes).length !== V12_SEAL_ROUTE_KEYS.size) fail("V12_SEAL_ROUTES_SHAPE_INVALID");
    if (Object.values(routes).some((value) => value !== true)) fail("V12_SEAL_ROUTES_NOT_READY");
    const auth = exactKeys(source.auth, V12_SEAL_AUTH_KEYS, "V12_SEAL_AUTH_SHAPE_INVALID");
    if (Object.keys(auth).length !== V12_SEAL_AUTH_KEYS.size) fail("V12_SEAL_AUTH_SHAPE_INVALID");
    if (Object.values(auth).some((value) => typeof value !== "boolean") || auth.owner_routes_fail_closed !== (auth.ready !== true) || (auth.ready === true && auth.enabled !== true)) fail("V12_SEAL_AUTH_STATE_INVALID");
    if (source.native_receipt !== null || source.release_receipt !== false || source.credit !== 0 || source.publication_unit_credit !== 0 || source.mainnet_30_credit !== 0 || source.build_credit_eligible !== false || source.execution_authority !== V12_SEAL_EXECUTION_AUTHORITY || source.external_actions !== 0) fail("V12_SEAL_SECURITY_BOUNDARY_MISMATCH");
    if (typeof source.seal_digest !== "string" || !DIGEST.test(source.seal_digest) || source.seal_digest !== source.seal_digest.toLowerCase()) fail("V12_SEAL_DIGEST_SHAPE_INVALID");
    if (source.seal_digest !== digestValue(payload)) fail("V12_SEAL_DIGEST_MISMATCH");
    return Object.freeze({ ok: true });
  } catch (error) {
    return Object.freeze({ ok: false, reason: error.code ?? "V12_SEAL_INVALID", failure_codes: [error.code ?? "V12-F99"] });
  }
}

export const V12_MANIFEST_BOM_IDENTITY_FIELDS = Object.freeze([...MANIFEST_BOM_IDENTITY_FIELDS]);
