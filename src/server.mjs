import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { digest } from "./base-neutral-receipt-controls.mjs";
import {
  buildEventAdmissionPreview,
  buildPlatformGatesProjection,
  buildOperatorWorkbench,
  buildRecurringSettlementProjection,
  buildReadOnlySimulation,
  buildStandardWebAppMetadata,
  buildVisitorCaseCatalog,
} from "./base-erp-workbench.mjs";
import { renderOperatorWorkbenchPage } from "./operator-workbench-page.mjs";
import { evaluateRefundProposal } from "./base-refund-ceiling-guard.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const DEFAULT_RELEASE_PATH = resolve(PROJECT_ROOT, "runtime/release_candidate_2026-08-10.json");
const PRIMARY_BASE_ACCOUNT = "0xba36d092db2999bb1fabbaf281ac956a97189c25";
const FULL_COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const DEFAULT_COMMIT_PLACEHOLDER = "PENDING_OWNER_PUBLIC_COMMIT";
const H219_RELEASE_ID = "base-erp-public-product-20260815-v8";
const H219_BOM_SCHEMA_VERSION = "base-erp-v8-bom-v1";
const H219_RELEASE_SCHEMA_VERSION = "base-erp-v8-release-identity-v1";
const H219_BASE_TARGET = Object.freeze({
  github_repo: "gaysonloser/base-erp-settlement-workbench",
  render_service_id: "srv-d9t0bsafngtc7387gqo0",
  render_domain: "base-erp-settlement-workbench.onrender.com",
  dashboard_app_id: "6a7a0717e209a55163497d2d",
  canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com",
});
const H219_BOM_PATH_ALLOWLIST = Object.freeze([
  "projects/2026-08_Base_ERP_Settlement_Workbench/assets/base-app/base-erp-workbench-screenshot-source.png",
  "projects/2026-08_Base_ERP_Settlement_Workbench/assets/base-app/base-erp-workbench-thumbnail-source.png",
  "projects/2026-08_Base_ERP_Settlement_Workbench/config/base_erp_product_contract_v1.json",
  "projects/2026-08_Base_ERP_Settlement_Workbench/config/release_identity_and_exposure_contract_v1.json",
  "projects/2026-08_Base_ERP_Settlement_Workbench/package-lock.json",
  "projects/2026-08_Base_ERP_Settlement_Workbench/package.json",
  "projects/2026-08_Base_ERP_Settlement_Workbench/render.yaml",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-erp-workbench.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-native-platform-evidence-contract.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-native-platform-execution-gates.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-platform-feasibility-contract.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/operator-workbench-page.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/server.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-native-platform-execution-gates.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/operator-workbench-browser.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/operator-workbench-page.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/server.test.mjs",
]);
const H214_READBACK_PATH = "runtime/h214_recurring_settlement_readback_2026-08-14.json";
const H215_READBACK_PATH = "runtime/h215_operator_workbench_readback_2026-08-14.json";
const H217_MODULE_PATH = "src/base-native-platform-execution-gates.mjs";
const H217_READBACK_PATH = "runtime/h217_remaining_platform_readback_2026-08-15.json";
const CIRCLE_MATRIX_PATH = "config/base_circle_platform_isolation_matrix_v1.json";
const H217_MODULE_SHA256 = "96f9839cbebb6bff775a5b0cc84a7ae7d71b0168847f2a1eb08c0b59d6f80b42";
const H217_READBACK_SHA256 = "f7aea1ec1ea6d3377334f8f1d32938054f4bd4b809f622673fb056868be2c8b1";
const CIRCLE_MATRIX_SHA256 = "c538e47c4b7951f341b36e351858bf3e1c28dd772d7d3f9c3588f1f0093f19de";
const PUBLIC_PLATFORM_ORDER = Object.freeze([
  "github",
  "render",
  "base_app",
  "base_dashboard",
  "base_dev",
  "talent",
  "guild",
  "basename_base_org",
]);
const RECURRING_BINDING_QUERY_KEYS = new Set([
  "permission_id", "permission_hash", "payer", "spender", "account", "address",
  "token", "recipient", "amount", "network", "adapter", "status", "release",
  "release_id", "release_fingerprint", "bom_fingerprint", "calls_id", "callsid",
  "tx_hash", "txhash", "calldata", "wallet_request",
]);
const PUBLIC_ASSETS = Object.freeze({
  "/assets/base-app/base-erp-workbench-screenshot-1284x2778.jpg": Object.freeze({
    file: "assets/base-app/base-erp-workbench-screenshot-1284x2778.jpg",
    type: "image/jpeg",
  }),
  "/assets/base-app/base-erp-workbench-screenshot-source.png": Object.freeze({
    file: "assets/base-app/base-erp-workbench-screenshot-source.png",
    type: "image/png",
  }),
  "/assets/base-app/base-erp-workbench-thumbnail-1200x628.jpg": Object.freeze({
    file: "assets/base-app/base-erp-workbench-thumbnail-1200x628.jpg",
    type: "image/jpeg",
  }),
  "/assets/base-app/base-erp-workbench-thumbnail-source.png": Object.freeze({
    file: "assets/base-app/base-erp-workbench-thumbnail-source.png",
    type: "image/png",
  }),
});

function parseStrictJson(text) {
  let index = 0;
  const source = String(text);
  const whitespace = () => { while (/\s/.test(source[index] ?? "")) index += 1; };
  const fail = () => { throw new SyntaxError("invalid JSON or duplicate object key"); };
  const parseString = () => {
    if (source[index] !== '"') fail();
    const start = index;
    index += 1;
    let escaped = false;
    while (index < source.length) {
      const char = source[index++];
      if (escaped) { escaped = false; continue; }
      if (char === "\\") { escaped = true; continue; }
      if (char === '"') return JSON.parse(source.slice(start, index));
      if (char < " ") fail();
    }
    fail();
  };
  const parseNumber = () => {
    const match = source.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) fail();
    index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail();
    return value;
  };
  const parseValue = () => {
    whitespace();
    const char = source[index];
    if (char === '"') return parseString();
    if (char === "{") {
      index += 1; whitespace();
      const object = {}; const keys = new Set();
      if (source[index] === "}") { index += 1; return object; }
      while (index < source.length) {
        whitespace();
        const key = parseString();
        if (keys.has(key)) fail();
        keys.add(key); whitespace();
        if (source[index++] !== ":") fail();
        object[key] = parseValue(); whitespace();
        if (source[index] === "}") { index += 1; return object; }
        if (source[index++] !== ",") fail();
      }
      fail();
    }
    if (char === "[") {
      index += 1; whitespace(); const array = [];
      if (source[index] === "]") { index += 1; return array; }
      while (index < source.length) {
        array.push(parseValue()); whitespace();
        if (source[index] === "]") { index += 1; return array; }
        if (source[index++] !== ",") fail();
      }
      fail();
    }
    if (source.startsWith("true", index)) { index += 4; return true; }
    if (source.startsWith("false", index)) { index += 5; return false; }
    if (source.startsWith("null", index)) { index += 4; return null; }
    return parseNumber();
  };
  const value = parseValue(); whitespace();
  if (index !== source.length) fail();
  return value;
}

function readJsonFile(filePath) {
  const resolvedPath = filePath instanceof URL ? filePath : resolve(String(filePath));
  return parseStrictJson(readFileSync(resolvedPath, "utf8"));
}

function canonicalizeH219(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeH219).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"));
    if (new Set(keys).size !== keys.length) throw new TypeError("duplicate normalized object key");
    keys.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizeH219(value[key])}`).join(",")}}`;
  }
  throw new TypeError("unsupported JSON value");
}

function canonicalDigest(value) {
  return createHash("sha256").update(canonicalizeH219(value), "utf8").digest("hex");
}

function h219BaseTargetEqual(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const expectedKeys = Object.keys(H219_BASE_TARGET);
  const actualKeys = Object.keys(value);
  return actualKeys.length === expectedKeys.length
    && expectedKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key) && value[key] === H219_BASE_TARGET[key]);
}

function currentV8ReleaseReady(release) {
  return release?.schema_version === "base-erp-v8-public-release-v1"
    && release.release_schema_version === H219_RELEASE_SCHEMA_VERSION
    && release.release_id === H219_RELEASE_ID
    && release.release_identity_valid === true
    && h219BaseTargetEqual(release.base_target)
    && release.bom_verified === true
    && release.bom_fingerprint_valid === true
    && release.bom_files_verified === true
    && release.bom_source_bytes_safe === true
    && typeof release.bom_fingerprint === "string"
    && DIGEST_PATTERN.test(release.bom_fingerprint)
    && release.immutable_bom_sha256 === release.bom_fingerprint
    && typeof release.release_fingerprint === "string"
    && DIGEST_PATTERN.test(release.release_fingerprint)
    && typeof release.git_commit === "string"
    && FULL_COMMIT_PATTERN.test(release.git_commit)
    && release.commit_placeholder === false;
}

const CURRENT_V8_UNAVAILABLE = Object.freeze({
  error: "release_unavailable",
  reason: "current_v8_identity_unready",
});

function resolveProjectPath(filePath) {
  const raw = String(filePath).normalize("NFC");
  const prefix = "projects/2026-08_Base_ERP_Settlement_Workbench/";
  const relative = raw.startsWith(prefix) ? raw.slice(prefix.length) : raw;
  if (!relative || relative.startsWith("/") || relative.includes("\\") || relative.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error("invalid BOM path");
  }
  return resolve(PROJECT_ROOT, relative);
}

function asNonEmptyString(value, fallback) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function resolveCommit({ candidate, env }) {
  const source = env?.RENDER_GIT_COMMIT ?? env?.RENDER_GIT_COMMIT_SHA ?? env?.GIT_COMMIT_SHA ?? env?.SOURCE_VERSION;
  if (typeof source === "string" && FULL_COMMIT_PATTERN.test(source.trim())) {
    return { value: source.trim(), placeholder: false, source: "environment" };
  }
  // The candidate commit identifies the intended release, not the bytes that
  // the current process is actually serving.  Without a deployment-provided
  // commit we cannot prove those identities match, so health must fail closed.
  return { value: DEFAULT_COMMIT_PLACEHOLDER, placeholder: true, source: "owner_public_commit_pending" };
}

function sha256File(filePath) {
  try {
    const raw = readFileSync(resolveProjectPath(filePath));
    // The H214 readback carries the final release/BOM fingerprints. Its BOM
    // entry is therefore sealed over a placeholder projection so the release
    // identity can join the readback without an impossible self-hash cycle.
    if (filePath === H214_READBACK_PATH || filePath === H215_READBACK_PATH) {
      const readback = JSON.parse(raw.toString("utf8"));
      if (readback.release_join && typeof readback.release_join === "object") {
        readback.release_join = {
          ...readback.release_join,
          release_fingerprint: "<current>",
          bom_fingerprint: "<current>",
        };
      }
      if (readback.release_bom && typeof readback.release_bom === "object") {
        readback.release_bom = {
          ...readback.release_bom,
          release_fingerprint: "<current>",
          bom_fingerprint: "<current>",
        };
      }
      return digest(readback);
    }
    return createHash("sha256").update(raw).digest("hex");
  } catch {
    return null;
  }
}

function verifyBom(candidate) {
  const entries = Array.isArray(candidate?.immutable_release_bom) ? candidate.immutable_release_bom : [];
  const rawEntries = entries.map((entry) => ({
    path: typeof entry?.path === "string" ? entry.path.normalize("NFC") : null,
    digest: typeof entry?.digest === "string" ? entry.digest : null,
  }));
  const h219AllowlistValid = candidate.schema_version !== "base-erp-v8-release-candidate-v1"
    || (rawEntries.length === H219_BOM_PATH_ALLOWLIST.length
      && rawEntries.every((entry, index) => entry.path === H219_BOM_PATH_ALLOWLIST[index]));
  const normalizedBom = entries
    .map((entry) => ({
      path: typeof entry?.path === "string" ? entry.path.normalize("NFC") : null,
      digest: typeof entry?.digest === "string" ? entry.digest : null,
    }))
    .filter((entry) => entry.path !== null && entry.digest !== null)
    .sort((left, right) => Buffer.from(left.path, "utf8").compare(Buffer.from(right.path, "utf8")));
  const normalizedPaths = normalizedBom.map((entry) => entry.path);
  const caseFoldPaths = normalizedPaths.map((path) => path.toLocaleLowerCase("en-US"));
  const structureValid = normalizedBom.length === entries.length
    && normalizedBom.length > 0
    && h219AllowlistValid
    && (candidate.schema_version === "base-erp-v8-release-candidate-v1" ? normalizedBom.length === 17 : true)
    && normalizedBom.every((entry) => DIGEST_PATTERN.test(entry.digest))
    && new Set(normalizedPaths).size === normalizedPaths.length
    && new Set(caseFoldPaths).size === caseFoldPaths.length
    && normalizedPaths.every((path) => {
      try {
        const stat = lstatSync(resolveProjectPath(path));
        return stat.isFile() && !stat.isSymbolicLink();
      } catch { return false; }
    });
  const bomFiles = normalizedBom.map((entry) => ({ path: entry.path, sha256: entry.digest }));
  const bomPayload = { schema_version: H219_BOM_SCHEMA_VERSION, files: bomFiles };
  const expectedBomFingerprint = candidate.schema_version === "base-erp-v8-release-candidate-v1"
    ? canonicalDigest(bomPayload)
    : digest(normalizedBom);
  const fingerprintValid = structureValid
    && typeof candidate.bom_fingerprint === "string"
    && DIGEST_PATTERN.test(candidate.bom_fingerprint)
    && candidate.bom_fingerprint === expectedBomFingerprint;
  const filesVerified = structureValid && normalizedBom.every((entry) => sha256File(entry.path) === entry.digest);
  const sourceBytesSafe = candidate.schema_version !== "base-erp-v8-release-candidate-v1"
    || normalizedBom.every((entry) => {
      try {
        const bytes = readFileSync(resolveProjectPath(entry.path));
        const actualCommit = FULL_COMMIT_PATTERN.test(String(candidate.git_commit ?? "")) ? String(candidate.git_commit) : null;
        return (!actualCommit || !bytes.includes(Buffer.from(actualCommit, "utf8")))
          && !bytes.includes(Buffer.from(String(candidate.release_fingerprint ?? ""), "utf8"))
          && !bytes.includes(Buffer.from(String(candidate.bom_fingerprint ?? ""), "utf8"));
      } catch { return false; }
    });
  return {
    bom_verified: Boolean(fingerprintValid && filesVerified && sourceBytesSafe),
    bom_fingerprint_valid: Boolean(fingerprintValid),
    bom_files_verified: Boolean(filesVerified),
    bom_source_bytes_safe: Boolean(sourceBytesSafe),
    bom_schema_version: candidate.schema_version === "base-erp-v8-release-candidate-v1" ? H219_BOM_SCHEMA_VERSION : null,
  };
}

/**
 * Read only the public, non-secret portion of the current release candidate.
 * Runtime cursor, authority details and wallet capabilities are intentionally
 * omitted from this document; /healthz exposes only a bounded writer-idle state.
 */
export function readReleaseDocument({ releasePath = DEFAULT_RELEASE_PATH, env = process.env } = {}) {
  const candidate = readJsonFile(releasePath);
  const commit = resolveCommit({ candidate, env });
  const bomVerification = verifyBom(candidate);
  const bom = Array.isArray(candidate.immutable_release_bom)
    ? candidate.immutable_release_bom.map((entry) => ({ path: entry.path, digest: entry.digest }))
    : [];
  const limitations = Array.from(new Set([
    ...(Array.isArray(candidate.limitations) ? candidate.limitations : []),
    "This local candidate has no Base Mainnet receipt, ERP authoritative readback, or complete eight-surface public receipt.",
    "Public writes and wallet actions are disabled until an owner-visible gate is satisfied.",
  ]));
  const releaseIdentity = candidate.schema_version === "base-erp-v8-release-candidate-v1"
    ? {
      schema_version: H219_RELEASE_SCHEMA_VERSION,
      release_id: candidate.release_id,
      bom_fingerprint: candidate.bom_fingerprint,
      base_target: candidate.base_target,
    }
    : null;
  const releaseIdentityFingerprintValid = releaseIdentity
    ? releaseIdentity.release_id === H219_RELEASE_ID
      && h219BaseTargetEqual(releaseIdentity.base_target)
      && typeof releaseIdentity.bom_fingerprint === "string"
      && DIGEST_PATTERN.test(releaseIdentity.bom_fingerprint)
      && typeof candidate.release_fingerprint === "string"
      && DIGEST_PATTERN.test(candidate.release_fingerprint)
      && canonicalDigest(releaseIdentity) === candidate.release_fingerprint
    : true;
  return Object.freeze({
    schema_version: candidate.schema_version === "base-erp-v8-release-candidate-v1" ? "base-erp-v8-public-release-v1" : "base-erp-public-release-v1",
    project_name: asNonEmptyString(candidate.project_name, "Base ERP Settlement Workbench"),
    release_id: asNonEmptyString(candidate.release_id, "unbound-release"),
    release_fingerprint: asNonEmptyString(candidate.release_fingerprint, ""),
    bom_fingerprint: asNonEmptyString(candidate.bom_fingerprint, ""),
    immutable_bom_sha256: candidate.immutable_bom_sha256 ?? candidate.bom_fingerprint ?? null,
    immutable_release_bom: bom,
    material_outcome: asNonEmptyString(candidate.material_outcome, "Receipt-first ERP settlement preparation"),
    generated_at_cst: candidate.generated_at_cst ?? null,
    network: asNonEmptyString(candidate.network, "Base Mainnet preflight contract only; no chain action"),
    public_identity: Object.freeze({
      basename: asNonEmptyString(candidate.basename, "gaysonloser.base.eth"),
      primary_base_account: asNonEmptyString(candidate.primary_base_account, PRIMARY_BASE_ACCOUNT),
    }),
    git_commit: commit.value,
    commit_placeholder: commit.placeholder,
    commit_source: commit.source,
    ...bomVerification,
    release_identity_valid: typeof candidate.release_id === "string"
      && candidate.release_id.trim() !== ""
      && DIGEST_PATTERN.test(typeof candidate.release_fingerprint === "string" ? candidate.release_fingerprint : "")
      && DIGEST_PATTERN.test(typeof candidate.bom_fingerprint === "string" ? candidate.bom_fingerprint : "")
      && releaseIdentityFingerprintValid,
    ...(releaseIdentity ? { base_target: Object.freeze({ ...(releaseIdentity.base_target ?? {}) }), release_schema_version: H219_RELEASE_SCHEMA_VERSION } : {}),
    public_write_authorized: false,
    publication_status: "local_candidate_non_public_receipt",
    evidence_level: asNonEmptyString(candidate.evidence_level, "L1_local_tests"),
    limitations,
  });
}

export function readHealth({ release = readReleaseDocument(), runtimeReader = null, observedAt = new Date().toISOString() } = {}) {
  let runtimeStatus = "not_required";
  let runtimeReason;
  if (typeof runtimeReader === "function") {
    try {
      const runtime = runtimeReader();
      runtimeStatus = runtime.writer_idle === true && runtime.writer_idle_authority?.writer_idle === true
        ? "writer_idle_bound"
        : "writer_idle_unbound";
    } catch (error) {
      runtimeStatus = "runtime_binding_unreadable";
      runtimeReason = error instanceof Error ? error.message : "runtime binding unreadable";
    }
  }
  const ready = currentV8ReleaseReady(release);
  return Object.freeze({
    ready,
    status: ready ? "ok" : "degraded",
    runtime_status: runtimeStatus,
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    immutable_bom_sha256: release.immutable_bom_sha256,
    git_commit: release.git_commit,
    commit_placeholder: release.commit_placeholder,
    observed_at: observedAt,
    public_write_authorized: false,
    ...(runtimeReason ? { runtime_reason: runtimeReason } : {}),
  });
}

function readCandidateJson(releasePath) {
  try {
    return readJsonFile(releasePath);
  } catch {
    return {};
  }
}

function platformEvidence(candidate, release) {
  const source = candidate?.eight_surface_evidence_map ?? {};
  return Object.fromEntries(PUBLIC_PLATFORM_ORDER.map((platform) => {
    const row = source[platform] && typeof source[platform] === "object" ? source[platform] : {};
    const candidateReference = row.candidate_reference && typeof row.candidate_reference === "object"
      ? row.candidate_reference
      : null;
    const readback = row.readback && typeof row.readback === "object" ? row.readback : null;
    const strictReceipt = row.receipt && typeof row.receipt === "object" ? row.receipt : null;
    const boundCandidate = candidateReference
      && candidateReference.release_id === release.release_id
      && candidateReference.release_fingerprint === release.release_fingerprint
      && candidateReference.bom_fingerprint === release.bom_fingerprint;
    const boundReceipt = strictReceipt
      && strictReceipt.release_id === release.release_id
      && strictReceipt.release_fingerprint === release.release_fingerprint
      && strictReceipt.bom_fingerprint === release.bom_fingerprint
      && strictReceipt.current === true
      && strictReceipt.historical === false
      && strictReceipt.synthetic === false;
    const receiptBound = Boolean(boundReceipt);
    return [platform, {
      status: asNonEmptyString(row.status, "missing_current_receipt"),
      proof_ref: candidateReference?.proof_ref ?? readback?.proof_ref ?? null,
      candidate_reference_present: Boolean(boundCandidate),
      visitor_visible_release_mapping: readback?.release_mapping_observed === true,
      owner_readback_required: !receiptBound,
      receipt: receiptBound ? strictReceipt : null,
      countable: receiptBound,
    }];
  }));
}

/**
 * Visitor-visible, read-only product/evidence contract. It intentionally
 * exposes the boundaries between account preflight, simulation, executable
 * owner-gated work, chain truth, ERP reconciliation and publication proof.
 * It never reads a wallet provider, accepts credentials, signs, broadcasts or
 * turns candidate references into receipts.
 */
export function readPublicEvidenceDocument({ releasePath = DEFAULT_RELEASE_PATH, env = process.env } = {}) {
  const release = readReleaseDocument({ releasePath, env });
  const candidate = readCandidateJson(releasePath);
  const baseMcpTools = Number.isInteger(candidate.interaction_evidence?.base_mcp_tools)
    ? candidate.interaction_evidence.base_mcp_tools
    : 0;
  const capabilityStatus = baseMcpTools > 0
    ? "help_probe_passed_primary_base_account"
    : "task_manifest_absent";
  const surfaces = platformEvidence(candidate, release);
  const countablePlatforms = PUBLIC_PLATFORM_ORDER.filter((platform) => surfaces[platform].countable);
  const simulationRecords = (() => {
    try {
      const fixture = readJsonFile(resolve(PROJECT_ROOT, "fixtures/simulated_transactions.json"));
      return Array.isArray(fixture) ? fixture.length : 0;
    } catch {
      return 0;
    }
  })();
  const chainCount = typeof candidate.transaction_receipts_or_not_yet_available === "string"
    && candidate.transaction_receipts_or_not_yet_available.includes("chain_count_zero")
    ? 0
    : null;
  return Object.freeze({
    schema_version: "base-erp-public-evidence-v1",
    generated_at_cst: release.generated_at_cst,
    public_write_authorized: false,
    external_actions: 0,
    release: Object.freeze({
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      immutable_bom_sha256: release.immutable_bom_sha256,
      git_commit: release.git_commit,
      commit_placeholder: release.commit_placeholder,
      project_name: release.project_name,
      material_outcome: release.material_outcome,
      network: release.network,
      public_identity: release.public_identity,
    }),
    account_connect_preflight: Object.freeze({
      network: "base_mainnet",
      chain_id: 8453,
      primary_base_account: release.public_identity.primary_base_account,
      mode: "read_only_preflight",
      connected: false,
      owner_confirmation: "NOT_GRANTED",
      capability_status: capabilityStatus,
      wallet_write_allowed: false,
      stop_conditions: [
        ...(baseMcpTools > 0 ? [] : ["no callable Base MCP namespace in this task"]),
        "no owner-visible review window",
        "no signature, broadcast, receipt or finality",
      ],
    }),
    execution_layers: Object.freeze({
      simulation: Object.freeze({
        available: true,
        record_count: simulationRecords,
        broadcast: false,
        countable_daily_trace: false,
        source: "fixtures/simulated_transactions.json",
      }),
      executable: Object.freeze({
        available: false,
        owner_gate: "not_observed",
        mcp_namespace: baseMcpTools > 0 ? `base_mcp_live_${baseMcpTools}_tools` : "task_manifest_absent",
        public_write_authorized: false,
        payload: null,
      }),
    }),
    settlement_workflow: Object.freeze({
      mode: "receipt_first_fail_closed",
      stages: [
        { id: "account_connect", status: "owner_gate_required", consequence: "none" },
        { id: "receipt_capture", status: chainCount === 0 ? "unproven" : "receipt_required", consequence: "none" },
        { id: "finality_reconciliation", status: "unproven", required: "l1_batch_finality" },
        { id: "erp_reconciliation", status: "unproven", authority: "authoritative_erp_readback" },
        { id: "business_close", status: "unproven", consequence: "none" },
      ],
      chain_count: chainCount,
      boundaries: {
        chain_success_implies_erp_posting: false,
        erp_write_exposed: false,
        business_close_claimed: false,
      },
    }),
    publication: Object.freeze({
      required_platforms: PUBLIC_PLATFORM_ORDER,
      strict_receipt_count: countablePlatforms.length,
      strict_receipt_platforms: countablePlatforms,
      publication_unit_count: countablePlatforms.length === PUBLIC_PLATFORM_ORDER.length ? 1 : 0,
      same_release_join: {
        release_id: release.release_id,
        release_fingerprint: release.release_fingerprint,
        bom_fingerprint: release.bom_fingerprint,
      },
      surfaces,
    }),
    safety: Object.freeze({
      lifecycle_states: ["prepared", "owner_gate_required", "broadcast", "receipt_pending", "final", "reconciled", "exception", "replay_locked"],
      retry: {
        allowed_after_terminal_resolution: true,
        requires_new_owner_authorized_candidate: true,
        unresolved_request_replay: "forbidden",
      },
      deduplication: {
        key: "release_id + platform + material_outcome + proof_ref",
        duplicate_consequence: "noop",
        conflicting_source: "fail_closed",
      },
      replay: {
        prior_failed_or_unresolved_packet: "replay_locked_until_terminal_resolution",
        historical_receipt_credit: 0,
        synthetic_receipt_credit: 0,
      },
    }),
    limitations: release.limitations,
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderHomePage(release) {
  const identity = release.public_identity ?? {};
  const limitations = release.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="base:app_id" content="6a7a0717e209a55163497d2d">
    <title>${escapeHtml(release.project_name)}</title>
    <style>body{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1.25rem;color:#172033;background:#f7f8fb}main{background:#fff;border:1px solid #dfe4ef;border-radius:16px;padding:2rem;box-shadow:0 8px 30px #17203312}h1{margin-top:0}code{word-break:break-all}a{color:#0052ff}dt{font-weight:700;margin-top:1rem}dd{margin:0}</style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(release.project_name)}</h1>
      <p>Receipt-first Base Smart Wallet and ERP settlement workbench. This page is a public read-only deployment surface for the current release candidate.</p>
      <dl>
        <dt>Release</dt><dd><code>${escapeHtml(release.release_id)}</code></dd>
        <dt>Public identity</dt><dd>${escapeHtml(identity.basename)} · <code>${escapeHtml(identity.primary_base_account)}</code></dd>
        <dt>Material outcome</dt><dd>${escapeHtml(release.material_outcome)}</dd>
        <dt>Network</dt><dd>${escapeHtml(release.network)}</dd>
        <dt>Release fingerprint</dt><dd><code>${escapeHtml(release.release_fingerprint)}</code></dd>
        <dt>BOM fingerprint</dt><dd><code>${escapeHtml(release.bom_fingerprint)}</code></dd>
        <dt>Git commit</dt><dd><code>${escapeHtml(release.git_commit)}</code></dd>
        <dt>Evidence level</dt><dd>${escapeHtml(release.evidence_level)}</dd>
      </dl>
      <h2>Limits</h2>
      <ul>${limitations}</ul>
      <h2>Visitor mode</h2>
      <p>Explore the seven document-aware settlement profiles and run a deterministic, non-broadcast simulation. It never requests a wallet, signs, sends or posts to ERP.</p>
      <p><a href="/workbench/">Open operator workbench</a> · <a href="/cases.json">Case catalog</a> · <a href="/simulate.json?profile_id=customer_invoice_receipt">Run a read-only simulation</a> · <a href="/event-admission.json">Event admission status</a> · <a href="/app.json">Standard web-app metadata</a></p>
      <p>Public writes and wallet actions are disabled. See <a href="/evidence/">Evidence Workbench</a>, <a href="/release.json">release.json</a> for the bounded public release document and <a href="/healthz">healthz</a> for runtime readiness.</p>
    </main>
  </body>
</html>`;
}

export function renderEvidencePage(evidence) {
  const surfaces = PUBLIC_PLATFORM_ORDER.map((platform) => {
    const row = evidence.publication.surfaces[platform];
    const proof = row.proof_ref ? `<a href="${escapeHtml(row.proof_ref)}">proof</a>` : "—";
    return `<tr><td>${escapeHtml(platform)}</td><td>${escapeHtml(row.status)}</td><td>${row.countable ? "strict receipt" : "candidate/blocker"}</td><td>${proof}</td></tr>`;
  }).join("");
  const stages = evidence.settlement_workflow.stages
    .map((stage) => `<li><strong>${escapeHtml(stage.id)}</strong>: ${escapeHtml(stage.status)}</li>`)
    .join("");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(evidence.release.project_name)} · Evidence</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f7f8fb}main{background:#fff;border:1px solid #dfe4ef;border-radius:16px;padding:1.5rem;box-shadow:0 8px 30px #17203312}h1{margin-top:0}code{word-break:break-all}table{width:100%;border-collapse:collapse;margin:1rem 0}th,td{text-align:left;border-bottom:1px solid #e4e8f0;padding:.55rem}a{color:#0052ff}.pill{display:inline-block;border:1px solid #ccd5e5;border-radius:999px;padding:.15rem .5rem;margin:.15rem 0}</style></head>
<body><main><h1>${escapeHtml(evidence.release.project_name)} · Evidence Workbench</h1>
<p>Visitor-visible, read-only release metadata and fail-closed settlement/publication evidence. No wallet, signer, ERP writer or public write is exposed.</p>
<p><span class="pill">${escapeHtml(evidence.release.release_id)}</span> <span class="pill">strict receipts ${evidence.publication.strict_receipt_count}/8</span> <span class="pill">publication unit ${evidence.publication.publication_unit_count}</span></p>
<h2>Release identity</h2><dl><dt>Release fingerprint</dt><dd><code>${escapeHtml(evidence.release.release_fingerprint)}</code></dd><dt>BOM fingerprint</dt><dd><code>${escapeHtml(evidence.release.bom_fingerprint)}</code></dd><dt>Commit</dt><dd><code>${escapeHtml(evidence.release.git_commit)}</code></dd><dt>Identity</dt><dd>${escapeHtml(evidence.release.public_identity.basename)} · <code>${escapeHtml(evidence.release.public_identity.primary_base_account)}</code></dd></dl>
<h2>Account/connect preflight</h2><p>Base Mainnet · chain ${evidence.account_connect_preflight.chain_id} · ${escapeHtml(evidence.account_connect_preflight.primary_base_account)} · <strong>${escapeHtml(evidence.account_connect_preflight.owner_confirmation)}</strong>. Wallet write allowed: <strong>${evidence.account_connect_preflight.wallet_write_allowed}</strong>.</p>
<h2>Settlement workflow</h2><ol>${stages}</ol>
<h2>Execution layers</h2><p>Simulation: ${evidence.execution_layers.simulation.record_count} records, broadcast=${evidence.execution_layers.simulation.broadcast}, daily-countable=${evidence.execution_layers.simulation.countable_daily_trace}. Executable: ${evidence.execution_layers.executable.available}, owner gate=${escapeHtml(evidence.execution_layers.executable.owner_gate)}.</p>
<h2>Eight-platform publication evidence</h2><table><thead><tr><th>Platform</th><th>Status</th><th>Credit</th><th>Proof</th></tr></thead><tbody>${surfaces}</tbody></table>
<h2>Safety</h2><p>Retries require terminal resolution and a new owner-authorized candidate; duplicate keys are no-op and conflicting replay is fail-closed. Prior unresolved packets remain replay-locked.</p>
<h2>Visitor product surfaces</h2><p><a href="/cases.json">Case catalog</a> · <a href="/simulate.json?profile_id=customer_invoice_receipt">Read-only simulation</a> · <a href="/event-admission.json">Event admission</a> · <a href="/app.json">App metadata</a></p>
<p><a href="/evidence.json">evidence.json</a> · <a href="/release.json">release.json</a> · <a href="/healthz">healthz</a> · <a href="/">home</a></p>
</main></body></html>`;
}

function writeResponse(response, status, body, contentType, { head = false } = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  response.writeHead(status, {
    "content-type": contentType,
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  if (!head) response.end(payload);
  else response.end();
}

function writeAsset(response, pathname, { head = false } = {}) {
  const asset = PUBLIC_ASSETS[pathname];
  if (!asset) return false;
  try {
    const payload = readFileSync(resolve(PROJECT_ROOT, asset.file));
    response.writeHead(200, {
      "content-type": asset.type,
      "content-length": payload.byteLength,
      "cache-control": "public, max-age=300",
      "x-content-type-options": "nosniff",
    });
    if (!head) response.end(payload);
    else response.end();
  } catch {
    writeResponse(response, 404, { error: "asset_not_found", path: pathname }, "application/json; charset=utf-8", { head });
  }
  return true;
}

function hasRecurringBindingQuery(parsedUrl) {
  return [...parsedUrl.searchParams.keys()].some((key) => RECURRING_BINDING_QUERY_KEYS.has(key.toLowerCase()));
}

function hasUnsupportedWorkbenchQuery(parsedUrl) {
  return [...parsedUrl.searchParams.keys()].some((key) => key !== "profile_id");
}

function readPlatformGatesProjection(release, platformGatesSourceReader = null) {
  try {
    const source = typeof platformGatesSourceReader === "function" ? platformGatesSourceReader() : null;
    const matrix = source?.matrix ?? readJsonFile(resolve(PROJECT_ROOT, CIRCLE_MATRIX_PATH));
    const matrixTargetValid = matrix?.schema_version === "base-circle-platform-isolation-matrix-v1"
      && matrix?.base_identity?.repository === "gaysonloser/base-erp-settlement-workbench"
      && matrix?.base_identity?.render_url === "https://base-erp-settlement-workbench.onrender.com";
    const matrixSha = source?.matrix_sha256 ?? sha256File(CIRCLE_MATRIX_PATH);
    if (!matrixTargetValid || matrixSha !== CIRCLE_MATRIX_SHA256) throw new Error("isolation_matrix_invalid");
    const h217Readback = source?.h217_readback ?? readJsonFile(resolve(PROJECT_ROOT, H217_READBACK_PATH));
    const moduleSha = source?.h217_module_sha256 ?? sha256File(H217_MODULE_PATH);
    const readbackSha = source?.h217_readback_sha256 ?? sha256File(H217_READBACK_PATH);
    if (moduleSha !== H217_MODULE_SHA256 || readbackSha !== H217_READBACK_SHA256) throw new Error("h217_source_invalid_or_circle_collision");
    return buildPlatformGatesProjection({
      release,
      h217_readback: h217Readback,
      h217_module_sha256: moduleSha,
      h217_readback_sha256: readbackSha,
      circle_matrix_sha256: matrixSha,
    });
  } catch {
    throw new Error("h217_source_invalid_or_circle_collision");
  }
}

function hasRequestBody(request) {
  const contentLength = request.headers["content-length"];
  if (contentLength !== undefined && Number(contentLength) > 0) return true;
  return request.headers["transfer-encoding"] !== undefined;
}

export function createAppServer({ releasePath = DEFAULT_RELEASE_PATH, env = process.env, runtimeReader = null, platformGatesSourceReader = null } = {}) {
  return createServer((request, response) => {
    const head = request.method === "HEAD";
    if (request.method !== "GET" && !head) {
      writeResponse(response, 405, { error: "method_not_allowed", allowed: ["GET", "HEAD"] }, "application/json; charset=utf-8");
      return;
    }
    let parsedUrl;
    try {
      parsedUrl = new URL(request.url ?? "/", "http://localhost");
    } catch {
      writeResponse(response, 400, { error: "invalid_request_url" }, "application/json; charset=utf-8", { head });
      return;
    }
    const pathname = parsedUrl.pathname;
    if (pathname === "/favicon.ico") {
      response.writeHead(204, { "cache-control": "public, max-age=300" });
      response.end();
      return;
    }
    if (writeAsset(response, pathname, { head })) return;
    let release;
    try {
      release = readReleaseDocument({ releasePath, env });
    } catch (error) {
      writeResponse(response, 503, { error: "release_unavailable", reason: error instanceof Error ? error.message : "release unavailable" }, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/healthz") {
      const health = readHealth({ release, runtimeReader });
      writeResponse(response, health.ready ? 200 : 503, health, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/release.json") {
      if (!currentV8ReleaseReady(release)) {
        writeResponse(response, 503, CURRENT_V8_UNAVAILABLE, "application/json; charset=utf-8", { head });
        return;
      }
      writeResponse(response, 200, release, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/evidence.json") {
      writeResponse(response, 200, readPublicEvidenceDocument({ releasePath, env }), "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/cases.json") {
      writeResponse(response, 200, buildVisitorCaseCatalog({ release }), "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/recurring-settlement.json") {
      if (parsedUrl.searchParams.size > 0) {
        writeResponse(response, 400, { error: "client_binding_not_accepted" }, "application/json; charset=utf-8", { head });
        return;
      }
      writeResponse(response, 200, buildRecurringSettlementProjection({ release }), "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/platform-gates.json") {
      if (parsedUrl.searchParams.size > 0 || hasRequestBody(request)) {
        writeResponse(response, 400, { error: "client_binding_not_accepted" }, "application/json; charset=utf-8", { head });
        return;
      }
      if (!currentV8ReleaseReady(release)) {
        writeResponse(response, 503, CURRENT_V8_UNAVAILABLE, "application/json; charset=utf-8", { head });
        return;
      }
      try {
        writeResponse(response, 200, readPlatformGatesProjection(release, platformGatesSourceReader), "application/json; charset=utf-8", { head });
      } catch {
        writeResponse(response, 503, { error: "platform_gates_unavailable", reason: "h217_source_invalid_or_circle_collision" }, "application/json; charset=utf-8", { head });
      }
      return;
    }
    if (pathname === "/workbench.json") {
      if (hasUnsupportedWorkbenchQuery(parsedUrl)) {
        writeResponse(response, 400, { error: "workbench_input_invalid", reason: "client_binding_not_accepted" }, "application/json; charset=utf-8", { head });
        return;
      }
      if (!currentV8ReleaseReady(release)) {
        writeResponse(response, 503, CURRENT_V8_UNAVAILABLE, "application/json; charset=utf-8", { head });
        return;
      }
      try {
        const platform_gates = readPlatformGatesProjection(release, platformGatesSourceReader);
        writeResponse(response, 200, buildOperatorWorkbench({ release, selected_profile_id: parsedUrl.searchParams.get("profile_id") ?? undefined, platform_gates }), "application/json; charset=utf-8", { head });
      } catch (error) {
        if (error instanceof Error && error.message === "h217_source_invalid_or_circle_collision") {
          writeResponse(response, 503, { error: "platform_gates_unavailable", reason: "h217_source_invalid_or_circle_collision" }, "application/json; charset=utf-8", { head });
        } else {
          writeResponse(response, 400, { error: "workbench_input_invalid", reason: error instanceof Error ? error.message : "invalid workbench input" }, "application/json; charset=utf-8", { head });
        }
      }
      return;
    }
    if (pathname === "/refund-preview.json") {
      const originalDirection = parsedUrl.searchParams.get("original_direction") ?? "outbound";
      const refundedToDate = parsedUrl.searchParams.get("refunded_to_date") ?? "120.00";
      const result = evaluateRefundProposal({
        original: {
          case_id: parsedUrl.searchParams.get("original_case_id") ?? "BASE-ORIGINAL-DEMO-001",
          candidate_count: Number(parsedUrl.searchParams.get("candidate_count") ?? "1"),
          principal: parsedUrl.searchParams.get("principal") ?? "1000.00",
          party: parsedUrl.searchParams.get("party") ?? "demo-counterparty",
          direction: originalDirection,
          source_document: parsedUrl.searchParams.get("source_document") ?? "PINV-DEMO-001",
          refund_history: [{ refund_id: "REFUND-HISTORY-DEMO-001", amount: refundedToDate }],
          refunded_to_date: refundedToDate,
        },
        proposed: {
          party: parsedUrl.searchParams.get("proposed_party") ?? parsedUrl.searchParams.get("party") ?? "demo-counterparty",
          direction: parsedUrl.searchParams.get("proposed_direction") ?? (originalDirection === "outbound" ? "inbound" : "outbound"),
          amount: parsedUrl.searchParams.get("amount") ?? "80.00",
          original_source_document: parsedUrl.searchParams.get("proposed_source_document") ?? parsedUrl.searchParams.get("source_document") ?? "PINV-DEMO-001",
        },
      });
      writeResponse(response, 200, result, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/simulate.json") {
      try {
        const simulation = buildReadOnlySimulation({
          release,
          profile_id: parsedUrl.searchParams.get("profile_id") ?? "",
          amount: parsedUrl.searchParams.get("amount") ?? "100.00",
          currency: parsedUrl.searchParams.get("currency") ?? "USDC",
          network: parsedUrl.searchParams.get("network") ?? undefined,
          business_reference: parsedUrl.searchParams.get("business_reference") ?? "visitor-demo-001",
        });
        writeResponse(response, 200, simulation, "application/json; charset=utf-8", { head });
      } catch (error) {
        writeResponse(response, 400, { error: "simulation_input_invalid", reason: error instanceof Error ? error.message : "invalid simulation input" }, "application/json; charset=utf-8", { head });
      }
      return;
    }
    if (pathname === "/event-admission.json") {
      try {
        writeResponse(response, 200, buildEventAdmissionPreview({ release, case_id: parsedUrl.searchParams.get("case_id") ?? undefined }), "application/json; charset=utf-8", { head });
      } catch (error) {
        writeResponse(response, 400, { error: "event_admission_input_invalid", reason: error instanceof Error ? error.message : "invalid event admission input" }, "application/json; charset=utf-8", { head });
      }
      return;
    }
    if (pathname === "/app.json" || pathname === "/.well-known/base-app.json") {
      try {
        writeResponse(response, 200, buildStandardWebAppMetadata({
          release,
          primary_url: env?.PUBLIC_BASE_URL ?? env?.BASE_APP_PRIMARY_URL ?? "https://base-erp-settlement-workbench.onrender.com/",
        }), "application/json; charset=utf-8", { head });
      } catch (error) {
        writeResponse(response, 503, { error: "app_metadata_unavailable", reason: error instanceof Error ? error.message : "app metadata unavailable" }, "application/json; charset=utf-8", { head });
      }
      return;
    }
    if (pathname === "/evidence" || pathname === "/evidence/") {
      writeResponse(response, 200, renderEvidencePage(readPublicEvidenceDocument({ releasePath, env })), "text/html; charset=utf-8", { head });
      return;
    }
    if (pathname === "/workbench" || pathname === "/workbench/") {
      if (hasUnsupportedWorkbenchQuery(parsedUrl)) {
        writeResponse(response, 400, { error: "workbench_input_invalid", reason: "client_binding_not_accepted" }, "application/json; charset=utf-8", { head });
        return;
      }
      if (!currentV8ReleaseReady(release)) {
        writeResponse(response, 503, CURRENT_V8_UNAVAILABLE, "application/json; charset=utf-8", { head });
        return;
      }
      try {
        const platform_gates = readPlatformGatesProjection(release, platformGatesSourceReader);
        writeResponse(response, 200, renderOperatorWorkbenchPage(buildOperatorWorkbench({ release, selected_profile_id: parsedUrl.searchParams.get("profile_id") ?? undefined, platform_gates })), "text/html; charset=utf-8", { head });
      } catch (error) {
        if (error instanceof Error && error.message === "h217_source_invalid_or_circle_collision") {
          writeResponse(response, 503, { error: "platform_gates_unavailable", reason: "h217_source_invalid_or_circle_collision" }, "application/json; charset=utf-8", { head });
        } else {
          writeResponse(response, 400, { error: "workbench_input_invalid", reason: error instanceof Error ? error.message : "invalid workbench input" }, "application/json; charset=utf-8", { head });
        }
      }
      return;
    }
    if (pathname === "/") {
      writeResponse(response, 200, renderHomePage(release), "text/html; charset=utf-8", { head });
      return;
    }
    writeResponse(response, 404, { error: "not_found", path: pathname }, "application/json; charset=utf-8", { head });
  });
}

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new RangeError("PORT must be an integer between 0 and 65535");
  return port;
}

export function listenServer({ host = process.env.HOST || "0.0.0.0", port = parsePort(process.env.PORT || "3000"), releasePath = DEFAULT_RELEASE_PATH, env = process.env, runtimeReader = null, platformGatesSourceReader = null } = {}) {
  const server = createAppServer({ releasePath, env, runtimeReader, platformGatesSourceReader });
  return new Promise((resolvePromise, rejectPromise) => {
    const onError = (error) => {
      server.removeListener("listening", onListening);
      rejectPromise(error);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      resolvePromise({ server, address: server.address() });
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(parsePort(port), host);
  });
}

async function main() {
  const { server, address } = await listenServer();
  const printableAddress = typeof address === "object" && address !== null ? `http://${address.address}:${address.port}` : String(address);
  process.stdout.write(`Base ERP Settlement Workbench listening at ${printableAddress}\n`);
  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    server.close(() => process.exit(0));
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
