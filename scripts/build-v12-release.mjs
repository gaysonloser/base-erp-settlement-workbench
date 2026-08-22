import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
  V12_BOM_SCHEMA_VERSION,
  V12_COMMIT_PLACEHOLDER,
  V12_CANDIDATE_SCHEMA_VERSION,
  V12_MANIFEST_SCHEMA_VERSION,
  V12_RELEASE_FINGERPRINT_ALGORITHM,
  V12_RELEASE_ID_PATTERN,
  canonicalV12ReleaseFingerprintBasis,
  computeV12ReleaseFingerprint,
  digestV12,
  digestV12ManifestForBom,
  digestV12ManifestSelfHash,
} from "../src/base-release-v12.mjs";

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_PATH = resolve(PROJECT_ROOT, "src/release_manifest_v12.json");
const CANDIDATE_PATH = resolve(PROJECT_ROOT, "runtime/release_candidate_v12_local_2026-08-22.json");
const RELEASE_ID = "base-erp-public-product-20260822-v12";
if (!V12_RELEASE_ID_PATTERN.test(RELEASE_ID)) throw new Error("v12 release id invalid");

const BASE_TARGET = {
  github_repo: "gaysonloser/base-erp-settlement-workbench",
  render_service_id: "srv-d9t0bsafngtc7387gqo0",
  render_domain: "base-erp-settlement-workbench.onrender.com",
  dashboard_app_id: "6a7a0717e209a55163497d2d",
  canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com",
};
const COMMIT_BINDING = {
  mode: "runtime_commit_env",
  env_names: ["GIT_COMMIT_SHA", "RENDER_GIT_COMMIT", "RENDER_GIT_COMMIT_SHA", "SOURCE_VERSION"],
  expected_commit: null,
  require_full_40_hex: true,
  require_consistent_values: true,
  placeholder: V12_COMMIT_PLACEHOLDER,
};

// This is the public v11 closure plus the v12 identity/verification additions.
// Runtime receipts, candidates, authority, shared/upstream and governance files
// are intentionally excluded.
const PUBLIC_FILES = [
  ".gitignore",
  "README.md",
  "assets/base-app/base-erp-workbench-screenshot-source.png",
  "assets/base-app/base-erp-workbench-thumbnail-source.png",
  "config/base_erp_product_contract_v1.json",
  "config/release_identity_and_exposure_contract_v1.json",
  "package-lock.json",
  "package.json",
  "public/assets/base-auth-sdk.bundle.js",
  "public/assets/base-auth-sdk-v12.bundle.js",
  "render.yaml",
  "scripts/build-auth-bundle.mjs",
  "scripts/build-auth-bundle-v12.mjs",
  "scripts/build-v12-release.mjs",
  "src/auth/auth-core.mjs",
  "src/auth/browser-auth.mjs",
  "src/auth/browser-entry.mjs",
  "src/base-account-wallet-bridge.mjs",
  "src/base-erp-workbench.mjs",
  "src/base-native-platform-evidence-contract.mjs",
  "src/base-native-platform-execution-gates.mjs",
  "src/base-neutral-receipt-controls.mjs",
  "src/base-platform-feasibility-contract.mjs",
  "src/base-recurring-settlement-contract.mjs",
  "src/base-refund-ceiling-guard.mjs",
  "src/base-release-evidence-integrity-seal.mjs",
  "src/base-release-v12.mjs",
  "src/base-wallet-erp-action-plan.mjs",
  "src/operator-workbench-page.mjs",
  "src/release_manifest_v12.json",
  "src/server.mjs",
  "test/auth-core.test.mjs",
  "test/auth-release-candidate.test.mjs",
  "test/auth-server.test.mjs",
  "test/base-account-wallet-bridge.test.mjs",
  "test/base-native-platform-execution-gates.test.mjs",
  "test/base-release-evidence-integrity-seal.test.mjs",
  "test/base-release-v12.test.mjs",
  "test/base-wallet-erp-action-plan.test.mjs",
  "test/browser-auth.test.mjs",
  "test/fixtures/release-fixtures.mjs",
  "test/operator-workbench-browser.test.mjs",
  "test/operator-workbench-page.test.mjs",
  "test/server.test.mjs",
];

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readBytes(relative) {
  return readFileSync(resolve(PROJECT_ROOT, relative));
}

function sourceDigest(relative, manifest) {
  return relative === "src/release_manifest_v12.json"
    ? digestV12ManifestForBom(manifest)
    : sha256Bytes(readBytes(relative));
}

function bomEntries(manifest) {
  return PUBLIC_FILES
    .map((relative) => ({
      path: `projects/2026-08_Base_ERP_Settlement_Workbench/${relative}`,
      digest: sourceDigest(relative, manifest),
    }))
    .sort((left, right) => Buffer.from(left.path, "utf8").compare(Buffer.from(right.path, "utf8")));
}

function sourceCatalog(manifest) {
  return Object.fromEntries([...PUBLIC_FILES].sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"))).map((relative) => [relative, sourceDigest(relative, manifest)]));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

const manifest = {
  schema_version: V12_MANIFEST_SCHEMA_VERSION,
  release_id: RELEASE_ID,
  release_fingerprint_algorithm: V12_RELEASE_FINGERPRINT_ALGORITHM,
  release_fingerprint_basis: null,
  release_fingerprint: "0".repeat(64),
  bom_schema_version: V12_BOM_SCHEMA_VERSION,
  bom_fingerprint: "0".repeat(64),
  immutable_bom_sha256: "0".repeat(64),
  bom_file_count: PUBLIC_FILES.length,
  immutable_release_bom: [],
  source_files: [...PUBLIC_FILES].sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"))),
  source_catalog_fingerprint: "0".repeat(64),
  commit_binding: COMMIT_BINDING,
  project_name: "Base ERP Settlement Workbench",
  material_outcome: "Tracked v12 public release identity with deterministic BOM/source binding and fail-closed owner action boundaries",
  generated_at_cst: "2026-08-22T00:00:00.000Z",
  network: "Base Mainnet preflight contract only; no chain action",
  base_target: BASE_TARGET,
  public_identity: { basename: "gaysonloser.base.eth" },
  evidence_level: "L1_local_release_integrity",
  deployment: false,
  receipt: null,
  external_actions: 0,
  public_write_authorized: false,
  credits: { mainnet_transaction_credit: 0, publication_unit_credit: 0 },
  execution_authority: "none_until_02_Build_revalidates",
  circle_isolation: { checked: true, collision: false, target_reuse: false, external_actions: 0 },
  limitations: [
    "No Base Mainnet receipt, ERP authoritative readback or complete eight-surface public receipt is claimed.",
    "Render must inject one consistent full 40-hex commit from the declared environment binding before readiness becomes healthy.",
    "Owner authentication and wallet action routes remain fail-closed until separately configured and owner-reviewed.",
  ],
  state: "tracked_deployment_manifest_v12",
  manifest_self_hash: "0".repeat(64),
};

manifest.immutable_release_bom = bomEntries(manifest);
manifest.bom_fingerprint = digestV12(manifest.immutable_release_bom);
manifest.immutable_bom_sha256 = manifest.bom_fingerprint;
const catalog = sourceCatalog(manifest);
manifest.source_catalog_fingerprint = digestV12(catalog);
manifest.release_fingerprint_basis = canonicalV12ReleaseFingerprintBasis({
  release_id: manifest.release_id,
  bom_fingerprint: manifest.bom_fingerprint,
  base_target: manifest.base_target,
  commit_binding: manifest.commit_binding,
  source_catalog_fingerprint: manifest.source_catalog_fingerprint,
});
manifest.release_fingerprint = computeV12ReleaseFingerprint({
  release_id: manifest.release_id,
  bom_fingerprint: manifest.bom_fingerprint,
  base_target: manifest.base_target,
  commit_binding: manifest.commit_binding,
  source_catalog_fingerprint: manifest.source_catalog_fingerprint,
});
manifest.manifest_self_hash = digestV12ManifestSelfHash(manifest);
writeJson(MANIFEST_PATH, manifest);

const candidate = {
  schema_version: V12_CANDIDATE_SCHEMA_VERSION,
  candidate_id: "base-erp-v12-local-candidate-20260822",
  release_id: manifest.release_id,
  release_fingerprint: manifest.release_fingerprint,
  release_fingerprint_algorithm: manifest.release_fingerprint_algorithm,
  release_fingerprint_basis: manifest.release_fingerprint_basis,
  bom_fingerprint: manifest.bom_fingerprint,
  immutable_bom_sha256: manifest.immutable_bom_sha256,
  bom_file_count: manifest.bom_file_count,
  immutable_release_bom: manifest.immutable_release_bom,
  source_digest_catalog: catalog,
  source_catalog_fingerprint: manifest.source_catalog_fingerprint,
  commit_binding: manifest.commit_binding,
  git_commit: V12_COMMIT_PLACEHOLDER,
  commit_sha: V12_COMMIT_PLACEHOLDER,
  commit_placeholder: true,
  commit_gate: {
    state: "placeholder_until_owner_public_commit",
    required: "one consistent full 40-hex deployment commit matching the tracked manifest bytes",
    placeholder: V12_COMMIT_PLACEHOLDER,
    failure_code: "V12-F03",
  },
  project_name: manifest.project_name,
  material_outcome: manifest.material_outcome,
  generated_at_cst: manifest.generated_at_cst,
  network: manifest.network,
  base_target: manifest.base_target,
  public_identity: manifest.public_identity,
  evidence_level: manifest.evidence_level,
  deployment: false,
  receipt: null,
  external_actions: 0,
  public_write_authorized: false,
  circle_isolation: manifest.circle_isolation,
  credits: manifest.credits,
  limitations: manifest.limitations,
  state: "candidate_local_unpublished_v12",
  self_hash: null,
};
const { self_hash: _ignoredSelfHash, ...candidateWithoutSelfHash } = candidate;
candidate.self_hash = digestV12(candidateWithoutSelfHash);
writeJson(CANDIDATE_PATH, candidate);
process.stdout.write(JSON.stringify({
  manifest_path: "src/release_manifest_v12.json",
  candidate_path: "runtime/release_candidate_v12_local_2026-08-22.json",
  release_id: manifest.release_id,
  bom_file_count: manifest.bom_file_count,
  bom_fingerprint: manifest.bom_fingerprint,
  source_catalog_fingerprint: manifest.source_catalog_fingerprint,
  release_fingerprint: manifest.release_fingerprint,
  manifest_self_hash: manifest.manifest_self_hash,
  candidate_self_hash: candidate.self_hash,
}, null, 2));
