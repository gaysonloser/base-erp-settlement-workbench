import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { digest as h220Digest } from "../../src/base-release-evidence-integrity-seal.mjs";
import { V9_SOURCE_CATALOG_FINGERPRINT, computeV9ReleaseFingerprint } from "../../src/server.mjs";

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const PROJECT_PREFIX = "projects/2026-08_Base_ERP_Settlement_Workbench/";
const README_SHA256 = "c259da3c0eae7395cb7321c5a55eb265cf41637c5bf40aa70042e0abf6efd7de";

const BASE_TARGET = Object.freeze({
  github_repo: "gaysonloser/base-erp-settlement-workbench",
  render_service_id: "srv-d9t0bsafngtc7387gqo0",
  render_domain: "base-erp-settlement-workbench.onrender.com",
  dashboard_app_id: "6a7a0717e209a55163497d2d",
  canonical_primary_url: "https://base-erp-settlement-workbench.onrender.com",
});

// This is a disposable, read-only projection of the frozen v9 allowlist. It
// deliberately contains no runtime candidate/readback path and is regenerated
// from the checked-out public bytes for each test process.
const V9_BOM_PATHS = Object.freeze([
  "projects/2026-08_Base_ERP_Settlement_Workbench/README.md",
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
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-release-evidence-integrity-seal.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-wallet-erp-action-plan.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/operator-workbench-page.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/src/server.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-native-platform-execution-gates.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-release-evidence-integrity-seal.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-wallet-erp-action-plan.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/operator-workbench-browser.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/operator-workbench-page.test.mjs",
  "projects/2026-08_Base_ERP_Settlement_Workbench/test/server.test.mjs",
].sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"))));

const V9_SOURCE_FILES = Object.freeze([
  "README.md",
  "src/base-release-evidence-integrity-seal.mjs",
  "test/base-release-evidence-integrity-seal.test.mjs",
]);

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readProjectBytes(path) {
  const relative = path.startsWith(PROJECT_PREFIX) ? path.slice(PROJECT_PREFIX.length) : path;
  return readFileSync(resolve(PROJECT_ROOT, relative));
}

function digestProjectFile(path) {
  return sha256Bytes(readProjectBytes(path));
}

function assertStableSourceCatalog(sourceDigestCatalog) {
  const expected = Object.fromEntries(V9_SOURCE_FILES.map((path) => [path, digestProjectFile(`${PROJECT_PREFIX}${path}`)]));
  if (expected["README.md"] !== README_SHA256) throw new Error("README fixture hash drift");
  if (h220Digest(expected) !== V9_SOURCE_CATALOG_FINGERPRINT) throw new Error("v9 source catalog drift");
  if (sourceDigestCatalog && JSON.stringify(sourceDigestCatalog) !== JSON.stringify(expected)) throw new Error("v9 source catalog fixture mismatch");
  return expected;
}

export const SYNTHETIC_README_SHA256 = README_SHA256;
export const SYNTHETIC_FIXTURE_WRITE_SET = Object.freeze(["test/fixtures/release-fixtures.mjs"]);
export const SYNTHETIC_V9_COMMIT = "a".repeat(40);
export const SYNTHETIC_V11_COMMIT = "PENDING_OWNER_PUBLIC_COMMIT";
export const SYNTHETIC_V9_BOM_PATHS = V9_BOM_PATHS;

export function buildSyntheticV9Candidate({ commit = SYNTHETIC_V9_COMMIT } = {}) {
  const immutable_release_bom = V9_BOM_PATHS.map((path) => ({ path, digest: digestProjectFile(path) }));
  const source_digest_catalog = assertStableSourceCatalog();
  const bom_fingerprint = h220Digest(immutable_release_bom);
  const release_fingerprint_basis = {
    schema_version: "base-erp-v9-release-identity-v1",
    release_id: "base-erp-public-product-20260816-v9",
    bom_fingerprint,
    base_target: BASE_TARGET,
    commit_sha: commit,
    source_catalog_fingerprint: h220Digest(source_digest_catalog),
  };
  const candidate = {
    schema_version: "base-erp-v9-release-candidate-v1",
    candidate_id: "base-erp-v9-synthetic-test-fixture",
    release_id: release_fingerprint_basis.release_id,
    release_fingerprint_algorithm: "sha256(base-erp-v9-canonical-release-identity-v1)",
    release_fingerprint: computeV9ReleaseFingerprint(release_fingerprint_basis),
    release_fingerprint_basis,
    bom_fingerprint,
    immutable_bom_sha256: bom_fingerprint,
    bom_file_count: immutable_release_bom.length,
    immutable_release_bom,
    source_catalog_fingerprint: h220Digest(source_digest_catalog),
    source_digest_catalog,
    commit_sha: commit,
    commit_placeholder: commit === SYNTHETIC_V11_COMMIT,
    commit_gate: commit === SYNTHETIC_V11_COMMIT
      ? { state: "placeholder", required: "test-only synthetic commit binding", placeholder: SYNTHETIC_V11_COMMIT, failure_code: "V9-F99" }
      : { state: "bound_owner_public_commit_for_test", required: "test-only synthetic commit binding", placeholder: SYNTHETIC_V11_COMMIT, failure_code: null },
    project_name: "Base ERP Settlement Workbench synthetic test fixture",
    material_outcome: "Read-only deterministic release validation fixture",
    generated_at_cst: "2026-08-22T00:00:00+08:00",
    network: "Base Mainnet preflight contract only; no chain action",
    basename: "gaysonloser.base.eth",
    primary_base_account: null,
    base_target: BASE_TARGET,
    circle_isolation: { checked: true, collision: false, target_reuse: false, external_actions: 0 },
    eight_surface_evidence_map: {},
    h220: { packet_id: "base-erp-h220-release-evidence-integrity-seal-20260816", occurrence: 1, execution_authority: "none_until_02_Build_revalidates", required_route_count: 10, required_platform_count: 9, freshness_max_age_seconds: 900, generated_by: "test_fixture", existing_base_sepolia_rehearsal_only: true },
    deployment: false,
    receipt: null,
    external_actions: 0,
    public_write_authorized: false,
    credits: { mainnet_transaction_credit: 0, publication_unit_credit: 0 },
    evidence_level: "L1_synthetic_read_only_fixture",
    limitations: ["Synthetic test fixture only; no public or chain receipt is claimed."],
  };
  const { self_hash: _ignoredSelfHash, ...withoutSelfHash } = candidate;
  candidate.self_hash = h220Digest(withoutSelfHash);
  return candidate;
}

export function buildSyntheticV11Candidate() {
  const immutable_release_bom = Array.from({ length: 37 }, (_, index) => ({
    path: `synthetic/v11/${String(index + 1).padStart(2, "0")}.json`,
    digest: sha256Bytes(Buffer.from(`base-erp-v11-synthetic-fixture-${index + 1}\n`, "utf8")),
  }));
  const source_digest_catalog = { "synthetic/v11/source.json": sha256Bytes(Buffer.from("base-erp-v11-synthetic-source\n", "utf8")) };
  const candidate = {
    schema_version: "base-erp-v11-release-candidate-v1",
    candidate_id: "base-erp-v11-synthetic-test-fixture",
    release_id: "base-erp-public-product-20260822-v11",
    release_fingerprint_algorithm: "sha256(base-erp-v11-canonical-release-identity-v1)",
    release_fingerprint_basis: { schema_version: "base-erp-v11-release-identity-v1", release_id: "base-erp-public-product-20260822-v11", bom_fingerprint: h220Digest(immutable_release_bom), source_catalog_fingerprint: h220Digest(source_digest_catalog), base_target: BASE_TARGET, commit_sha: SYNTHETIC_V11_COMMIT },
    immutable_release_bom,
    bom_file_count: immutable_release_bom.length,
    bom_fingerprint: h220Digest(immutable_release_bom),
    source_digest_catalog,
    source_catalog_fingerprint: h220Digest(source_digest_catalog),
    git_commit: SYNTHETIC_V11_COMMIT,
    commit_sha: SYNTHETIC_V11_COMMIT,
    commit_placeholder: true,
    commit_gate: { state: "placeholder", required: "test-only synthetic commit binding", placeholder: SYNTHETIC_V11_COMMIT, failure_code: "V11-F99" },
    base_target: BASE_TARGET,
    circle_isolation: { checked: true, collision: false, target_reuse: false, external_actions: 0 },
    deployment: false,
    receipt: null,
    external_actions: 0,
    credits: { mainnet_transaction_credit: 0, publication_unit_credit: 0 },
    state: "candidate_local_unpublished_v11",
  };
  candidate.release_fingerprint = h220Digest(candidate.release_fingerprint_basis);
  const { self_hash: _ignoredSelfHash, ...withoutSelfHash } = candidate;
  candidate.self_hash = h220Digest(withoutSelfHash);
  return candidate;
}
