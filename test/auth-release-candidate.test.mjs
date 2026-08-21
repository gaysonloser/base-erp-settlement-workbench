import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

import { digest } from "../src/base-release-evidence-integrity-seal.mjs";

const CANDIDATE_PATH = "runtime/release_candidate_v11_local_2026-08-22.json";
const PREFIX = "projects/2026-08_Base_ERP_Settlement_Workbench/";

function sha(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

test("v11 candidate is a distinct unpublished, self-hashed, complete 37-file local packet", () => {
  const candidate = JSON.parse(readFileSync(CANDIDATE_PATH, "utf8"));
  assert.equal(candidate.schema_version, "base-erp-v11-release-candidate-v1");
  assert.equal(candidate.state, "candidate_local_unpublished_v11");
  assert.equal(candidate.release_id, "base-erp-public-product-20260822-v11");
  const isPlaceholder = candidate.git_commit === "PENDING_OWNER_PUBLIC_COMMIT";
  assert.equal(candidate.commit_placeholder, isPlaceholder);
  if (isPlaceholder) {
    assert.equal(candidate.commit_sha, "PENDING_OWNER_PUBLIC_COMMIT");
    assert.equal(candidate.commit_gate.state, "placeholder");
  } else {
    assert.match(candidate.git_commit, /^[0-9a-f]{40}$/);
    assert.equal(candidate.commit_sha, candidate.git_commit);
    assert.equal(candidate.commit_gate.state, "bound_local_public_commit");
    assert.equal(candidate.commit_gate.failure_code, null);
    assert.equal(candidate.eight_surface_evidence_map.github.status, "current_native_receipt");
    assert.equal(candidate.eight_surface_evidence_map.github.receipt.commit_sha, candidate.git_commit);
  }
  assert.equal(candidate.deployment, false);
  assert.equal(candidate.receipt, null);
  assert.equal(candidate.external_actions, 0);
  assert.deepEqual(candidate.credits, { mainnet_transaction_credit: 0, publication_unit_credit: 0 });
  assert.equal(candidate.immutable_release_bom.length, 37);
  assert.equal(candidate.bom_file_count, 37);
  assert.equal(candidate.immutable_release_bom.some(({ path }) => path.endsWith(CANDIDATE_PATH)), false);
  assert.equal(candidate.bom_fingerprint, digest(candidate.immutable_release_bom));
  const { self_hash, ...withoutSelfHash } = candidate;
  assert.equal(self_hash, digest(withoutSelfHash));
  for (const entry of candidate.immutable_release_bom) {
    assert.equal(sha(entry.path.slice(PREFIX.length)), entry.digest, entry.path);
  }
  for (const [path, digestValue] of Object.entries(candidate.source_digest_catalog)) {
    assert.equal(sha(path), digestValue, path);
  }
  assert.equal(candidate.source_catalog_fingerprint, digest(candidate.source_digest_catalog));
  assert.equal(candidate.release_fingerprint, digest(candidate.release_fingerprint_basis));
  assert.deepEqual(candidate.circle_isolation, { checked: true, collision: false, target_reuse: false, external_actions: 0 });
  assert.equal(/(^|[^a-z])(circle|arc)([^a-z]|$)/i.test(JSON.stringify(candidate.base_target)), false);
  const collision = { ...candidate, base_target: { ...candidate.base_target, github_repo: "gaysonloser/arc-payment-receipt" } };
  assert.equal(/(^|[^a-z])(circle|arc)([^a-z]|$)/i.test(JSON.stringify(collision.base_target)), true);
});

test("v11 dependency versions are exact and README remains immutable", () => {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
  assert.equal(packageJson.devDependencies["@base-org/account"], "2.5.10");
  assert.equal(packageJson.dependencies.viem, "2.55.19");
  assert.equal(packageJson.overrides.axios, "1.18.0");
  assert.equal(packageJson.devDependencies.esbuild, "0.28.2");
  assert.equal(lock.packages["node_modules/@base-org/account"].version, "2.5.10");
  assert.equal(lock.packages["node_modules/@base-org/account"].dev, true);
  assert.equal(lock.packages["node_modules/axios"].version, "1.18.0");
  assert.equal(lock.packages["node_modules/viem"].version, "2.55.19");
  assert.equal(lock.packages["node_modules/esbuild"].version, "0.28.2");
  assert.equal(statSync("README.md").mode & 0o222, 0);
  const bundle = readFileSync("public/assets/base-auth-sdk.bundle.js", "utf8");
  assert.doesNotMatch(bundle, /localStorage|sessionStorage|console\./);
  assert.doesNotMatch(bundle, /AxiosError|formDataToJSON|\baxios\b/i);
  assert.match(bundle, /telemetry:!1|telemetry:false/);
});
