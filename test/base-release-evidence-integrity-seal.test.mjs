import assert from "node:assert/strict";
import test from "node:test";

import {
  BASE_SEPOLIA_CHAIN_ID,
  FINALITY_STAGES,
  REQUIRED_PLATFORM_IDS,
  REQUIRED_ROUTE_PATHS,
  digest,
  evaluateReleaseEvidenceSeal,
  verifyReleaseEvidenceSeal,
} from "../src/base-release-evidence-integrity-seal.mjs";

const evaluationTime = "2026-08-16T18:10:00.000Z";
const observedAt = "2026-08-16T18:05:00.000Z";
const sourceDigests = {
  "README.md": "e".repeat(64),
  "src/server.mjs": "f".repeat(64),
};
const release = {
  release_id: "base-erp-public-product-20260816-v9",
  release_fingerprint: "a".repeat(64),
  bom_fingerprint: "b".repeat(64),
  commit_sha: "c".repeat(40),
  source_catalog_fingerprint: digest(sourceDigests),
};

function route(path, index) {
  return {
    path,
    method: "GET",
    http_status: 200,
    claim_state: "current",
    response_sha256: digest({ path, release }),
    release_identity: release,
    observed_at: observedAt,
    generated_by: ["code_test_contract", `src/server.mjs`, `test/v9-${index}.test.mjs`],
  };
}

function fixture(overrides = {}) {
  const routeReadbacks = REQUIRED_ROUTE_PATHS.map((path, index) => route(path, index));
  const claimBindings = routeReadbacks.map((item, index) => ({
    claim_id: `claim-${index + 1}`,
    source_path: index % 2 ? "README.md" : "src/server.mjs",
    source_sha256: index % 2 ? "e".repeat(64) : "f".repeat(64),
    route_path: item.path,
    route_response_sha256: item.response_sha256,
    release_identity: release,
    observed_at: observedAt,
    generated_by: "code_test_contract",
  }));
  const platformEvidence = REQUIRED_PLATFORM_IDS.map((platform) => ({
    platform,
    evidence_class: platform === "base_app" ? "attribution_metadata" : platform === "base_sepolia_rehearsal" ? "chain_receipt" : "native_platform_receipt",
    state: "owner_gate_pending",
    current: false,
    historical: false,
    synthetic: false,
    release_identity: release,
    observed_at: observedAt,
    is_receipt: false,
    receipt_ref: null,
    attribution_observed: platform === "base_app",
  }));
  return {
    release_identity: release,
    source_digests: sourceDigests,
    evaluation_time: evaluationTime,
    max_age_seconds: 900,
    route_readbacks: routeReadbacks,
    claim_bindings: claimBindings,
    platform_evidence: platformEvidence,
    runtime_binding: {
      runtime_sha256: "d".repeat(64),
      run_id: "02_Build-20260816-181000",
      cursor: { active_item_id: "" },
      writer_idle: true,
      observed_at: observedAt,
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      commit_sha: release.commit_sha,
      source_catalog_fingerprint: release.source_catalog_fingerprint,
    },
    ...overrides,
  };
}

test("v9 candidate seals code/test-generated routes and keeps all credit zero", () => {
  const result = evaluateReleaseEvidenceSeal(fixture());
  assert.equal(result.ok, true);
  assert.equal(result.state, "integrity_seal_candidate_ready");
  assert.equal(result.credit, 0);
  assert.equal(result.publication_unit_credit, 0);
  assert.equal(result.mainnet_30_credit, 0);
  assert.equal(result.build_credit_eligible, false);
  assert.equal(verifyReleaseEvidenceSeal(result).ok, true);
});

test("v9 seal digest is deterministic", () => {
  const first = evaluateReleaseEvidenceSeal(fixture());
  const second = evaluateReleaseEvidenceSeal(fixture());
  assert.equal(first.seal_digest, second.seal_digest);
});

test("stale route evidence fails closed", () => {
  const result = evaluateReleaseEvidenceSeal(fixture({
    route_readbacks: REQUIRED_ROUTE_PATHS.map((path, index) => route(path, index)).map((item) => ({
      ...item,
      observed_at: "2026-08-16T17:00:00.000Z",
    })),
  }));
  assert.equal(result.reason, "evidence_stale");
  assert.equal(result.failure_codes[0], "V9-F05");
});

test("README or route bytes bound to a different response digest fail closed", () => {
  const input = fixture();
  input.claim_bindings[0].route_response_sha256 = "e".repeat(64);
  const result = evaluateReleaseEvidenceSeal(input);
  assert.equal(result.reason, "claim_route_digest_mismatch");
});

test("Base App attribution is not a receipt and new Sepolia rehearsal is forbidden", () => {
  const input = fixture();
  const baseApp = input.platform_evidence.find((row) => row.platform === "base_app");
  baseApp.is_receipt = true;
  baseApp.evidence_class = "attribution_metadata";
  baseApp.receipt_ref = "builder-code:bc_public";
  assert.equal(evaluateReleaseEvidenceSeal(input).reason, "attribution_claimed_as_receipt");

  const sepoliaInput = fixture();
  const sepolia = sepoliaInput.platform_evidence.find((row) => row.platform === "base_sepolia_rehearsal");
  sepolia.evidence_class = "chain_receipt";
  sepolia.state = "observed";
  sepolia.is_receipt = true;
  sepolia.receipt_ref = "tx:existing-rehearsal";
  sepolia.new_rehearsal = true;
  sepolia.chain_id = BASE_SEPOLIA_CHAIN_ID;
  sepolia.receipt_status = "0x1";
  sepolia.finality_stage = FINALITY_STAGES[3];
  sepolia.transaction_hash = `0x${"1".repeat(64)}`;
  assert.equal(evaluateReleaseEvidenceSeal(sepoliaInput).reason, "new_rehearsal_forbidden");
});

test("runtime drift and CIRCLE collision fail closed", () => {
  const drift = fixture();
  drift.runtime_binding.writer_idle = false;
  assert.equal(evaluateReleaseEvidenceSeal(drift).reason, "runtime_writer_not_idle");
  const collision = fixture();
  collision.platform_evidence[0].target = "gaysonloser/arc-payment-receipt";
  assert.equal(evaluateReleaseEvidenceSeal(collision).reason, "circle_target_collision");
});

test("missing route cannot become a candidate", () => {
  const input = fixture();
  input.route_readbacks = input.route_readbacks.slice(1);
  assert.equal(evaluateReleaseEvidenceSeal(input).reason, "route_set_incomplete");
});

test("non-current route and untrusted producer fail closed", () => {
  const notCurrent = fixture();
  notCurrent.route_readbacks[0].http_status = 503;
  assert.equal(evaluateReleaseEvidenceSeal(notCurrent).reason, "route_not_current");

  const untrusted = fixture();
  untrusted.route_readbacks[0].generated_by = ["prose"];
  assert.equal(evaluateReleaseEvidenceSeal(untrusted).reason, "route_not_code_generated");
});

test("commit and source-byte bindings cannot drift", () => {
  const commitDrift = fixture();
  commitDrift.route_readbacks[0].release_identity = { ...release, commit_sha: "d".repeat(40) };
  assert.equal(evaluateReleaseEvidenceSeal(commitDrift).reason, "route_release_binding_mismatch");

  const sourceDrift = fixture();
  sourceDrift.claim_bindings[0].source_sha256 = "a".repeat(64);
  assert.equal(evaluateReleaseEvidenceSeal(sourceDrift).reason, "claim_source_digest_mismatch");

  const catalogDrift = fixture();
  catalogDrift.source_digests = { ...sourceDigests, "README.md": "a".repeat(64) };
  catalogDrift.claim_bindings = catalogDrift.claim_bindings.map((claim) => claim.source_path === "README.md"
    ? { ...claim, source_sha256: "a".repeat(64) }
    : claim);
  assert.equal(evaluateReleaseEvidenceSeal(catalogDrift).reason, "source_catalog_fingerprint_mismatch");
});

test("claim coverage and platform freshness flags are deterministic", () => {
  const missingClaim = fixture();
  missingClaim.claim_bindings = missingClaim.claim_bindings.slice(1);
  assert.equal(evaluateReleaseEvidenceSeal(missingClaim).reason, "claim_set_incomplete");

  const synthetic = fixture();
  synthetic.platform_evidence[0].synthetic = true;
  assert.equal(evaluateReleaseEvidenceSeal(synthetic).reason, "platform_historical_or_synthetic");
});

test("Base App attribution and new rehearsal cannot be relabeled", () => {
  const app = fixture();
  const baseApp = app.platform_evidence.find((row) => row.platform === "base_app");
  baseApp.evidence_class = "native_platform_receipt";
  baseApp.is_receipt = true;
  baseApp.current = true;
  baseApp.state = "current";
  assert.equal(evaluateReleaseEvidenceSeal(app).reason, "base_app_attribution_class_invalid");

  const rehearsal = fixture();
  const sepolia = rehearsal.platform_evidence.find((row) => row.platform === "base_sepolia_rehearsal");
  sepolia.new_rehearsal = true;
  assert.equal(evaluateReleaseEvidenceSeal(rehearsal).reason, "new_rehearsal_forbidden");
});

test("seal verification covers zero-credit and execution-authority output", () => {
  const seal = evaluateReleaseEvidenceSeal(fixture());
  const tampered = { ...seal, credit: 99 };
  assert.equal(verifyReleaseEvidenceSeal(tampered).reason, "integrity_seal_security_boundary_mismatch");

  const tamperedAuthority = { ...seal, execution_authority: "full" };
  assert.equal(verifyReleaseEvidenceSeal(tamperedAuthority).reason, "integrity_seal_security_boundary_mismatch");
});
