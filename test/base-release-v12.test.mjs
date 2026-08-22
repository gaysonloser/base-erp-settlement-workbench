import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  V12_COMMIT_PLACEHOLDER,
  buildV12IntegritySeal,
  canonicalV12ReleaseFingerprintBasis,
  computeV12ReleaseFingerprint,
  digestV12,
  digestV12ManifestForBom,
  digestV12ManifestSelfHash,
  resolveV12Commit,
  validateV12Manifest,
  verifyV12IntegritySeal,
} from "../src/base-release-v12.mjs";
import { createAppServer, readHealth, readReleaseDocument } from "../src/server.mjs";
import { buildReleaseBoundUnsignedCallPlan, computeBridgeReleaseFingerprint } from "../src/base-account-wallet-bridge.mjs";

const TEST_COMMIT = "a".repeat(40);
const manifest = JSON.parse(readFileSync("src/release_manifest_v12.json", "utf8"));

test("v12 tracked manifest is public-only, deterministic and self-consistent", () => {
  const validation = validateV12Manifest(manifest);
  assert.equal(validation.ok, true, JSON.stringify(validation));
  assert.equal(manifest.public_identity.primary_base_account, undefined);
  assert.equal(manifest.deployment, false);
  assert.equal(manifest.receipt, null);
  assert.equal(manifest.external_actions, 0);
  assert.equal(manifest.credits.mainnet_transaction_credit, 0);
  assert.equal(manifest.credits.publication_unit_credit, 0);
  assert.equal(manifest.immutable_release_bom.length, manifest.bom_file_count);
  assert.equal(manifest.immutable_bom_sha256, manifest.bom_fingerprint);
  assert.equal(manifest.immutable_release_bom.find((entry) => entry.path.endsWith("src/release_manifest_v12.json")).digest, digestV12ManifestForBom(manifest));
  const serialized = JSON.stringify(manifest);
  assert.doesNotMatch(serialized, /call_template|wallet_address|primary_base_account|owner_digest|auth_hmac|rpc_secret|private_key/i);
});

test("v12 commit binding accepts one full commit, rejects missing/invalid/conflicting observations", () => {
  const ready = resolveV12Commit({ commit_binding: manifest.commit_binding, env: { RENDER_GIT_COMMIT: TEST_COMMIT } });
  assert.equal(ready.value, TEST_COMMIT);
  assert.equal(ready.placeholder, false);
  const missing = resolveV12Commit({ commit_binding: manifest.commit_binding, env: {} });
  assert.equal(missing.value, V12_COMMIT_PLACEHOLDER);
  assert.equal(missing.placeholder, true);
  const invalid = resolveV12Commit({ commit_binding: manifest.commit_binding, env: { GIT_COMMIT_SHA: "f".repeat(64) } });
  assert.equal(invalid.placeholder, true);
  const conflict = resolveV12Commit({ commit_binding: manifest.commit_binding, env: { GIT_COMMIT_SHA: TEST_COMMIT, SOURCE_VERSION: "b".repeat(40) } });
  assert.equal(conflict.reason, "V12_COMMIT_CONFLICT");
  const first = computeV12ReleaseFingerprint(manifest.release_fingerprint_basis);
  const second = computeV12ReleaseFingerprint({ ...manifest.release_fingerprint_basis, observed_commit: "f".repeat(40) });
  assert.equal(first, manifest.release_fingerprint);
  assert.equal(second, first);
});

test("v12 bridge normalizes the commit-binding basis without accepting arbitrary 64-hex commits", () => {
  const binding = {
    release_id: manifest.release_id,
    release_fingerprint: manifest.release_fingerprint,
    bom_fingerprint: manifest.bom_fingerprint,
    commit_sha: TEST_COMMIT,
    commit_binding: manifest.commit_binding,
    source_catalog_fingerprint: manifest.source_catalog_fingerprint,
    base_target: manifest.base_target,
  };
  assert.equal(computeBridgeReleaseFingerprint(binding), manifest.release_fingerprint);
  assert.doesNotThrow(() => buildReleaseBoundUnsignedCallPlan({
    release: binding,
    call_template: { to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x" },
  }));
  assert.throws(() => buildReleaseBoundUnsignedCallPlan({
    release: { ...binding, commit_sha: "f".repeat(64) },
    call_template: { to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x" },
  }), /BRIDGE_COMMIT_INVALID/);
});

test("v12 default release path is tracked and public routes are ready only with a full runtime commit", async () => {
  const unbound = readReleaseDocument({ env: {} });
  assert.equal(unbound.schema_version, "base-erp-v12-public-release-v1");
  assert.equal(unbound.release_id, manifest.release_id);
  assert.equal(unbound.commit_placeholder, true);
  assert.equal(unbound.v12_release_ready, false);
  assert.equal(readHealth({ release: unbound }).ready, false);

  const server = createAppServer({ env: { GIT_COMMIT_SHA: TEST_COMMIT } });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  try {
    const base = `http://127.0.0.1:${address.port}`;
    for (const path of ["/healthz", "/release.json", "/integrity-seal.json", "/workbench", "/workbench/", "/wallet-action-plan.json", "/wallet-action-bridge.json"]) {
      const response = await fetch(`${base}${path}`);
      assert.equal(response.status, path === "/healthz" || path === "/release.json" || path === "/integrity-seal.json" || path.startsWith("/workbench") || path.startsWith("/wallet-action") ? 200 : response.status, path);
    }
    const release = await fetch(`${base}/release.json`).then((response) => response.json());
    assert.equal(release.release_id, manifest.release_id);
    assert.equal(release.git_commit, TEST_COMMIT);
    assert.equal(release.public_identity.primary_base_account, null);
    const seal = await fetch(`${base}/integrity-seal.json`).then((response) => response.json());
    assert.equal(seal.ok, true);
    assert.equal(seal.credit, 0);
    assert.equal(seal.external_actions, 0);
    assert.equal(verifyV12IntegritySeal(seal, { expectedRelease: readReleaseDocument({ env: { GIT_COMMIT_SHA: TEST_COMMIT } }) }).ok, true);
    const bridge = await fetch(`${base}/wallet-action-bridge.json`).then((response) => response.json());
    assert.equal(bridge.reason, "owner_auth_required");
    assert.equal(Object.prototype.hasOwnProperty.call(bridge, "call_template"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(bridge, "to"), false);
    const bundle = await fetch(`${base}/assets/base-auth-sdk-v12.bundle.js`).then((response) => response.text());
    assert.match(bundle, /BaseAuthControllerFactory/);
    assert.match(bundle, /telemetry:!1|telemetry:false/);
    assert.doesNotMatch(bundle, /AxiosError|formDataToJSON|\baxios\b/i);
    const nonce = await fetch(`${base}/auth/nonce`);
    assert.equal(nonce.status, 503);
    assert.deepEqual(await nonce.json(), { error: "auth_disabled" });
    const owner = await fetch(`${base}/owner/wallet-action-bridge.json`);
    assert.equal(owner.status, 503);
    assert.deepEqual(await owner.json(), { error: "auth_disabled" });
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("v12 manifest safety rejects wallet/account and owner secret fields", () => {
  for (const field of ["primary_base_account", "wallet_address", "call_template", "owner_digest", "rpc_secret", "api_key", "password", "token", "cookie", "mnemonic", "seed", "authorization", "call_data", "privateKey"]) {
    const mutated = structuredClone(manifest);
    mutated[field] = null;
    assert.equal(validateV12Manifest(mutated).ok, false, field);
  }
  const hiddenAddress = structuredClone(manifest);
  hiddenAddress.public_identity = { basename: "gaysonloser.base.eth", metadata: "0x1111111111111111111111111111111111111111" };
  assert.equal(validateV12Manifest(hiddenAddress).ok, false, "hidden wallet address");
});

test("v12 integrity seal is schema-strict, release-anchored and zero-credit", () => {
  const release = readReleaseDocument({ env: { GIT_COMMIT_SHA: TEST_COMMIT } });
  const seal = buildV12IntegritySeal({ release, observedAt: "2026-08-22T12:00:00.000Z" });
  assert.equal(verifyV12IntegritySeal(seal, { expectedRelease: release }).ok, true);
  assert.equal(verifyV12IntegritySeal(seal).ok, false, "unanchored seal must fail closed");

  const forge = (mutate) => {
    const forged = structuredClone(seal);
    mutate(forged);
    const { seal_digest: _ignored, ...payload } = forged;
    forged.seal_digest = digestV12(payload);
    return forged;
  };
  assert.equal(verifyV12IntegritySeal(forge((value) => { value.release_identity.release_id = "base-erp-public-product-20990101-v12"; }), { expectedRelease: release }).ok, false);
  assert.equal(verifyV12IntegritySeal(forge((value) => { value.native_receipt = { fabricated: true }; }), { expectedRelease: release }).ok, false);
  assert.equal(verifyV12IntegritySeal(forge((value) => { value.execution_authority = "forged"; }), { expectedRelease: release }).ok, false);
  assert.equal(verifyV12IntegritySeal(forge((value) => { delete value.public_routes.workbench; }), { expectedRelease: release }).ok, false);
  assert.equal(verifyV12IntegritySeal(forge((value) => { value.auth = { enabled: false, ready: true, owner_routes_fail_closed: false }; }), { expectedRelease: release }).ok, false);
});

test("v12 source/catalog/fingerprint and BASE/CIRCLE drift remain fail-closed", () => {
  const directory = mkdtempSync(join(tmpdir(), "base-erp-v12-drift-"));
  const path = join(directory, "manifest.json");
  try {
    const mutatedCatalog = structuredClone(manifest);
    mutatedCatalog.source_catalog_fingerprint = "0".repeat(64);
    mutatedCatalog.release_fingerprint_basis = canonicalV12ReleaseFingerprintBasis(mutatedCatalog);
    mutatedCatalog.release_fingerprint = computeV12ReleaseFingerprint(mutatedCatalog.release_fingerprint_basis);
    mutatedCatalog.manifest_self_hash = digestV12ManifestSelfHash(mutatedCatalog);
    writeFileSync(path, JSON.stringify(mutatedCatalog));
    const catalogRelease = readReleaseDocument({ releasePath: path, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
    assert.equal(catalogRelease.v12_release_ready, false);
    assert.equal(catalogRelease.v12_candidate_gate.reason, "v12_source_catalog_fingerprint_mismatch");

    const mutatedTarget = structuredClone(manifest);
    mutatedTarget.base_target.github_repo = "gaysonloser/arc-payment-receipt";
    mutatedTarget.release_fingerprint_basis = canonicalV12ReleaseFingerprintBasis(mutatedTarget);
    mutatedTarget.release_fingerprint = computeV12ReleaseFingerprint(mutatedTarget.release_fingerprint_basis);
    mutatedTarget.manifest_self_hash = digestV12ManifestSelfHash(mutatedTarget);
    writeFileSync(path, JSON.stringify(mutatedTarget));
    const targetRelease = readReleaseDocument({ releasePath: path, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
    assert.equal(targetRelease.v12_release_ready, false);
    assert.equal(targetRelease.v12_candidate_gate.reason, "v12_bom_file_drift");

    const mutatedFingerprint = structuredClone(manifest);
    mutatedFingerprint.release_fingerprint = "f".repeat(64);
    mutatedFingerprint.manifest_self_hash = digestV12ManifestSelfHash(mutatedFingerprint);
    writeFileSync(path, JSON.stringify(mutatedFingerprint));
    const fingerprintRelease = readReleaseDocument({ releasePath: path, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
    assert.equal(fingerprintRelease.v12_release_ready, false);
    assert.equal(fingerprintRelease.v12_candidate_gate.reason, "V12_MANIFEST_FINGERPRINT_INVALID");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
