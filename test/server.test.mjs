import test from "node:test";
import assert from "node:assert/strict";

import { createAppServer } from "../src/server.mjs";

const TEST_COMMIT = "a".repeat(40);

async function withServer(run, { env = { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT }, runtimeReader = null } = {}) {
  const server = createAppServer({ env, runtimeReader });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("HTTP health endpoint reports the writer-idle runtime binding", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.status, "ok");
    assert.equal(body.ready, true);
    assert.equal(body.runtime_status, "not_required");
    assert.equal(body.public_write_authorized, false);
    assert.match(body.release_id, /^base-erp-/);
    assert.match(body.release_fingerprint, /^[0-9a-f]{64}$/);
    assert.match(body.bom_fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(body.immutable_bom_sha256, body.bom_fingerprint);
    assert.equal(body.git_commit, TEST_COMMIT);
    assert.match(body.observed_at, /^2026|^20/);
  });
});

test("release endpoint binds the public document to the current release identity", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/release.json`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.schema_version, "base-erp-public-release-v1");
    assert.equal(body.project_name, "Base ERP Settlement Workbench");
    assert.match(body.release_fingerprint, /^[0-9a-f]{64}$/);
    assert.match(body.bom_fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(body.public_write_authorized, false);
    assert.equal(body.commit_placeholder, false);
    assert.equal(body.git_commit, TEST_COMMIT);
    assert.equal(body.public_identity.basename, "gaysonloser.base.eth");
    assert.equal(body.public_identity.primary_base_account.toLowerCase(), "0xba36d092db2999bb1fabbaf281ac956a97189c25");
    assert.ok(Array.isArray(body.immutable_release_bom));
    assert.ok(body.immutable_release_bom.some((entry) => entry.path === "src/server.mjs"));
  });
});

test("public evidence endpoint exposes the typed fail-closed product boundary", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/evidence.json`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.schema_version, "base-erp-public-evidence-v1");
    assert.equal(body.public_write_authorized, false);
    assert.equal(body.external_actions, 0);
    assert.equal(body.release.release_id, "base-erp-public-product-20260810-v1");
    assert.equal(body.account_connect_preflight.network, "base_mainnet");
    assert.equal(body.account_connect_preflight.chain_id, 8453);
    assert.equal(body.account_connect_preflight.owner_confirmation, "NOT_GRANTED");
    assert.equal(body.account_connect_preflight.wallet_write_allowed, false);
    assert.equal(body.execution_layers.simulation.broadcast, false);
    assert.equal(body.execution_layers.simulation.countable_daily_trace, false);
    assert.equal(body.execution_layers.executable.available, false);
    assert.equal(body.settlement_workflow.boundaries.chain_success_implies_erp_posting, false);
    assert.deepEqual(body.publication.required_platforms, ["github", "render", "base_app", "base_dashboard", "base_dev", "talent", "guild", "basename_base_org"]);
    assert.equal(body.publication.strict_receipt_count, 0);
    assert.equal(body.publication.publication_unit_count, 0);
    for (const platform of body.publication.required_platforms) {
      assert.equal(body.publication.surfaces[platform].countable, false, platform);
      assert.equal(body.publication.surfaces[platform].receipt, null, platform);
    }
    assert.equal(body.safety.retry.unresolved_request_replay, "forbidden");
    assert.equal(body.safety.deduplication.duplicate_consequence, "noop");
    assert.equal(body.safety.replay.historical_receipt_credit, 0);
  });
});

test("visitor evidence page links release identity and all eight publication surfaces", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/evidence/`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /text\/html/);
    const body = await response.text();
    assert.match(body, /Evidence Workbench/);
    assert.match(body, /Account\/connect preflight/);
    assert.match(body, /Settlement workflow/);
    assert.match(body, /Eight-platform publication evidence/);
    assert.match(body, /strict receipts 0\/8/);
    for (const platform of ["github", "render", "base_app", "base_dashboard", "base_dev", "talent", "guild", "basename_base_org"]) {
      assert.match(body, new RegExp(platform));
    }
    assert.match(body, /href="\/evidence\.json"/);
    assert.match(body, /href="\/release\.json"/);
  });
});

test("public home page exposes product identity and explicit limits", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /text\/html/);
    const body = await response.text();
    assert.match(body, /Base ERP Settlement Workbench/);
    assert.match(body, /<meta name="base:app_id" content="6a7a0717e209a55163497d2d">/);
    assert.match(body, /gaysonloser\.base\.eth/);
    assert.match(body, /0xba36d092db2999bb1fabbaf281ac956a97189c25/i);
    assert.match(body, /BOM fingerprint/);
    assert.match(body, /Network/);
    assert.match(body, new RegExp(TEST_COMMIT));
    assert.match(body, /Public writes and wallet actions are disabled/);
    assert.match(body, /href="\/release\.json"/);
    assert.match(body, /href="\/evidence\//);
    assert.match(body, /href="\/healthz"/);
  });
});

test("health, release JSON and home page share one release identity", async () => {
  await withServer(async (baseUrl) => {
    const [healthResponse, releaseResponse, homeResponse] = await Promise.all([
      fetch(`${baseUrl}/healthz`),
      fetch(`${baseUrl}/release.json`),
      fetch(`${baseUrl}/`),
    ]);
    const health = await healthResponse.json();
    const release = await releaseResponse.json();
    const home = await homeResponse.text();
    assert.equal(health.release_id, release.release_id);
    assert.equal(health.release_fingerprint, release.release_fingerprint);
    assert.equal(health.bom_fingerprint, release.bom_fingerprint);
    assert.equal(health.git_commit, release.git_commit);
    assert.match(home, new RegExp(release.release_id));
    assert.match(home, new RegExp(release.bom_fingerprint));
    assert.match(home, new RegExp(release.git_commit));
  });
});

test("health is fail-closed while the deployment commit is still a placeholder", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.ready, false);
    assert.equal(body.status, "degraded");
    assert.equal(body.commit_placeholder, true);
  }, { env: { ...process.env, GIT_COMMIT_SHA: undefined, RENDER_GIT_COMMIT: undefined, RENDER_GIT_COMMIT_SHA: undefined, SOURCE_VERSION: undefined } });
});

test("HTTP server handles unsupported methods and unknown paths, then shuts down cleanly", async () => {
  await withServer(async (baseUrl) => {
    const methodResponse = await fetch(`${baseUrl}/healthz`, { method: "POST" });
    assert.equal(methodResponse.status, 405);
    assert.deepEqual(await methodResponse.json(), { error: "method_not_allowed", allowed: ["GET", "HEAD"] });
    const missingResponse = await fetch(`${baseUrl}/missing`);
    assert.equal(missingResponse.status, 404);
    assert.deepEqual(await missingResponse.json(), { error: "not_found", path: "/missing" });
    const headResponse = await fetch(`${baseUrl}/release.json`, { method: "HEAD" });
    assert.equal(headResponse.status, 200);
    assert.equal(await headResponse.text(), "");
  });
});
