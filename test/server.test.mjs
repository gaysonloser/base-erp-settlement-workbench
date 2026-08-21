import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { V9_SOURCE_CATALOG_FINGERPRINT, buildV9IntegritySealInput, computeV9ReleaseFingerprint, createAppServer, listenServer, readHealth, readReleaseDocument } from "../src/server.mjs";
import {
  REQUIRED_PLATFORM_IDS,
  REQUIRED_ROUTE_PATHS,
  digest as h220Digest,
  evaluateReleaseEvidenceSeal,
  verifyReleaseEvidenceSeal,
} from "../src/base-release-evidence-integrity-seal.mjs";
import { buildOperatorWorkbench, buildPlatformGatesProjection, buildRecurringSettlementProjection, buildWalletErpActionPlanProjection } from "../src/base-erp-workbench.mjs";
import { renderOperatorWorkbenchPage } from "../src/operator-workbench-page.mjs";

const TEST_COMMIT = "a".repeat(40);

function canonicalH219(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalH219).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"));
    keys.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalH219(value[key])}`).join(",")}}`;
  }
  throw new TypeError("unsupported test JSON value");
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function withTempCandidate(candidate, run) {
  const directory = mkdtempSync(join(tmpdir(), "base-erp-h219-candidate-"));
  const releasePath = join(directory, "release.json");
  writeFileSync(releasePath, JSON.stringify(candidate, null, 2));
  try {
    return await run(releasePath);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * The frozen runtime candidate pins the pre-H220 digests of src/server.mjs and
 * test/server.test.mjs inside its immutable BOM. Tests that need a current-v8
 * ready release recompute those two entries plus the BOM/release fingerprints
 * so the production candidate file stays frozen and untouched.
 */
function recomputeCurrentCandidate() {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_2026-08-10.json", "utf8"));
  // The v8 candidate is frozen on disk, but this helper intentionally creates
  // a disposable current-v8 projection for server tests. Recompute every
  // pinned file so accepted H220/v9 implementation edits (including the
  // workbench and route modules) do not make the temporary candidate stale.
  candidate.immutable_release_bom = candidate.immutable_release_bom.map((entry) => ({
    ...entry,
    digest: sha256(readFileSync(entry.path.slice("projects/2026-08_Base_ERP_Settlement_Workbench/".length))),
  }));
  candidate.bom_fingerprint = sha256(canonicalH219({
    schema_version: "base-erp-v8-bom-v1",
    files: candidate.immutable_release_bom.map((entry) => ({ path: entry.path, sha256: entry.digest })),
  }));
  candidate.immutable_bom_sha256 = candidate.bom_fingerprint;
  candidate.release_fingerprint = sha256(canonicalH219({
    schema_version: "base-erp-v8-release-identity-v1",
    release_id: candidate.release_id,
    bom_fingerprint: candidate.bom_fingerprint,
    base_target: candidate.base_target,
  }));
  return candidate;
}

function recomputeV9Candidate({ commit = TEST_COMMIT } = {}) {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_v9_local_2026-08-16.json", "utf8"));
  const additionalV9Files = [
    "projects/2026-08_Base_ERP_Settlement_Workbench/src/base-wallet-erp-action-plan.mjs",
    "projects/2026-08_Base_ERP_Settlement_Workbench/test/base-wallet-erp-action-plan.test.mjs",
  ];
  const existingPaths = new Set(candidate.immutable_release_bom.map((entry) => entry.path));
  candidate.immutable_release_bom = [
    ...candidate.immutable_release_bom,
    ...additionalV9Files.filter((path) => !existingPaths.has(path)).map((path) => ({ path })),
  ]
    .map((entry) => ({
      path: entry.path,
      digest: sha256(readFileSync(entry.path.slice("projects/2026-08_Base_ERP_Settlement_Workbench/".length))),
    }))
    .sort((left, right) => Buffer.from(left.path, "utf8").compare(Buffer.from(right.path, "utf8")));
  candidate.bom_fingerprint = h220Digest(candidate.immutable_release_bom);
  candidate.immutable_bom_sha256 = candidate.bom_fingerprint;
  candidate.source_digest_catalog = {
    "README.md": sha256(readFileSync("README.md")),
    "src/base-release-evidence-integrity-seal.mjs": sha256(readFileSync("src/base-release-evidence-integrity-seal.mjs")),
    "test/base-release-evidence-integrity-seal.test.mjs": sha256(readFileSync("test/base-release-evidence-integrity-seal.test.mjs")),
  };
  candidate.source_catalog_fingerprint = h220Digest(candidate.source_digest_catalog);
  candidate.commit_sha = commit;
  candidate.commit_placeholder = false;
  candidate.commit_gate = {
    state: "bound_owner_public_commit_for_test",
    required: "one owner-confirmed lowercase full 40-hex commit for this exact v9 BOM",
    placeholder: "PENDING_OWNER_PUBLIC_COMMIT",
    failure_code: null,
  };
  candidate.release_fingerprint = computeV9ReleaseFingerprint({
    release_id: candidate.release_id,
    bom_fingerprint: candidate.bom_fingerprint,
    base_target: candidate.base_target,
    commit_sha: candidate.commit_sha,
    source_catalog_fingerprint: candidate.source_catalog_fingerprint,
  });
  const { self_hash: ignoredSelfHash, ...withoutSelfHash } = candidate;
  candidate.self_hash = h220Digest(withoutSelfHash);
  return candidate;
}

const TEST_RELEASE = Object.freeze({
  release_id: "base-erp-public-product-20260814-v5",
  release_fingerprint: "5962684e0f5df38691ecdaa0b75ba023dcf1a64bf85cc15e512d8e307704ea4f",
  bom_fingerprint: "2b617a7ae4e2ef976e97310ab533f8f067c758dd0feaf3013709a06d01a6d612",
  material_outcome: "Base-native operator workbench with seven scenario queues, causal evidence timeline, deterministic simulation and cumulative refund ceiling guard",
});

const RECURRING_PERMISSION_HASH = "a".repeat(64);
const RECURRING_PAYER = "0x1111111111111111111111111111111111111111";
const RECURRING_SPENDER = "0x2222222222222222222222222222222222222222";
const RECURRING_TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const RECURRING_SALT = "0x" + "00".repeat(32);

const RECURRING_SUBSCRIPTION_RECORD = Object.freeze({
  case: Object.freeze({
    case_id: "base-erp-h214-recurring-001",
    permission_hash_digest: RECURRING_PERMISSION_HASH,
    permission_ref: "internal-server-record-001",
    payer: RECURRING_PAYER,
    spender: RECURRING_SPENDER,
    token: RECURRING_TOKEN,
    chain_id: 84532,
    testnet: true,
    allowance: "500.00",
    period_seconds: 86400,
    start: 1750000000,
    end: 1752688000,
    recurring_charge: "25.00",
    status_adapter: "subscription",
    recipient_policy: Object.freeze({ mode: "none" }),
    current_period_start: 1750000000,
    next_period_start: 1750086400,
  }),
  subscription_readback: Object.freeze({
    isSubscribed: true,
    remainingChargeInPeriod: "450.00",
    currentPeriodStart: 1750000000,
    nextPeriodStart: 1750086400,
  }),
  observed: Object.freeze({ amount: "25.00" }),
});

const RECURRING_SPEND_PERMISSION_RECORD = Object.freeze({
  case: Object.freeze({
    case_id: "base-erp-h214-recurring-002",
    permission_hash_digest: "b".repeat(64),
    permission_ref: "internal-server-record-002",
    payer: RECURRING_PAYER,
    spender: RECURRING_SPENDER,
    token: RECURRING_TOKEN,
    chain_id: 84532,
    testnet: true,
    allowance: "500.00",
    period_seconds: 86400,
    start: 1750000000,
    end: 1752688000,
    recurring_charge: "20.00",
    status_adapter: "spend_permission",
    recipient_policy: Object.freeze({ mode: "none" }),
    permission_tuple: Object.freeze({
      account: RECURRING_PAYER,
      spender: RECURRING_SPENDER,
      token: RECURRING_TOKEN,
      allowance: "500.00",
      period: 86400,
      start: 1750000000,
      end: 1752688000,
      salt: RECURRING_SALT,
      extraData: "0x",
    }),
    current_period_start: 1750000000,
    next_period_start: 1750086400,
  }),
  permission_readback: Object.freeze({
    permission: Object.freeze({
      account: RECURRING_PAYER,
      spender: RECURRING_SPENDER,
      token: RECURRING_TOKEN,
      allowance: "500.00",
      period: 86400,
      start: 1750000000,
      end: 1752688000,
      salt: RECURRING_SALT,
      extraData: "0x",
    }),
    isActive: true,
    remainingSpend: "480.00",
    currentPeriodStart: 1750000000,
    nextPeriodStart: 1750086400,
  }),
  observed: Object.freeze({ amount: "20.00" }),
});

async function withServer(run, { env = { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT }, runtimeReader = null, platformGatesSourceReader = null, releasePath = undefined } = {}) {
  if (releasePath === undefined) {
    return withTempCandidate(recomputeCurrentCandidate(), (tempPath) => withServer(run, { env, runtimeReader, platformGatesSourceReader, releasePath: tempPath }));
  }
  const server = createAppServer({ env, runtimeReader, platformGatesSourceReader, releasePath });
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

async function assertCurrentV8SurfacesFailClosed(baseUrl) {
  for (const pathname of ["/release.json", "/healthz", "/platform-gates.json", "/workbench.json", "/workbench", "/workbench/"]) {
    const response = await fetch(`${baseUrl}${pathname}`);
    assert.equal(response.status, 503, pathname);
    const body = await response.json();
    if (pathname === "/healthz") {
      assert.equal(body.ready, false, pathname);
      assert.equal(body.status, "degraded", pathname);
    } else {
      assert.deepEqual(body, { error: "release_unavailable", reason: "current_v8_identity_unready" }, pathname);
    }
  }
}

test("production default release keeps the immutable v9 template fail-closed while code bytes require a new candidate", () => {
  const unbound = readReleaseDocument({ env: {} });
  assert.equal(unbound.schema_version, "base-erp-v9-public-release-v1");
  assert.equal(unbound.release_id, "base-erp-public-product-20260816-v9");
  assert.equal(unbound.commit_placeholder, true);
  assert.equal(unbound.v9_release_ready, false);
  assert.equal(unbound.v9_candidate_gate.reason, "v9_bom_fingerprint_mismatch");
  assert.equal(readHealth({ release: unbound }).ready, false);

  const bound = readReleaseDocument({ env: { GIT_COMMIT_SHA: TEST_COMMIT } });
  assert.equal(bound.schema_version, "base-erp-v9-public-release-v1");
  assert.equal(bound.commit_placeholder, false);
  assert.equal(bound.git_commit, TEST_COMMIT);
  assert.equal(bound.v9_release_ready, false);
  assert.equal(bound.v9_candidate_gate.reason, "v9_bom_fingerprint_mismatch");
  assert.equal(readHealth({ release: bound }).ready, false);

  const drifted = readReleaseDocument({ env: { GIT_COMMIT_SHA: "f".repeat(64) } });
  assert.equal(drifted.commit_placeholder, true);
  assert.equal(drifted.v9_release_ready, false);
  assert.equal(drifted.v9_candidate_gate.reason, "v9_bom_fingerprint_mismatch");
  assert.equal(readHealth({ release: drifted }).ready, false);
});

test("npm start default listener preserves the immutable v9 gate until a new candidate is selected", async () => {
  const { server, address } = await listenServer({ host: "127.0.0.1", port: 0, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
  assert.equal(typeof address, "object");
  try {
    const releaseResponse = await fetch(`http://127.0.0.1:${address.port}/release.json`);
    assert.equal(releaseResponse.status, 503);
    assert.deepEqual(await releaseResponse.json(), { error: "release_unavailable", reason: "current_v9_identity_unready" });
    const healthResponse = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(healthResponse.status, 503);
    assert.equal((await healthResponse.json()).ready, false);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("H219 local health remains fail-closed until a deployment-injected commit is present", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    assert.equal(response.status, 503);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.status, "degraded");
    assert.equal(body.ready, false);
    assert.equal(body.runtime_status, "not_required");
    assert.equal(body.public_write_authorized, false);
    assert.match(body.release_id, /^base-erp-/);
    assert.match(body.release_fingerprint, /^[0-9a-f]{64}$/);
    assert.match(body.bom_fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(body.immutable_bom_sha256, body.bom_fingerprint);
    assert.equal(body.git_commit, "PENDING_OWNER_PUBLIC_COMMIT");
    assert.match(body.observed_at, /^2026|^20/);
  }, { env: { ...process.env } });
});

test("H219 BOM accepts only the exact normalized ordered 17-path allowlist", async () => {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_2026-08-10.json", "utf8"));
  const cases = {
    missing: (value) => { value.immutable_release_bom = value.immutable_release_bom.slice(0, -1); },
    extra: (value) => { value.immutable_release_bom.push({ path: "projects/2026-08_Base_ERP_Settlement_Workbench/src/extra.mjs", digest: "0".repeat(64) }); },
    reordered: (value) => {
      [value.immutable_release_bom[0], value.immutable_release_bom[1]] = [value.immutable_release_bom[1], value.immutable_release_bom[0]];
    },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    const tampered = structuredClone(candidate);
    mutate(tampered);
    await withTempCandidate(tampered, (releasePath) => {
      const release = readReleaseDocument({ releasePath, env: {} });
      assert.equal(release.bom_verified, false, label);
      assert.equal(release.bom_fingerprint_valid, false, label);
      assert.equal(readHealth({ release }).ready, false, label);
    });
  }
});

test("H219 rejects alternate base targets even when their release fingerprint is recomputed", async () => {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_2026-08-10.json", "utf8"));
  const alternate = structuredClone(candidate);
  alternate.base_target.render_domain = "alternate-base-target.invalid";
  alternate.release_fingerprint = sha256(canonicalH219({
    schema_version: "base-erp-v8-release-identity-v1",
    release_id: alternate.release_id,
    bom_fingerprint: alternate.bom_fingerprint,
    base_target: alternate.base_target,
  }));
  await withTempCandidate(alternate, async (releasePath) => {
    const release = readReleaseDocument({ releasePath, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
    assert.equal(release.release_identity_valid, false);
    assert.equal(readHealth({ release }).ready, false);
    await withServer(async (baseUrl) => {
      const health = await fetch(`${baseUrl}/healthz`);
      assert.equal(health.status, 503);
      assert.equal((await health.json()).ready, false);
      const platform = await fetch(`${baseUrl}/platform-gates.json`);
      assert.equal(platform.status, 503);
      assert.deepEqual(await platform.json(), { error: "release_unavailable", reason: "current_v8_identity_unready" });
    }, { releasePath, env: { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT } });
  });
});

test("H219 all current-v8 public surfaces share fail-closed readiness", async () => {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_2026-08-10.json", "utf8"));
  const recompute = (value) => {
    value.release_fingerprint = sha256(canonicalH219({
      schema_version: "base-erp-v8-release-identity-v1",
      release_id: value.release_id,
      bom_fingerprint: value.bom_fingerprint,
      base_target: value.base_target,
    }));
  };
  const cases = {
    alternate: (value) => {
      value.base_target.render_domain = "alternate-base-target.invalid";
      recompute(value);
    },
    circle: (value) => {
      value.base_target = {
        github_repo: "gaysonloser/arc-payment-receipt",
        render_service_id: "srv-d9cumml8nd3s73c9nehg",
        render_domain: "arc-payment-receipt.onrender.com",
        dashboard_app_id: "circle-collision-app",
        canonical_primary_url: "https://arc-payment-receipt.onrender.com",
      };
      recompute(value);
    },
    stale: (value) => {
      value.release_id = "base-erp-public-product-20260815-v7";
      recompute(value);
    },
    missing: (value) => {
      delete value.base_target;
    },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    const tampered = structuredClone(candidate);
    mutate(tampered);
    await withTempCandidate(tampered, async (releasePath) => {
      await withServer((baseUrl) => assertCurrentV8SurfacesFailClosed(baseUrl), {
        releasePath,
        env: { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT },
      });
    });
    assert.ok(label);
  }
  await withServer((baseUrl) => assertCurrentV8SurfacesFailClosed(baseUrl), { env: {} });
});

test("H219 requires lowercase BOM/release digests and deployment commit", async () => {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_2026-08-10.json", "utf8"));
  const uppercaseBom = structuredClone(candidate);
  uppercaseBom.immutable_release_bom[0].digest = uppercaseBom.immutable_release_bom[0].digest.toUpperCase();
  await withTempCandidate(uppercaseBom, (releasePath) => {
    const release = readReleaseDocument({ releasePath, env: {} });
    assert.equal(release.bom_verified, false);
    assert.equal(release.bom_fingerprint_valid, false);
  });

  const uppercaseRelease = structuredClone(candidate);
  uppercaseRelease.release_fingerprint = uppercaseRelease.release_fingerprint.toUpperCase();
  await withTempCandidate(uppercaseRelease, (releasePath) => {
    const release = readReleaseDocument({ releasePath, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
    assert.equal(release.release_identity_valid, false);
    assert.equal(readHealth({ release }).ready, false);
  });

  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.ready, false);
    assert.equal(body.commit_placeholder, true);
    assert.equal(body.git_commit, "PENDING_OWNER_PUBLIC_COMMIT");
  }, { env: { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT.toUpperCase() } });
});

test("release endpoint binds the public document to the current release identity", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/release.json`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.schema_version, "base-erp-v8-public-release-v1");
    assert.equal(body.project_name, "Base ERP Settlement Workbench");
    assert.match(body.release_fingerprint, /^[0-9a-f]{64}$/);
    assert.match(body.bom_fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(body.public_write_authorized, false);
    assert.equal(body.commit_placeholder, false);
    assert.equal(body.git_commit, TEST_COMMIT);
    assert.equal(body.public_identity.basename, "gaysonloser.base.eth");
    assert.equal(body.public_identity.primary_base_account.toLowerCase(), "0xba36d092db2999bb1fabbaf281ac956a97189c25");
    assert.ok(Array.isArray(body.immutable_release_bom));
    assert.ok(body.immutable_release_bom.some((entry) => entry.path.endsWith("/src/server.mjs")));
  });
});

test("public evidence endpoint exposes the typed fail-closed product boundary", async () => {
  await withServer(async (baseUrl) => {
    const [response, releaseResponse] = await Promise.all([
      fetch(`${baseUrl}/evidence.json`),
      fetch(`${baseUrl}/release.json`),
    ]);
    assert.equal(response.status, 200);
    assert.equal(releaseResponse.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    const release = await releaseResponse.json();
    assert.equal(body.schema_version, "base-erp-public-evidence-v1");
    assert.equal(body.public_write_authorized, false);
    assert.equal(body.external_actions, 0);
    assert.equal(body.release.release_id, release.release_id);
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
    assert.deepEqual(body.publication.strict_receipt_platforms, []);
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

test("visitor case catalog exposes seven H209 profiles on one release join key", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/cases.json`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.schema_version, "base-erp-visitor-case-catalog-v1");
    assert.equal(body.mode, "visitor_read_only");
    assert.equal(body.profiles.length, 7);
    assert.deepEqual(body.erp_domains, ["Sales Invoice", "Payment Entry", "Bank Transaction", "General Ledger", "Payment Ledger", "Accounting Period", "Period Closing Voucher"]);
    assert.equal(body.release.current, true);
    assert.equal(body.release.historical, false);
    assert.equal(body.release.synthetic, false);
    assert.ok(body.profiles.every((profile) => profile.chain_id === 84532 && profile.safety.wallet_write_allowed === false));
  });
});

test("operator workbench exposes four persistent decision landmarks and seven selectable cases", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/workbench.json?profile_id=payment_refund_incoming`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.schema_version, "base-erp-operator-workbench-v1");
    assert.equal(body.mode, "visitor_read_only");
    assert.deepEqual(body.landmarks, ["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]);
    assert.equal(body.queue.length, 7);
    assert.equal(body.queue.filter((row) => row.selected).length, 1);
    assert.equal(body.selected_case.profile_id, "payment_refund_incoming");
    assert.equal(body.selected_case.verb, "Resolve payment refund");
    assert.match(body.selected_case.consequence_preview.accounting, /refund ceiling/i);
    assert.equal(body.selected_case.consequence_preview.chain_success_implies_erp_posting, false);
    assert.equal(body.safety.wallet_write_allowed, false);
    assert.equal(body.safety.erp_write_allowed, false);
    assert.equal(body.safety.broadcast, false);
  });
});

test("wallet ERP action plan is public, release-bound and permanently non-executable", async () => {
  await withServer(async (baseUrl) => {
    const [planResponse, workbenchResponse, pageResponse] = await Promise.all([
      fetch(`${baseUrl}/wallet-action-plan.json?profile_id=customer_invoice_receipt`),
      fetch(`${baseUrl}/workbench.json?profile_id=customer_invoice_receipt`),
      fetch(`${baseUrl}/workbench/?profile_id=customer_invoice_receipt`),
    ]);
    assert.equal(planResponse.status, 200);
    assert.equal(workbenchResponse.status, 200);
    assert.equal(pageResponse.status, 200);
    const plan = await planResponse.json();
    const workbench = await workbenchResponse.json();
    const page = await pageResponse.text();
    assert.equal(plan.schema_version, "base-wallet-erp-action-plan-v1");
    assert.equal(plan.release.release_id, workbench.release.release_id);
    assert.equal(plan.release.release_fingerprint, workbench.release.release_fingerprint);
    assert.equal(plan.release.bom_fingerprint, workbench.release.bom_fingerprint);
    assert.equal(plan.wallet.chain, "eip155:8453");
    assert.equal(plan.wallet.wallet_method, "wallet_sendCalls");
    assert.equal(plan.wallet.account_bound, true);
    assert.equal(plan.wallet.payload_present, false);
    assert.equal(plan.wallet.unsigned, true);
    assert.equal(plan.execution_authority, "owner_review_required");
    assert.equal(plan.action_enabled, false);
    assert.equal(plan.accounting.mainnet_transaction_credit, 0);
    assert.equal(plan.accounting.publication_unit_credit, 0);
    assert.deepEqual(workbench.wallet_action_plan, plan);
    assert.match(page, /Wallet ERP action plan/);
    assert.match(page, /Owner-visible review required/);
    assert.match(page, /Action disabled/);
    assert.doesNotMatch(JSON.stringify(plan), /0x[a-f0-9]{40}|calldata|callsid|tx_hash|signed_payload|balance|portfolio/i);
  });
});

test("wallet ERP action plan projection disables unsupported outbound non-refund profiles", () => {
  const plan = buildWalletErpActionPlanProjection({ release: TEST_RELEASE, selected_profile_id: "supplier_advance" });
  assert.equal(plan.action_enabled, false);
  assert.equal(plan.unavailable_reason, "profile_direction_not_supported");
  assert.equal(plan.wallet.payload_present, false);
  assert.equal(plan.accounting.mainnet_transaction_credit, 0);
});

test("wallet bridge visitor endpoint is owner-gated and never exposes executable calldata", async () => {
  await withServer(async (baseUrl) => {
    const [response, head, query, method] = await Promise.all([
      fetch(`${baseUrl}/wallet-action-bridge.json`),
      fetch(`${baseUrl}/wallet-action-bridge.json`, { method: "HEAD" }),
      fetch(`${baseUrl}/wallet-action-bridge.json?to=0x1111111111111111111111111111111111111111`),
      fetch(`${baseUrl}/wallet-action-bridge.json`, { method: "POST" }),
    ]);
    assert.equal(response.status, 200);
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
    const body = await response.json();
    assert.equal(body.schema_version, "base-account-wallet-bridge-public-v1");
    assert.equal(body.bridge_available, false);
    assert.equal(body.execution_ready, false);
    assert.equal(body.reason, "owner_auth_required");
    assert.equal(body.owner_review_required, true);
    assert.equal(body.accounting.mainnet_transaction_credit, 0);
    assert.equal(body.accounting.publication_unit_credit, 0);
    for (const key of ["call_template", "to", "value", "data", "calls", "calls_id", "receipt"]) assert.equal(Object.prototype.hasOwnProperty.call(body, key), false, key);
    assert.equal(query.status, 400);
    assert.equal((await query.json()).reason, "client_binding_not_accepted");
    assert.equal(method.status, 405);
    assert.deepEqual(await method.json(), { error: "method_not_allowed", allowed: ["GET", "HEAD"] });
  }, { env: { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT, BASE_ERP_WALLET_BRIDGE_CALL_TEMPLATE_JSON: JSON.stringify({ to: "0x1111111111111111111111111111111111111111", value: "0x0", data: "0x" }) } });
});

test("operator workbench HTML is decision-first and preserves explicit stop conditions", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/workbench/?profile_id=customer_invoice_receipt`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /text\/html/);
    const body = await response.text();
    for (const landmark of ["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]) {
      assert.match(body, new RegExp(`id="${landmark}"`));
    }
    assert.match(body, /Match incoming customer receipt/);
    assert.match(body, /Stop condition/);
    assert.match(body, /Finality pending/);
    assert.match(body, /ERP consequence preview/);
    assert.match(body, /No wallet request, signature, broadcast, ERP write or platform write is exposed/);
    assert.match(body, /<button disabled>Review evidence<\/button>/);
    assert.match(body, /data-wallet-bridge="connect"[^>]*disabled/);
    assert.match(body, /Owner review unavailable/);
  });
});

test("operator workbench rejects unknown case profiles without falling through", async () => {
  await withServer(async (baseUrl) => {
    const jsonResponse = await fetch(`${baseUrl}/workbench.json?profile_id=unknown`);
    assert.equal(jsonResponse.status, 400);
    assert.equal((await jsonResponse.json()).error, "workbench_input_invalid");
    const htmlResponse = await fetch(`${baseUrl}/workbench/?profile_id=unknown`);
    assert.equal(htmlResponse.status, 400);
    assert.equal((await htmlResponse.json()).error, "workbench_input_invalid");
  });
});

test("H218 platform-gates route is deterministic, read-only and fail-closed on bindings", async () => {
  await withServer(async (baseUrl) => {
    const [firstResponse, secondResponse, headResponse] = await Promise.all([
      fetch(`${baseUrl}/platform-gates.json`),
      fetch(`${baseUrl}/platform-gates.json`),
      fetch(`${baseUrl}/platform-gates.json`, { method: "HEAD" }),
    ]);
    assert.equal(firstResponse.status, 200);
    assert.equal(secondResponse.status, 200);
    assert.equal(headResponse.status, 200);
    assert.match(firstResponse.headers.get("content-type") ?? "", /application\/json/);
    assert.equal(Number(headResponse.headers.get("content-length")), Number(firstResponse.headers.get("content-length")));
    assert.equal(await headResponse.text(), "");
    const first = await firstResponse.json();
    const second = await secondResponse.json();
    assert.deepEqual(first, second);
    assert.equal(first.schema_version, "base-erp-h218-platform-gates-public-v1");
    assert.equal(first.mode, "visitor_read_only");
    assert.deepEqual(first.rows.map((row) => row.platform_row_id), [
      "base_sepolia_rehearsal",
      "talent_native_domain",
      "guild_native_domain",
      "basename_base_org_identity",
    ]);
    assert.equal(first.aggregate.credit, 0);
    assert.equal(first.aggregate.native_receipt_count, 0);
    assert.equal(first.safety.public_write_authorized, false);
    assert.equal(first.isolation.action_enabled, false);
    const method = await fetch(`${baseUrl}/platform-gates.json`, { method: "POST" });
    assert.equal(method.status, 405);
    assert.deepEqual(await method.json(), { error: "method_not_allowed", allowed: ["GET", "HEAD"] });
    const query = await fetch(`${baseUrl}/platform-gates.json?release_id=secret-value`);
    assert.equal(query.status, 400);
    assert.deepEqual(await query.json(), { error: "client_binding_not_accepted" });
    assert.doesNotMatch(await (await fetch(`${baseUrl}/platform-gates.json?release_id=secret-value`)).text(), /secret-value/);
  });
});

test("H218 projection composes one shared four-row object and keeps identity redacted", async () => {
  await withServer(async (baseUrl) => {
    const projection = await (await fetch(`${baseUrl}/platform-gates.json`)).json();
    const workbench = await (await fetch(`${baseUrl}/workbench.json?profile_id=customer_invoice_receipt`)).json();
    assert.deepEqual(workbench.platform_gates, projection);
    const page = await (await fetch(`${baseUrl}/workbench/`)).text();
    assert.match(page, /id="platform-gates-panel"/);
    assert.equal((page.match(/data-platform-gate="/g) ?? []).length, 4);
    assert.match(page, /href="\/platform-gates\.json"/);
    assert.match(page, /Native receipt: null · release receipt: false · credit: 0/);
    assert.doesNotMatch(JSON.stringify(projection), /0x[a-f0-9]{40}/i);
    assert.doesNotMatch(JSON.stringify(projection), /wallet_sendCalls|0x[a-f0-9]{40}|gaysonloser\.base\.eth/i);
    for (const row of projection.rows) {
      assert.equal(row.receipt.native_receipt, null);
      assert.equal(row.receipt.release_receipt, false);
      assert.equal(row.credit, 0);
      assert.equal(row.publication_unit_credit, 0);
    }
  });
});

test("H219 HTTP surface fails closed for injected H217 hash drift and stale closure", async () => {
  const h217Readback = JSON.parse(readFileSync("runtime/h217_remaining_platform_readback_2026-08-15.json", "utf8"));
  const matrix = JSON.parse(readFileSync("config/base_circle_platform_isolation_matrix_v1.json", "utf8"));
  const validSource = {
    matrix,
    matrix_sha256: "c538e47c4b7951f341b36e351858bf3e1c28dd772d7d3f9c3588f1f0093f19de",
    h217_readback: h217Readback,
    h217_module_sha256: "96f9839cbebb6bff775a5b0cc84a7ae7d71b0168847f2a1eb08c0b59d6f80b42",
    h217_readback_sha256: "f7aea1ec1ea6d3377334f8f1d32938054f4bd4b809f622673fb056868be2c8b1",
  };
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/platform-gates.json`);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "platform_gates_unavailable", reason: "h217_source_invalid_or_circle_collision" });
  }, { platformGatesSourceReader: () => ({ ...validSource, h217_module_sha256: "0".repeat(64) }) });

  const stale = structuredClone(h217Readback);
  stale.packet_revalidation.occurrence = 2;
  await withServer(async (baseUrl) => {
    for (const path of ["/platform-gates.json", "/workbench.json", "/workbench/"]) {
      const response = await fetch(`${baseUrl}${path}`);
      assert.equal(response.status, 503, path);
      const body = await response.json();
      assert.deepEqual(body, { error: "platform_gates_unavailable", reason: "h217_source_invalid_or_circle_collision" });
    }
  }, { platformGatesSourceReader: () => ({ ...validSource, h217_readback: stale }) });
});

test("H218 projection rejects stale H217 source closure and isolation collisions", () => {
  const h217Readback = JSON.parse(readFileSync("runtime/h217_remaining_platform_readback_2026-08-15.json", "utf8"));
  const release = {
    release_id: "base-erp-public-product-20260815-v7",
    release_fingerprint: "bfd8e57684b0c43bb92dbc9ac3bcd7426b226dc816541c008c7085b7cc6ae5ae",
    bom_fingerprint: "3b856d0a18fc996b47e5bb4bb0b4c06a73e28ff2f5a0ce13e08612b27ad3529c",
  };
  assert.throws(() => buildPlatformGatesProjection({ release, h217_readback: h217Readback, h217_readback_sha256: "0".repeat(64) }), /h217_source_invalid_or_circle_collision/);
  const collision = structuredClone(h217Readback);
  collision.evidence_envelope.release_join = { ...collision.evidence_envelope.release_join, release_id: "circle-collision" };
  assert.throws(() => buildPlatformGatesProjection({ release, h217_readback: collision }), /h217_source_invalid_or_circle_collision/);
});

test("H215 operator surface preserves the seven-row queue, dual origins and independent truth lanes", () => {
  const workbench = buildOperatorWorkbench({ release: TEST_RELEASE, selected_profile_id: "customer_invoice_receipt" });
  assert.equal(workbench.contract_version, "base-erp-h215-operator-workbench-v1");
  assert.deepEqual(workbench.operator_surface.shell.landmarks, ["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]);
  assert.equal(workbench.operator_surface.queue.count, 7);
  assert.deepEqual(workbench.operator_surface.entry_points.map((entry) => entry.id), ["erp_initiated", "chain_observed"]);
  assert.equal(workbench.operator_surface.selected_origin, null);
  assert.equal(workbench.operator_surface.decision_canvas.state, "validation_required");
  assert.deepEqual(Object.keys(workbench.operator_surface.evidence_inspector.facts), ["chain", "receipt", "finality", "erp_posting", "business_close"]);
  assert.equal(workbench.operator_surface.evidence_inspector.facts.chain.state, "not_evaluated");
  assert.equal(workbench.operator_surface.evidence_inspector.facts.erp_posting.claimed, false);
  assert.equal(workbench.operator_surface.evidence_inspector.facts.business_close.claimed, false);
  assert.equal(workbench.operator_surface.network_gate.rehearsal.chain_id, 84532);
  assert.equal(workbench.operator_surface.network_gate.rehearsal.descriptor_only, true);
  assert.equal(workbench.operator_surface.network_gate.mainnet.chain_id, 8453);
  assert.equal(workbench.operator_surface.network_gate.mainnet.enabled, false);
  assert.equal(workbench.operator_surface.safety.external_actions, 0);
  assert.equal(workbench.operator_surface.safety.execution_authority, "none_until_02_Build_revalidates");
});

test("H215 workbench rejects every client binding except one profile_id without echo", async () => {
  await withServer(async (baseUrl) => {
    for (const query of ["origin=chain_observed", "entry=erp_initiated", "state=matched", "network=8453", "identity=wallet", "release=base-erp-public-product-20260814-v6", "calls=hint", "calldata=0xdeadbeef"]) {
      const [jsonResponse, htmlResponse] = await Promise.all([
        fetch(`${baseUrl}/workbench.json?${query}`),
        fetch(`${baseUrl}/workbench/?${query}`),
      ]);
      assert.equal(jsonResponse.status, 400, query);
      assert.equal(htmlResponse.status, 400, query);
      assert.deepEqual(await jsonResponse.json(), { error: "workbench_input_invalid", reason: "client_binding_not_accepted" });
      assert.deepEqual(await htmlResponse.json(), { error: "workbench_input_invalid", reason: "client_binding_not_accepted" });
      assert.doesNotMatch(JSON.stringify(await fetch(`${baseUrl}/workbench.json?${query}`).then((response) => response.json())), new RegExp(query.split("=")[1]));
    }
    const profile = await fetch(`${baseUrl}/workbench.json?profile_id=customer_invoice_receipt`);
    assert.equal(profile.status, 200);
    assert.equal((await profile.json()).contract_version, "base-erp-h215-operator-workbench-v1");
  });
});

test("H214 recurring settlement visitor route is deterministic and workbench-owned", async () => {
  await withServer(async (baseUrl) => {
    const [firstResponse, secondResponse, headResponse, workbenchResponse] = await Promise.all([
      fetch(`${baseUrl}/recurring-settlement.json`),
      fetch(`${baseUrl}/recurring-settlement.json`),
      fetch(`${baseUrl}/recurring-settlement.json`, { method: "HEAD" }),
      fetch(`${baseUrl}/workbench.json?profile_id=payment_refund_incoming`),
    ]);
    assert.equal(firstResponse.status, 200);
    assert.equal(secondResponse.status, 200);
    assert.equal(headResponse.status, 200);
    assert.equal(await headResponse.text(), "");
    const first = await firstResponse.json();
    const second = await secondResponse.json();
    const workbench = await workbenchResponse.json();
    assert.deepEqual(first, second);
    assert.equal(first.schema_version, "base-erp-h214-recurring-settlement-public-v1");
    assert.equal(first.mode, "visitor_read_only");
    assert.equal(first.selector, "server_owned_default");
    assert.equal(first.status.state, "status_readback_pending");
    assert.equal(first.status.observed, false);
    assert.equal(first.plan.network.chain_id, 84532);
    assert.equal(first.route_previews.charge.cdp.preview_only, true);
    assert.equal(first.route_previews.charge.cdp.calls_status_route, false);
    assert.equal(first.route_previews.charge.manual.descriptor_only, true);
    assert.equal(first.route_previews.charge.manual.calls_status_route, true);
    assert.equal(first.route_previews.charge.cdp.tx_hash, null);
    assert.equal(first.route_previews.charge.manual.calls_id, null);
    assert.equal(first.gates.receipt.transaction_hash, null);
    assert.equal(first.gates.finality.required, "l1_batch_final");
    assert.equal(first.gates.erp.posting, false);
    assert.equal(first.gates.erp.business_close, false);
    assert.equal(first.safety.external_actions, 0);
    assert.equal(first.safety.public_write_authorized, false);
    assert.equal(workbench.queue.length, 7);
    assert.deepEqual(workbench.recurring_settlement, first);
  });
});

test("H214 recurring visitor routes reject client binding hints without echo and preserve method/path gates", async () => {
  await withServer(async (baseUrl) => {
    const [dedicated, generic, head, method, missing] = await Promise.all([
      fetch(`${baseUrl}/recurring-settlement.json?permission_id=0xdeadbeef`),
      fetch(`${baseUrl}/workbench.json?permission_hash=${"a".repeat(64)}`),
      fetch(`${baseUrl}/recurring-settlement.json?tx_hash=0xdeadbeef`, { method: "HEAD" }),
      fetch(`${baseUrl}/recurring-settlement.json`, { method: "POST" }),
      fetch(`${baseUrl}/recurring-settlement-missing.json`),
    ]);
    assert.equal(dedicated.status, 400);
    assert.deepEqual(await dedicated.json(), { error: "client_binding_not_accepted" });
    assert.equal(generic.status, 400);
    assert.deepEqual(await generic.json(), { error: "workbench_input_invalid", reason: "client_binding_not_accepted" });
    assert.equal(head.status, 400);
    assert.equal(await head.text(), "");
    assert.equal(method.status, 405);
    assert.deepEqual(await method.json(), { error: "method_not_allowed", allowed: ["GET", "HEAD"] });
    assert.equal(missing.status, 404);
    assert.deepEqual(await missing.json(), { error: "not_found", path: "/recurring-settlement-missing.json" });
  });
});

test("refund preview endpoint exposes cumulative ceiling math without an executable consequence", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/refund-preview.json?principal=500.00&refunded_to_date=125.00&amount=75.00`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.schema_version, "base-refund-ceiling-guard-v1");
    assert.equal(body.ok, true);
    assert.equal(body.action_enabled, false);
    assert.equal(body.remaining_ceiling_before, "375");
    assert.equal(body.remaining_ceiling_after, "300");
    assert.equal(body.payment_entry_projection, null);
  });
});

test("read-only simulation is deterministic and explicitly non-executable", async () => {
  await withServer(async (baseUrl) => {
    const url = `${baseUrl}/simulate.json?profile_id=customer_invoice_receipt&amount=12.50&currency=USDC&business_reference=invoice-demo-001`;
    const [firstResponse, secondResponse] = await Promise.all([fetch(url), fetch(url)]);
    assert.equal(firstResponse.status, 200);
    assert.equal(secondResponse.status, 200);
    const first = await firstResponse.json();
    const second = await secondResponse.json();
    assert.deepEqual(first, second);
    assert.equal(first.mode, "simulation_non_executable");
    assert.equal(first.case.profile_id, "customer_invoice_receipt");
    assert.equal(first.case.chain_id, 84532);
    assert.equal(first.safety.broadcast, false);
    assert.equal(first.safety.signed, false);
    assert.equal(first.safety.transaction_hash, null);
    assert.equal(first.safety.countable_daily_trace, false);
    assert.equal(first.expected_effects.event_history, "not_observed");
    assert.match(first.simulation_id, /^sim-[0-9a-f]{24}$/);
  });
});

test("simulation rejects unknown profiles and unsupported network input", async () => {
  await withServer(async (baseUrl) => {
    const unknown = await fetch(`${baseUrl}/simulate.json?profile_id=unknown-profile`);
    assert.equal(unknown.status, 400);
    assert.equal((await unknown.json()).error, "simulation_input_invalid");
    const unsupported = await fetch(`${baseUrl}/simulate.json?profile_id=customer_invoice_receipt&network=base_vibenet`);
    assert.equal(unsupported.status, 400);
    assert.equal((await unsupported.json()).error, "simulation_input_invalid");
  });
});

test("event admission remains blocked until independent durable event evidence exists", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/event-admission.json?case_id=case-demo-001`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.schema_version, "base-erp-event-admission-v1");
    assert.equal(body.case_id, "case-demo-001");
    assert.equal(body.status, "blocked_missing_event_history");
    assert.equal(body.observed, false);
    assert.equal(body.current_release_bound, true);
    assert.equal(body.raw_payload_digest, null);
    assert.equal(body.durable_store_pointer, null);
    assert.equal(body.credit, 0);
  });
});

test("standard web-app metadata and existing Base App assets are served without write capability", async () => {
  await withServer(async (baseUrl) => {
    const [metadataResponse, wellKnownResponse, assetResponse, headResponse] = await Promise.all([
      fetch(`${baseUrl}/app.json`),
      fetch(`${baseUrl}/.well-known/base-app.json`),
      fetch(`${baseUrl}/assets/base-app/base-erp-workbench-thumbnail-1200x628.jpg`),
      fetch(`${baseUrl}/assets/base-app/base-erp-workbench-thumbnail-1200x628.jpg`, { method: "HEAD" }),
    ]);
    assert.equal(metadataResponse.status, 200);
    assert.equal(wellKnownResponse.status, 200);
    const metadata = await metadataResponse.json();
    const wellKnown = await wellKnownResponse.json();
    assert.deepEqual(metadata, wellKnown);
    assert.equal(metadata.schema_version, "base-erp-standard-web-app-metadata-v1");
    assert.equal(metadata.primary_url, "https://base-erp-settlement-workbench.onrender.com/");
    assert.equal(metadata.screenshots.length, 2);
    assert.equal(metadata.public_write_authorized, false);
    assert.equal(metadata.wallet_actions_exposed, false);
    assert.match(metadata.icon, /^\/assets\/base-app\//);
    assert.equal(assetResponse.status, 200);
    assert.match(assetResponse.headers.get("content-type"), /^image\/jpeg/);
    assert.ok(Number(assetResponse.headers.get("content-length")) > 0);
    assert.equal(headResponse.status, 200);
    assert.equal(await headResponse.text(), "");
  });
});

test("HTML responses use self-only connect CSP and nonce-bind inline scripts", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/workbench/`);
    assert.equal(response.status, 200);
    const policy = response.headers.get("content-security-policy");
    assert.match(policy, /connect-src 'self' https:\/\/rpc\.wallet\.coinbase\.com/);
    assert.match(policy, /script-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
    assert.doesNotMatch(policy, /\*|cca-lite|amplitude/i);
    assert.doesNotMatch(policy, /script-src[^;]*unsafe-inline/i);
    const html = await response.text();
    assert.match(html, /<script nonce="[A-Za-z0-9+/=]+">/);
    assert.equal((html.match(/<script nonce="([A-Za-z0-9+/=]+)">/g) ?? []).length > 0, true);
  });
});

test("recurring settlement visitor projection is deterministic and status-readback-pending", () => {
  const first = buildRecurringSettlementProjection({ release: TEST_RELEASE });
  const second = buildRecurringSettlementProjection({ release: TEST_RELEASE });
  assert.deepEqual(first, second);
  assert.equal(first.schema_version, "base-erp-h214-recurring-settlement-public-v1");
  assert.equal(first.mode, "visitor_read_only");
  assert.equal(first.selector, "server_owned_default");
  assert.equal(first.status.state, "status_readback_pending");
  assert.equal(first.status.adapter, "subscription");
  assert.equal(first.plan.status_adapter, "subscription");
  assert.equal(first.plan.network.chain_id, 84532);
  assert.equal(first.plan.network.testnet, true);
  assert.equal(first.plan.recurring_charge.value, null);
  assert.equal(first.plan.remaining_allowance.value, null);
  assert.equal(first.plan.period.no_rollover, true);
  assert.equal(first.plan.period.state, "not_observed");
  assert.equal(first.status.observed, false);
  assert.equal(first.status.subscription.remaining_charge_in_period, null);
  assert.equal(first.route_previews.charge.cdp.execution_route, "cdp_tx_hash");
  assert.equal(first.route_previews.charge.cdp.preview_only, true);
  assert.equal(first.route_previews.charge.cdp.descriptor_only, false);
  assert.equal(first.route_previews.charge.cdp.calls_status_route, false);
  assert.equal(first.route_previews.charge.cdp.tx_hash, null);
  assert.equal(first.route_previews.charge.cdp.calls_id, null);
  assert.equal(first.route_previews.charge.cdp.wallet_request, null);
  assert.equal(first.route_previews.charge.manual.execution_route, "manual_wallet_sendCalls");
  assert.equal(first.route_previews.charge.manual.preview_only, false);
  assert.equal(first.route_previews.charge.manual.descriptor_only, true);
  assert.equal(first.route_previews.charge.manual.atomic_required, true);
  assert.equal(first.route_previews.charge.manual.calls_status_route, true);
  assert.equal(first.route_previews.charge.manual.calls_id, null);
  assert.equal(first.route_previews.charge.manual.tx_hash, null);
  assert.equal(first.route_previews.charge.manual.wallet_request, null);
  assert.equal(first.gates.receipt.state, "not_observed");
  assert.equal(first.gates.receipt.transaction_hash, null);
  assert.equal(first.gates.finality.required, "l1_batch_final");
  assert.equal(first.gates.erp.posting, false);
  assert.equal(first.gates.erp.business_close, false);
  assert.equal(first.safety.external_actions, 0);
  assert.equal(first.safety.wallet_request, null);
  assert.equal(first.safety.broadcast, false);
  const raw = JSON.stringify(first);
  assert.ok(!raw.includes(RECURRING_PAYER.toLowerCase()));
  assert.ok(!raw.includes(RECURRING_SPENDER.toLowerCase()));
  assert.ok(!raw.includes(RECURRING_TOKEN));
  assert.ok(!raw.includes(RECURRING_PERMISSION_HASH));
});

test("recurring settlement composes H213 for a server-owned subscription record", () => {
  const projection = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: RECURRING_SUBSCRIPTION_RECORD });
  assert.equal(projection.status.state, "active");
  assert.equal(projection.status.observed, true);
  assert.equal(projection.status.subscription.remaining_charge_in_period, "450");
  assert.equal(projection.status.subscription.current_period_start, 1750000000);
  assert.equal(projection.status.subscription.next_period_start, 1750086400);
  assert.equal(projection.plan.status_adapter, "subscription");
  assert.equal(projection.plan.network.chain_id, 84532);
  assert.equal(projection.plan.recurring_charge.value, "25");
  assert.equal(projection.plan.remaining_allowance.value, "450");
  assert.equal(projection.plan.period.no_rollover, true);
  assert.equal(projection.plan.period.current_period_start, 1750000000);
  assert.equal(projection.plan.period.next_period_start, 1750086400);
  assert.equal(projection.gates.erp.posting, false);
  assert.equal(projection.gates.erp.business_close, false);
  assert.equal(projection.safety.public_write_authorized, false);
  const raw = JSON.stringify(projection);
  assert.ok(!raw.includes(RECURRING_PAYER.toLowerCase()));
  assert.ok(!raw.includes(RECURRING_SPENDER.toLowerCase()));
  assert.ok(!raw.includes(RECURRING_TOKEN));
  assert.ok(!raw.includes(RECURRING_PERMISSION_HASH));
});

test("recurring settlement composes H213 for a server-owned spend permission record", () => {
  const projection = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: RECURRING_SPEND_PERMISSION_RECORD });
  assert.equal(projection.status.state, "active");
  assert.equal(projection.status.observed, true);
  assert.equal(projection.status.spend_permission.remaining_spend, "480");
  assert.equal(projection.status.adapter, "spend_permission");
  assert.equal(projection.plan.network.chain_id, 84532);
  assert.equal(projection.plan.recurring_charge.value, "20");
  assert.equal(projection.plan.remaining_allowance.value, "480");
  const raw = JSON.stringify(projection);
  assert.ok(!raw.includes(RECURRING_SALT));
  assert.ok(!raw.includes(RECURRING_PAYER.toLowerCase()));
  assert.ok(!raw.includes(RECURRING_TOKEN));
});

test("recurring settlement composes H213 deterministically for repeated record calls", () => {
  const first = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: RECURRING_SUBSCRIPTION_RECORD });
  const second = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: RECURRING_SUBSCRIPTION_RECORD });
  assert.deepEqual(first, second);
  const pendingFirst = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: { ...RECURRING_SUBSCRIPTION_RECORD, subscription_readback: {} } });
  const pendingSecond = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: { ...RECURRING_SUBSCRIPTION_RECORD, subscription_readback: {} } });
  assert.deepEqual(pendingFirst, pendingSecond);
});

test("recurring settlement record with a pending readback stays pending with bound metadata only", () => {
  const projection = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: { ...RECURRING_SUBSCRIPTION_RECORD, subscription_readback: {} } });
  assert.equal(projection.status.state, "status_readback_pending");
  assert.equal(projection.status.observed, false);
  assert.equal(projection.status.adapter, "subscription");
  assert.equal(projection.plan.status_adapter, "subscription");
  assert.equal(projection.plan.recurring_charge.value, "25");
  assert.equal(projection.plan.remaining_allowance.value, null);
  assert.equal(projection.plan.period.current_period_start, null);
});

test("invalid recurring settlement records map to recovery_ready with stable reasons and no raw echo", () => {
  const cases = [
    { record: {}, reason: "server_record_case_required" },
    { record: "client-hint", reason: "server_record_invalid" },
    { record: { case: { case_id: "base-erp-h214-recurring-bad", permission_ref: "internal-bad", payer: RECURRING_PAYER, spender: RECURRING_SPENDER, token: RECURRING_TOKEN, chain_id: 84532, testnet: true, allowance: "500.00", period_seconds: 86400, start: 1750000000, end: 1752688000, recurring_charge: "25.00", status_adapter: "subscription" } }, reason: "subscribe_rejected_no_permission" },
    { record: { ...RECURRING_SUBSCRIPTION_RECORD, client_hints: { id: "injected" } }, reason: "browser_client_hints_rejected" },
    { record: { case: { ...RECURRING_SUBSCRIPTION_RECORD.case, client_hints: { id: "injected" } }, subscription_readback: RECURRING_SUBSCRIPTION_RECORD.subscription_readback, observed: RECURRING_SUBSCRIPTION_RECORD.observed }, reason: "browser_client_hints_rejected" },
  ];
  for (const { record, reason } of cases) {
    const projection = buildRecurringSettlementProjection({ release: TEST_RELEASE, server_record: record });
    assert.equal(projection.status.state, "recovery_ready", reason);
    assert.equal(projection.status.reason, reason);
    assert.equal(projection.status.observed, false);
    assert.equal(projection.status.subscription, null);
    assert.equal(projection.status.spend_permission, null);
    const raw = JSON.stringify(projection);
    assert.ok(!raw.includes(RECURRING_PAYER.toLowerCase()));
    assert.ok(!raw.includes(RECURRING_SPENDER.toLowerCase()));
    assert.ok(!raw.includes(RECURRING_TOKEN));
    assert.ok(!raw.includes(RECURRING_PERMISSION_HASH));
  }
});

test("operator workbench adds the recurring settlement projection without changing the seven-row queue", () => {
  const visitor = buildOperatorWorkbench({ release: TEST_RELEASE, selected_profile_id: "payment_refund_incoming" });
  assert.equal(visitor.queue.length, 7);
  assert.equal(visitor.queue.filter((row) => row.selected).length, 1);
  assert.equal(visitor.selected_case.profile_id, "payment_refund_incoming");
  assert.deepEqual(visitor.landmarks, ["global-control-shell", "case-queue", "decision-canvas", "evidence-inspector"]);
  assert.equal(visitor.recurring_settlement.schema_version, "base-erp-h214-recurring-settlement-public-v1");
  assert.equal(visitor.recurring_settlement.status.state, "status_readback_pending");
  const observed = buildOperatorWorkbench({ release: TEST_RELEASE, server_record: RECURRING_SUBSCRIPTION_RECORD });
  assert.equal(observed.queue.length, 7);
  assert.equal(observed.queue.filter((row) => row.selected).length, 1);
  assert.equal(observed.recurring_settlement.status.state, "active");
  assert.equal(observed.recurring_settlement.plan.recurring_charge.value, "25");
});

test("operator workbench HTML renders the recurring settlement surface with actions disabled", () => {
  const html = renderOperatorWorkbenchPage(buildOperatorWorkbench({ release: TEST_RELEASE }));
  assert.match(html, /Recurring settlement/);
  assert.match(html, /status_readback_pending/);
  assert.match(html, /subscription/);
  assert.match(html, /spend_permission/);
  assert.match(html, /No rollover/);
  assert.match(html, /cdp_tx_hash/);
  assert.match(html, /preview only/);
  assert.match(html, /wallet_sendCalls/);
  assert.match(html, /descriptor only/);
  assert.match(html, /atomic required/);
  assert.match(html, /l1_batch_final/);
  assert.match(html, /non-posting/);
  assert.match(html, /business close false/);
  assert.match(html, /<button disabled>Recurring actions disabled<\/button>/);
  assert.ok(!html.includes(RECURRING_PAYER.toLowerCase()));
  assert.ok(!html.includes(RECURRING_SPENDER.toLowerCase()));
  assert.ok(!html.includes(RECURRING_TOKEN));
  assert.ok(!html.includes(RECURRING_PERMISSION_HASH));
});

test("operator workbench HTML renders observed recurring readback values without raw identity", () => {
  const html = renderOperatorWorkbenchPage(buildOperatorWorkbench({ release: TEST_RELEASE, server_record: RECURRING_SUBSCRIPTION_RECORD }));
  assert.match(html, /Recurring settlement/);
  assert.ok(html.includes("25 per period"));
  assert.ok(html.includes(">450<"));
  assert.match(html, />subscription · chain 84532/);
  assert.ok(!html.includes(RECURRING_PAYER.toLowerCase()));
  assert.ok(!html.includes(RECURRING_SPENDER.toLowerCase()));
  assert.ok(!html.includes(RECURRING_TOKEN));
  assert.ok(!html.includes(RECURRING_PERMISSION_HASH));
});

const V9_OBSERVED_AT = "2026-08-16T18:05:00.000Z";

function v9TestReleaseIdentity(release) {
  return {
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    commit_sha: release.git_commit,
    source_catalog_fingerprint: V9_SOURCE_CATALOG_FINGERPRINT,
  };
}

function v9TestRuntimeBinding(releaseIdentity, observedAt = V9_OBSERVED_AT) {
  return {
    runtime_sha256: "d".repeat(64),
    run_id: "02_Build-20260816-181000",
    cursor: { active_item_id: "" },
    writer_idle: true,
    observed_at: observedAt,
    release_id: releaseIdentity.release_id,
    release_fingerprint: releaseIdentity.release_fingerprint,
    bom_fingerprint: releaseIdentity.bom_fingerprint,
    commit_sha: releaseIdentity.commit_sha,
    source_catalog_fingerprint: releaseIdentity.source_catalog_fingerprint,
  };
}

async function startV9Server({ releasePath, runtimeReader = () => ({ runtime_sha256: "d".repeat(64), run_id: "02_Build-20260816-181000", cursor: { active_item_id: "" }, writer_idle: true, writer_idle_authority: { writer_idle: true } }) } = {}) {
  const server = createAppServer({ releasePath, env: { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT }, runtimeReader });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  return { server, baseUrl: `http://127.0.0.1:${address.port}` };
}

async function actualV9RouteReadbacks(baseUrl, releaseIdentity, observedAt = V9_OBSERVED_AT) {
  const readbacks = [];
  for (const path of REQUIRED_ROUTE_PATHS) {
    const response = await fetch(`${baseUrl}${path}`);
    const payload = await response.text();
    readbacks.push({
      path,
      method: "GET",
      http_status: response.status,
      claim_state: response.status === 200 ? "current" : "unready",
      response_sha256: sha256(payload),
      release_identity: releaseIdentity,
      observed_at: observedAt,
      generated_by: ["code_test_contract", "src/server.mjs", "test/server.test.mjs"],
    });
  }
  return readbacks;
}

async function withV9Baseline(run) {
  return withTempCandidate(recomputeV9Candidate(), async (releasePath) => {
    const { server, baseUrl } = await startV9Server({ releasePath });
    try {
      const release = readReleaseDocument({ releasePath, env: { GIT_COMMIT_SHA: TEST_COMMIT } });
      const candidate = JSON.parse(readFileSync(releasePath, "utf8"));
      const releaseIdentity = v9TestReleaseIdentity(release);
      const input = buildV9IntegritySealInput({
        release,
        candidate,
        routeReadbacks: await actualV9RouteReadbacks(baseUrl, releaseIdentity),
        runtimeBinding: v9TestRuntimeBinding(releaseIdentity),
        observedAt: V9_OBSERVED_AT,
      });
      return await run({ release, input, releaseIdentity, candidate, releasePath, baseUrl });
    } finally {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
}

test("v9 integrity seal input binds the actual v9 candidate and stays zero-credit deterministic", async () => {
  await withV9Baseline(({ release, input, releaseIdentity, candidate }) => {
    const first = evaluateReleaseEvidenceSeal(input);
    const second = evaluateReleaseEvidenceSeal(buildV9IntegritySealInput({
      release,
      candidate,
      routeReadbacks: Object.values(input.route_readbacks),
      runtimeBinding: v9TestRuntimeBinding(releaseIdentity),
      observedAt: V9_OBSERVED_AT,
    }));
    assert.equal(first.ok, true);
    assert.equal(first.state, "integrity_seal_candidate_ready");
    assert.equal(first.seal_digest, second.seal_digest);
    assert.deepEqual(first.release_identity, {
      release_id: release.release_id,
      release_fingerprint: release.release_fingerprint,
      bom_fingerprint: release.bom_fingerprint,
      commit_sha: TEST_COMMIT,
      source_catalog_fingerprint: V9_SOURCE_CATALOG_FINGERPRINT,
    });
    assert.equal(Object.keys(first.source_digests).length, 3);
    assert.equal(Object.keys(first.route_readbacks).length, 10);
    assert.equal(first.claim_bindings.length, 10);
    assert.deepEqual(Object.keys(first.platform_evidence), [...REQUIRED_PLATFORM_IDS]);
    for (const route of Object.values(first.route_readbacks)) {
      assert.equal(route.http_status, 200);
      assert.equal(route.claim_state, "current");
      assert.ok(route.generated_by.includes("code_test_contract"));
    }
    for (const claim of first.claim_bindings) {
      assert.equal(claim.source_sha256, first.source_digests[claim.source_path]);
      assert.equal(claim.route_response_sha256, first.route_readbacks[claim.route_path].response_sha256);
      assert.equal(claim.generated_by, "code_test_contract");
    }
    const baseApp = first.platform_evidence.base_app;
    assert.equal(baseApp.evidence_class, "attribution_metadata");
    assert.equal(baseApp.attribution_observed, true);
    assert.equal(baseApp.is_receipt, false);
    const rehearsal = first.platform_evidence.base_sepolia_rehearsal;
    assert.equal(rehearsal.evidence_class, "chain_receipt");
    assert.equal(rehearsal.is_receipt, false);
    for (const row of Object.values(first.platform_evidence)) {
      assert.equal(row.is_receipt, false);
      assert.equal(row.credit, 0);
      assert.equal(row.current, false);
      assert.equal(row.historical, false);
      assert.equal(row.synthetic, false);
    }
    assert.equal(first.runtime_binding.writer_idle, true);
    assert.deepEqual(first.runtime_binding.cursor, { active_item_id: "" });
    assert.equal(first.credit, 0);
    assert.equal(first.publication_unit_credit, 0);
    assert.equal(first.mainnet_30_credit, 0);
    assert.equal(first.build_credit_eligible, false);
    assert.equal(first.execution_authority, "none_until_02_Build_revalidates");
    assert.equal(first.external_actions, 0);
    assert.equal(verifyReleaseEvidenceSeal(first).ok, true);
  });
});

test("v9 integration fails closed for stale/forged catalog, drift, rehearsal, collision and credit", async () => {
  await withV9Baseline(({ input, releaseIdentity }) => {
    const expect = (mutated, reason) => {
      const result = evaluateReleaseEvidenceSeal(mutated);
      assert.equal(result.ok, false, reason);
      assert.equal(result.reason, reason);
      assert.equal(result.fail_closed, true);
      assert.equal(result.credit, 0);
      assert.equal(result.external_actions, 0);
    };

    const staleRoutes = structuredClone(input);
    staleRoutes.route_readbacks[0].observed_at = "2026-08-16T17:00:00.000Z";
    expect(staleRoutes, "evidence_stale");

    const staleClaims = structuredClone(input);
    staleClaims.claim_bindings[0].observed_at = "2026-08-16T17:00:00.000Z";
    expect(staleClaims, "claim_stale");

    const forgedCatalog = structuredClone(input);
    forgedCatalog.source_digests = { ...input.source_digests, "README.md": "0".repeat(64) };
    expect(forgedCatalog, "source_catalog_fingerprint_mismatch");

    const commitDrift = structuredClone(input);
    commitDrift.route_readbacks[0].release_identity = { ...releaseIdentity, commit_sha: "d".repeat(40) };
    expect(commitDrift, "route_release_binding_mismatch");

    const runtimeWriterBusy = structuredClone(input);
    runtimeWriterBusy.runtime_binding.writer_idle = false;
    expect(runtimeWriterBusy, "runtime_writer_not_idle");

    const runtimeHashInvalid = structuredClone(input);
    runtimeHashInvalid.runtime_binding.runtime_sha256 = "not-a-sha256-digest";
    expect(runtimeHashInvalid, "runtime_hash_invalid");

    const runtimeCommitDrift = structuredClone(input);
    runtimeCommitDrift.runtime_binding.commit_sha = "d".repeat(40);
    expect(runtimeCommitDrift, "runtime_release_binding_mismatch");

    const syntheticRow = structuredClone(input);
    syntheticRow.platform_evidence[0].synthetic = true;
    expect(syntheticRow, "platform_historical_or_synthetic");

    const stalePlatform = structuredClone(input);
    stalePlatform.platform_evidence[0].observed_at = "2026-08-16T17:00:00.000Z";
    expect(stalePlatform, "platform_evidence_stale");

    const newRehearsal = structuredClone(input);
    newRehearsal.platform_evidence.find((row) => row.platform === "base_sepolia_rehearsal").new_rehearsal = true;
    expect(newRehearsal, "new_rehearsal_forbidden");

    const relabelAttribution = structuredClone(input);
    relabelAttribution.platform_evidence.find((row) => row.platform === "base_app").is_receipt = true;
    expect(relabelAttribution, "attribution_claimed_as_receipt");

    const circleCollision = structuredClone(input);
    circleCollision.platform_evidence[0].target = "gaysonloser/arc-payment-receipt";
    expect(circleCollision, "circle_target_collision");

    const seal = evaluateReleaseEvidenceSeal(input);
    for (const tampered of [
      { ...seal, credit: 99 },
      { ...seal, publication_unit_credit: 1 },
      { ...seal, external_actions: 1 },
      { ...seal, build_credit_eligible: true },
    ]) {
      const verified = verifyReleaseEvidenceSeal(tampered);
      assert.equal(verified.ok, false);
      assert.equal(verified.reason, "integrity_seal_security_boundary_mismatch");
      assert.ok(verified.failure_codes.includes("V9-F55"));
    }
  });
});

test("v9 integrity seal route seals actual v9-ready public routes with zero credit", async () => {
  const runtimeReader = () => ({
    runtime_sha256: "d".repeat(64),
    run_id: "02_Build-20260816-181000",
    cursor: { active_item_id: "" },
    writer_idle: true,
    writer_idle_authority: { writer_idle: true },
  });
  await withTempCandidate(recomputeV9Candidate(), async (releasePath) => withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/integrity-seal.json`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, true);
    assert.equal(body.state, "integrity_seal_candidate_ready");
    assert.equal(body.seal_verified, true);
    assert.equal(body.credit, 0);
    assert.equal(body.publication_unit_credit, 0);
    assert.equal(body.mainnet_30_credit, 0);
    assert.equal(body.build_credit_eligible, false);
    assert.equal(body.execution_authority, "none_until_02_Build_revalidates");
    assert.equal(body.external_actions, 0);
    assert.deepEqual(body.failure_codes, []);
    assert.equal(body.release_identity.release_id, "base-erp-public-product-20260816-v9");
    assert.equal(body.release_identity.commit_sha, TEST_COMMIT);
    assert.equal(body.release_identity.source_catalog_fingerprint, V9_SOURCE_CATALOG_FINGERPRINT);
    assert.equal(Object.keys(body.route_readbacks).length, 10);
    for (const path of REQUIRED_ROUTE_PATHS) {
      const route = body.route_readbacks[path];
      assert.equal(route.http_status, 200, path);
      assert.equal(route.claim_state, "current", path);
      assert.match(route.response_sha256, /^[0-9a-f]{64}$/);
      assert.ok(route.generated_by.includes("code_test_contract"));
      assert.deepEqual(route.release_identity, body.release_identity);
    }
    assert.equal(body.claim_bindings.length, 10);
    for (const claim of body.claim_bindings) {
      assert.equal(claim.source_sha256, body.source_digests[claim.source_path]);
      assert.equal(claim.route_response_sha256, body.route_readbacks[claim.route_path].response_sha256);
      assert.equal(claim.generated_by, "code_test_contract");
    }
    assert.deepEqual(Object.keys(body.platform_evidence), [...REQUIRED_PLATFORM_IDS]);
    for (const row of Object.values(body.platform_evidence)) {
      assert.equal(row.is_receipt, false);
      assert.equal(row.credit, 0);
      assert.equal(row.current, false);
      assert.equal(row.historical, false);
      assert.equal(row.synthetic, false);
    }
    assert.equal(body.platform_evidence.base_app.evidence_class, "attribution_metadata");
    assert.equal(body.platform_evidence.base_app.attribution_observed, true);
    assert.equal(body.platform_evidence.base_sepolia_rehearsal.evidence_class, "chain_receipt");
    assert.equal(body.runtime_binding.writer_idle, true);
    assert.deepEqual(body.runtime_binding.cursor, { active_item_id: "" });
    assert.equal(body.runtime_binding.run_id, "02_Build-20260816-181000");
    assert.equal(verifyReleaseEvidenceSeal(body).ok, true);
  }, { runtimeReader, releasePath }));
});

test("v9 candidate gate rejects catalog drift, fake owner receipts and BASE/CIRCLE collisions", async () => {
  await withV9Baseline(({ release, input, candidate }) => {
    const expectRejected = (mutated, code) => {
      assert.throws(
        () => buildV9IntegritySealInput({
          release,
          candidate: mutated,
          routeReadbacks: input.route_readbacks,
          runtimeBinding: input.runtime_binding,
          observedAt: V9_OBSERVED_AT,
        }),
        (error) => error?.v9_gate === true && error.failure_code === code,
      );
    };
    const catalog = structuredClone(candidate);
    catalog.source_digest_catalog["README.md"] = "0".repeat(64);
    expectRejected(catalog, "V9-F56");
    const fakeOwnerReceipt = structuredClone(candidate);
    fakeOwnerReceipt.eight_surface_evidence_map = {
      ...(fakeOwnerReceipt.eight_surface_evidence_map ?? {}),
      github: {
        ...(fakeOwnerReceipt.eight_surface_evidence_map?.github ?? {}),
      is_receipt: true,
      receipt_ref: "fake-owner-receipt",
      provenance: { owner_native: false, source: "self_reported", observed_at: V9_OBSERVED_AT },
      },
    };
    expectRejected(fakeOwnerReceipt, "V9-F57");
    const arbitraryFingerprint = structuredClone(candidate);
    arbitraryFingerprint.release_fingerprint = "f".repeat(64);
    expectRejected(arbitraryFingerprint, "V9-F99");
    const arbitraryCommit = structuredClone(candidate);
    arbitraryCommit.commit_sha = "f".repeat(64);
    arbitraryCommit.commit_placeholder = false;
    expectRejected(arbitraryCommit, "V9-F99");
    const collision = structuredClone(candidate);
    collision.base_target.github_repo = "gaysonloser/arc-payment-receipt";
    expectRejected(collision, "V9-F01");
    const staleSelfHash = structuredClone(candidate);
    staleSelfHash.self_hash = "0".repeat(64);
    expectRejected(staleSelfHash, "V9-F99");
    const staleBomCount = structuredClone(candidate);
    staleBomCount.bom_file_count -= 1;
    expectRejected(staleBomCount, "V9-F99");
  });
});

test("v9 integrity seal route rejects client binding and fails closed on runtime/commit drift", async () => {
  await withTempCandidate(recomputeV9Candidate(), async (releasePath) => withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/integrity-seal.json?release_id=secret-value`);
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "client_binding_not_accepted" });
  }, { releasePath }));
  await withTempCandidate(recomputeV9Candidate(), async (releasePath) => withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/integrity-seal.json`);
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.equal(body.fail_closed, true);
    assert.ok(body.failure_codes.includes("V9-F31"));
  }, { releasePath }));
  await withTempCandidate(recomputeV9Candidate(), async (releasePath) => withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/integrity-seal.json`);
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.ok(body.failure_codes.includes("V9-F37"));
  }, { runtimeReader: () => ({ runtime_sha256: "d".repeat(64), run_id: "drift", cursor: { active_item_id: "" }, writer_idle: false }), releasePath }));
  await withTempCandidate(JSON.parse(readFileSync("runtime/release_candidate_v9_local_2026-08-16.json", "utf8")), async (releasePath) => withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/integrity-seal.json`);
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.ok(body.failure_codes.includes("V9-F99"));
  }, { env: { ...process.env }, releasePath }));
});
