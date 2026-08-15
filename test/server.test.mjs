import test from "node:test";
import assert from "node:assert/strict";

import { createAppServer } from "../src/server.mjs";
import { buildOperatorWorkbench, buildRecurringSettlementProjection } from "../src/base-erp-workbench.mjs";
import { renderOperatorWorkbenchPage } from "../src/operator-workbench-page.mjs";

const TEST_COMMIT = "a".repeat(40);

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
    assert.equal(body.release.release_id, "base-erp-public-product-20260815-v6");
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
