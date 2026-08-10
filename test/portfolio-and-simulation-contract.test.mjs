import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const root = new URL("../", import.meta.url);
const readJson = (relativePath) => JSON.parse(fs.readFileSync(new URL(relativePath, root), "utf8"));

const portfolio = readJson("config/real_interaction_portfolio_contract_v1.json");
const simulationSchema = readJson("config/simulated_transaction_record_schema.json");
const fixture = readJson("fixtures/simulated_transactions.json");
const primary = portfolio.identity.primary_base_account.toLowerCase();

const expectedLanes = new Set([
  "base_mainnet_state_change",
  "base_sepolia_product_evidence",
  "vibenet_b20_experiment",
  "x402_independent_authorization",
  "contract_deploy_or_call",
  "swap",
]);

test("real-interaction portfolio is planning-only and cannot register a daily queue", () => {
  assert.equal(portfolio.activation.mode, "planning_only");
  assert.equal(portfolio.activation.runtime_queue_registration, false);
  assert.equal(portfolio.activation.current_run_date_cst, "2026-08-04");
  assert.equal(portfolio.activation.eligible_from, "next_cst_date_after_current_run");
  assert.equal(portfolio.identity.basename, "gaysonloser.base.eth");
  assert.equal(portfolio.identity.primary_base_account.toLowerCase(), primary);
  assert.equal(portfolio.identity.full_address_required_in_release, true);
  assert.deepEqual(new Set(portfolio.lanes.map((lane) => lane.id)), expectedLanes);
});

test("portfolio separates network/counting boundaries and preserves the eight-platform fingerprint", () => {
  const byId = Object.fromEntries(portfolio.lanes.map((lane) => [lane.id, lane]));
  assert.deepEqual(byId.base_mainnet_state_change.chain_ids, [8453]);
  assert.equal(byId.base_mainnet_state_change.daily_30_eligible, true);
  assert.deepEqual(byId.base_sepolia_product_evidence.chain_ids, [84532]);
  assert.equal(byId.base_sepolia_product_evidence.daily_30_eligible, false);
  assert.deepEqual(byId.vibenet_b20_experiment.chain_ids, [84538453]);
  assert.equal(byId.vibenet_b20_experiment.daily_30_eligible, false);
  assert.deepEqual(byId.swap.chain_ids, [8453]);
  assert.equal(byId.swap.daily_30_eligible, "conditional");
  assert.deepEqual(portfolio.publication_bundle.required_platforms, [
    "github",
    "render",
    "base_app",
    "base_dashboard",
    "base_dev",
    "talent",
    "guild",
    "basename_base_org",
  ]);
  assert.equal(portfolio.publication_bundle.same_outcome_required, true);
  assert.equal(portfolio.publication_bundle.same_release_fingerprint_required, true);
});

test("every simulation record is complete, isolated and structurally non-countable", () => {
  const scenarioEnum = new Set(simulationSchema.properties.scenario.enum);
  const records = fixture.records;
  assert.equal(records.length, scenarioEnum.size);
  assert.deepEqual(new Set(records.map((record) => record.scenario)), scenarioEnum);
  assert.equal(new Set(records.map((record) => record.record_id)).size, records.length);

  for (const record of records) {
    assert.equal(record.schema_version, "1.0");
    assert.equal(record.simulated, true, record.record_id);
    assert.equal(record.evidence_level, "L0", record.record_id);
    assert.equal(record.count_eligible, false, record.record_id);
    assert.equal(record.transaction_hash, null, record.record_id);
    assert.equal(record.broadcast_status, "not_broadcast", record.record_id);
    assert.equal(record.wallet.toLowerCase(), primary, record.record_id);
    assert.ok(record.assumptions.length >= 1, record.record_id);
    assert.ok([8453, 84532, 84538453].includes(record.chain_id), record.record_id);
  }
});

test("simulation fixture covers the intended network boundaries", () => {
  const byScenario = Object.fromEntries(fixture.records.map((record) => [record.scenario, record]));
  assert.equal(byScenario.smart_wallet_payable.chain_id, 8453);
  assert.equal(byScenario.smart_wallet_receivable.chain_id, 84532);
  assert.equal(byScenario.x402_service_settlement.chain_id, 84532);
  assert.equal(byScenario.b20_inventory_lifecycle.chain_id, 84538453);
  assert.equal(byScenario.treasury_swap_reconciliation.chain_id, 8453);
  assert.equal(byScenario.agentic_workflow_evidence.broadcast_status, "not_broadcast");
  assert.match(byScenario.agentic_workflow_evidence.assumptions.join(" "), /Agentic Wallet is absent/);
});
