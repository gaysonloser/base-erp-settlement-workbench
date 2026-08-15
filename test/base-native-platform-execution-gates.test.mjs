import test from "node:test";
import assert from "node:assert/strict";
import {
  AUTHORITY_NONE,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_ID_HEX,
  BASE_SEPOLIA_DESCRIPTOR,
  BASE_SEPOLIA_EXPLORER_URL,
  BASE_SEPOLIA_RPC_URL,
  CIRCLE_DENYLIST,
  EXECUTION_AUTHORITY,
  H217_BATCH_ID,
  H217_CONTRACT,
  H217_FAILURE_MODES,
  H217_PACKET_ID,
  H217_PLATFORM_ROW_IDS,
  H217_RELEASE_ENVELOPE,
  H217_RELEASE_JOIN,
  H217_SOURCE_HASHES,
  H217_TEST_VECTORS,
  SCHEMA_VERSION,
  aggregateCredit,
  buildH217Readback,
  compareReleaseJoin,
  createH217EvidenceEnvelope,
  digest,
  evaluateBaseSepoliaRehearsal,
  evaluateBasenameIdentity,
  evaluateGuildNativeDomain,
  evaluateH217Row,
  evaluateTalentNativeDomain,
  getH217Contract,
  validateBaseCircleIsolation,
  validateCurrentV7Release,
  validateH217Envelope,
  validateH217PacketRevalidation,
  validateH217PublicEnvelope,
} from "../src/base-native-platform-execution-gates.mjs";

const tx = (hex = "1") => `0x${hex.repeat(64).slice(0, 64)}`;
const goodReceipt = { chain_id: 84532, transaction_hash: tx("a"), block_hash: tx("b"), block_number: 7, transaction_index: 0, status: "0x1", gas_used: "0x1", logs: [] };
const goodTalent = { project_id: "talent-project-1", project_url: "https://talent.app/project/base-erp", owner_readback: { project_id: "talent-project-1", title: "Base ERP Settlement Workbench" } };
const goodGuild = { guild_slug: "base-erp-settlement-workbench", project_url: "https://guild.xyz/base-erp-settlement-workbench", visitor_readback: { roles: [], requirements: [], rewards: [] } };
const goodBasename = { account_level_singleton: true, resolver_readback: { primary: true } };
const packet = { status: "accepted_for_02_Build_bounded_pending_revalidation_non_executable", batch_id: H217_BATCH_ID, acceptance: { review_status: "reviewed", review_verdict: "pass", reviewer: "independent fresh root gpt-5.6-sol/medium", severity: { p0: 0, p1: 0, p2: 0 } } };

test("H217 schema, packet, authority and exact source hashes", () => {
  assert.equal(SCHEMA_VERSION, "base-erp-h217-platform-execution-gates-v1");
  assert.equal(H217_PACKET_ID, "base-erp-h217-remaining-platform-execution-gates-20260815");
  assert.equal(EXECUTION_AUTHORITY, "none_until_02_Build_revalidates");
  assert.equal(AUTHORITY_NONE, EXECUTION_AUTHORITY);
  assert.deepEqual(Object.keys(H217_SOURCE_HASHES), ["manifest_sha256", "artifact_sha256", "handoff_sha256"]);
  for (const value of Object.values(H217_SOURCE_HASHES)) assert.match(value, /^[0-9a-f]{64}$/);
});

test("H217 has exactly four rows, sixteen vectors and sixteen fail-closed modes", () => {
  assert.deepEqual([...H217_PLATFORM_ROW_IDS], ["base_sepolia_rehearsal", "talent_native_domain", "guild_native_domain", "basename_base_org_identity"]);
  assert.equal(H217_TEST_VECTORS.length, 16);
  assert.deepEqual(H217_TEST_VECTORS.map(({ id }) => id), Array.from({ length: 16 }, (_, i) => `H217-${String(i + 1).padStart(2, "0")}`));
  assert.equal(H217_FAILURE_MODES.length, 16);
  assert.deepEqual(H217_FAILURE_MODES.map(({ id }) => id), Array.from({ length: 16 }, (_, i) => `H217-F${String(i + 1).padStart(2, "0")}`));
  for (const failure of H217_FAILURE_MODES) {
    assert.equal(failure.fail_closed, true);
    assert.equal(failure.credit, 0);
  }
});

test("Base Sepolia descriptor is exact and rehearsal-only", () => {
  assert.equal(BASE_SEPOLIA_CHAIN_ID, 84532);
  assert.equal(BASE_SEPOLIA_CHAIN_ID_HEX, "0x14a34");
  assert.equal(BASE_SEPOLIA_RPC_URL, "https://sepolia.base.org");
  assert.equal(BASE_SEPOLIA_EXPLORER_URL, "https://sepolia.basescan.org");
  assert.deepEqual(BASE_SEPOLIA_DESCRIPTOR, { network: "base-sepolia", chain_id: 84532, chain_id_hex: "0x14a34", rpc_url: BASE_SEPOLIA_RPC_URL, explorer_url: BASE_SEPOLIA_EXPLORER_URL, rehearsal_only: true });
  assert.equal(evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR }).status, "rehearsal_pending");
});

test("H217-01/02 descriptor validation fails closed on wrong chain or explorer", () => {
  const valid = evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR });
  assert.equal(valid.reason, "descriptor_valid_receipt_missing");
  assert.equal(valid.credit, 0);
  const wrongChain = evaluateBaseSepoliaRehearsal({ descriptor: { ...BASE_SEPOLIA_DESCRIPTOR, chain_id: 8453 } });
  assert.equal(wrongChain.failure_state.id, "H217-F03");
  const wrongExplorer = evaluateBaseSepoliaRehearsal({ descriptor: { ...BASE_SEPOLIA_DESCRIPTOR, explorer_url: "https://basescan.org" } });
  assert.equal(wrongExplorer.failure_state.id, "H217-F03");
});

test("H217-03 null receipt remains rehearsal pending", () => {
  const result = evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR, receipt: null });
  assert.equal(result.status, "rehearsal_pending");
  assert.equal(result.native_receipt, null);
  assert.equal(result.finality_stage, null);
  assert.equal(result.failure_state.id, "H217-F04");
  assert.equal(result.credit, 0);
});

test("H217-04 receipt without explicit finality never infers finality", () => {
  const result = evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR, receipt: goodReceipt });
  assert.equal(result.status, "finality_missing");
  assert.equal(result.finality_stage, null);
  assert.equal(result.failure_state.id, "H217-F05");
  assert.equal(result.credit, 0);
});

test("H217-05 explicit finality permits rehearsal readback but remains zero credit", () => {
  const result = evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR, receipt: goodReceipt, finality_stage: "l1_batch_finality" });
  assert.equal(result.status, "rehearsal_readback_valid");
  assert.equal(result.failure_state, null);
  assert.equal(result.finality_stage, "l1_batch_finality");
  assert.equal(result.release_receipt, false);
  assert.equal(result.credit, 0);
});

test("Sepolia invalid receipt fields fail closed", () => {
  const invalid = evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR, receipt: { ...goodReceipt, transaction_hash: "0x1" }, finality_stage: "l1_batch_finality" });
  assert.equal(invalid.failure_state.id, "H217-F04");
  assert.equal(invalid.credit, 0);
});

test("H217-06 exact v7 release join is required and immutable", () => {
  const ok = validateCurrentV7Release(H217_RELEASE_ENVELOPE);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.release_join, H217_RELEASE_JOIN);
  assert.equal(compareReleaseJoin(H217_RELEASE_ENVELOPE, H217_RELEASE_ENVELOPE, H217_RELEASE_ENVELOPE).same_release, true);
  const bad = validateCurrentV7Release({ ...H217_RELEASE_ENVELOPE, bom_fingerprint: "0".repeat(64) });
  assert.equal(bad.ok, false);
  assert.equal(bad.failure_id, "H217-F02");
});

test("Public v7 envelope joins GitHub, Render and canonical Dashboard without aliases", () => {
  // Independent literal: this must not merely self-confirm a copied constant.
  assert.equal(H217_RELEASE_ENVELOPE.render_deployment_id, "dep-da00nk1t0dsc738jpuv0");
  assert.notEqual(H217_RELEASE_ENVELOPE.render_deployment_id, "dep-da00fm1egvs73fib5c0");
  const result = validateH217PublicEnvelope({
    release: H217_RELEASE_ENVELOPE,
    github: { ...H217_RELEASE_ENVELOPE, repo: "gaysonloser/base-erp-settlement-workbench", branch: "main", commit_sha: H217_RELEASE_ENVELOPE.commit_sha },
    render: { ...H217_RELEASE_ENVELOPE, service_id: H217_RELEASE_ENVELOPE.render_service_id, deployment_id: H217_RELEASE_ENVELOPE.render_deployment_id, commit_sha: H217_RELEASE_ENVELOPE.commit_sha, health_ready: true, health_status: "ok" },
    dashboard: { app_id: H217_RELEASE_ENVELOPE.canonical_dashboard_app_id, primary_url: H217_RELEASE_ENVELOPE.canonical_primary_url },
  });
  assert.equal(result.ok, true);
  assert.equal(result.credit, 0);
  assert.equal(result.legs.dashboard, true);
  for (const missing of ["github", "render", "dashboard"]) {
    const incomplete = {
      release: H217_RELEASE_ENVELOPE,
      github: { ...H217_RELEASE_ENVELOPE, repo: "gaysonloser/base-erp-settlement-workbench", branch: "main", commit_sha: H217_RELEASE_ENVELOPE.commit_sha },
      render: { ...H217_RELEASE_ENVELOPE, service_id: H217_RELEASE_ENVELOPE.render_service_id, deployment_id: H217_RELEASE_ENVELOPE.render_deployment_id, commit_sha: H217_RELEASE_ENVELOPE.commit_sha, health_ready: true, health_status: "ok" },
      dashboard: { app_id: H217_RELEASE_ENVELOPE.canonical_dashboard_app_id, primary_url: H217_RELEASE_ENVELOPE.canonical_primary_url },
    };
    delete incomplete[missing];
    const missingResult = validateH217PublicEnvelope(incomplete);
    assert.equal(missingResult.ok, false, `${missing} leg must be mandatory`);
    assert.equal(missingResult.failure_id, "H217-F01");
  }
  const staleDeployment = validateH217PublicEnvelope({
    release: H217_RELEASE_ENVELOPE,
    github: { ...H217_RELEASE_ENVELOPE, repo: "gaysonloser/base-erp-settlement-workbench", branch: "main", commit_sha: H217_RELEASE_ENVELOPE.commit_sha },
    render: { ...H217_RELEASE_ENVELOPE, service_id: H217_RELEASE_ENVELOPE.render_service_id, deployment_id: "dep-da00fm1egvs73fib5c0", commit_sha: H217_RELEASE_ENVELOPE.commit_sha, health_ready: true, health_status: "ok" },
    dashboard: { app_id: H217_RELEASE_ENVELOPE.canonical_dashboard_app_id, primary_url: H217_RELEASE_ENVELOPE.canonical_primary_url },
  });
  assert.equal(staleDeployment.ok, false);
  assert.equal(staleDeployment.failure_id, "H217-F01");
  const alias = validateH217PublicEnvelope({ release: H217_RELEASE_ENVELOPE, dashboard: { app_id: "arc-payment-receipt", primary_url: "https://arc-payment-receipt.onrender.com" } });
  assert.equal(alias.ok, false);
  assert.equal(alias.failure_id, "H217-F14");
});

test("H217-07/08 Talent remains native-domain and never a release receipt", () => {
  const absent = evaluateTalentNativeDomain({ projects_found: 0 });
  assert.equal(absent.status, "owner_gate");
  assert.equal(absent.failure_state.id, "H217-F06");
  const observed = evaluateTalentNativeDomain({ ...goodTalent, current_release_join: H217_RELEASE_JOIN });
  assert.equal(observed.status, "native_domain_readback");
  assert.equal(observed.release_receipt, false);
  assert.equal(observed.native_receipt, null);
  assert.deepEqual(observed.release_join, H217_RELEASE_JOIN);
  assert.equal(observed.credit, 0);
});

test("H217-09 Talent API/login or write paths are stopped without echoing credentials", () => {
  const auth = evaluateTalentNativeDomain({ login_required: true, api_key: "secret", project_id: "p" });
  assert.equal(auth.failure_state.id, "H217-F07");
  assert.equal(auth.write_authorized, false);
  assert.equal(JSON.stringify(auth).includes("secret"), false);
  const write = evaluateTalentNativeDomain({ write_requested: true });
  assert.equal(write.failure_state.id, "H217-F16");
  assert.equal(write.external_actions, 0);
});

test("H217-10 generic Guild page is context only", () => {
  const generic = evaluateGuildNativeDomain({ generic_base_page: true, member_count: "617K", join_guild_visible: true });
  assert.equal(generic.status, "context_only");
  assert.equal(generic.failure_state.id, "H217-F09");
  assert.equal(generic.release_receipt, false);
  assert.equal(generic.credit, 0);
});

test("H217-11 exact Guild project readback is native-domain only", () => {
  const observed = evaluateGuildNativeDomain({ ...goodGuild, current_release_join: H217_RELEASE_JOIN });
  assert.equal(observed.status, "native_domain_readback");
  assert.equal(observed.release_receipt, false);
  assert.equal(observed.native_receipt, null);
  assert.equal(observed.credit, 0);
  const incomplete = evaluateGuildNativeDomain({ project_url: goodGuild.project_url, visitor_readback: { roles: [] } });
  assert.equal(incomplete.failure_state.id, "H217-F10");
});

test("H217-12 Basename singleton is identity-only and omits release join", () => {
  const identity = evaluateBasenameIdentity(goodBasename);
  assert.equal(identity.status, "identity_only");
  assert.equal(identity.release_join, null);
  assert.equal(identity.release_receipt, false);
  assert.equal(identity.credit, 0);
});

test("H217-13 Basename profile or registration cannot be a project receipt", () => {
  const rejected = evaluateBasenameIdentity({ ...goodBasename, as_project_receipt: true });
  assert.equal(rejected.status, "rejected");
  assert.equal(rejected.reason, "identity_receipt_not_release_receipt");
  assert.equal(rejected.release_join, null);
  const missing = evaluateBasenameIdentity({ account_level_singleton: true });
  assert.equal(missing.failure_state.id, "H217-F12");
});

test("H217 rows evaluate through one dispatcher", () => {
  assert.equal(evaluateH217Row({ platform: "base_sepolia", descriptor: BASE_SEPOLIA_DESCRIPTOR }).platform_row_id, "base_sepolia_rehearsal");
  assert.equal(evaluateH217Row({ platform: "talent", projects_found: 0 }).platform_row_id, "talent_native_domain");
  assert.equal(evaluateH217Row({ platform: "guild", generic_base_page: true }).platform_row_id, "guild_native_domain");
  assert.equal(evaluateH217Row({ platform: "basename", account_level_singleton: true, resolver_readback: {} }).platform_row_id, "basename_base_org_identity");
});

test("H217-14 envelope never expands four rows into eight receipts", () => {
  const envelope = createH217EvidenceEnvelope({ rows: [evaluateBaseSepoliaRehearsal({ descriptor: BASE_SEPOLIA_DESCRIPTOR }), evaluateTalentNativeDomain({ projects_found: 0 }), evaluateGuildNativeDomain({ generic_base_page: true }), evaluateBasenameIdentity(goodBasename)], release_join: H217_RELEASE_JOIN });
  assert.equal(envelope.platform_rows.length, 4);
  assert.deepEqual(envelope.platform_rows.map(({ platform_row_id }) => platform_row_id), H217_PLATFORM_ROW_IDS);
  assert.equal(envelope.publication_unit_credit, 0);
  assert.equal(envelope.aggregate_publication_unit_credit, 0);
  assert.equal(aggregateCredit(envelope.platform_rows), 0);
  assert.equal(validateH217Envelope(envelope).ok, true);
});

test("H217-15 exact BASE/CIRCLE isolation fails closed", () => {
  assert.deepEqual([...CIRCLE_DENYLIST], ["gaysonloser/arc-payment-receipt", "srv-d9cumml8nd3s73c9nehg", "arc-payment-receipt.onrender.com", "programme-final-20260810"]);
  assert.equal(validateBaseCircleIsolation({ target: "base-erp-settlement-workbench.onrender.com" }).ok, true);
  for (const target of CIRCLE_DENYLIST) {
    const result = validateBaseCircleIsolation({ target });
    assert.equal(result.ok, false);
    assert.equal(result.failure_id, "H217-F14");
    assert.equal(result.action_enabled, false);
    assert.equal(result.credit, 0);
  }
});

test("H217-16 unsupported, stale and external actions stay forbidden", () => {
  const unknown = evaluateH217Row({ platform: "unknown" });
  assert.equal(unknown.failure_state.id, "H217-F16");
  const badEnvelope = validateH217Envelope({ schema_version: "stale" });
  assert.equal(badEnvelope.ok, false);
  assert.equal(badEnvelope.failure_id, "H217-F16");
  const envelope = createH217EvidenceEnvelope({ rows: [{ platform_row_id: "unknown", external_actions: 1 }] });
  assert.equal(envelope.external_actions, 0);
  assert.equal(envelope.wallet_authority, false);
  assert.equal(envelope.public_write_authority, false);
  assert.equal(envelope.deployment_authority, false);
});

test("packet revalidation requires exact accepted exchange occurrence and fresh Sol/medium pass", () => {
  const result = validateH217PacketRevalidation({ ...H217_SOURCE_HASHES, exchange_sha256: "dcbab1831d14ce36bec6a14579c2b8d1d991992435f693b440a12939bab6300e", exchange_mode: "0444", exchange_occurrences: 1, exchange_packet: packet });
  assert.equal(result.ok, true);
  assert.equal(result.accepted_once, true);
  assert.deepEqual(result.review.severity, { p0: 0, p1: 0, p2: 0 });
  const duplicate = validateH217PacketRevalidation({ ...H217_SOURCE_HASHES, exchange_occurrences: 2, exchange_packet: packet });
  assert.equal(duplicate.ok, false);
});

test("contract snapshot preserves zero-credit and no-authority boundaries", () => {
  assert.equal(H217_CONTRACT.platform_rows.length, 4);
  assert.equal(H217_CONTRACT.test_vectors.length, 16);
  assert.equal(H217_CONTRACT.failure_modes.length, 16);
  assert.equal(H217_CONTRACT.default_credit, 0);
  assert.equal(H217_CONTRACT.aggregate_publication_unit_credit, 0);
  assert.equal(H217_CONTRACT.external_actions, 0);
  assert.equal(H217_CONTRACT.wallet_authority, false);
  assert.deepEqual(getH217Contract().release_join, H217_RELEASE_JOIN);
});

test("deterministic H217 readback records current v7, runtime and exact write-set inputs", () => {
  const readback = buildH217Readback({
    exchange_sha256: "dcbab1831d14ce36bec6a14579c2b8d1d991992435f693b440a12939bab6300e",
    exchange_packet: packet,
    implementation: { source_sha256: "a".repeat(64), test_sha256: "b".repeat(64) },
    runtime: { run_id: "02_Build-20260815-122052", status: "running", external_trace_units: 0, public_update_units: 0 },
    runtime_authority: { writer_idle: true },
    tests: { focused: { passed: 0, failed: 0 }, full: { passed: 0, failed: 0 } },
    public_envelope: { release: H217_RELEASE_ENVELOPE },
  });
  assert.equal(readback.schema_version, "base-erp-h217-platform-execution-gates-readback-v1");
  assert.equal(readback.packet_revalidation.ok, true);
  assert.equal(readback.release_join.release_id, H217_RELEASE_ENVELOPE.release_id);
  assert.equal(readback.queue_cursor_counters.changed, false);
  assert.equal(readback.self_hash, "H217_READBACK_SELF_HASH_PLACEHOLDER");
  assert.equal(readback.implementation.exact_write_set.length, 3);
  assert.equal(readback.evidence_envelope.credit, 0);
  assert.equal(digest({ stable: true }), digest({ stable: true }));
});
