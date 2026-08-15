import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SCHEMA_VERSION,
  H216_PACKET_ID,
  EXECUTION_AUTHORITY,
  AUTHORITY_NONE,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_ID_HEX,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_RPC_URL,
  BASE_SEPOLIA_EXPLORER_URL,
  RELEASE_JOIN_FIELDS,
  CANONICAL_APP_LABELS,
  CANONICAL_APP_ID,
  CANONICAL_PRIMARY_URL,
  PLATFORM_ROW_IDS,
  PLATFORM_ROWS,
  H216_PLATFORM_ROWS,
  H216_FAILURE_MODES,
  FAILURE_MODES,
  FAILURE_MODE_IDS,
  H216_FAILURE_MODE_RECORDS,
  H216_TEST_VECTORS,
  TEST_VECTOR_IDS,
  BASE_SEPOLIA_DESCRIPTOR,
  BASE_SEPOLIA,
  CIRCLE_DENYLIST,
  validateBaseCircleIsolation,
  checkBaseCircleIsolation,
  evaluateBaseSepolia,
  evaluateCanonicalApp,
  evaluateDashboardBaseDev,
  evaluateBaseAppReadiness,
  evaluateBasenameIdentity,
  evaluateTalentDomain,
  evaluateGuildDomain,
  evaluateGithubRelease,
  evaluateRenderRelease,
  joinGithubRenderRelease,
  evaluatePlatformEvidence,
  createPlatformEvidenceEnvelope,
  validatePlatformEvidenceEnvelope,
  getH216Contract,
  H216_CONTRACT,
  CONTRACT,
} from '../src/base-native-platform-evidence-contract.mjs';

const ROW_IDS = Object.freeze([
  'base_sepolia_rehearsal',
  'base_dashboard_base_dev',
  'base_app_readiness',
  'basename_base_org_identity',
  'talent_native_domain',
  'guild_native_domain',
  'github_current_release',
  'render_current_release',
]);

const VECTORS = Object.freeze([
  { id: 'H216-01', name: 'Base Sepolia descriptor', input: 'chain_id=84532 and rpc=https://sepolia.base.org', expected: 'rehearsal_descriptor; receipt and finality remain separate; credit=0' },
  { id: 'H216-02', name: 'receipt before mining', input: 'eth_getTransactionReceipt returns null', expected: 'not_mined; no receipt; credit=0' },
  { id: 'H216-03', name: 'receipt success', input: 'status=0x1 with transactionHash/blockHash/blockNumber/logs', expected: 'receipt_observed; require finality stage and current release join' },
  { id: 'H216-04', name: 'receipt revert', input: 'status=0x0', expected: 'receipt_failed; stop; credit=0' },
  { id: 'H216-05', name: 'four finality stages', input: 'Flashblock/L2/L1 batch/L1 batch finality', expected: 'stage explicit; no stage inference' },
  { id: 'H216-06', name: 'withdrawal boundary', input: 'Base-to-Ethereum withdrawal', expected: 'separate seven-day path; not regular Base receipt' },
  { id: 'H216-07', name: 'wallet_sendCalls descriptor', input: 'version/from/chainId/atomicRequired/calls', expected: 'descriptor_only; no wallet call' },
  { id: 'H216-08', name: 'calls status atomic', input: 'status=200, atomic=true, receipts[]', expected: 'owner readback evidence; still require finality/release join' },
  { id: 'H216-09', name: 'Dashboard canonical identity', input: 'same app_id and primary_url read back under Dashboard/Base.dev labels', expected: 'one canonical row' },
  { id: 'H216-10', name: 'Dashboard generic redirect', input: 'base.dev redirects without app_id', expected: 'owner_platform_gate; credit=0' },
  { id: 'H216-11', name: 'metadata complete', input: 'name/icon/tagline/description/screenshots/category/primary_url/builder_code', expected: 'readiness candidate; not release receipt' },
  { id: 'H216-12', name: 'Base App old manifest', input: 'Farcaster manifest or CDN only', expected: 'deprecated/non-receipt; credit=0' },
  { id: 'H216-13', name: 'Base App readiness', input: 'mobile/in-app browser + wallet-ready + canonical metadata', expected: 'readiness_only; release_receipt=null' },
  { id: 'H216-14', name: 'Basename resolver', input: 'name resolves with owner/primary/text record readback', expected: 'identity_only; release fields null' },
  { id: 'H216-15', name: 'Basename profile page', input: 'public profile page without resolver/owner receipt', expected: 'insufficient; credit=0' },
  { id: 'H216-16', name: 'Talent profile read', input: 'documented profile/account/project API response', expected: 'native-domain observation; no release receipt' },
  { id: 'H216-17', name: 'Talent write gate', input: 'API key/wallet nonce/signature/JWT required', expected: 'owner_platform_gate; no write' },
  { id: 'H216-18', name: 'Talent 429', input: 'security checkpoint 429', expected: 'unavailable; credit=0' },
  { id: 'H216-19', name: 'Guild permanent URL', input: 'owner-created URL and visitor/admin readback', expected: 'community evidence; no release receipt' },
  { id: 'H216-20', name: 'Guild verification', input: 'complete roles/requirements/rewards + public launch + verification', expected: 'community verification; release fields null' },
  { id: 'H216-21', name: 'Guild generic Base page', input: 'guild.xyz/base member count only', expected: 'not project identity; credit=0' },
  { id: 'H216-22', name: 'GitHub current join', input: 'repo/main/commit and release envelope match', expected: 'current source-release leg observed' },
  { id: 'H216-23', name: 'GitHub placeholder', input: 'PENDING_OWNER_PUBLIC_COMMIT', expected: 'owner gate; credit=0' },
  { id: 'H216-24', name: 'Render deploy join', input: 'service/deploy/commit/current URL and release envelope match', expected: 'current deployed leg observed' },
  { id: 'H216-25', name: 'Render URL only', input: 'onrender.com page without deploy/commit readback', expected: 'insufficient; credit=0' },
  { id: 'H216-26', name: 'release mismatch', input: 'GitHub release_fingerprint differs from Render', expected: 'aggregate reject; credit=0' },
  { id: 'H216-27', name: 'all rows current', input: 'every required platform has exact owner receipt and same release join', expected: 'eligible for independent Build/owner gate; H216 still does not increment credit' },
  { id: 'H216-28', name: 'CIRCLE collision', input: 'target/service/app/domain/release matches CIRCLE denylist', expected: 'fail_closed_no_overwrite; credit=0' },
  { id: 'H216-29', name: 'external write attempt', input: 'wallet/login/platform/public write is proposed', expected: 'stop; 03_Base authority absent' },
  { id: 'H216-30', name: 'stale official source', input: 'source changes before review', expected: 'invalidate and request fresh review' },
]);

const FAILURE_NAMES = Object.freeze([
  'descriptor_present_receipt_missing',
  'receipt_chain_mismatch',
  'finality_inferred',
  'alias_duplication',
  'readiness_as_receipt',
  'basename_identity_as_release',
  'talent_gate',
  'guild_gate',
  'github_placeholder',
  'render_stale',
  'release_join_mismatch',
  'circle_collision',
  'external_write_attempt',
  'stale_source',
]);

const HASH = 'a'.repeat(64);
const RELEASE = Object.freeze({
  release_id: HASH,
  release_fingerprint: 'b'.repeat(64),
  bom_fingerprint: 'c'.repeat(64),
});
const COMMIT = '0x' + 'c'.repeat(64);
const tx = (hex) => '0x' + String(hex).repeat(64);
const rowOf = (envelope, id) => envelope.platform_rows.find((row) => row.platform_row_id === id);
const METADATA_COMPLETE = Object.freeze({
  name: 1,
  icon: 1,
  tagline: 1,
  description: 1,
  screenshots: 1,
  category: 1,
  primary_url: 1,
  builder_code: 1,
});
const CANONICAL = Object.freeze({ app_id: CANONICAL_APP_ID, primary_url: CANONICAL_PRIMARY_URL, metadata_complete: true, owner_verified: true });
const GITHUB = Object.freeze({ repo: 'gaysonloser/base-erp-settlement-workbench', branch: 'main', commit_sha: COMMIT, ...RELEASE });
const RENDER = Object.freeze({ service_name: 'base-erp-settlement-workbench', domain: 'https://base-erp-settlement-workbench.onrender.com', deploy_id: 'dep-20260815', commit_sha: COMMIT, ...RELEASE });

test('H216 schema version and packet identity are non-executable', () => {
  assert.equal(SCHEMA_VERSION, 'base-erp-h216-native-platform-evidence-v1');
  assert.equal(H216_PACKET_ID, 'base-erp-h216-base-native-platform-evidence-access-contract-20260815');
  assert.equal(EXECUTION_AUTHORITY, 'none_until_02_Build_revalidates');
  assert.equal(AUTHORITY_NONE, EXECUTION_AUTHORITY);
});

test('H216 rows exactly eight platform row ids', () => {
  assert.equal(PLATFORM_ROW_IDS.length, 8);
  assert.deepEqual([...PLATFORM_ROW_IDS], ROW_IDS);
  assert.equal(H216_PLATFORM_ROWS, PLATFORM_ROW_IDS);
  assert.equal(PLATFORM_ROWS, PLATFORM_ROW_IDS);
});

test('H216 vectors exactly thirty H216-01..H216-30 with artifact text', () => {
  assert.equal(H216_TEST_VECTORS.length, 30);
  assert.deepEqual(H216_TEST_VECTORS.map((v) => v.id), VECTORS.map((v) => v.id));
  assert.deepEqual(H216_TEST_VECTORS.map((v) => v.name), VECTORS.map((v) => v.name));
  assert.deepEqual(H216_TEST_VECTORS.map((v) => v.input), VECTORS.map((v) => v.input));
  assert.deepEqual(H216_TEST_VECTORS.map((v) => v.expected), VECTORS.map((v) => v.expected));
  assert.deepEqual(TEST_VECTOR_IDS, H216_TEST_VECTORS.map((v) => v.id));
  for (const v of H216_TEST_VECTORS) {
    assert.ok(v.expected.length > 0);
    assert.ok(!/credit\s*>\s*0|credit[:=]\s*[1-9]/i.test(v.expected), `${v.id} must never promise credit`);
  }
});

test('H216 failures exactly fourteen H216-F01..H216-F14 all fail closed', () => {
  assert.equal(H216_FAILURE_MODES.length, 14);
  assert.deepEqual(H216_FAILURE_MODES.map((f) => f.id), Array.from({ length: 14 }, (_, i) => `H216-F${String(i + 1).padStart(2, '0')}`));
  assert.deepEqual(H216_FAILURE_MODES.map((f) => f.name), FAILURE_NAMES);
  assert.deepEqual(H216_FAILURE_MODES.map((f) => f.code), FAILURE_NAMES);
  assert.deepEqual(FAILURE_MODE_IDS, H216_FAILURE_MODES.map((f) => f.id));
  assert.equal(FAILURE_MODES, H216_FAILURE_MODES);
  assert.equal(H216_FAILURE_MODE_RECORDS, H216_FAILURE_MODES);
  for (const f of H216_FAILURE_MODES) {
    assert.equal(f.fail_closed, true, `${f.id} must be fail-closed`);
    assert.equal(typeof f.policy, 'string');
    assert.ok(f.policy.length > 0);
    assert.ok(!/credit\s*>\s*0|credit[:=]\s*[1-9]/i.test(f.policy), `${f.id} policy must never grant credit`);
  }
});

test('H216 defaults every row and aggregate credit zero', () => {
  const envelope = createPlatformEvidenceEnvelope();
  assert.equal(envelope.platform_rows.length, 8);
  assert.deepEqual(envelope.platform_rows.map((row) => row.platform_row_id), ROW_IDS);
  for (const id of ROW_IDS) {
    const row = rowOf(envelope, id);
    assert.equal(row.credit, 0, `${id} default credit must be 0`);
    assert.equal(row.status, 'not_accepted');
  }
  assert.equal(envelope.publication_unit_credit, 0);
  assert.equal(envelope.external_actions, 0);
  assert.equal(envelope.native_receipt, null);
  assert.equal(envelope.execution_authority, EXECUTION_AUTHORITY);
  assert.equal(envelope.circle_target_absent, true);
  assert.equal(envelope.isolation.ok, true);
});

test('H216 base sepolia constants 84532/0x14a34 with basescan descriptor', () => {
  assert.equal(BASE_SEPOLIA_CHAIN_ID, 84532);
  assert.equal(BASE_SEPOLIA_CHAIN_ID_HEX, '0x14a34');
  assert.equal(BASE_SEPOLIA_NETWORK, 'base-sepolia');
  assert.equal(BASE_SEPOLIA_RPC_URL, 'https://sepolia.base.org');
  assert.equal(BASE_SEPOLIA_EXPLORER_URL, 'https://sepolia.basescan.org');
  assert.deepEqual(BASE_SEPOLIA_DESCRIPTOR, {
    network: 'base-sepolia',
    chain_id: 84532,
    chain_id_hex: '0x14a34',
    rpc_url: 'https://sepolia.base.org',
    explorer_url: 'https://sepolia.basescan.org',
    rehearsal_only: true,
  });
  assert.equal(BASE_SEPOLIA, BASE_SEPOLIA_DESCRIPTOR);
});

test('H216 canonical app identity and release join fields', () => {
  assert.equal(CANONICAL_APP_ID, '6a7a0717e209a55163497d2d');
  assert.equal(CANONICAL_PRIMARY_URL, 'https://base-erp-settlement-workbench.onrender.com');
  assert.deepEqual([...CANONICAL_APP_LABELS], ['Base Dashboard', 'Base.dev']);
  assert.deepEqual([...RELEASE_JOIN_FIELDS], ['release_id', 'release_fingerprint', 'bom_fingerprint']);
});

test('H216 CIRCLE denylist exact entries', () => {
  assert.deepEqual([...CIRCLE_DENYLIST], [
    'gaysonloser/arc-payment-receipt',
    'srv-d9cumml8nd3s73c9nehg',
    'arc-payment-receipt.onrender.com',
    'programme-final-20260810',
  ]);
});

test('H216-28 strict CIRCLE/Arc isolation fails closed with zero credit', () => {
  const clean = checkBaseCircleIsolation({ target: 'base-erp-settlement-workbench.onrender.com' });
  assert.equal(clean.state, 'base_identity_isolated');
  assert.equal(clean.ok, true);
  assert.equal(clean.circle_collision, false);
  assert.equal(clean.action_enabled, false);
  assert.equal(clean.credit, 0);
  for (const target of ['gaysonloser/arc-payment-receipt', 'arc-payment-receipt.onrender.com', 'CIRCLE singleton release repo', 'ARC service name']) {
    const r = checkBaseCircleIsolation({ target });
    assert.equal(r.state, 'owner_platform_gate_no_overwrite', `${target} must fail closed`);
    assert.equal(r.ok, false);
    assert.equal(r.circle_collision, true);
    assert.equal(r.action_enabled, false);
    assert.equal(r.credit, 0);
  }
  const validated = validateBaseCircleIsolation({ target: 'arc-payment-receipt.onrender.com' });
  assert.equal(validated.ok, false);
  assert.equal(validated.state, 'owner_platform_gate');
  assert.equal(validated.failure_id, 'H216-F12');
  assert.equal(validated.circle_target_absent, false);
  assert.equal(validated.credit, 0);
  const releaseCollision = validateBaseCircleIsolation({ target: 'base-erp-settlement-workbench.onrender.com', release_id: 'arc-project-h216' });
  assert.equal(releaseCollision.ok, false);
  assert.equal(releaseCollision.failure_id, 'H216-F12');
  assert.equal(releaseCollision.credit, 0);
});

test('H216-01 base sepolia descriptor keeps receipt and finality separate', () => {
  const r = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, rpc: 'https://sepolia.base.org' });
  assert.equal(r.status, 'rehearsal_only');
  assert.equal(r.reason, 'descriptor_present_receipt_missing');
  assert.equal(r.failure_state.id, 'H216-F01');
  assert.equal(r.target_identity.chain_id, 84532);
  assert.equal(r.target_identity.explorer_url, 'https://sepolia.basescan.org');
  assert.equal(r.native_receipt, null);
  assert.equal(r.finality_stage, 'not_observed');
  assert.equal(r.credit, 0);
});

test('H216-02 receipt before mining stays not observed', () => {
  const r = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt: null });
  assert.equal(r.status, 'rehearsal_only');
  assert.equal(r.native_receipt, null);
  assert.equal(r.failure_state.id, 'H216-F01');
  assert.equal(r.credit, 0);
});

test('H216-03 receipt success requires explicit finality stage', () => {
  const receipt = { status: '0x1', transactionHash: tx('3'), chainId: 84532, blockHash: tx('3'), blockNumber: 3, logs: [] };
  const r = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt, finality_stage: 'l1_batch_finality' });
  assert.equal(r.status, 'receipt_observed');
  assert.equal(r.reason, 'rehearsal_receipt_observed');
  assert.equal(r.failure_state, null);
  assert.equal(r.native_receipt.transactionHash, receipt.transactionHash);
  assert.equal(r.finality_stage, 'l1_batch_finality');
  assert.equal(r.credit, 0);
  const noStage = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt });
  assert.equal(noStage.status, 'receipt_observed');
  assert.equal(noStage.reason, 'finality_inferred');
  assert.equal(noStage.failure_state.id, 'H216-F03');
  assert.equal(noStage.credit, 0);
});

test('H216-04 receipt revert stops and stays zero', () => {
  const receipt = { status: '0x0', transactionHash: tx('4'), chainId: 84532 };
  const r = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt, finality_stage: 'l1_batch_finality' });
  assert.equal(r.status, 'receipt_failed');
  assert.equal(r.reason, 'receipt_failed');
  assert.equal(r.failure_state.id, 'H216-F02');
  assert.equal(r.credit, 0);
  const failed = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt: { ...receipt, status: 'failed' }, finality_stage: 'l1_batch_finality' });
  assert.equal(failed.status, 'receipt_failed');
  assert.equal(failed.credit, 0);
});

test('H216-05 four documented finality stages explicit and no inference', () => {
  const receipt = { status: '0x1', transactionHash: tx('5'), chainId: 84532, blockHash: tx('5'), blockNumber: 5, logs: [] };
  for (const stage of ['flashblock_preconfirmation', 'l2_block_inclusion', 'l1_batch_inclusion', 'l1_batch_finality']) {
    const r = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt, finality_stage: stage });
    assert.equal(r.status, 'receipt_observed');
    assert.equal(r.finality_stage, stage);
    assert.equal(r.failure_state, null);
  }
  const inferred = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt, finality_stage: 'probably_final' });
  assert.equal(inferred.status, 'receipt_observed');
  assert.equal(inferred.reason, 'finality_inferred');
  assert.equal(inferred.failure_state.id, 'H216-F03');
  assert.equal(inferred.credit, 0);
});

test('H216-F02 chain mismatch fails closed and never joins release', () => {
  const descriptorMismatch = evaluateBaseSepolia({ chain_id: 8453, descriptor: { chain_id: 84532 } });
  assert.equal(descriptorMismatch.status, 'owner_platform_gate');
  assert.equal(descriptorMismatch.reason, 'descriptor_mismatch');
  assert.equal(descriptorMismatch.failure_state.id, 'H216-F02');
  assert.equal(descriptorMismatch.credit, 0);
  const receiptMismatch = evaluateBaseSepolia({ descriptor: { chain_id: 84532 }, receipt: { status: '0x1', transactionHash: tx('2'), chainId: 8453 }, finality_stage: 'l1_batch_finality' });
  assert.equal(receiptMismatch.status, 'owner_platform_gate');
  assert.equal(receiptMismatch.reason, 'receipt_chain_mismatch');
  assert.equal(receiptMismatch.failure_state.id, 'H216-F02');
  assert.equal(receiptMismatch.credit, 0);
});

test('H216-06/07/08 withdrawal, sendCalls and calls-status never fabricate a receipt', () => {
  for (const input of [{ withdrawal: 'base_to_ethereum' }, { wallet_send_calls: { version: '2.0.0', chainId: 84532, calls: [] } }, { calls_status: { status: 200, atomic: true, receipts: [{ status: '0x1', transaction_hash: tx('8'), chain_id: 84532 }] } }]) {
    const r = evaluateBaseSepolia(input);
    assert.equal(r.status, 'rehearsal_only');
    assert.equal(r.reason, 'descriptor_present_receipt_missing');
    assert.equal(r.native_receipt, null);
    assert.equal(r.wallet_request, undefined);
    assert.equal(r.credit, 0);
  }
});

test('H216-09 Dashboard and Base.dev collapse to one canonical identity', () => {
  assert.equal(evaluateDashboardBaseDev, evaluateCanonicalApp);
  const canonicalKey = `${CANONICAL_APP_ID}|${CANONICAL_PRIMARY_URL}`;
  for (const label of ['Base Dashboard', 'Base.dev']) {
    const r = evaluateCanonicalApp({ ...CANONICAL, label });
    assert.equal(r.status, 'canonical_route_verified');
    assert.equal(r.canonical_state, 'canonical_identity_verified');
    assert.equal(r.reason, 'one_canonical_app_route');
    assert.equal(r.failure_state, null);
    assert.equal(r.canonical_key, canonicalKey);
    assert.equal(r.target_identity.canonical_key, canonicalKey);
    assert.equal(r.duplicate_rows, false);
    assert.equal(r.release_receipt, false);
    assert.equal(r.credit, 0);
  }
});

test('H216-10 generic base.dev redirect gates', () => {
  const missing = evaluateCanonicalApp({ label: 'Base.dev' });
  assert.equal(missing.status, 'owner_platform_gate');
  assert.equal(missing.reason, 'missing_app_id');
  assert.equal(missing.failure_state.id, 'H216-F04');
  assert.equal(missing.credit, 0);
  const redirect = evaluateCanonicalApp({ label: 'Base.dev', app_id: CANONICAL_APP_ID, primary_url: 'https://base.dev', generic_redirect: true });
  assert.equal(redirect.status, 'owner_platform_gate');
  assert.equal(redirect.reason, 'generic_base_dev_redirect');
  assert.equal(redirect.failure_state.id, 'H216-F04');
  assert.equal(redirect.credit, 0);
});

test('H216-11 complete metadata is readiness candidate, never a release receipt', () => {
  const r = evaluateBaseAppReadiness({ app_id: CANONICAL_APP_ID, primary_url: CANONICAL_PRIMARY_URL, metadata: METADATA_COMPLETE });
  assert.equal(r.status, 'readiness_candidate');
  assert.equal(r.reason, 'readiness_candidate_not_release');
  assert.equal(r.failure_state.id, 'H216-F05');
  assert.equal(r.release_receipt, null);
  assert.equal(r.credit, 0);
  const noApp = evaluateBaseAppReadiness({});
  assert.equal(noApp.status, 'readiness_gate');
  assert.equal(noApp.reason, 'readiness_claimed_without_canonical_app_id');
  assert.equal(noApp.failure_state.id, 'H216-F05');
  assert.equal(noApp.credit, 0);
});

test('H216-12 Farcaster manifest or CDN only is deprecated non-receipt', () => {
  for (const evidence of [{ farcaster_manifest_only: true }, { cdn_asset_only: true }, { continue_on_web_only: true }]) {
    const r = evaluateBaseAppReadiness({ app_id: CANONICAL_APP_ID, primary_url: CANONICAL_PRIMARY_URL, ...evidence });
    assert.equal(r.status, 'deprecated_non_receipt');
    assert.equal(r.reason, 'deprecated_readiness_surface');
    assert.equal(r.failure_state.id, 'H216-F05');
    assert.equal(r.release_receipt, null);
    assert.equal(r.credit, 0);
  }
});

test('H216-13 Base App readiness stays separate from release receipt', () => {
  const r = evaluateBaseAppReadiness({ app_id: CANONICAL_APP_ID, primary_url: CANONICAL_PRIMARY_URL, metadata: METADATA_COMPLETE, primary_url_resolves: true, mobile_ready: true, wallet_ready: true });
  assert.equal(r.status, 'readiness_only');
  assert.equal(r.reason, 'base_app_readiness_observed');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_receipt, null);
  assert.equal(r.credit, 0);
});

test('H216-14 Basename resolver readback is identity only', () => {
  const r = evaluateBasenameIdentity({ name: 'gaysonloser.base.eth', resolved_owner: '0xBa36D092dB2999bb1FaBbaf281AC956A97189C25', primary_name: true, text_records: {} });
  assert.equal(r.status, 'identity_only');
  assert.equal(r.reason, 'identity_observed_no_release_receipt');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_join.release_id, null);
  assert.equal(r.release_join.release_fingerprint, null);
  assert.equal(r.release_join.bom_fingerprint, null);
  assert.equal(r.credit, 0);
});

test('H216-15 Basename profile page without resolver is insufficient', () => {
  const r = evaluateBasenameIdentity({ profile_page_only: true });
  assert.equal(r.status, 'identity_gate');
  assert.equal(r.reason, 'profile_page_without_resolver_readback');
  assert.equal(r.failure_state.id, 'H216-F06');
  assert.equal(r.credit, 0);
});

test('H216-16 Talent documented API response is native-domain observation only', () => {
  const r = evaluateTalentDomain({ profile_id: 'base-erp-settlement-workbench', documented_fields: { name: 1 }, source_timestamp: '2026-08-15T00:00:00+08:00' });
  assert.equal(r.status, 'native_domain_observed');
  assert.equal(r.reason, 'profile_reputation_read_surface_only');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_join.release_id, null);
  assert.equal(r.release_receipt, null);
  assert.equal(r.credit, 0);
});

test('H216-17 Talent write gate stops without write', () => {
  const r = evaluateTalentDomain({ write_gate: 'wallet_auth' });
  assert.equal(r.status, 'talent_platform_gate');
  assert.equal(r.reason, 'owner_readback_missing');
  assert.equal(r.failure_state.id, 'H216-F07');
  assert.equal(r.credit, 0);
});

test('H216-18 Talent 429 security checkpoint is unavailable', () => {
  const r = evaluateTalentDomain({ security_checkpoint_429: true });
  assert.equal(r.status, 'talent_unavailable');
  assert.equal(r.reason, '429_security_checkpoint');
  assert.equal(r.failure_state.id, 'H216-F07');
  assert.equal(r.credit, 0);
  const http = evaluateTalentDomain({ http_status: 429 });
  assert.equal(http.status, 'talent_unavailable');
  assert.equal(http.credit, 0);
});

test('H216-19 Guild permanent URL with owner readback is community evidence', () => {
  const r = evaluateGuildDomain({ guild_url: 'https://guild.xyz/base-erp-settlement-workbench', visitor_readback: {}, admin_readback: {} });
  assert.equal(r.status, 'community_only');
  assert.equal(r.reason, 'community_roles_requirements_rewards_only');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_join.release_id, null);
  assert.equal(r.release_receipt, null);
  assert.equal(r.credit, 0);
});

test('H216-20 Guild verification stays community-only with null release fields', () => {
  const r = evaluateGuildDomain({ guild_url: 'https://guild.xyz/base-erp-settlement-workbench', visitor_readback: {}, admin_readback: {}, roles: true, requirements: true, rewards: true, verification: true });
  assert.equal(r.status, 'community_only');
  assert.equal(r.reason, 'community_roles_requirements_rewards_only');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_join.bom_fingerprint, null);
  assert.equal(r.release_receipt, null);
  assert.equal(r.credit, 0);
});

test('H216-21 generic guild.xyz/base page is not project identity', () => {
  const r = evaluateGuildDomain({ generic_base_page: true, member_count: 1234 });
  assert.equal(r.status, 'community_only');
  assert.equal(r.reason, 'generic_guild_xyz_base_page');
  assert.equal(r.failure_state.id, 'H216-F08');
  assert.equal(r.credit, 0);
});

test('H216-22 GitHub current release leg observed', () => {
  const r = evaluateGithubRelease(GITHUB);
  assert.equal(r.status, 'current_release_leg_observed');
  assert.equal(r.reason, 'owner_readback_required_for_credit');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_join.release_id, RELEASE.release_id);
  assert.equal(r.release_join.release_fingerprint, RELEASE.release_fingerprint);
  assert.equal(r.release_join.bom_fingerprint, RELEASE.bom_fingerprint);
  assert.equal(r.credit, 0);
});

test('H216-23 GitHub placeholder commit gates', () => {
  const r = evaluateGithubRelease({ ...GITHUB, commit_sha: 'PENDING_OWNER_PUBLIC_COMMIT' });
  assert.equal(r.status, 'owner_platform_gate');
  assert.equal(r.reason, 'github_placeholder');
  assert.equal(r.failure_state.id, 'H216-F09');
  assert.equal(r.credit, 0);
});

test('H216-24 Render deploy leg observed', () => {
  const r = evaluateRenderRelease(RENDER);
  assert.equal(r.status, 'current_release_leg_observed');
  assert.equal(r.reason, 'owner_readback_required_for_credit');
  assert.equal(r.failure_state, null);
  assert.equal(r.release_join.release_id, RELEASE.release_id);
  assert.equal(r.release_join.release_fingerprint, RELEASE.release_fingerprint);
  assert.equal(r.release_join.bom_fingerprint, RELEASE.bom_fingerprint);
  assert.equal(r.credit, 0);
});

test('H216-25 Render URL only is insufficient', () => {
  const r = evaluateRenderRelease({ domain: 'https://base-erp-settlement-workbench.onrender.com' });
  assert.equal(r.status, 'owner_platform_gate');
  assert.equal(r.reason, 'render_stale');
  assert.equal(r.failure_state.id, 'H216-F10');
  assert.equal(r.credit, 0);
});

test('H216-26 release fingerprint mismatch rejects aggregate', () => {
  const mismatched = { ...RENDER, release_fingerprint: 'd'.repeat(64) };
  const r = joinGithubRenderRelease({ github: GITHUB, render: mismatched, expected_release: RELEASE });
  assert.equal(r.ok, false);
  assert.equal(r.state, 'owner_platform_gate');
  assert.equal(r.reason, 'release_join_mismatch');
  assert.equal(r.failure_id, 'H216-F11');
  assert.deepEqual([...r.mismatch_fields], ['release_fingerprint']);
  assert.equal(r.credit, 0);
  assert.equal(r.publication_unit_credit, 0);
});

test('same current release envelope joins GitHub and Render', () => {
  const r = joinGithubRenderRelease({ github: GITHUB, render: RENDER, expected_release: RELEASE });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'current_release_join_observed');
  assert.equal(r.reason, 'same_current_release_envelope');
  assert.equal(r.failure_id, null);
  assert.equal(r.same_release, true);
  assert.equal(r.credit, 0);
});

test('missing release join fields gate', () => {
  const r = evaluateGithubRelease({ repo: 'gaysonloser/base-erp-settlement-workbench', branch: 'main', commit_sha: COMMIT });
  assert.equal(r.status, 'owner_platform_gate');
  assert.equal(r.failure_state.id, 'H216-F09');
  assert.equal(r.credit, 0);
});

test('H216-27 all rows current validates but H216 never increments credit', () => {
  const receipt = { status: '0x1', transactionHash: tx('7'), chainId: 84532, blockHash: tx('7'), blockNumber: 7, logs: [] };
  const rows = [
    evaluatePlatformEvidence({ platform_row_id: 'base_sepolia_rehearsal', descriptor: { chain_id: 84532 }, receipt, finality_stage: 'l1_batch_finality' }),
    evaluatePlatformEvidence({ platform_row_id: 'base_dashboard_base_dev', ...CANONICAL }),
    evaluatePlatformEvidence({ platform_row_id: 'base_app_readiness', app_id: CANONICAL_APP_ID, primary_url: CANONICAL_PRIMARY_URL, metadata: METADATA_COMPLETE, primary_url_resolves: true, mobile_ready: true, wallet_ready: true }),
    evaluatePlatformEvidence({ platform_row_id: 'basename_base_org_identity', name: 'gaysonloser.base.eth', resolved_owner: '0xBa36D092dB2999bb1FaBbaf281AC956A97189C25', primary_name: true, text_records: {} }),
    evaluatePlatformEvidence({ platform_row_id: 'talent_native_domain', profile_id: 'base-erp-settlement-workbench', documented_fields: { name: 1 }, source_timestamp: '2026-08-15T00:00:00+08:00' }),
    evaluatePlatformEvidence({ platform_row_id: 'guild_native_domain', guild_url: 'https://guild.xyz/base-erp-settlement-workbench', visitor_readback: {}, admin_readback: {} }),
    evaluatePlatformEvidence({ platform_row_id: 'github_current_release', ...GITHUB }),
    evaluatePlatformEvidence({ platform_row_id: 'render_current_release', ...RENDER }),
  ];
  for (const row of rows) assert.equal(row.credit, 0);
  const envelope = createPlatformEvidenceEnvelope({ rows, release_join: RELEASE });
  assert.equal(envelope.platform_rows.length, 8);
  for (const id of ROW_IDS) assert.equal(rowOf(envelope, id).credit, 0);
  assert.equal(envelope.publication_unit_credit, 0);
  assert.equal(envelope.external_actions, 0);
  assert.equal(envelope.circle_target_absent, true);
  assert.equal(envelope.failure_state, null);
  const validation = validatePlatformEvidenceEnvelope(envelope);
  assert.equal(validation.ok, true);
  assert.equal(validation.reason, 'h216_envelope_valid');
  assert.equal(validation.platform_rows, 8);
  assert.equal(validation.test_vectors, 30);
  assert.equal(validation.failure_modes, 14);
  assert.equal(validation.credit, 0);
  assert.equal(validation.publication_unit_credit, 0);
});

test('H216-28 envelope CIRCLE collision fails closed', () => {
  const colliding = evaluatePlatformEvidence({ platform_row_id: 'base_dashboard_base_dev', app_id: 'arc-payment-receipt', primary_url: 'https://arc.example', metadata_complete: true, owner_verified: true });
  assert.equal(colliding.failure_state.id, 'H216-F12');
  const envelope = createPlatformEvidenceEnvelope({ rows: [colliding] });
  assert.equal(envelope.circle_target_absent, false);
  assert.equal(envelope.failure_state.id, 'H216-F12');
  assert.equal(envelope.isolation.ok, false);
  assert.equal(envelope.publication_unit_credit, 0);
  const validation = validatePlatformEvidenceEnvelope(envelope);
  assert.equal(validation.ok, false);
  assert.equal(validation.reason, 'circle_target_collision');
});

test('H216-29 no wallet or public/platform write authority exists', () => {
  const envelope = createPlatformEvidenceEnvelope();
  assert.equal(envelope.wallet_authority, false);
  assert.equal(envelope.public_write_authority, false);
  assert.equal(envelope.deployment_authority, false);
  assert.equal(envelope.external_actions, 0);
  assert.equal(envelope.wallet_request, undefined);
  const validation = validatePlatformEvidenceEnvelope(envelope);
  assert.equal(validation.ok, true);
  assert.equal(validation.external_actions, 0);
});

test('H216-30 stale or unsupported source invalidates and requests fresh review', () => {
  const stale = validatePlatformEvidenceEnvelope({ schema_version: 'stale-schema' });
  assert.equal(stale.ok, false);
  assert.equal(stale.failure_id, 'H216-F14');
  assert.equal(stale.state, 'owner_platform_gate');
  assert.equal(stale.credit, 0);
  const unsupported = evaluatePlatformEvidence({ platform_row_id: 'unsupported_row' });
  assert.equal(unsupported.status, 'owner_platform_gate');
  assert.equal(unsupported.failure_state.id, 'H216-F14');
  assert.equal(unsupported.credit, 0);
});

test('H216 contract snapshot keeps eight rows, thirty vectors, fourteen failures, zero credit', () => {
  const contract = getH216Contract();
  assert.equal(contract.schema_version, SCHEMA_VERSION);
  assert.equal(contract.platform_rows.length, 8);
  for (const row of contract.platform_rows) assert.equal(row.default_credit, 0);
  assert.deepEqual(contract.base_sepolia, BASE_SEPOLIA_DESCRIPTOR);
  assert.equal(contract.canonical_app.duplicate_rows, false);
  assert.equal(contract.canonical_app.credit, 0);
  assert.equal(contract.base_app.release_receipt, null);
  assert.equal(contract.base_app.credit, 0);
  assert.equal(contract.native_domains.release_receipts, false);
  assert.equal(contract.native_domains.credit, 0);
  assert.deepEqual([...contract.release_join.required_fields], ['release_id', 'release_fingerprint', 'bom_fingerprint']);
  assert.equal(contract.release_join.credit, 0);
  assert.equal(contract.failure_modes.length, 14);
  assert.equal(contract.test_vectors.length, 30);
  assert.equal(contract.default_credit, 0);
  assert.equal(contract.aggregate_publication_unit_credit, 0);
  assert.equal(contract.execution_authority, EXECUTION_AUTHORITY);
  assert.equal(contract.external_actions, 0);
  assert.equal(contract.circle_target_absent, true);
  assert.deepEqual(H216_CONTRACT, contract);
  assert.equal(CONTRACT, H216_CONTRACT);
});
