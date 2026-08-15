import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bindRecurringCase,
  subscriptionGetStatus,
  permissionGetStatus,
  evaluateStatusAdapter,
  effectivePeriod,
  deriveOperationKey,
  reserveOperationKey,
  evaluateCharge,
  evaluateRevoke,
  cdpCharge,
  cdpRevoke,
  prepareCharge,
  prepareRevoke,
  verifySendCallsEnvelope,
  bindCallsId,
  interpretCallsStatus,
  readReceiptFinality,
  readCdpTransaction,
  buildNonPostingErpProjection,
  matchReconciliation,
  buildReadbackRecord,
  baseSepoliaRehearsal,
  checkBaseCircleIsolation,
  SCHEMA_VERSION,
  AUTHORITY_NONE,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_MAINNET_CHAIN_ID,
} from '../src/base-recurring-settlement-contract.mjs';

const release = {
  release_id: 'base-erp-public-product-20260814-v4',
  release_fingerprint: '5962684e0f5df38691ecdaa0b75ba023dcf1a64bf85cc15e512d8e307704ea4f',
  bom_fingerprint: '2b617a7ae4e2ef976e97310ab533f8f067c758dd0feaf3013709a06d01a6d612',
  material_outcome: 'h213_rehearsal_descriptor_only',
};
const payer = '0xBa36D092dB2999bb1FaBbaf281AC956A97189C25';
const spender = '0x1111111111111111111111111111111111111111';
const recipient = '0x2222222222222222222222222222222222222222';
const digestHex = 'd1fbbcdaf8c4c9ac62db0193d4ced147a414aa97b745f7cfd33b5fd539ba1b6f';
const baseCase = {
  case_id: 'H213-001',
  permission_ref: 'sp-h213-001',
  permission_hash_digest: digestHex,
  payer,
  spender,
  token: 'USDC',
  chain_id: 84532,
  testnet: true,
  allowance: '100',
  period_seconds: 86400,
  start: 1700000000,
  end: 1700864000,
  recurring_charge: '50',
  recipient_policy: { mode: 'fixed', default_recipient: recipient },
  status_adapter: 'subscription',
  release,
};
const permissionTuple = { account: payer, spender, token: 'USDC', allowance: '100', period: 86400, start: 1700000000, end: 1700864000, salt: '0x00', extraData: '0x' };
const cse = bindRecurringCase(baseCase);
const cseGeneric = bindRecurringCase({ ...baseCase, status_adapter: 'spend_permission', permission_tuple: permissionTuple });
const tx = (hex) => '0x' + hex.repeat(64);
const activeSub = subscriptionGetStatus({ id: digestHex, testnet: true, readback: { isSubscribed: true, remainingChargeInPeriod: '100' }, case: cse });
const oneCall = [{ to: spender, data: '0xspend' }];

test('H213-01 valid subscription bind', () => {
  assert.equal(cse.state, 'permission_bound');
  assert.equal(cse.schema_version, SCHEMA_VERSION);
  assert.equal(cse.status_adapter, 'subscription');
  assert.equal(cse.permission_hash_digest, digestHex);
  assert.equal(cse.payer, payer.toLowerCase());
  assert.equal(cse.spender, spender.toLowerCase());
  assert.equal(cse.release_join.release_fingerprint, release.release_fingerprint);
  assert.equal(cse.authority, AUTHORITY_NONE);
});

test('H213-02 subscribe rejected', () => {
  assert.equal(bindRecurringCase({ ...baseCase, permission_hash_digest: undefined }).reason, 'subscribe_rejected_no_permission');
  assert.equal(bindRecurringCase({ ...baseCase, permission_ref: '' }).reason, 'subscribe_rejected_no_permission');
});

test('H213-03 permission hash malformed', () => {
  assert.equal(bindRecurringCase({ ...baseCase, permission_hash_digest: 'browser-handle-123' }).reason, 'invalid_permission_hash');
  assert.equal(subscriptionGetStatus({ id: 'not-a-digest', testnet: true }).reason, 'invalid_permission_hash');
});

test('H213-04 payer or spender mismatch', () => {
  assert.equal(permissionGetStatus({ permission: { ...permissionTuple, account: '0x9999999999999999999999999999999999999999' }, readback: { isActive: true, remainingSpend: '5' }, case: cseGeneric }).reason, 'permission_tuple_mismatch');
  assert.equal(permissionGetStatus({ permission: { ...permissionTuple, spender: '0x8888888888888888888888888888888888888888' }, readback: { isActive: true, remainingSpend: '5' }, case: cseGeneric }).reason, 'permission_tuple_mismatch');
  assert.equal(permissionGetStatus({ permission: { ...permissionTuple, token: 'DAI' }, readback: { isActive: true, remainingSpend: '5' }, case: cseGeneric }).reason, 'permission_tuple_mismatch');
});

test('H213-05 network mismatch', () => {
  assert.equal(subscriptionGetStatus({ id: digestHex, testnet: false, readback: { isSubscribed: true, remainingChargeInPeriod: '50' }, case: cse }).reason, 'network_mismatch');
});

test('H213-06 subscription adapter inactive', () => {
  const r = subscriptionGetStatus({ id: digestHex, testnet: true, readback: { isSubscribed: false, remainingChargeInPeriod: '12' }, case: cse });
  assert.equal(r.state, 'inactive');
  assert.equal(r.remaining_charge_in_period, '12');
  assert.equal(r.terminal, true);
});

test('H213-07 generic adapter revoked', () => {
  const r = permissionGetStatus({ permission: permissionTuple, readback: { isActive: true, isRevoked: true, isExpired: false, remainingSpend: '5' }, case: cseGeneric });
  assert.equal(r.state, 'revoked');
  assert.equal(r.remaining_spend, '5');
  assert.equal(r.terminal, true);
});

test('H213-08 generic adapter expired', () => {
  const r = permissionGetStatus({ permission: permissionTuple, readback: { isActive: true, isRevoked: false, isExpired: true, remainingSpend: '5' }, case: cseGeneric });
  assert.equal(r.state, 'expired');
  assert.equal(r.is_revoked, false);
  assert.equal(r.terminal, true);
});

test('H213-09 amount overflow', () => {
  const r = evaluateCharge({ case: cse, status_result: activeSub, requested_amount: '200' });
  assert.equal(r.state, 'recovery_ready');
  assert.equal(r.reason, 'amount_exceeds_remaining_allowance');
  assert.equal(r.remaining, '100');
});

test('H213-10 period reset no rollover', () => {
  const next = cse.current_period_start + cse.period_seconds;
  const period = effectivePeriod({ case: cse, status_result: { state: 'active', remaining_charge_in_period: '5', current_period_start: next } });
  assert.equal(period.state, 'period_reset');
  assert.equal(period.remaining, '100');
  assert.equal(period.unused_carried, '0');
  const charge = evaluateCharge({ case: cse, status_result: { state: 'active', remaining_charge_in_period: '5', current_period_start: next }, requested_amount: '50' });
  assert.equal(charge.state, 'charge_candidate');
  assert.equal(charge.remaining_after, '50');
  assert.equal(charge.current_period_start, next);
});

test('H213-11 duplicate operation key', () => {
  const first = reserveOperationKey({ case: cse, amount: '50', current_period_start: cse.current_period_start, release, ledger: {} });
  assert.equal(first.state, 'operation_reserved');
  const unresolved = reserveOperationKey({ case: cse, amount: '50', current_period_start: cse.current_period_start, release, ledger: { [first.operation_key]: { state: 'calls_pending' } } });
  assert.equal(unresolved.state, 'recovery_ready');
  assert.equal(unresolved.reason, 'operation_unresolved_replay_locked');
  const resolved = reserveOperationKey({ case: cse, amount: '50', current_period_start: cse.current_period_start, release, ledger: { [first.operation_key]: { state: 'reconciled' } } });
  assert.equal(resolved.reason, 'duplicate_operation_key');
  const other = reserveOperationKey({ case: cse, amount: '60', current_period_start: cse.current_period_start, release, ledger: {} });
  assert.notEqual(other.operation_key, first.operation_key);
  assert.equal(deriveOperationKey({ case: cse, amount: '50', current_period_start: cse.current_period_start, release }).operation_key, first.operation_key);
});

test('H213-12 first-use two-call manual shape', () => {
  const r = prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'supported' }, call_shape: [{ to: spender, data: '0xapprove' }, { to: recipient, data: '0xspend' }] });
  assert.equal(r.state, 'owner_review_required');
  assert.equal(r.execution_route, 'manual');
  assert.equal(r.descriptor.calls.length, 2);
  assert.equal(r.descriptor.version, '2.0.0');
  assert.equal(r.descriptor.atomicRequired, true);
  assert.equal(r.descriptor.from, spender.toLowerCase());
  assert.equal(r.descriptor.chainId, 84532);
  assert.match(r.descriptor_digest, /^[0-9a-f]{64}$/);
  assert.equal(r.calls_id, null);
  assert.equal(r.tx_hash, null);
  assert.equal(r.side_effect_free, true);
});

test('H213-13 registered one-call manual shape', () => {
  const r = prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'supported' }, call_shape: oneCall });
  assert.equal(r.state, 'owner_review_required');
  assert.equal(r.descriptor.calls.length, 1);
  assert.equal(r.descriptor.atomicRequired, true);
  assert.equal(r.amount, '50');
});

test('H213-14 atomic unsupported', () => {
  assert.equal(prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'unsupported' }, call_shape: oneCall }).reason, 'atomic_capability_not_supported');
  assert.equal(prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'ready' }, call_shape: oneCall }).reason, 'atomic_capability_ready_only');
  assert.equal(prepareRevoke({ case: cse, status_result: activeSub, capability_readback: { atomic: 'unsupported' }, call_shape: oneCall }).reason, 'atomic_capability_not_supported');
});

test('H213-15 call descriptor drift', () => {
  const prepared = prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'supported' }, call_shape: oneCall });
  const drift = verifySendCallsEnvelope({ prepared, envelope: { version: '2.0.0', chainId: cse.chain_id, from: spender, atomicRequired: true, calls: [{ to: spender, data: '0xother', value: '0x0' }] } });
  assert.equal(drift.state, 'recovery_ready');
  assert.equal(drift.reason, 'call_descriptor_drift');
  const ok = verifySendCallsEnvelope({ prepared, envelope: prepared.descriptor });
  assert.equal(ok.state, 'send_calls_verified');
  assert.equal(ok.call_count, 1);
});

test('H213-16 manual calls pending', () => {
  const r = interpretCallsStatus({ calls_id: 'cid-h213-16', status: 100 });
  assert.equal(r.state, 'calls_pending');
  assert.equal(r.wait, true);
});

test('H213-17 manual calls terminal failure', () => {
  const r = interpretCallsStatus({ calls_id: 'cid-h213-17', status: 500 });
  assert.equal(r.state, 'calls_terminal_failure');
  assert.equal(r.reason, 'send_calls_terminal_failure');
  assert.equal(interpretCallsStatus({ calls_id: 'cid-h213-17b', status: 400 }).state, 'calls_terminal_failure');
});

test('H213-18 manual partial batch', () => {
  const r600 = interpretCallsStatus({ calls_id: 'cid-h213-18', status: 600 });
  assert.equal(r600.state, 'recovery_ready');
  assert.equal(r600.reason, 'manual_partial_batch');
  const rNonAtomic = interpretCallsStatus({ calls_id: 'cid-h213-18b', status: 200, atomic: false, receipts: [{ status: '0x1', transaction_hash: tx('1') }, { status: '0x1', transaction_hash: tx('2') }] });
  assert.equal(rNonAtomic.state, 'recovery_ready');
  assert.equal(rNonAtomic.reason, 'manual_non_atomic_batch');
});

test('H213-19 manual successful receipt not final', () => {
  const r = interpretCallsStatus({ calls_id: 'cid-h213-19', status: 200, atomic: true, receipts: [{ status: '0x1', transaction_hash: tx('a'), chain_id: 84532 }], expected: { transaction_hash: tx('a'), chain_id: 84532 } });
  assert.equal(r.state, 'receipt_success_unfinalized');
  assert.equal(r.erp_posting, false);
  const f = readReceiptFinality({ receipt: r.receipts[0], finality_stage: 'l2_included', expected: { transaction_hash: tx('a'), chain_id: 84532 } });
  assert.equal(f.state, 'finality_pending');
  assert.equal(f.reason, 'receipt_not_final');
});

test('H213-20 reverted receipt', () => {
  assert.equal(interpretCallsStatus({ calls_id: 'cid-h213-20', status: 200, atomic: true, receipts: [{ status: '0x0' }] }).reason, 'receipt_reverted');
  const wrong = readReceiptFinality({ receipt: { status: '0x1', transaction_hash: tx('b'), chain_id: 84532 }, finality_stage: 'l1_batch_final', expected: { transaction_hash: tx('a'), chain_id: 84532 } });
  assert.equal(wrong.state, 'recovery_ready');
  assert.equal(wrong.reason, 'receipt_intent_mismatch');
});

test('H213-21 reorg or removed evidence', () => {
  const r = readReceiptFinality({ receipt: { status: '0x1', transaction_hash: tx('a') }, finality_stage: 'reorged' });
  assert.equal(r.state, 'recovery_ready');
  assert.equal(r.reason, 'reorg_evidence_removed');
  assert.equal(readReceiptFinality({ receipt: { status: '0x1' }, finality_stage: 'removed' }).reason, 'reorg_evidence_removed');
});

test('H213-22 ERP operation mismatch', () => {
  const finality = readReceiptFinality({ receipt: { status: '0x1', transaction_hash: tx('a'), chain_id: 84532 }, finality_stage: 'l1_batch_final', expected: { transaction_hash: tx('a'), chain_id: 84532 } });
  const projection = buildNonPostingErpProjection({ case: cse, operation: 'op-123', receipt: finality.receipt, period_start: cse.current_period_start, period_end: cse.next_period_start, amount: '50', release });
  assert.equal(projection.state, 'erp_projection_ready');
  const bad = matchReconciliation({ projection, readback: { ...projection, operation_key: 'op-OTHER' } });
  assert.equal(bad.state, 'recovery_ready');
  assert.equal(bad.reason, 'erp_operation_mismatch');
  const wrongPeriod = matchReconciliation({ projection, readback: { ...projection, period_start: cse.next_period_start } });
  assert.equal(wrongPeriod.reason, 'erp_operation_mismatch');
});

test('H213-23 release mismatch', () => {
  const projection = buildNonPostingErpProjection({ case: cse, operation: 'op-1', receipt: { transaction_hash: tx('a') }, period_start: cse.current_period_start, period_end: cse.next_period_start, amount: '50', release });
  const readback = { ...projection, release_join: { ...release, release_fingerprint: '0'.repeat(64) } };
  const r = matchReconciliation({ projection, readback });
  assert.equal(r.state, 'recovery_ready');
  assert.equal(r.reason, 'release_identity_mismatch');
  const missing = matchReconciliation({ projection, readback: { ...projection, release_join: undefined } });
  assert.equal(missing.reason, 'release_identity_mismatch');
});

test('H213-24 user revoke with zero remaining', () => {
  const activeZero = subscriptionGetStatus({ id: digestHex, testnet: true, readback: { isSubscribed: true, remainingChargeInPeriod: '0' }, case: cse });
  const rev = evaluateRevoke({ case: cse, status_result: activeZero });
  assert.equal(rev.state, 'revocation_candidate');
  assert.equal(rev.positive_remaining_required, false);
  assert.equal(rev.remaining, '0');
  const charge = evaluateCharge({ case: cse, status_result: activeZero, requested_amount: '1' });
  assert.equal(charge.reason, 'amount_exceeds_remaining_allowance');
  const cdp = cdpRevoke({ case: cse, status_result: activeZero, result: { tx_hash: tx('c') } });
  assert.equal(cdp.state, 'revoke_tx_pending');
  assert.equal(cdp.calls_id, null);
});

test('H213-25 CIRCLE collision', () => {
  const r = checkBaseCircleIsolation({ target: 'CIRCLE singleton release repo' });
  assert.equal(r.state, 'owner_platform_gate_no_overwrite');
  assert.equal(r.reason, 'base_circle_identity_collision');
  assert.equal(checkBaseCircleIsolation({ release: { release_id: 'arc-project-h213' } }).state, 'owner_platform_gate_no_overwrite');
  assert.equal(checkBaseCircleIsolation({ target: 'base-erp-settlement-workbench.onrender.com', release }).state, 'base_identity_isolated');
});

test('H213-26 CDP charge tx_hash direct receipt/finality only', () => {
  const cdp = cdpCharge({ case: cse, status_result: activeSub, requested_amount: '50', result: { tx_hash: tx('d') } });
  assert.equal(cdp.state, 'tx_pending');
  assert.equal(cdp.execution_route, 'cdp');
  assert.equal(cdp.tx_hash, tx('d'));
  assert.equal(cdp.calls_id, null);
  assert.equal(cdp.receipt_route, 'direct_receipt_finality');
  assert.equal(cdp.calls_status_route, false);
  const final = readCdpTransaction({ tx_hash: cdp.tx_hash, receipt: { status: '0x1', transaction_hash: tx('d'), chain_id: 84532 }, finality_stage: 'l1_batch_final', expected: { chain_id: 84532 } });
  assert.equal(final.state, 'charge_receipt_final');
  assert.equal(final.calls_status_route, false);
  assert.equal(final.erp_posting, false);
});

test('H213-27 revoke final blocks future charge', () => {
  const revoked = permissionGetStatus({ permission: permissionTuple, readback: { isActive: false, isRevoked: true, isExpired: false }, case: cseGeneric });
  const charge = evaluateCharge({ case: cseGeneric, status_result: revoked, requested_amount: '1' });
  assert.equal(charge.state, 'recovery_ready');
  assert.equal(charge.reason, 'charge_blocked_not_active');
  assert.equal(evaluateRevoke({ case: cseGeneric, status_result: revoked }).reason, 'already_revoked');
  const final = readCdpTransaction({ tx_hash: tx('e'), receipt: { status: '0x1', transaction_hash: tx('e'), chain_id: 84532 }, finality_stage: 'l1_batch_final', expected: { chain_id: 84532 }, kind: 'revoke' });
  assert.equal(final.state, 'revoke_receipt_final');
});

test('H213-28 never mix tx_hash and callsId', () => {
  assert.equal(bindCallsId({ calls_id: tx('e'), operation_key: 'k', descriptor_digest: digestHex }).reason, 'calls_id_tx_hash_mix_rejected');
  assert.equal(interpretCallsStatus({ calls_id: tx('e'), status: 200, receipts: [{ status: '0x1' }] }).reason, 'calls_id_tx_hash_mix_rejected');
  assert.equal(readCdpTransaction({ tx_hash: 'cid-not-a-tx-hash', receipt: { status: '0x1' }, finality_stage: 'l1_batch_final' }).reason, 'cdp_tx_hash_invalid');
  assert.equal(cdpCharge({ case: cse, status_result: activeSub, requested_amount: '50', result: {} }).reason, 'cdp_tx_hash_missing');
  const manual = bindCallsId({ operation_key: 'op-28', descriptor_digest: digestHex, calls_id: 'cid-28' });
  assert.equal(manual.state, 'calls_pending');
  assert.equal(manual.tx_hash, null);
  assert.equal(manual.calls_status_route, true);
});

test('H213-29 readback authority and no fabrication', () => {
  const rb = buildReadbackRecord({ case: cse, operation: 'op-x', receipt: { status: '0x1' }, finality_stage: 'l1_batch_final' });
  assert.equal(rb.authority, AUTHORITY_NONE);
  assert.equal(rb.execution_authority, AUTHORITY_NONE);
  assert.equal(rb.executable, false);
  assert.equal(rb.wallet_request, null);
  assert.equal(rb.broadcast, false);
  assert.equal(rb.erp_posting, false);
  assert.equal(rb.fabricated, false);
  assert.equal(rb.calls_id, null);
  assert.equal(rb.tx_hash, null);
  assert.equal(rb.case_id, cse.case_id);
});

test('H213-30 base sepolia rehearsal descriptor-only', () => {
  const r = baseSepoliaRehearsal({ case: cse, route: 'manual_charge', capability_readback: { atomic: 'supported' }, call_shape: oneCall });
  assert.equal(r.executable, false);
  assert.equal(r.descriptor_only, true);
  assert.equal(r.broadcast, false);
  assert.equal(r.calls_id, null);
  assert.equal(r.tx_hash, null);
  assert.equal(r.chain_id, BASE_SEPOLIA_CHAIN_ID);
  assert.equal(r.descriptor.atomicRequired, true);
  const mainnetCase = bindRecurringCase({ ...baseCase, chain_id: BASE_MAINNET_CHAIN_ID, testnet: false });
  assert.equal(baseSepoliaRehearsal({ case: mainnetCase, route: 'manual_charge' }).reason, 'rehearsal_requires_base_sepolia');
  assert.equal(baseSepoliaRehearsal({ case: cse, route: 'manual_charge', capability_readback: { atomic: 'ready' } }).reason, 'atomic_capability_ready_only');
  const cdpRehearsal = baseSepoliaRehearsal({ case: cse, route: 'cdp_charge' });
  assert.equal(cdpRehearsal.tx_hash, null);
  assert.equal(cdpRehearsal.descriptor_only, true);
});

test('H213-31 non-posting ERP projection reconciled', () => {
  const projection = buildNonPostingErpProjection({ case: cse, operation: 'op-31', receipt: { transaction_hash: tx('f') }, period_start: cse.current_period_start, period_end: cse.next_period_start, amount: '50', release });
  assert.equal(projection.posting, false);
  assert.equal(projection.case_id, cse.case_id);
  assert.equal(projection.permission_hash_digest, digestHex);
  assert.equal(projection.release_join.release_fingerprint, release.release_fingerprint);
  assert.equal(projection.erp_readback_required, true);
  const ok = matchReconciliation({ projection, readback: { ...projection } });
  assert.equal(ok.state, 'reconciled');
  assert.equal(ok.reconciliation_ready, true);
  assert.equal(ok.business_close, false);
  assert.equal(ok.erp_posting, false);
  const posted = matchReconciliation({ projection, readback: { ...projection, erp_posting: true } });
  assert.equal(posted.state, 'recovery_ready');
  assert.equal(posted.reason, 'erp_posting_readback_rejected');
  const missing = matchReconciliation({ projection, readback: null });
  assert.equal(missing.state, 'erp_readback_pending');
});

test('H213-32 browser-only client hints rejected', () => {
  assert.equal(bindRecurringCase({ ...baseCase, client_hints: { id: 'browser-guid-1', payer: '0x9'.repeat(40) } }).reason, 'browser_client_hints_rejected');
  assert.equal(bindRecurringCase({ ...baseCase, payer: '0x9'.repeat(40) }).reason, 'payer_not_bound');
});

test('H213-33 revoke gated on revocable active state', () => {
  const inactive = subscriptionGetStatus({ id: digestHex, testnet: true, readback: { isSubscribed: false }, case: cse });
  assert.equal(evaluateRevoke({ case: cse, status_result: inactive }).reason, 'revoke_not_revocable');
  const expired = permissionGetStatus({ permission: permissionTuple, readback: { isActive: false, isRevoked: false, isExpired: true }, case: cseGeneric });
  assert.equal(evaluateRevoke({ case: cseGeneric, status_result: expired }).reason, 'revoke_not_revocable');
});

test('H213-34 adapter selection and unclassified generic state', () => {
  const sub = evaluateStatusAdapter({ status_adapter: 'subscription', case: cse, id: digestHex, testnet: true, subscription_readback: { isSubscribed: true, remainingChargeInPeriod: '100' } });
  assert.equal(sub.state, 'active');
  assert.equal(sub.remaining_charge_in_period, '100');
  const gen = evaluateStatusAdapter({ status_adapter: 'spend_permission', case: cseGeneric, permission_readback: { permission: permissionTuple, isActive: true, isRevoked: false, isExpired: false, remainingSpend: '100' } });
  assert.equal(gen.state, 'active');
  assert.equal(gen.remaining_spend, '100');
  assert.equal(permissionGetStatus({ permission: permissionTuple, readback: { isActive: false, isRevoked: false, isExpired: false } }).reason, 'permission_not_active_unclassified');
  assert.equal(evaluateStatusAdapter({ status_adapter: 'unknown', case: cse }).reason, 'status_adapter_unsupported');
  assert.equal(prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'supported' }, call_shape: oneCall, expected_payer: '0x9999999999999999999999999999999999999999' }).reason, 'expected_payer_mismatch');
});

test('H213-35 missing subscription status stays pending', () => {
  const r = subscriptionGetStatus({ id: digestHex, testnet: true, readback: {}, case: cse });
  assert.equal(r.state, 'status_readback_pending');
  assert.equal(r.reason, 'subscription_status_missing');
});

test('H213-36 generic period fields bind the observed period', () => {
  const next = cseGeneric.current_period_start + cseGeneric.period_seconds;
  const r = permissionGetStatus({ permission: permissionTuple, readback: { isActive: true, isRevoked: false, isExpired: false, remainingSpend: '5', currentPeriod: { start: next, end: next + 86400 }, nextPeriodStart: next + 86400 }, case: cseGeneric });
  assert.equal(r.current_period_start, next);
  assert.equal(r.next_period_start, next + 86400);
  const period = effectivePeriod({ case: cseGeneric, status_result: r });
  assert.equal(period.state, 'period_reset');
  const revoke = evaluateRevoke({ case: cseGeneric, status_result: r });
  assert.equal(revoke.current_period_start, next);
});

test('H213-37 sendCalls envelope and atomicity are explicit', () => {
  const prepared = prepareCharge({ case: cse, status_result: activeSub, requested_amount: '50', capability_readback: { atomic: 'supported' }, call_shape: oneCall });
  assert.equal(verifySendCallsEnvelope({ prepared }).reason, 'send_calls_envelope_missing');
  assert.equal(interpretCallsStatus({ calls_id: 'cid-h213-37', status: 200, receipts: [{ status: '0x1', transaction_hash: tx('7'), chain_id: 84532 }] }).reason, 'manual_non_atomic_batch');
});

test('H213-38 finality requires exact receipt binding', () => {
  const missingBinding = readReceiptFinality({ receipt: { status: '0x1', transaction_hash: tx('8'), chain_id: 84532 }, finality_stage: 'l1_batch_final' });
  assert.equal(missingBinding.state, 'recovery_ready');
  assert.equal(missingBinding.reason, 'receipt_binding_missing');
  const missingChain = readReceiptFinality({ receipt: { status: '0x1', transaction_hash: tx('8') }, finality_stage: 'l1_batch_final', expected: { transaction_hash: tx('8'), chain_id: 84532 } });
  assert.equal(missingChain.reason, 'receipt_binding_missing');
});

test('H213-39 reconciliation includes permission and full release join', () => {
  const projection = buildNonPostingErpProjection({ case: cse, operation: 'op-39', receipt: { transaction_hash: tx('9') }, period_start: cse.current_period_start, period_end: cse.next_period_start, amount: '50', release });
  const badPermission = matchReconciliation({ projection, readback: { ...projection, permission_hash_digest: '0'.repeat(64) } });
  assert.equal(badPermission.reason, 'erp_operation_mismatch');
  const badMaterialOutcome = matchReconciliation({ projection, readback: { ...projection, release_join: { ...release, material_outcome: 'other' } } });
  assert.equal(badMaterialOutcome.reason, 'release_identity_mismatch');
});

test('H213-40 generic adapter requires a server-owned full tuple', () => {
  assert.equal(bindRecurringCase({ ...baseCase, status_adapter: 'spend_permission' }).reason, 'permission_tuple_required');
  assert.equal(bindRecurringCase({ ...baseCase, status_adapter: 'spend_permission', permission_tuple: { ...permissionTuple, extraData: undefined } }).reason, 'permission_tuple_incomplete');
  assert.equal(permissionGetStatus({ permission: { ...permissionTuple, salt: '0x01' }, readback: { isActive: true, remainingSpend: '5' }, case: cseGeneric }).detail, 'salt_or_extra_data_mismatch');
});
