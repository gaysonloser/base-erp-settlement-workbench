import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWalletErpActionPlan } from '../src/base-wallet-erp-action-plan.mjs';

const base = {
  release: {
    release_id: 'base-erp-public-product-20260821-v10',
    release_fingerprint: 'release-digest',
    bom_fingerprint: 'bom-digest',
  },
  scenario: { direction: 'receivable' },
  wallet: { chain: 'eip155:8453', wallet_method: 'wallet_sendCalls', account_bound: true },
  amount: { amount_minor: 1250, currency: 'USD' },
  erp: { target: 'payment_entry_draft' },
};

const expectCode = (input, code) => assert.throws(
  () => buildWalletErpActionPlan(input),
  error => error?.code === code && error.message === code,
);

test('builds a deterministic unsigned Base Mainnet receivable plan', () => {
  const first = buildWalletErpActionPlan(base);
  const second = buildWalletErpActionPlan(structuredClone(base));
  assert.deepEqual(first, second);
  assert.match(first.action_plan_id, /^wallet_erp_[0-9a-f]{64}$/);
  assert.equal(first.wallet.unsigned, true);
  assert.equal(first.wallet.payload_present, false);
  assert.equal(first.execution_authority, 'owner_review_required');
  assert.equal(first.action_enabled, false);
  assert.equal(first.accounting.mainnet_transaction_credit, 0);
  assert.equal(first.accounting.publication_unit_credit, 0);
});
test('supports the bounded refund branch and ERP allowlist', () => {
  const plan = buildWalletErpActionPlan({
    ...base,
    scenario: { direction: 'refund' },
    erp: { target: 'journal_entry_draft' },
  });
  assert.equal(plan.scenario.direction, 'refund');
  assert.equal(plan.erp.target, 'journal_entry_draft');
});

test('deep-freezes the full plan', () => {
  const plan = buildWalletErpActionPlan(base);
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.release), true);
  assert.equal(Object.isFrozen(plan.required_evidence.wallet), true);
  assert.throws(() => { plan.wallet.unsigned = false; }, TypeError);
});

test('fails closed on incomplete release binding', () => {
  expectCode({ ...base, release: { ...base.release, release_id: '' } }, 'RELEASE_ID_REQUIRED');
  expectCode({ ...base, release: { ...base.release, release_fingerprint: '' } }, 'RELEASE_FINGERPRINT_REQUIRED');
  expectCode({ ...base, release: { ...base.release, bom_fingerprint: '' } }, 'BOM_FINGERPRINT_REQUIRED');
});

test('fails closed on wallet binding drift', () => {
  expectCode({ ...base, wallet: { ...base.wallet, chain: 'eip155:84532' } }, 'WALLET_CHAIN_UNSUPPORTED');
  expectCode({ ...base, wallet: { ...base.wallet, wallet_method: 'eth_sendTransaction' } }, 'WALLET_METHOD_UNSUPPORTED');
  expectCode({ ...base, wallet: { ...base.wallet, account_bound: false } }, 'WALLET_ACCOUNT_NOT_BOUND');
});

test('fails closed on amount and currency drift', () => {
  for (const amount_minor of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    expectCode({ ...base, amount: { ...base.amount, amount_minor } }, 'AMOUNT_MINOR_INVALID');
  }
  for (const currency of ['usd', 'USDC', 'U1D']) {
    expectCode({ ...base, amount: { ...base.amount, currency } }, 'CURRENCY_INVALID');
  }
});

test('fails closed on scenario and ERP target drift', () => {
  expectCode({ ...base, scenario: { direction: 'swap' } }, 'SCENARIO_DIRECTION_UNSUPPORTED');
  expectCode({ ...base, erp: { target: 'arbitrary_doctype' } }, 'ERP_TARGET_UNSUPPORTED');
});

test('rejects unknown fields at every input boundary', () => {
  expectCode({ ...base, address: 'forbidden' }, 'ACTION_PLAN_UNKNOWN_FIELD');
  expectCode({ ...base, wallet: { ...base.wallet, calldata: 'forbidden' } }, 'WALLET_UNKNOWN_FIELD');
  expectCode({ ...base, release: { ...base.release, token: 'forbidden' } }, 'RELEASE_BINDING_UNKNOWN_FIELD');
});

test('serialized output contains no identity, secret, balance, receipt, or execution payload fields', () => {
  const serialized = JSON.stringify(buildWalletErpActionPlan(base)).toLowerCase();
  for (const forbidden of ['address', 'identity', 'token', 'secret', 'cookie', 'calldata', 'tx_hash', 'balance', 'portfolio', 'signed_payload', 'callsid']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});
