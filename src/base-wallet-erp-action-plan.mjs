import { createHash } from 'node:crypto';

const TOP_LEVEL_FIELDS = new Set(['release', 'scenario', 'wallet', 'amount', 'erp']);
const RELEASE_FIELDS = new Set(['release_id', 'release_fingerprint', 'bom_fingerprint']);
const SCENARIO_FIELDS = new Set(['direction']);
const WALLET_FIELDS = new Set(['chain', 'wallet_method', 'account_bound']);
const AMOUNT_FIELDS = new Set(['amount_minor', 'currency']);
const ERP_FIELDS = new Set(['target']);

const DIRECTIONS = new Set(['receivable', 'refund']);
const ERP_TARGETS = new Set([
  'payment_entry_draft',
  'journal_entry_draft',
  'sales_invoice_reconciliation',
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function plainObject(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code);
  }
  return value;
}

function exactFields(value, allowed, code) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(code);
  }
}

function nonEmptyString(value, code) {
  if (typeof value !== 'string' || value.trim() === '') fail(code);
  return value.trim();
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function stableDigest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export function buildWalletErpActionPlan(input = {}) {
  const root = plainObject(input, 'ACTION_PLAN_INPUT_INVALID');
  exactFields(root, TOP_LEVEL_FIELDS, 'ACTION_PLAN_UNKNOWN_FIELD');

  const release = plainObject(root.release, 'RELEASE_BINDING_REQUIRED');
  exactFields(release, RELEASE_FIELDS, 'RELEASE_BINDING_UNKNOWN_FIELD');
  const normalizedRelease = {
    release_id: nonEmptyString(release.release_id, 'RELEASE_ID_REQUIRED'),
    release_fingerprint: nonEmptyString(release.release_fingerprint, 'RELEASE_FINGERPRINT_REQUIRED'),
    bom_fingerprint: nonEmptyString(release.bom_fingerprint, 'BOM_FINGERPRINT_REQUIRED'),
  };

  const scenario = plainObject(root.scenario, 'SCENARIO_REQUIRED');
  exactFields(scenario, SCENARIO_FIELDS, 'SCENARIO_UNKNOWN_FIELD');
  if (!DIRECTIONS.has(scenario.direction)) fail('SCENARIO_DIRECTION_UNSUPPORTED');

  const wallet = plainObject(root.wallet, 'WALLET_BINDING_REQUIRED');
  exactFields(wallet, WALLET_FIELDS, 'WALLET_UNKNOWN_FIELD');
  if (wallet.chain !== 'eip155:8453') fail('WALLET_CHAIN_UNSUPPORTED');
  if (wallet.wallet_method !== 'wallet_sendCalls') fail('WALLET_METHOD_UNSUPPORTED');
  if (wallet.account_bound !== true) fail('WALLET_ACCOUNT_NOT_BOUND');

  const amount = plainObject(root.amount, 'AMOUNT_REQUIRED');
  exactFields(amount, AMOUNT_FIELDS, 'AMOUNT_UNKNOWN_FIELD');
  if (!Number.isSafeInteger(amount.amount_minor) || amount.amount_minor <= 0) fail('AMOUNT_MINOR_INVALID');
  if (typeof amount.currency !== 'string' || !/^[A-Z]{3}$/.test(amount.currency)) fail('CURRENCY_INVALID');

  const erp = plainObject(root.erp, 'ERP_TARGET_REQUIRED');
  exactFields(erp, ERP_FIELDS, 'ERP_UNKNOWN_FIELD');
  if (!ERP_TARGETS.has(erp.target)) fail('ERP_TARGET_UNSUPPORTED');

  const normalized = {
    release: normalizedRelease,
    scenario: { direction: scenario.direction },
    amount: { amount_minor: amount.amount_minor, currency: amount.currency },
    erp: { target: erp.target },
    wallet: {
      chain: 'eip155:8453',
      wallet_method: 'wallet_sendCalls',
      account_bound: true,
    },
  };

  const actionPlanId = `wallet_erp_${stableDigest(normalized)}`;
  return deepFreeze({
    schema_version: 'base-wallet-erp-action-plan-v1',
    action_plan_id: actionPlanId,
    ...normalized,
    wallet: {
      ...normalized.wallet,
      payload_present: false,
      unsigned: true,
    },
    execution_authority: 'owner_review_required',
    action_enabled: false,
    stop_conditions: [
      'stop_before_broadcast_without_owner_visible_review',
      'stop_on_release_or_bom_drift',
      'stop_on_wallet_chain_or_method_drift',
      'stop_on_missing_receipt_or_finality',
      'stop_on_erp_or_publication_readback_mismatch',
    ],
    required_evidence: {
      wallet: ['receipt_status_success', 'l1_batch_finality', 'unique_state_change'],
      erp: ['draft_or_posting_readback', 'ledger_close_readback'],
      publication: ['current_release_provenance', 'independent_platform_receipts'],
    },
    accounting: {
      mainnet_transaction_credit: 0,
      publication_unit_credit: 0,
      credit_state: 'zero_until_all_required_evidence_passes',
    },
  });
}
