import { createHash } from 'node:crypto';

const SCHEMA_VERSION = 'base-erp-h213-recurring-settlement-v1';
const AUTHORITY_NONE = 'none_until_02_Build_revalidates';
const BASE_SEPOLIA_CHAIN_ID = 84532;
const BASE_MAINNET_CHAIN_ID = 8453;
const SCALE = 1000000n;
const AMOUNT_RE = /^(0|[1-9]\d*)(?:\.(\d{1,6}))?$/;
const HASH_RE = /^[0-9a-f]{64}$/i;
const ADDRESS_RE = /^0x[0-9a-f]{40}$/i;
const TX_HASH_RE = /^0x[0-9a-f]{64}$/i;
const CIRCLE_IDENTIFIERS = Object.freeze(['circle', 'arc']);
const TERMINAL_STATES = new Set(['inactive', 'expired', 'revoked', 'reconciled', 'calls_terminal_failure', 'recovery_ready', 'recovery_exhausted']);

function fail(state, reason, extra = {}) {
  const { reason: detail, ...rest } = extra;
  return { schema_version: SCHEMA_VERSION, state, reason, ...(detail ? { detail } : {}), ...rest };
}

function canonical(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonical);
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
}

function digest(value) {
  return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

function parseUnits(value, name = 'amount') {
  const match = String(value ?? '').match(AMOUNT_RE);
  if (!match) throw new TypeError(`${name} must be a decimal string with at most 6 places`);
  const whole = match[1];
  const fraction = match[2] ?? '';
  return BigInt(whole) * SCALE + BigInt((fraction + '000000').slice(0, 6));
}

function toUnits(value) {
  return typeof value === 'bigint' ? value : parseUnits(value);
}

function formatUnits(value) {
  const units = toUnits(value);
  const whole = units / SCALE;
  const fraction = String(units % SCALE).padStart(6, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

function periodStart(value) {
  if (Number.isSafeInteger(Number(value))) return Number(value);
  if (!value || typeof value !== 'object') return null;
  for (const key of ['start', 'startTime', 'start_timestamp', 'startTimestamp', 'currentPeriodStart', 'current_period_start']) {
    if (Number.isSafeInteger(Number(value[key]))) return Number(value[key]);
  }
  return null;
}

export { SCHEMA_VERSION, AUTHORITY_NONE, BASE_SEPOLIA_CHAIN_ID, BASE_MAINNET_CHAIN_ID, CIRCLE_IDENTIFIERS, parseUnits, formatUnits };

export function bindRecurringCase(input = {}) {
  const rel = input.release ?? {};
  const release_join = {
    release_id: rel.release_id,
    release_fingerprint: rel.release_fingerprint,
    bom_fingerprint: rel.bom_fingerprint,
    material_outcome: rel.material_outcome,
  };
  if (!release_join.release_id || !release_join.release_fingerprint || !release_join.bom_fingerprint || !release_join.material_outcome) {
    return fail('recovery_ready', 'release_join_incomplete');
  }
  const case_id = String(input.case_id ?? '').trim();
  if (!case_id) return fail('recovery_ready', 'case_id_required');
  const permission_hash_digest = String(input.permission_hash_digest ?? '').toLowerCase();
  if (!permission_hash_digest) return fail('recovery_ready', 'subscribe_rejected_no_permission');
  if (!HASH_RE.test(permission_hash_digest)) return fail('recovery_ready', 'invalid_permission_hash');
  const permission_ref = String(input.permission_ref ?? '').trim();
  if (!permission_ref) return fail('recovery_ready', 'subscribe_rejected_no_permission');
  if (input.client_hints && typeof input.client_hints === 'object' && Object.keys(input.client_hints).length > 0) {
    return fail('recovery_ready', 'browser_client_hints_rejected');
  }
  const payer = String(input.payer ?? '');
  const spender = String(input.spender ?? '');
  if (!ADDRESS_RE.test(payer)) return fail('recovery_ready', 'payer_not_bound');
  if (!ADDRESS_RE.test(spender)) return fail('recovery_ready', 'spender_not_bound');
  if (payer.toLowerCase() === spender.toLowerCase()) return fail('recovery_ready', 'payer_spender_must_differ');
  const token = String(input.token ?? '').trim();
  if (!token) return fail('recovery_ready', 'token_required');
  const chain_id = Number(input.chain_id);
  if (!Number.isSafeInteger(chain_id) || chain_id <= 0) return fail('recovery_ready', 'chain_id_invalid');
  if (typeof input.testnet !== 'boolean') return fail('recovery_ready', 'testnet_required');
  let allowance_units;
  try {
    allowance_units = parseUnits(input.allowance, 'allowance');
  } catch {
    return fail('recovery_ready', 'invalid_allowance');
  }
  if (allowance_units <= 0n) return fail('recovery_ready', 'allowance_not_positive');
  const period_seconds = Number(input.period_seconds);
  if (!Number.isSafeInteger(period_seconds) || period_seconds <= 0) return fail('recovery_ready', 'period_seconds_invalid');
  const start = Number(input.start);
  const end = Number(input.end);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= end) return fail('recovery_ready', 'period_start_end_invalid');
  let recurring_units;
  try {
    recurring_units = parseUnits(input.recurring_charge, 'recurring_charge');
  } catch {
    return fail('recovery_ready', 'invalid_recurring_charge');
  }
  if (recurring_units <= 0n) return fail('recovery_ready', 'recurring_charge_not_positive');
  if (recurring_units > allowance_units) return fail('recovery_ready', 'recurring_charge_exceeds_allowance');
  const rp = input.recipient_policy ?? {};
  const recipient_mode = String(rp.mode ?? '').trim();
  if (!recipient_mode) return fail('recovery_ready', 'recipient_policy_required');
  if (recipient_mode === 'fixed' && !ADDRESS_RE.test(String(rp.default_recipient ?? ''))) return fail('recovery_ready', 'recipient_policy_invalid');
  const adapter = input.status_adapter ?? 'subscription';
  if (adapter !== 'subscription' && adapter !== 'spend_permission') return fail('recovery_ready', 'status_adapter_unsupported');
  const supplied_tuple = input.permission_tuple ?? input.permissionTuple;
  let permission_tuple = null;
  if (adapter === 'spend_permission' && (!supplied_tuple || typeof supplied_tuple !== 'object')) {
    return fail('recovery_ready', 'permission_tuple_required');
  }
  if (supplied_tuple !== undefined) {
    const tuple = supplied_tuple ?? {};
    const tuple_account = String(tuple.account ?? '');
    const tuple_spender = String(tuple.spender ?? '');
    const tuple_token = String(tuple.token ?? '');
    if (!ADDRESS_RE.test(tuple_account) || !ADDRESS_RE.test(tuple_spender) || !tuple_token || tuple.salt === undefined || tuple.extraData === undefined) {
      return fail('recovery_ready', 'permission_tuple_incomplete');
    }
    try {
      if (tuple_account.toLowerCase() !== payer.toLowerCase() || tuple_spender.toLowerCase() !== spender.toLowerCase() || tuple_token !== token || formatUnits(tuple.allowance) !== formatUnits(allowance_units) || Number(tuple.period) !== period_seconds || Number(tuple.start) !== start || Number(tuple.end) !== end) {
        return fail('recovery_ready', 'permission_tuple_mismatch');
      }
    } catch {
      return fail('recovery_ready', 'permission_tuple_mismatch');
    }
    permission_tuple = {
      account: tuple_account.toLowerCase(),
      spender: tuple_spender.toLowerCase(),
      token: tuple_token,
      allowance: formatUnits(tuple.allowance),
      period: period_seconds,
      start,
      end,
      salt: tuple.salt,
      extraData: tuple.extraData,
    };
  }
  const current_period_start = Number.isSafeInteger(Number(input.current_period_start)) ? Number(input.current_period_start) : start;
  const next_period_start = Number.isSafeInteger(Number(input.next_period_start)) ? Number(input.next_period_start) : current_period_start + period_seconds;
  if (current_period_start < start || next_period_start <= current_period_start) return fail('recovery_ready', 'period_window_invalid');
  return {
    schema_version: SCHEMA_VERSION,
    state: 'permission_bound',
    case_id,
    permission_ref,
    permission_hash_digest,
    status_adapter: adapter,
    payer: payer.toLowerCase(),
    spender: spender.toLowerCase(),
    token,
    chain_id,
    testnet: input.testnet,
    allowance: formatUnits(allowance_units),
    period_seconds,
    start,
    end,
    recurring_charge: formatUnits(recurring_units),
    permission_tuple,
    recipient_policy: { mode: recipient_mode, default_recipient: recipient_mode === 'fixed' ? String(rp.default_recipient).toLowerCase() : null },
    current_period_start,
    next_period_start,
    operation_key: null,
    release_join,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

export function subscriptionGetStatus({ id, testnet, readback = {}, case: cse } = {}) {
  try {
    const id_text = String(id ?? '');
    if (!HASH_RE.test(id_text)) return fail('recovery_ready', 'invalid_permission_hash');
    if (typeof testnet !== 'boolean') return fail('recovery_ready', 'invalid_testnet_flag');
    if (cse) {
      if (id_text.toLowerCase() !== String(cse.permission_hash_digest).toLowerCase()) return fail('recovery_ready', 'permission_hash_mismatch');
      if (testnet !== cse.testnet) return fail('recovery_ready', 'network_mismatch');
    }
    const remaining = formatUnits(readback.remainingChargeInPeriod ?? readback.remaining_charge_in_period ?? '0');
    const current = readback.currentPeriodStart ?? readback.current_period_start ?? null;
    const next = readback.nextPeriodStart ?? readback.next_period_start ?? null;
    const subscribed = readback.isSubscribed ?? readback.is_subscribed;
    if (subscribed === false) {
      return { schema_version: SCHEMA_VERSION, state: 'inactive', is_subscribed: false, remaining_charge_in_period: remaining, current_period_start: current, next_period_start: next, terminal: true, action_enabled: false };
    }
    if (subscribed !== true) return fail('status_readback_pending', 'subscription_status_missing');
    return { schema_version: SCHEMA_VERSION, state: 'active', is_subscribed: true, remaining_charge_in_period: remaining, current_period_start: current, next_period_start: next, terminal: false, action_enabled: true };
  } catch (e) {
    return fail('recovery_ready', e.message || 'invalid_status_readback');
  }
}

export function permissionGetStatus({ permission = {}, readback = {}, case: cse } = {}) {
  try {
    const tuple = {
      account: String(permission.account ?? ''),
      spender: String(permission.spender ?? ''),
      token: String(permission.token ?? ''),
      allowance: permission.allowance,
      period: permission.period,
      start: permission.start,
      end: permission.end,
      salt: String(permission.salt ?? ''),
      extraData: permission.extraData ?? null,
    };
    if (!tuple.account || !tuple.spender || !tuple.token) return fail('recovery_ready', 'permission_tuple_incomplete');
    if (cse) {
      if (tuple.account.toLowerCase() !== String(cse.payer).toLowerCase() || tuple.spender.toLowerCase() !== String(cse.spender).toLowerCase()) {
        return fail('recovery_ready', 'permission_tuple_mismatch', { reason: 'payer_or_spender_mismatch' });
      }
      if (tuple.token !== cse.token) return fail('recovery_ready', 'permission_tuple_mismatch', { reason: 'token_mismatch' });
      try {
        if (formatUnits(tuple.allowance) !== formatUnits(cse.allowance)) return fail('recovery_ready', 'permission_tuple_mismatch', { reason: 'allowance_mismatch' });
      } catch {
        return fail('recovery_ready', 'permission_tuple_mismatch', { reason: 'allowance_mismatch' });
      }
      if (Number(tuple.period) !== cse.period_seconds || Number(tuple.start) !== cse.start || Number(tuple.end) !== cse.end) {
        return fail('recovery_ready', 'permission_tuple_mismatch', { reason: 'period_tuple_mismatch' });
      }
      if (cse.permission_tuple) {
        if (String(tuple.salt) !== String(cse.permission_tuple.salt) || digest(tuple.extraData) !== digest(cse.permission_tuple.extraData)) {
          return fail('recovery_ready', 'permission_tuple_mismatch', { reason: 'salt_or_extra_data_mismatch' });
        }
      }
    }
    const remaining = formatUnits(readback.remainingSpend ?? readback.remaining_spend ?? '0');
    const current = readback.currentPeriod ?? readback.current_period ?? null;
    const next = readback.nextPeriodStart ?? readback.next_period_start ?? null;
    const current_period_start = periodStart(readback.currentPeriodStart ?? readback.current_period_start ?? current);
    const next_period_start = periodStart(next);
    if (readback.isRevoked === true || readback.is_revoked === true) {
      return { schema_version: SCHEMA_VERSION, state: 'revoked', is_revoked: true, is_active: false, is_expired: false, remaining_spend: remaining, current_period: current, current_period_start, next_period_start, terminal: true, action_enabled: false };
    }
    if (readback.isExpired === true || readback.is_expired === true) {
      return { schema_version: SCHEMA_VERSION, state: 'expired', is_revoked: false, is_active: false, is_expired: true, remaining_spend: remaining, current_period: current, current_period_start, next_period_start, terminal: true, action_enabled: false };
    }
    if (readback.isActive !== true && readback.is_active !== true) return fail('recovery_ready', 'permission_not_active_unclassified');
    return { schema_version: SCHEMA_VERSION, state: 'active', is_revoked: false, is_expired: false, is_active: true, remaining_spend: remaining, current_period: current, current_period_start, next_period_start, terminal: false, action_enabled: true };
  } catch (e) {
    return fail('recovery_ready', e.message || 'invalid_permission_readback');
  }
}

export function evaluateStatusAdapter({ status_adapter, case: cse, id, testnet, subscription_readback, permission_readback } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  const adapter = status_adapter ?? cse.status_adapter;
  if (adapter === 'subscription') return subscriptionGetStatus({ id, testnet, readback: subscription_readback, case: cse });
  if (adapter === 'spend_permission') return permissionGetStatus({ permission: permission_readback?.permission, readback: permission_readback, case: cse });
  return fail('recovery_ready', 'status_adapter_unsupported');
}

export function effectivePeriod({ case: cse, status_result = {} } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  const has_charge = status_result.remaining_charge_in_period !== undefined && status_result.remaining_charge_in_period !== null;
  const has_spend = status_result.remaining_spend !== undefined && status_result.remaining_spend !== null;
  if (!has_charge && !has_spend) return fail('recovery_ready', 'remaining_allowance_unavailable');
  let remaining;
  try {
    remaining = formatUnits(has_charge ? status_result.remaining_charge_in_period : status_result.remaining_spend);
  } catch {
    return fail('recovery_ready', 'invalid_remaining_allowance');
  }
  const raw = status_result.current_period_start ?? periodStart(status_result.current_period);
  const observed = raw !== undefined && raw !== null && Number.isSafeInteger(Number(raw)) ? Number(raw) : cse.current_period_start;
  if (observed === cse.current_period_start) {
    return { schema_version: SCHEMA_VERSION, state: 'period_current', current_period_start: cse.current_period_start, next_period_start: cse.next_period_start, remaining, unused_carried: '0', rollover: false };
  }
  if (observed < cse.current_period_start) return fail('recovery_ready', 'period_regression', { observed, expected: cse.current_period_start });
  return { schema_version: SCHEMA_VERSION, state: 'period_reset', current_period_start: observed, next_period_start: observed + cse.period_seconds, remaining: cse.allowance, unused_carried: '0', rollover: false, reset_from_readback: true };
}

export function deriveOperationKey({ case: cse, amount, current_period_start, release, kind = 'charge' } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  const rel = release ?? cse.release_join ?? {};
  let amount_text;
  try {
    amount_text = formatUnits(amount ?? '0');
  } catch {
    return fail('recovery_ready', 'invalid_amount');
  }
  const operation_key = digest({ kind: `h213_${kind}`, case_id: cse.case_id, permission_hash_digest: cse.permission_hash_digest, chain_id: cse.chain_id, current_period_start, amount: amount_text, release_fingerprint: rel.release_fingerprint ?? null });
  return { schema_version: SCHEMA_VERSION, state: 'operation_key_derived', operation_key, kind };
}

export function reserveOperationKey({ case: cse, amount, current_period_start, release, kind = 'charge', ledger = {} } = {}) {
  const derived = deriveOperationKey({ case: cse, amount, current_period_start, release, kind });
  if (derived.state !== 'operation_key_derived') return derived;
  const key = derived.operation_key;
  const prior = ledger[key];
  if (prior) {
    const unresolved = prior.state !== undefined && !TERMINAL_STATES.has(prior.state);
    return fail('recovery_ready', unresolved ? 'operation_unresolved_replay_locked' : 'duplicate_operation_key', { operation_key: key, prior_state: prior.state ?? 'unknown' });
  }
  return { schema_version: SCHEMA_VERSION, state: 'operation_reserved', operation_key: key, kind, replay_locked: false };
}

export function evaluateCharge({ case: cse, status_result, requested_amount, operation_key, ledger = {}, release } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  if (!status_result || status_result.state !== 'active') return fail('recovery_ready', 'charge_blocked_not_active', { status: status_result?.state ?? 'unknown' });
  const period = effectivePeriod({ case: cse, status_result });
  if (period.state === 'recovery_ready') return period;
  let amount_units;
  try {
    amount_units = parseUnits(requested_amount, 'requested_amount');
  } catch {
    return fail('recovery_ready', 'invalid_amount');
  }
  if (amount_units <= 0n) return fail('recovery_ready', 'amount_not_positive');
  if (amount_units > toUnits(period.remaining)) return fail('recovery_ready', 'amount_exceeds_remaining_allowance', { remaining: period.remaining, requested: formatUnits(amount_units) });
  const rel = release ?? cse.release_join;
  if (!rel?.release_fingerprint || !rel?.bom_fingerprint) return fail('recovery_ready', 'release_join_incomplete');
  if (rel.release_fingerprint !== cse.release_join.release_fingerprint || rel.bom_fingerprint !== cse.release_join.bom_fingerprint) return fail('recovery_ready', 'release_identity_mismatch');
  const reserved = reserveOperationKey({ case: cse, amount: requested_amount, current_period_start: period.current_period_start, release: rel, kind: 'charge', ledger });
  if (reserved.state !== 'operation_reserved') return reserved;
  if (operation_key !== undefined && operation_key !== null && operation_key !== reserved.operation_key) return fail('recovery_ready', 'operation_key_mismatch');
  return {
    schema_version: SCHEMA_VERSION,
    state: 'charge_candidate',
    kind: 'charge',
    action_enabled: false,
    amount_allowed: formatUnits(amount_units),
    remaining_after: formatUnits(toUnits(period.remaining) - amount_units),
    current_period_start: period.current_period_start,
    next_period_start: period.next_period_start,
    rollover: false,
    operation_key: reserved.operation_key,
    wallet_request: null,
    calls_id: null,
    tx_hash: null,
    descriptor: null,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

export function evaluateRevoke({ case: cse, status_result, operation_key, ledger = {}, release } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  if (!status_result) return fail('recovery_ready', 'status_readback_required');
  if (status_result.state === 'revoked') return fail('recovery_ready', 'already_revoked');
  if (status_result.state !== 'active') return fail('recovery_ready', 'revoke_not_revocable', { status: status_result.state });
  const rel = release ?? cse.release_join;
  if (!rel?.release_fingerprint) return fail('recovery_ready', 'release_join_incomplete');
  const observed_period_start = Number.isSafeInteger(Number(status_result.current_period_start))
    ? Number(status_result.current_period_start)
    : (periodStart(status_result.current_period) ?? cse.current_period_start);
  const reserved = reserveOperationKey({ case: cse, amount: '0', current_period_start: observed_period_start, release: rel, kind: 'revoke', ledger });
  if (reserved.state !== 'operation_reserved') return reserved;
  if (operation_key !== undefined && operation_key !== null && operation_key !== reserved.operation_key) return fail('recovery_ready', 'operation_key_mismatch');
  const remaining = status_result.remaining_charge_in_period ?? status_result.remaining_spend ?? '0';
  return {
    schema_version: SCHEMA_VERSION,
    state: 'revocation_candidate',
    kind: 'revoke',
    permanent: true,
    positive_remaining_required: false,
    remaining,
    current_period_start: observed_period_start,
    operation_key: reserved.operation_key,
    wallet_request: null,
    calls_id: null,
    tx_hash: null,
    descriptor: null,
    action_enabled: false,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

export function cdpCharge({ case: cse, status_result, requested_amount, operation_key, ledger = {}, release, result = {} } = {}) {
  const candidate = evaluateCharge({ case: cse, status_result, requested_amount, operation_key, ledger, release });
  if (candidate.state !== 'charge_candidate') return candidate;
  const tx_hash = String(result.tx_hash ?? result.transaction_hash ?? result.transaction_id ?? '');
  if (!TX_HASH_RE.test(tx_hash)) return fail('recovery_ready', 'cdp_tx_hash_missing', { execution_route: 'cdp' });
  return {
    schema_version: SCHEMA_VERSION,
    state: 'tx_pending',
    kind: 'charge',
    execution_route: 'cdp',
    operation_key: candidate.operation_key,
    tx_hash: tx_hash.toLowerCase(),
    calls_id: null,
    descriptor: null,
    amount: candidate.amount_allowed,
    wallet_request: null,
    action_enabled: false,
    receipt_route: 'direct_receipt_finality',
    calls_status_route: false,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

export function cdpRevoke({ case: cse, status_result, operation_key, ledger = {}, release, result = {} } = {}) {
  const candidate = evaluateRevoke({ case: cse, status_result, operation_key, ledger, release });
  if (candidate.state !== 'revocation_candidate') return candidate;
  const tx_hash = String(result.tx_hash ?? result.transaction_hash ?? result.transaction_id ?? '');
  if (!TX_HASH_RE.test(tx_hash)) return fail('recovery_ready', 'cdp_tx_hash_missing', { execution_route: 'cdp' });
  return {
    schema_version: SCHEMA_VERSION,
    state: 'revoke_tx_pending',
    kind: 'revoke',
    execution_route: 'cdp',
    operation_key: candidate.operation_key,
    tx_hash: tx_hash.toLowerCase(),
    calls_id: null,
    descriptor: null,
    wallet_request: null,
    action_enabled: false,
    receipt_route: 'direct_receipt_finality',
    calls_status_route: false,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

function buildManualDescriptor({ cse, operation_key, capability_readback = {}, call_shape = [], expected_payer, expected_spender }) {
  const atomic = capability_readback.atomic;
  if (atomic !== 'supported') return fail('recovery_ready', atomic === 'ready' ? 'atomic_capability_ready_only' : 'atomic_capability_not_supported', { atomic: atomic ?? 'unknown' });
  if (!Array.isArray(call_shape) || call_shape.length === 0) return fail('recovery_ready', 'call_shape_empty');
  const payer = String(expected_payer ?? cse.payer ?? '').toLowerCase();
  const spender = String(expected_spender ?? cse.spender ?? '').toLowerCase();
  if (payer !== String(cse.payer).toLowerCase()) return fail('recovery_ready', 'expected_payer_mismatch');
  if (spender !== String(cse.spender).toLowerCase()) return fail('recovery_ready', 'expected_spender_mismatch');
  const calls = call_shape.map((c) => ({ to: String(c?.to ?? '').toLowerCase(), data: String(c?.data ?? ''), value: String(c?.value ?? '0x0') }));
  if (calls.some((c) => !ADDRESS_RE.test(c.to))) return fail('recovery_ready', 'call_target_invalid');
  const descriptor = { version: '2.0.0', chainId: cse.chain_id, from: spender, atomicRequired: true, calls };
  const descriptor_digest = digest(descriptor);
  return {
    schema_version: SCHEMA_VERSION,
    state: 'owner_review_required',
    execution_route: 'manual',
    operation_key,
    descriptor,
    descriptor_digest,
    calls_id: null,
    tx_hash: null,
    expected_payer: payer,
    expected_spender: spender,
    atomic_required: true,
    side_effect_free: true,
    wallet_request: null,
    action_enabled: false,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

export function prepareCharge({ case: cse, status_result, requested_amount, operation_key, ledger = {}, release, capability_readback = {}, call_shape = [], expected_payer, expected_spender } = {}) {
  const candidate = evaluateCharge({ case: cse, status_result, requested_amount, operation_key, ledger, release });
  if (candidate.state !== 'charge_candidate') return candidate;
  const manual = buildManualDescriptor({ cse, operation_key: candidate.operation_key, capability_readback, call_shape, expected_payer, expected_spender });
  if (manual.state !== 'owner_review_required') return manual;
  return { ...manual, kind: 'charge', amount: candidate.amount_allowed, remaining_after: candidate.remaining_after, current_period_start: candidate.current_period_start, next_period_start: candidate.next_period_start };
}

export function prepareRevoke({ case: cse, status_result, operation_key, ledger = {}, release, capability_readback = {}, call_shape = [], expected_payer, expected_spender } = {}) {
  const candidate = evaluateRevoke({ case: cse, status_result, operation_key, ledger, release });
  if (candidate.state !== 'revocation_candidate') return candidate;
  const manual = buildManualDescriptor({ cse, operation_key: candidate.operation_key, capability_readback, call_shape, expected_payer, expected_spender });
  if (manual.state !== 'owner_review_required') return manual;
  return { ...manual, kind: 'revoke', remaining: candidate.remaining, permanent: true };
}

export function verifySendCallsEnvelope({ prepared = {}, envelope = {} } = {}) {
  if (!prepared.descriptor_digest) return fail('recovery_ready', 'prepared_digest_missing');
  if (!envelope || typeof envelope !== 'object' || !Object.hasOwn(envelope, 'version') || !Object.hasOwn(envelope, 'chainId') || !Object.hasOwn(envelope, 'from') || !Object.hasOwn(envelope, 'atomicRequired') || !Object.hasOwn(envelope, 'calls')) {
    return fail('recovery_ready', 'send_calls_envelope_missing');
  }
  const version = envelope.version;
  const chainId = envelope.chainId;
  const from = String(envelope.from);
  const calls = envelope.calls;
  const atomicRequired = envelope.atomicRequired;
  if (version !== '2.0.0') return fail('recovery_ready', 'send_calls_version_unsupported', { version: version ?? 'missing' });
  if (chainId !== prepared.descriptor?.chainId) return fail('recovery_ready', 'send_calls_chain_mismatch');
  if (from.toLowerCase() !== String(prepared.descriptor?.from).toLowerCase()) return fail('recovery_ready', 'send_calls_from_mismatch');
  if (atomicRequired !== true) return fail('recovery_ready', 'atomic_required_missing', { atomicRequired: atomicRequired ?? 'missing' });
  if (!Array.isArray(calls)) return fail('recovery_ready', 'send_calls_calls_missing');
  const recomputed = digest({ version, chainId, from, atomicRequired, calls });
  if (recomputed !== prepared.descriptor_digest) return fail('recovery_ready', 'call_descriptor_drift', { recomputed, expected: prepared.descriptor_digest });
  return { schema_version: SCHEMA_VERSION, state: 'send_calls_verified', version, chainId, from: from.toLowerCase(), atomic_required: true, call_count: calls.length, descriptor_digest: prepared.descriptor_digest };
}

export function bindCallsId({ operation_key, descriptor_digest, calls_id, ledger = {} } = {}) {
  const cid = String(calls_id ?? '');
  if (!cid) return fail('recovery_ready', 'calls_id_missing');
  if (TX_HASH_RE.test(cid)) return fail('recovery_ready', 'calls_id_tx_hash_mix_rejected');
  if (!operation_key) return fail('recovery_ready', 'operation_key_missing');
  if (!HASH_RE.test(String(descriptor_digest ?? ''))) return fail('recovery_ready', 'descriptor_digest_missing');
  const prior = ledger[operation_key];
  if (prior && !TERMINAL_STATES.has(prior.state)) return fail('recovery_ready', 'operation_unresolved_replay_locked', { operation_key, prior_state: prior.state });
  return { schema_version: SCHEMA_VERSION, state: 'calls_pending', kind: 'manual', execution_route: 'manual', calls_id: cid, operation_key, descriptor_digest, tx_hash: null, wallet_request: null, wait: true, action_enabled: false, calls_status_route: true };
}

export function interpretCallsStatus({ calls_id, status, receipts = [], atomic, expected = {} } = {}) {
  const cid = String(calls_id ?? '');
  if (!cid) return fail('recovery_ready', 'calls_id_missing');
  if (TX_HASH_RE.test(cid)) return fail('recovery_ready', 'calls_id_tx_hash_mix_rejected');
  if (status === 100) return { schema_version: SCHEMA_VERSION, state: 'calls_pending', calls_id: cid, status, wait: true, action_enabled: false, calls_status_route: true };
  if (status === 400 || status === 500) return fail('calls_terminal_failure', 'send_calls_terminal_failure', { calls_id: cid, status, next_action: 'new_owner_authorized_key_and_owner_gate_required' });
  if (status === 600) return fail('recovery_ready', 'manual_partial_batch', { calls_id: cid, status, reason: 'partial_batch_status' });
  if (status !== 200) return fail('recovery_ready', 'send_calls_unknown_status', { calls_id: cid, status });
  const list = Array.isArray(receipts) ? receipts : receipts ? [receipts] : [];
  if (list.length === 0) return fail('recovery_ready', 'receipt_missing', { calls_id: cid });
  if (atomic !== true) return fail('recovery_ready', 'manual_non_atomic_batch', { calls_id: cid, atomic: atomic ?? 'missing' });
  if (list.some((r) => !r || r.status !== '0x1')) return fail('recovery_ready', 'receipt_reverted', { calls_id: cid, receipt_status: list.find((r) => !r || r.status !== '0x1')?.status ?? 'missing' });
  if (expected?.transaction_hash && !list.some((r) => String(r?.transaction_hash ?? '').toLowerCase() === String(expected.transaction_hash).toLowerCase())) {
    return fail('recovery_ready', 'receipt_intent_mismatch', { reason: 'transaction_hash_mismatch' });
  }
  if (expected?.chain_id !== undefined && list.some((r) => r?.chain_id !== undefined && r.chain_id !== expected.chain_id)) {
    return fail('recovery_ready', 'receipt_intent_mismatch', { reason: 'chain_id_mismatch' });
  }
  return { schema_version: SCHEMA_VERSION, state: 'receipt_success_unfinalized', calls_id: cid, status, atomic: atomic !== false, receipts: list, finality_required: 'l1_batch_final', action_enabled: false, calls_status_route: true, erp_posting: false };
}

export function readReceiptFinality({ receipt, finality_stage, expected = {}, kind = 'charge' } = {}) {
  if (!receipt || receipt.status !== '0x1') return fail('recovery_ready', 'receipt_reverted', { receipt_status: receipt?.status ?? 'missing' });
  const stage = String(finality_stage ?? '');
  if (stage === 'reorged' || stage === 'removed' || stage === 'reorg_detected' || stage === 'null') {
    return fail('recovery_ready', 'reorg_evidence_removed', { finality_stage: stage });
  }
  if (!expected?.transaction_hash || expected?.chain_id === undefined) return fail('recovery_ready', 'receipt_binding_missing');
  if (!receipt.transaction_hash) return fail('recovery_ready', 'receipt_binding_missing', { reason: 'transaction_hash_missing' });
  if (String(receipt.transaction_hash).toLowerCase() !== String(expected.transaction_hash).toLowerCase()) {
    return fail('recovery_ready', 'receipt_intent_mismatch', { reason: 'transaction_hash_mismatch' });
  }
  if (receipt.chain_id === undefined || receipt.chain_id === null) return fail('recovery_ready', 'receipt_binding_missing', { reason: 'chain_id_missing' });
  if (receipt.chain_id !== expected.chain_id) {
    return fail('recovery_ready', 'receipt_intent_mismatch', { reason: 'chain_id_mismatch' });
  }
  if (stage !== 'l1_batch_final') return fail('finality_pending', 'receipt_not_final', { finality_stage: stage || 'missing', required: 'l1_batch_final' });
  return { schema_version: SCHEMA_VERSION, state: kind === 'revoke' ? 'revoke_receipt_final' : 'charge_receipt_final', kind, receipt, finality_stage: stage, erp_posting: false, action_enabled: false };
}

export function readCdpTransaction({ tx_hash, receipt, finality_stage, expected = {}, kind = 'charge' } = {}) {
  if (!TX_HASH_RE.test(String(tx_hash ?? ''))) return fail('recovery_ready', 'cdp_tx_hash_invalid', { execution_route: 'cdp' });
  const finality = readReceiptFinality({ receipt, finality_stage, expected: { ...expected, transaction_hash: expected.transaction_hash ?? tx_hash }, kind });
  return { ...finality, execution_route: 'cdp', tx_hash: String(tx_hash).toLowerCase(), calls_id: null, calls_status_route: false };
}

export function buildNonPostingErpProjection({ case: cse, operation, receipt, period_start, period_end, amount, release } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  const tx_hash = String(receipt?.transaction_hash ?? receipt?.tx_hash ?? '');
  if (!TX_HASH_RE.test(tx_hash)) return fail('recovery_ready', 'erp_projection_receipt_missing');
  const operation_key = typeof operation === 'string' ? operation : operation?.operation_key;
  if (!operation_key) return fail('recovery_ready', 'erp_projection_operation_missing');
  if (!Number.isSafeInteger(period_start) || !Number.isSafeInteger(period_end) || period_end <= period_start) return fail('recovery_ready', 'erp_projection_period_invalid');
  const rel = release ?? cse.release_join;
  return {
    schema_version: SCHEMA_VERSION,
    state: 'erp_projection_ready',
    posting: false,
    case_id: cse.case_id,
    permission_hash_digest: cse.permission_hash_digest,
    operation_key,
    period_start,
    period_end,
    transaction_hash: tx_hash.toLowerCase(),
    amount: formatUnits(amount ?? '0'),
    asset: cse.token,
    chain_id: cse.chain_id,
    testnet: cse.testnet,
    release_join: { ...rel },
    erp_readback_required: true,
    business_close: false,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
  };
}

export function matchReconciliation({ projection, readback, case: cse, release } = {}) {
  if (!projection || projection.posting !== false) return fail('recovery_ready', 'non_posting_projection_required');
  if (!readback || typeof readback !== 'object') return fail('erp_readback_pending', 'erp_readback_missing');
  if (readback.posting === true || readback.erp_posting === true) return fail('recovery_ready', 'erp_posting_readback_rejected');
  const rel = release ?? cse?.release_join ?? projection.release_join;
  const rb_rel = readback.release_join ?? readback.release ?? {};
  if (rel?.release_fingerprint) {
    const release_keys = ['release_id', 'release_fingerprint', 'bom_fingerprint', 'material_outcome'];
    if (release_keys.some((key) => !rb_rel?.[key])) return fail('recovery_ready', 'release_identity_mismatch', { reason: 'release_join_missing_in_readback' });
    if (release_keys.some((key) => rb_rel[key] !== rel[key])) {
      return fail('recovery_ready', 'release_identity_mismatch', { reason: 'release_fingerprint_or_bom_mismatch' });
    }
  }
  const keys = ['case_id', 'permission_hash_digest', 'operation_key', 'period_start', 'period_end', 'transaction_hash', 'amount', 'asset', 'chain_id', 'testnet'];
  const pick = (o) => JSON.stringify(keys.map((k) => o?.[k] ?? null));
  if (pick(readback) !== pick(projection)) return fail('recovery_ready', 'erp_operation_mismatch', { reason: 'same_case_same_operation_join_missing' });
  return { schema_version: SCHEMA_VERSION, state: 'reconciled', posting: false, reconciliation_ready: true, business_close: false, erp_posting: false, authority: AUTHORITY_NONE, execution_authority: AUTHORITY_NONE, erp_readback_matched: true };
}

export function buildReadbackRecord({ case: cse, operation, descriptor, calls_id, tx_hash, receipt, finality_stage, erp_readback } = {}) {
  return {
    schema_version: SCHEMA_VERSION,
    authority: AUTHORITY_NONE,
    execution_authority: AUTHORITY_NONE,
    executable: false,
    testnet: cse?.testnet ?? false,
    chain_id: cse?.chain_id ?? null,
    case_id: cse?.case_id ?? null,
    permission_hash_digest: cse?.permission_hash_digest ?? null,
    operation_key: typeof operation === 'string' ? operation : operation?.operation_key ?? null,
    descriptor_digest: descriptor?.descriptor_digest ?? descriptor?.digest ?? null,
    calls_id: calls_id ?? null,
    tx_hash: tx_hash ?? null,
    receipt_status: receipt?.status ?? null,
    finality_stage: finality_stage ?? null,
    erp_readback_matched: erp_readback?.matched ?? erp_readback?.state === 'reconciled',
    wallet_request: null,
    broadcast: false,
    erp_posting: false,
    fabricated: false,
  };
}

export function baseSepoliaRehearsal({ case: cse, route = 'charge', call_shape, capability_readback = {} } = {}) {
  if (!cse) return fail('recovery_ready', 'case_not_bound');
  if (cse.testnet !== true || cse.chain_id !== BASE_SEPOLIA_CHAIN_ID) return fail('recovery_ready', 'rehearsal_requires_base_sepolia');
  const base = { schema_version: SCHEMA_VERSION, authority: AUTHORITY_NONE, execution_authority: AUTHORITY_NONE, executable: false, testnet: true, chain_id: BASE_SEPOLIA_CHAIN_ID, rehearsal: true, descriptor_only: true, broadcast: false, wallet_request: null, calls_id: null, tx_hash: null, receipt: null };
  if (route === 'cdp_charge' || route === 'cdp_revoke') {
    return { ...base, execution_route: route, note: 'cdp_helper_rehearsal_plan_only_no_tx_hash_fabricated' };
  }
  if (route === 'manual_charge' || route === 'manual_revoke') {
    const atomic = capability_readback.atomic;
    if (atomic !== 'supported') return fail('recovery_ready', atomic === 'ready' ? 'atomic_capability_ready_only' : 'atomic_capability_not_supported', { atomic: atomic ?? 'unknown' });
    const calls = Array.isArray(call_shape) ? call_shape.map((c) => ({ to: String(c?.to ?? '').toLowerCase(), data: String(c?.data ?? ''), value: String(c?.value ?? '0x0') })) : [];
    const descriptor = calls.length ? { version: '2.0.0', chainId: cse.chain_id, from: String(cse.spender).toLowerCase(), atomicRequired: true, calls } : null;
    return { ...base, execution_route: route, descriptor_only: true, descriptor, descriptor_digest: descriptor ? digest(descriptor) : null };
  }
  return fail('recovery_ready', 'rehearsal_route_unsupported');
}

export function checkBaseCircleIsolation({ target, release, circle_identifiers = CIRCLE_IDENTIFIERS } = {}) {
  const target_text = String(target ?? '').toLowerCase();
  const identifiers = Array.isArray(circle_identifiers) ? circle_identifiers : [circle_identifiers];
  for (const identifier of identifiers) {
    if (target_text.includes(String(identifier).toLowerCase())) {
      return fail('owner_platform_gate_no_overwrite', 'base_circle_identity_collision', { target, matched_identifier: identifier });
    }
  }
  const rel = release ?? {};
  const release_text = [rel.release_id, rel.release_fingerprint, rel.bom_fingerprint, rel.material_outcome].filter(Boolean).join('|').toLowerCase();
  for (const identifier of identifiers) {
    if (release_text.includes(String(identifier).toLowerCase())) {
      return fail('owner_platform_gate_no_overwrite', 'base_circle_identity_collision', { release, matched_identifier: identifier });
    }
  }
  return { schema_version: SCHEMA_VERSION, state: 'base_identity_isolated', circle_collision: false, base_identity: { repository: 'gaysonloser/base-erp-settlement-workbench', render_service: 'base-erp-settlement-workbench', basename: 'gaysonloser.base.eth' }, action_enabled: false };
}
