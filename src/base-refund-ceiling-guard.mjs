const AMOUNT = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/;
const DIRECTIONS = new Set(["inbound", "outbound"]);

function text(value, field) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${field} must be a non-empty string`);
  return value.trim();
}

function units(value, field, { positive = false } = {}) {
  const normalized = text(value, field);
  const match = normalized.match(AMOUNT);
  if (!match) throw new TypeError(`${field} must be a decimal with at most six places`);
  const [whole, fraction = ""] = normalized.split(".");
  const result = BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
  if (positive && result <= 0n) throw new RangeError(`${field} must be positive`);
  return result;
}

function decimal(value) {
  const whole = value / 1_000_000n;
  const fraction = String(value % 1_000_000n).padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : String(whole);
}

function blocked(reason, details = {}) {
  return Object.freeze({
    schema_version: "base-refund-ceiling-guard-v1",
    ok: false,
    fail_closed: true,
    action_enabled: false,
    reason,
    payment_entry_projection: null,
    bank_transaction_projection: null,
    gl_projection: null,
    ...details,
  });
}

/** Evaluate a refund proposal without creating a wallet or ERP payload. */
export function evaluateRefundProposal({ original, proposed } = {}) {
  try {
    if (!original || typeof original !== "object" || Array.isArray(original)) return blocked("original_event_missing");
    if (original.candidate_count !== undefined && original.candidate_count !== 1) return blocked("original_event_not_unique");
    if (!proposed || typeof proposed !== "object" || Array.isArray(proposed)) return blocked("proposed_refund_missing");
    const originalCaseId = text(original.case_id, "original.case_id");
    const originalParty = text(original.party, "original.party");
    const originalDirection = text(original.direction, "original.direction");
    if (!DIRECTIONS.has(originalDirection)) throw new TypeError("original.direction must be inbound or outbound");
    const originalSource = text(original.source_document, "original.source_document");
    const principal = units(original.principal, "original.principal", { positive: true });
    const proposedParty = text(proposed.party, "proposed.party");
    const proposedDirection = text(proposed.direction, "proposed.direction");
    if (!DIRECTIONS.has(proposedDirection)) throw new TypeError("proposed.direction must be inbound or outbound");
    const proposedSource = text(proposed.original_source_document, "proposed.original_source_document");
    const proposedAmount = units(proposed.amount, "proposed.amount", { positive: true });
    const history = original.refund_history ?? [];
    if (!Array.isArray(history)) throw new TypeError("original.refund_history must be an array");
    const seen = new Set();
    let refunded = 0n;
    for (const [index, item] of history.entries()) {
      const id = text(item?.refund_id, `original.refund_history[${index}].refund_id`);
      if (seen.has(id)) return blocked("duplicate_refund_history_id", { original_case_id: originalCaseId });
      seen.add(id);
      refunded += units(item?.amount, `original.refund_history[${index}].amount`, { positive: true });
    }
    if (original.refunded_to_date !== undefined && units(original.refunded_to_date, "original.refunded_to_date") !== refunded) {
      return blocked("refunded_to_date_history_mismatch", { original_case_id: originalCaseId, history_total: decimal(refunded) });
    }
    if (proposedParty !== originalParty) return blocked("refund_party_mismatch", { original_case_id: originalCaseId });
    const expectedDirection = originalDirection === "outbound" ? "inbound" : "outbound";
    if (proposedDirection !== expectedDirection) return blocked("refund_direction_mismatch", { original_case_id: originalCaseId, expected_direction: expectedDirection });
    if (proposedSource !== originalSource) return blocked("refund_source_document_mismatch", { original_case_id: originalCaseId });
    if (refunded >= principal) return blocked("refund_ceiling_exhausted", { original_case_id: originalCaseId, remaining_ceiling: "0" });
    const remainingBefore = principal - refunded;
    if (proposedAmount > remainingBefore) return blocked("refund_amount_exceeds_remaining_ceiling", {
      original_case_id: originalCaseId,
      refunded_to_date: decimal(refunded),
      remaining_ceiling: decimal(remainingBefore),
      proposed_amount: decimal(proposedAmount),
    });
    return Object.freeze({
      schema_version: "base-refund-ceiling-guard-v1",
      ok: true,
      fail_closed: false,
      action_enabled: false,
      reason: "refund_within_ceiling_requires_owner_review",
      original_case_id: originalCaseId,
      original_principal: decimal(principal),
      refunded_to_date: decimal(refunded),
      proposed_amount: decimal(proposedAmount),
      remaining_ceiling_before: decimal(remainingBefore),
      remaining_ceiling_after: decimal(remainingBefore - proposedAmount),
      expected_direction: expectedDirection,
      next_owner: "finance_reviewer",
      payment_entry_projection: null,
      bank_transaction_projection: null,
      gl_projection: null,
    });
  } catch (error) {
    return blocked("refund_input_invalid", { detail: error instanceof Error ? error.message : "invalid refund input" });
  }
}
