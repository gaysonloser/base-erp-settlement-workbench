import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRefundProposal } from "../src/base-refund-ceiling-guard.mjs";

function fixture() {
  return {
    original: {
      case_id: "BASE-ORIGINAL-001",
      candidate_count: 1,
      principal: "1000.00",
      party: "supplier-001",
      direction: "outbound",
      source_document: "PINV-001",
      refund_history: [{ refund_id: "REF-001", amount: "120.00" }],
      refunded_to_date: "120.00",
    },
    proposed: { party: "supplier-001", direction: "inbound", amount: "80.00", original_source_document: "PINV-001" },
  };
}

test("accepts a within-ceiling refund as owner-review-only and decrements remaining ceiling", () => {
  const result = evaluateRefundProposal(fixture());
  assert.equal(result.ok, true);
  assert.equal(result.action_enabled, false);
  assert.equal(result.refunded_to_date, "120");
  assert.equal(result.remaining_ceiling_before, "880");
  assert.equal(result.remaining_ceiling_after, "800");
  assert.equal(result.payment_entry_projection, null);
});

for (const [name, mutate, reason] of [
  ["wrong party", (input) => { input.proposed.party = "other"; }, "refund_party_mismatch"],
  ["wrong direction", (input) => { input.proposed.direction = "outbound"; }, "refund_direction_mismatch"],
  ["wrong source", (input) => { input.proposed.original_source_document = "PINV-999"; }, "refund_source_document_mismatch"],
  ["over refund", (input) => { input.proposed.amount = "880.000001"; }, "refund_amount_exceeds_remaining_ceiling"],
  ["non unique original", (input) => { input.original.candidate_count = 2; }, "original_event_not_unique"],
]) {
  test(`blocks ${name}`, () => {
    const input = fixture(); mutate(input);
    const result = evaluateRefundProposal(input);
    assert.equal(result.ok, false);
    assert.equal(result.fail_closed, true);
    assert.equal(result.reason, reason);
    assert.equal(result.action_enabled, false);
  });
}

test("blocks an exhausted cumulative ceiling", () => {
  const input = fixture();
  input.original.refund_history = [{ refund_id: "REF-001", amount: "1000.00" }];
  input.original.refunded_to_date = "1000.00";
  assert.equal(evaluateRefundProposal(input).reason, "refund_ceiling_exhausted");
});

test("requires append-only refund history to equal refunded-to-date", () => {
  const input = fixture();
  input.original.refund_history.push({ refund_id: "REF-002", amount: "30.00" });
  assert.equal(evaluateRefundProposal(input).reason, "refunded_to_date_history_mismatch");
  input.original.refunded_to_date = "150.00";
  const result = evaluateRefundProposal(input);
  assert.equal(result.ok, true);
  assert.equal(result.remaining_ceiling_after, "770");
});

test("missing original fails closed without accounting projections", () => {
  const result = evaluateRefundProposal({ proposed: fixture().proposed });
  assert.equal(result.reason, "original_event_missing");
  assert.equal(result.payment_entry_projection, null);
  assert.equal(result.bank_transaction_projection, null);
  assert.equal(result.gl_projection, null);
});
