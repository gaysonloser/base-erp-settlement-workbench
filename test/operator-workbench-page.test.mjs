import test from "node:test"
import assert from "node:assert/strict"

import { buildOperatorWorkbench, H215_VISIBLE_STATES } from "../src/base-erp-workbench.mjs"
import { renderOperatorWorkbenchPage } from "../src/operator-workbench-page.mjs"

const RELEASE = Object.freeze({
  release_id: "base-erp-h215-page-test",
  release_fingerprint: "a".repeat(64),
  bom_fingerprint: "b".repeat(64),
})

test("H215 page renders the required shell, queue, canvas and inspector landmarks", () => {
  const html = renderOperatorWorkbenchPage(buildOperatorWorkbench({ release: RELEASE }))
  for (const landmark of [
    '<header class="top" id="global-control-shell" role="banner"',
    '<section class="queue" id="case-queue" role="region"',
    '<main class="canvas" id="decision-canvas" role="main"',
    '<aside class="inspector" id="evidence-inspector" role="complementary"',
  ]) assert.match(html, new RegExp(landmark.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))
  assert.equal((html.match(/class="case(?: selected)? ?"/g) ?? []).length, 7)
  assert.equal((html.match(/data-origin="/g) ?? []).length, 2)
  assert.match(html, /aria-live="polite"/)
})

test("H215 page exposes every visible state and keeps actions non-executable", () => {
  const html = renderOperatorWorkbenchPage(buildOperatorWorkbench({ release: RELEASE }))
  for (const state of H215_VISIBLE_STATES) assert.ok(state.length > 0)
  assert.match(html, /validation_required/)
  assert.match(html, /erp_initiated/)
  assert.match(html, /chain_observed/)
  assert.match(html, /Base Sepolia/)
  assert.match(html, /Mainnet owner gate required/)
  assert.match(html, /<button disabled>Review evidence<\/button>/)
  assert.doesNotMatch(html, /wallet_sendCalls\s*\(/)
  assert.doesNotMatch(html, /0x[a-fA-F0-9]{40}/)
})

test("H215 page preserves independent truth labels and keyboard contract hooks", () => {
  const html = renderOperatorWorkbenchPage(buildOperatorWorkbench({ release: RELEASE }))
  assert.match(html, /Chain truth/)
  assert.match(html, /ERP truth/)
  assert.match(html, /Business close/)
  assert.match(html, /Escape/)
  assert.match(html, /focus-visible/)
  assert.match(html, /min-height:44px/)
  assert.match(html, /setAttribute\("aria-label", "Case queue"\)/)
  assert.match(html, /setOpen\(false\)/)
})
