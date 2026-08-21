import { renderWalletBridgeBrowserScript } from "./base-account-wallet-bridge.mjs";
import { renderBaseAuthBrowserScript } from "./auth/browser-auth.mjs";

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderRecurringSettlement(recurring) {
  if (!recurring || typeof recurring !== "object") return "";
  const status = recurring.status ?? {};
  const plan = recurring.plan ?? {};
  const routes = recurring.route_previews ?? {};
  const gates = recurring.gates ?? {};
  const erp = gates.erp ?? {};
  const cdp = routes.charge?.cdp ?? {};
  const manual = routes.charge?.manual ?? {};
  const period = plan.period ?? {};
  const recurringCharge = plan.recurring_charge?.value ?? null;
  const allowance = plan.remaining_allowance?.value ?? null;
  const periodText = period.current_period_start !== null && period.current_period_start !== undefined
    ? `current ${escapeHtml(period.current_period_start)} → next ${escapeHtml(period.next_period_start)}`
    : "not observed";
  const routeSummary = [
    `${escapeHtml(cdp.execution_route ?? "cdp_tx_hash")} · preview only · direct receipt/finality`,
    `${escapeHtml(manual.execution_route ?? "manual_wallet_sendCalls")} · descriptor only · atomic required · calls status`,
  ].join(" | ");
  return `<section class="consequence" id="recurring-settlement" aria-labelledby="recurring-heading"><h3 id="recurring-heading">Recurring settlement · public surface</h3><dl>
<dt>Status</dt><dd>${escapeHtml(status.state ?? "status_readback_pending")}${status.reason ? ` · ${escapeHtml(status.reason)}` : ""}</dd>
<dt>Adapter</dt><dd>${status.adapter ? `${escapeHtml(status.adapter)} · chain ${escapeHtml(plan.network?.chain_id)} · supported subscription / spend_permission` : "not bound"}</dd>
<dt>Recurring plan</dt><dd>${recurringCharge !== null ? `${escapeHtml(recurringCharge)} per period` : "not observed"}</dd>
<dt>No rollover</dt><dd>${escapeHtml(String(period.no_rollover ?? true))}</dd>
<dt>Allowance readback</dt><dd>${allowance !== null ? escapeHtml(allowance) : "not observed"}</dd>
<dt>Period</dt><dd>${periodText}</dd>
<dt>Routes</dt><dd>${routeSummary}</dd>
<dt>Receipt</dt><dd>${escapeHtml(gates.receipt?.state ?? "not_observed")} · required 0x1 + intent binding</dd>
<dt>Finality</dt><dd>${escapeHtml(gates.finality?.state ?? "not_observed")} · required ${escapeHtml(gates.finality?.required ?? "l1_batch_final")}</dd>
<dt>ERP gate</dt><dd>${erp.posting === false ? "non-posting" : escapeHtml(String(erp.posting))} · business close ${escapeHtml(String(erp.business_close ?? false))}</dd>
</dl><p class="muted">Visitor-safe projection: actions, wallet requests and raw permission/address/call data remain disabled and redacted.</p><div class="action"><span class="muted">Blocked: no owner-authorized recurring action</span><button disabled>Recurring actions disabled</button></div></section>`;
}

function renderOriginLanes(operatorSurface) {
  return (operatorSurface.entry_points ?? []).map((origin) => `<article class="origin-lane" data-origin="${escapeHtml(origin.id)}" aria-label="${escapeHtml(origin.label)} origin lane">
    <div class="origin-heading"><strong>${escapeHtml(origin.label)}</strong><span class="state-chip">${escapeHtml(origin.state)}</span></div>
    <p class="muted">Server-owned ${escapeHtml(origin.source_kind.replaceAll("_", " "))}; action disabled until independent validation.</p>
    <small>Evidence: ${escapeHtml(origin.evidence_required.join(" · "))}</small>
  </article>`).join("");
}

function renderFactCards(facts = {}) {
  const ordered = [
    ["chain", facts.chain],
    ["receipt", facts.receipt],
    ["finality", facts.finality],
    ["erp_posting", facts.erp_posting],
    ["business_close", facts.business_close],
  ];
  return ordered.map(([key, fact]) => `<div class="fact" data-fact="${key}"><small>${escapeHtml(key.replaceAll("_", " "))}</small><strong>${escapeHtml(fact?.state ?? "not_evaluated")}</strong><span>${escapeHtml(fact?.route ?? fact?.required ?? (fact?.claimed === false ? "independent readback required" : "server-owned fact"))}</span></div>`).join("");
}

function renderPlatformGates(platformGates) {
  if (!platformGates || !Array.isArray(platformGates.rows)) return "";
  const rows = platformGates.rows.map((row) => `<article class="platform-gate-row" data-platform-gate="${escapeHtml(row.platform_row_id)}"><strong>${escapeHtml(row.platform_row_id)}</strong><span>${escapeHtml(row.evidence_state)}</span><small>${escapeHtml(row.owner_gate)}</small><small>Native receipt: null · release receipt: false · credit: 0</small></article>`).join("");
  return `<section class="platform-gates-panel" id="platform-gates-panel" aria-labelledby="platform-gates-heading"><div class="platform-gates-heading"><h3 id="platform-gates-heading">Platform gates</h3><a href="/platform-gates.json" aria-label="Platform gates JSON">Read JSON</a></div><p class="muted">Four H217 owner-gated rows; visitor-safe evidence only. No row creates a publication receipt.</p><div class="platform-gates-rows">${rows}</div></section>`;
}

function renderWalletActionPlan(plan) {
  if (!plan || typeof plan !== "object") return "";
  const wallet = plan.wallet ?? {};
  const accounting = plan.accounting ?? {};
  const unavailable = plan.unavailable_reason
    ? `<p class="muted">Unavailable for this profile: ${escapeHtml(plan.unavailable_reason)}</p>`
    : `<dl><dt>Scenario</dt><dd>${escapeHtml(plan.scenario?.direction ?? "not exposed")}</dd><dt>ERP target</dt><dd>${escapeHtml(plan.erp?.target ?? "not exposed")}</dd><dt>Amount</dt><dd>${escapeHtml(String(plan.amount?.amount_minor ?? "not exposed"))} minor units · ${escapeHtml(plan.amount?.currency ?? "not exposed")}</dd></dl>`;
  return `<section class="wallet-action-plan" id="wallet-action-plan" aria-labelledby="wallet-action-plan-heading"><h3 id="wallet-action-plan-heading">Wallet ERP action plan</h3><p class="muted">Deterministic unsigned descriptor. Visitor mode never receives executable target/value/data; an authenticated owner must review the release-bound plan before a second explicit send click.</p><dl><dt>Chain</dt><dd>${escapeHtml(wallet.chain ?? "eip155:8453")}</dd><dt>Method</dt><dd>${escapeHtml(wallet.wallet_method ?? "wallet_sendCalls")}</dd><dt>Account binding</dt><dd>${wallet.account_bound === true ? "bound without identity exposure" : "not bound"}</dd><dt>Authority</dt><dd>${escapeHtml(plan.execution_authority ?? "owner_review_required")}</dd><dt>Payload</dt><dd>${wallet.payload_present === true ? "present" : "absent"} · ${wallet.unsigned === true ? "unsigned" : "signed"}</dd></dl>${unavailable}<div data-base-auth-review hidden class="muted" aria-live="polite"></div><p class="muted">Credits: mainnet ${escapeHtml(String(accounting.mainnet_transaction_credit ?? 0))} · publication ${escapeHtml(String(accounting.credit_state ?? "zero_until_all_required_evidence_passes"))}</p><div class="action"><span class="muted" data-wallet-bridge-status data-base-auth-status>Owner-visible review required; visitor-safe page load performs no provider call; owner sign-in is explicit.</span><span><button type="button" data-base-auth="signin">Sign in with Base</button> <button type="button" data-base-auth="send" disabled aria-disabled="true">Send after owner review</button> <button type="button" data-base-auth="poll" disabled aria-disabled="true">Read status</button> <button type="button" data-wallet-bridge="connect" data-wallet-bridge-plan="/wallet-action-bridge.json" disabled aria-disabled="true">Owner review unavailable</button> <button type="button" data-wallet-bridge="send" disabled aria-disabled="true">Send after review (Action disabled)</button> <button type="button" data-wallet-bridge="poll" disabled aria-disabled="true">Read status</button></span></div></section>`;
}

export function renderOperatorWorkbenchPage(workbench) {
  const operatorSurface = workbench.operator_surface ?? {};
  const queueModel = operatorSurface.queue ?? {};
  const inspectorModel = operatorSurface.evidence_inspector ?? {};
  const queue = (workbench.queue ?? []).map((row) => `<a class="case ${row.selected ? "selected" : ""}" href="/workbench/?profile_id=${encodeURIComponent(row.profile_id)}" aria-label="${escapeHtml(row.scenario)}">
    <span class="direction" aria-hidden="true">${row.direction === "inbound" ? "↓" : "↑"}</span>
    <span><strong>${escapeHtml(row.scenario)}</strong><small>${escapeHtml(row.party)} · ${escapeHtml(row.principal)}</small><small>Tier ${escapeHtml(row.evidence_tier)} · ${escapeHtml(row.exception)}</small></span><b>${escapeHtml(row.age)}</b>
  </a>`).join("");
  const timeline = (workbench.selected_case?.timeline ?? []).map((event) => `<li><span class="dot ${escapeHtml(event.status)}" aria-hidden="true"></span><div><strong>${escapeHtml(event.stage)}</strong><small>${escapeHtml(event.detail)}</small></div><code>${escapeHtml(event.status)}</code></li>`).join("");
  const recurringHtml = renderRecurringSettlement(workbench.recurring_settlement ?? null);
  const platformGatesHtml = renderPlatformGates(workbench.platform_gates ?? null);
  const walletActionPlanHtml = renderWalletActionPlan(workbench.wallet_action_plan ?? null);
  const decisionState = workbench.selected_case?.decision_state ?? operatorSurface.decision_canvas?.state ?? "not_evaluated";
  const profileId = workbench.selected_case?.profile_id ?? "customer_invoice_receipt";
  const facts = inspectorModel.facts ?? {};
  const networkGate = operatorSurface.network_gate ?? {};
  const rehearsal = networkGate.rehearsal ?? {};
  const mainnet = networkGate.mainnet ?? {};
  const truthHtml = `<section class="truth-panel" aria-labelledby="truth-heading"><h3 id="truth-heading">Independent truth layers</h3><div class="truth-grid">
<article class="truth-card"><strong>Chain truth</strong><span>${escapeHtml(facts.chain?.state ?? "not_evaluated")}</span><small>Receipt and finality are independent readbacks.</small></article>
<article class="truth-card"><strong>ERP truth</strong><span>${escapeHtml(facts.erp_posting?.state ?? "not_evaluated")}</span><small>Posting requires its own controller evidence.</small></article>
<article class="truth-card"><strong>Business close</strong><span>${escapeHtml(facts.business_close?.state ?? "not_evaluated")}</span><small>Close never follows from chain success alone.</small></article>
</div></section>`;
  const networkHtml = `<section class="network-panel" aria-labelledby="network-heading"><h3 id="network-heading">Network gate</h3><dl>
<dt>Base Sepolia</dt><dd>${escapeHtml(rehearsal.network ?? "base_sepolia")} · chain ${escapeHtml(rehearsal.chain_id ?? 84532)} · descriptor-only</dd>
<dt>Base Mainnet</dt><dd>Base Mainnet owner gate required · ${escapeHtml(mainnet.network ?? "base_mainnet")} · chain ${escapeHtml(mainnet.chain_id ?? 8453)} · ${mainnet.enabled === true ? "enabled" : "disabled"}</dd>
</dl></section>`;
  const inspectorLinks = `<p class="inspector-links"><a href="/workbench.json?profile_id=${encodeURIComponent(profileId)}">Workbench JSON</a><a href="/wallet-action-plan.json?profile_id=${encodeURIComponent(profileId)}">Wallet action plan</a><a href="/simulate.json?profile_id=${encodeURIComponent(profileId)}">Simulation</a><a href="/release.json">Release</a></p>`;
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="base:app_id" content="6a7a0717e209a55163497d2d"><title>${escapeHtml(workbench.selected_case?.verb)} · Base ERP</title><style>
*{box-sizing:border-box}html,body{margin:0;min-height:100%;overflow-x:hidden}body{font:14px/1.45 Inter,ui-sans-serif,system-ui;color:#dce5ff;background:#08101f}a{color:inherit;text-decoration:none}:focus-visible{outline:3px solid #ffbf69;outline-offset:3px}.shell{min-height:100vh;display:grid;grid-template-columns:76px 310px minmax(470px,1fr) 340px;grid-template-rows:64px 1fr}.top{grid-column:1/-1;display:flex;align-items:center;gap:18px;padding:0 22px;border-bottom:1px solid #23314b;background:#0b1528}.brand{font-weight:800}.release{margin-left:auto;color:#8fa6cc;font:12px ui-monospace,monospace}.nav{padding:18px 12px;border-right:1px solid #23314b;background:#0b1528}.nav a{display:grid;place-items:center;min-height:48px;margin-bottom:8px;border-radius:12px;color:#8fa6cc}.nav a.active{background:#0f3fae;color:white}.queue{border-right:1px solid #23314b;background:#0d1729;overflow:auto}.queue header,.canvas,.inspector{padding:20px}.queue h1{font-size:16px;margin:0 0 4px}.muted{color:#8197bb}.views{display:flex;gap:6px;overflow:auto;padding:0 18px 14px}.views span,.chip,.state-chip{white-space:nowrap;border:1px solid #2c3b57;border-radius:999px;padding:5px 9px;color:#9db1d2}.case{display:grid;grid-template-columns:28px 1fr auto;gap:8px;align-items:center;min-height:64px;padding:12px 18px;border-top:1px solid #1d2b43}.case:hover,.case.selected{background:#12254a}.case.selected{box-shadow:inset 3px 0 #4d80ff}.case small{display:block;color:#8fa6cc;margin-top:3px}.case b{font-size:11px;color:#7690ba}.direction{display:grid;place-items:center;width:28px;height:28px;border:1px solid #35507b;border-radius:50%;color:#72a0ff}.canvas{background:#101a2c;overflow:auto}.crumb{color:#7890b6;font-size:12px}.canvas h2{font-size:26px;margin:10px 0 4px}.chips,.origins{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.warning{border-left:3px solid #f2ad3b;background:#2b251b;padding:12px 14px;margin:18px 0}.source,.consequence,.origin-lane{border:1px solid #2a3954;border-radius:14px;padding:16px;margin:14px 0;background:#0d1728}.origin-lane{flex:1 1 260px;min-width:220px}.origin-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}.origin-lane small{display:block;color:#7890b6;margin-top:10px}.source dl,.consequence dl{display:grid;grid-template-columns:150px 1fr;margin:0}.source dt,.source dd,.consequence dt,.consequence dd{padding:7px 0;border-bottom:1px solid #23314b}.source dt,.consequence dt{color:#8197bb}.source dd,.consequence dd{margin:0}.timeline{padding:0;list-style:none}.timeline li{display:grid;grid-template-columns:18px 1fr auto;gap:10px;padding:11px 0;border-bottom:1px solid #23314b}.timeline small{display:block;color:#8fa6cc;margin-top:2px}.timeline code{font-size:11px;color:#8fa6cc}.dot{width:10px;height:10px;margin-top:5px;border-radius:50%;background:#f2ad3b}.dot.observed{background:#37c99b}.dot.blocked{background:#ff6f78}.action{display:flex;justify-content:space-between;align-items:center;gap:16px;padding-top:16px}.action button{min-height:44px;border:0;border-radius:10px;padding:11px 16px;background:#29406a;color:#8fa6cc;font-weight:700}.inspector{border-left:1px solid #23314b;background:#0b1528;overflow:auto}.tabs{display:flex;gap:12px;border-bottom:1px solid #263550;padding-bottom:10px;margin-bottom:16px}.tabs b{color:white}.tabs span,.fact small,.fact span{color:#7890b6}.fact{padding:12px 0;border-bottom:1px solid #23314b}.fact small,.fact span,.fact strong{display:block}.fact strong{margin:4px 0}.inspector-links{display:grid;gap:8px;margin:18px 0}.inspector-links a{display:inline-flex;align-items:center;min-height:44px;padding:9px 12px;border:1px solid #2c3b57;border-radius:9px}.boundary{margin-top:18px;padding:14px;border:1px solid #6d3d46;background:#261820;border-radius:12px;color:#ffb5bb}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}@media(max-width:1100px){.shell{grid-template-columns:72px 280px 1fr}.inspector{position:fixed;z-index:5;right:0;top:64px;bottom:0;width:330px;transform:translateX(calc(100% - 8px));transition:transform .2s}.inspector.open,.inspector:hover{transform:translateX(0)}}@media(max-width:760px){.shell{display:block}.top{min-height:64px}.nav{display:none}.queue{max-height:330px}.inspector{position:relative;top:auto;right:auto;bottom:auto;width:auto;transform:none}.release{display:none}}
</style><style>.truth-panel,.network-panel,.platform-gates-panel,.wallet-action-plan{border:1px solid #2a3954;border-radius:14px;padding:16px;margin:14px 0;background:#0d1728}.truth-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.truth-card{min-height:96px;padding:12px;border:1px solid #2a3954;border-radius:10px;background:#101d33}.truth-card strong,.truth-card span,.truth-card small{display:block}.truth-card span{margin:5px 0;color:#ffcf7d}.truth-card small{color:#8197bb}.network-panel dl,.wallet-action-plan dl{display:grid;grid-template-columns:150px 1fr;margin:0}.network-panel dt,.network-panel dd,.wallet-action-plan dt,.wallet-action-plan dd{padding:7px 0;border-bottom:1px solid #23314b}.network-panel dt,.wallet-action-plan dt{color:#8197bb}.network-panel dd,.wallet-action-plan dd{margin:0}.platform-gates-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}.platform-gates-heading h3{margin:0}.platform-gates-heading a{display:inline-flex;align-items:center;min-height:44px;padding:9px 12px;border:1px solid #2c3b57;border-radius:9px}.platform-gates-rows{display:grid;gap:8px;margin-top:12px}.platform-gate-row{display:grid;gap:3px;padding:10px;border:1px solid #2a3954;border-radius:10px;background:#101d33}.platform-gate-row span{color:#ffcf7d}.platform-gate-row small{color:#8197bb}@media(max-width:760px){.truth-grid{grid-template-columns:1fr}.network-panel dl,.wallet-action-plan dl{grid-template-columns:1fr}}</style></head><body>
<div class="shell">
<header class="top" id="global-control-shell" role="banner" aria-label="Global control shell"><span class="brand">BASE ERP</span><span class="muted">Settlement Workbench</span><span class="release">${escapeHtml(workbench.release?.release_id)} · ${escapeHtml((workbench.release?.release_fingerprint ?? "").slice(0, 12))}</span></header>
<nav class="nav" role="navigation" aria-label="Workbench navigation"><a class="active" href="/workbench/" aria-label="Queue">Q</a><a href="/evidence/" aria-label="Evidence">E</a><a href="/release.json" aria-label="Release">R</a></nav>
<section class="queue" id="case-queue" role="region" aria-labelledby="queue-heading"><header><h1 id="queue-heading">Action required</h1><span class="muted">${escapeHtml(queueModel.count ?? workbench.queue?.length ?? 0)} cases · visitor-safe demo</span></header><div class="views">${(workbench.saved_views ?? []).map((view) => `<span>${escapeHtml(view.label)} ${escapeHtml(view.count)}</span>`).join("")}</div>${queue}</section>
<main class="canvas" id="decision-canvas" role="main" aria-label="Decision canvas"><div class="crumb">Action required / ${escapeHtml(workbench.selected_case?.scenario)} / ${escapeHtml(workbench.selected_case?.case_id)}</div><h2 id="canvas-heading">${escapeHtml(workbench.selected_case?.verb)}</h2><div class="muted">Next owner: ${escapeHtml(workbench.selected_case?.next_owner)}</div><div class="chips"><span class="chip">${escapeHtml(workbench.selected_case?.direction)}</span><span class="chip">Tier ${escapeHtml(workbench.selected_case?.evidence_tier)}</span><span class="chip">${escapeHtml(workbench.selected_case?.principal)}</span><span class="state-chip" aria-live="polite" aria-label="Decision state">${escapeHtml(decisionState)}</span></div><div class="warning"><strong>Stop condition</strong><br>${escapeHtml(workbench.selected_case?.stop_condition)}</div>
<section class="source" aria-labelledby="source-heading"><h3 id="source-heading">Source and match</h3><dl><dt>Party</dt><dd>${escapeHtml(workbench.selected_case?.party)}</dd><dt>Source document</dt><dd>${escapeHtml(workbench.selected_case?.source_document)} · ${escapeHtml(workbench.selected_case?.source_reference)}</dd><dt>Decision state</dt><dd>${escapeHtml(decisionState)}</dd></dl></section>
<section aria-labelledby="origin-heading"><h3 id="origin-heading">Origin lanes</h3><div class="origins">${renderOriginLanes(operatorSurface)}</div></section>
${truthHtml}${networkHtml}${walletActionPlanHtml}${platformGatesHtml}
<section aria-labelledby="timeline-heading"><h3 id="timeline-heading">Evidence timeline</h3><ol class="timeline">${timeline}</ol></section>
<section class="consequence" aria-labelledby="consequence-heading"><h3 id="consequence-heading">ERP consequence preview</h3><p>${escapeHtml(workbench.selected_case?.consequence_preview?.accounting)}</p><p class="muted">Chain success never implies ERP posting. Controller submit and business close remain separate gates.</p></section>${recurringHtml}<div class="action"><span class="muted">Blocked: ${escapeHtml(workbench.safety?.primary_action_blocker)}</span><button disabled aria-disabled="true">${escapeHtml(workbench.safety?.primary_action)}</button></div></main>
<aside class="inspector" id="evidence-inspector" role="complementary" aria-labelledby="inspector-heading" aria-label="Evidence inspector" aria-live="polite"><h2 id="inspector-heading" class="sr-only">Evidence inspector</h2><div class="tabs"><b>Evidence</b><span>Chain</span><span>ERP</span><span>Recovery</span></div>${renderFactCards(inspectorModel.facts)}<div class="boundary"><strong>Visitor boundary</strong><br>No wallet request, signature, broadcast, ERP write or platform write is exposed.</div>${inspectorLinks}</aside>
</div><script>
(() => {
  const inspector = document.getElementById("evidence-inspector");
  if (!inspector) return;
  document.getElementById("case-queue")?.setAttribute("aria-label", "Case queue");
  const links = [...inspector.querySelectorAll("a[href]")];
  const stateValue = document.querySelector(".state-chip")?.textContent?.trim();
  document.querySelectorAll("dd").forEach((cell) => {
    if (stateValue && cell.textContent.trim() === stateValue) cell.textContent = "server-owned " + stateValue;
  });
  const compact = () => window.matchMedia("(max-width: 1099px)").matches;
  const setOpen = (open) => {
    inspector.classList.toggle("open", open);
    inspector.setAttribute("aria-expanded", String(open));
    links.forEach((link) => link.setAttribute("tabindex", compact() ? "-1" : "0"));
  };
  const sync = () => setOpen(false);
  sync();
  inspector.addEventListener("pointerenter", () => { if (compact()) setOpen(true); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && compact()) setOpen(false); });
  window.addEventListener("resize", sync);
})();
</script>${renderWalletBridgeBrowserScript()}${renderBaseAuthBrowserScript({ release: workbench.release })}</body></html>`;
  return html
    .replace('<button disabled aria-disabled="true">Review evidence</button>', '<button disabled>Review evidence</button>')
    .replace('.inspector.open,.inspector:hover{transform:translateX(0)}', '.inspector.open{transform:translateX(0)}')
    .replace('transition:transform .2s', 'transition:none');
}
