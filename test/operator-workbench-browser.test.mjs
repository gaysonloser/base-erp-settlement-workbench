import test from "node:test"
import assert from "node:assert/strict"
import { createRequire } from "node:module"
import { createHash } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { createAppServer } from "../src/server.mjs"
import { buildOperatorWorkbench } from "../src/base-erp-workbench.mjs"
import { renderOperatorWorkbenchPage } from "../src/operator-workbench-page.mjs"

const require = createRequire(import.meta.url)

const TEST_COMMIT = "a".repeat(40)

const TEST_RELEASE = Object.freeze({
  release_id: "base-erp-public-product-20260814-v5",
  release_fingerprint: "5962684e0f5df38691ecdaa0b75ba023dcf1a64bf85cc15e512d8e307704ea4f",
  bom_fingerprint: "2b617a7ae4e2ef976e97310ab533f8f067c758dd0feaf3013709a06d01a6d612",
  material_outcome: "Base-native operator workbench with seven scenario queues, causal evidence timeline, deterministic simulation and cumulative refund ceiling guard",
})

const H215_CONTRACT_VERSION = "base-erp-h215-operator-workbench-v1"

const H215_TEN_STATES = Object.freeze([
  "loading",
  "empty",
  "not_evaluated",
  "matched",
  "stale",
  "mismatch",
  "validation_required",
  "confirmation_required",
  "reorg_pending",
  "recovery_ready",
])

const WORKBENCH_LANDMARKS = Object.freeze([
  "global-control-shell",
  "case-queue",
  "decision-canvas",
  "evidence-inspector",
])

const VIEWPORT_VECTORS = Object.freeze([
  { name: "1440px", width: 1440, height: 900, scale: 1 },
  { name: "1280px", width: 1280, height: 800, scale: 1 },
  { name: "1024px", width: 1024, height: 768, scale: 1 },
  { name: "200% zoom", width: 1440, height: 900, scale: 2 },
])

const MIN_TARGET_SIZE = 44

const LANDMARK_ROLES = new Set(["banner", "navigation", "main", "complementary", "region"])

function loadChromium() {
  const candidates = [
    process.env.PLAYWRIGHT_MODULE_PATH,
    "playwright",
    "/Users/wein/.npm/_npx/e41f203b7505f1fb/node_modules/playwright",
  ].filter(Boolean)
  let lastError
  for (const candidate of candidates) {
    try {
      return require(candidate).chromium
    } catch (error) {
      lastError = error
    }
  }
  throw new Error(`H215 browser harness requires Playwright (${lastError instanceof Error ? lastError.message : "unresolvable"})`)
}

function resolveChromiumExecutable() {
  return process.env.H215_CHROME_EXECUTABLE ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
}

function canonicalH219(value) {
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"))
  if (value === null || typeof value === "boolean") return JSON.stringify(value)
  if (typeof value === "number") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalH219).join(",")}]`
  if (value && typeof value === "object") {
    const keys = Object.keys(value).map((key) => key.normalize("NFC"))
    keys.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")))
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalH219(value[key])}`).join(",")}}`
  }
  throw new TypeError("unsupported candidate value")
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex")
}

function recomputeCurrentV8Candidate() {
  const candidate = JSON.parse(readFileSync("runtime/release_candidate_2026-08-10.json", "utf8"))
  // This is a disposable current-v8 projection. Recompute every frozen BOM
  // entry so the temporary browser candidate follows the current workbench,
  // route and page bytes while the on-disk v8 evidence remains immutable.
  candidate.immutable_release_bom = candidate.immutable_release_bom.map((entry) => ({
    ...entry,
    digest: sha256(readFileSync(entry.path.slice("projects/2026-08_Base_ERP_Settlement_Workbench/".length))),
  }))
  candidate.bom_fingerprint = sha256(Buffer.from(canonicalH219({
    schema_version: "base-erp-v8-bom-v1",
    files: candidate.immutable_release_bom.map((entry) => ({ path: entry.path, sha256: entry.digest })),
  })))
  candidate.immutable_bom_sha256 = candidate.bom_fingerprint
  candidate.release_fingerprint = sha256(Buffer.from(canonicalH219({
    schema_version: "base-erp-v8-release-identity-v1",
    release_id: candidate.release_id,
    bom_fingerprint: candidate.bom_fingerprint,
    base_target: candidate.base_target,
  })))
  return candidate
}

async function launchBrowser() {
  return loadChromium().launch({ headless: true, executablePath: resolveChromiumExecutable() })
}

async function withServer(run, { env = { ...process.env, GIT_COMMIT_SHA: TEST_COMMIT } } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "base-erp-h218-browser-candidate-"))
  const releasePath = join(directory, "release.json")
  writeFileSync(releasePath, JSON.stringify(recomputeCurrentV8Candidate(), null, 2))
  const server = createAppServer({ env, releasePath })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  const address = server.address()
  assert.equal(typeof address, "object")
  try {
    return await run(`http://127.0.0.1:${address.port}`)
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
    rmSync(directory, { recursive: true, force: true })
  }
}

async function openVectorPage(browser, vector, url) {
  const context = await browser.newContext({ viewport: { width: vector.width, height: vector.height } })
  const page = await context.newPage()
  page.setDefaultTimeout(10000)
  const errors = []
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(`console.error: ${message.text()}`)
  })
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`))
  const response = await page.goto(url, { waitUntil: "domcontentloaded" })
  assert.ok(response.ok(), `[${vector.name}] /workbench/ must load (HTTP ${response.status()})`)
  if (vector.scale > 1) {
    const cdp = await context.newCDPSession(page)
    await cdp.send("Emulation.setPageScaleFactor", { pageScaleFactor: vector.scale })
  }
  return { context, page, errors }
}

async function assertNamedLandmark(page, vector, selector) {
  const info = await page.locator(selector).evaluate((element) => ({
    role: element.getAttribute("role"),
    label: element.getAttribute("aria-label"),
    labelledby: element.getAttribute("aria-labelledby"),
    computedRole: typeof element.getComputedRole === "function" ? element.getComputedRole() : null,
    computedName: typeof element.getComputedName === "function" ? element.getComputedName() : null,
  }))
  const role = info.computedRole ?? info.role
  const name = String(info.computedName ?? info.label ?? "").trim()
  assert.ok(
    LANDMARK_ROLES.has(role) && name.length > 0,
    `[${vector.name}] #${selector.slice(1)} must be a named landmark (role=${role}, name=${JSON.stringify(name)}, aria-label=${JSON.stringify(info.label)}, aria-labelledby=${JSON.stringify(info.labelledby)})`,
  )
}

async function assertDualOriginLanes(page, vector) {
  const lanes = await page.locator("[data-origin]").evaluateAll((elements) => elements.map((element) => {
    const style = getComputedStyle(element)
    return {
      origin: element.getAttribute("data-origin"),
      visible: element.getClientRects().length > 0 && style.display !== "none" && style.visibility !== "hidden",
      text: String(element.textContent ?? "").trim().slice(0, 120),
    }
  }))
  assert.equal(lanes.length, 2, `[${vector.name}] exactly two server-owned origin lanes must render (got ${lanes.length})`)
  const origins = new Set(lanes.map((lane) => lane.origin))
  for (const origin of ["erp_initiated", "chain_observed"]) {
    assert.ok(origins.has(origin), `[${vector.name}] missing dual-origin lane ${origin}`)
  }
  for (const lane of lanes) {
    assert.ok(lane.visible && lane.text.length > 0, `[${vector.name}] origin lane ${lane.origin} must be visible with server-owned text`)
  }
}

async function assertAriaLiveState(page, vector) {
  const live = await page.locator("[aria-live]").evaluateAll((elements) => elements.map((element) => ({
    live: element.getAttribute("aria-live"),
    label: element.getAttribute("aria-label") ?? "",
    role: element.getAttribute("role"),
  })))
  assert.ok(live.length >= 1, `[${vector.name}] the operator surface must expose an aria-live state region (got ${live.length})`)
  const named = live.find((region) => region.label.trim().length > 0)
  assert.ok(named, `[${vector.name}] the aria-live region must carry an accessible label`)
}

test("operator workbench routes: /workbench and /workbench/ are byte-equivalent and reject non-profile bindings", async () => {
  await withServer(async (baseUrl) => {
    const [withSlash, withoutSlash] = await Promise.all([
      fetch(`${baseUrl}/workbench/`),
      fetch(`${baseUrl}/workbench`),
    ])
    assert.equal(withSlash.status, 200)
    assert.equal(withoutSlash.status, 200)
    assert.match(withSlash.headers.get("content-type") ?? "", /text\/html/)
    const [withoutSlashBody, withSlashBody] = await Promise.all([withoutSlash.text(), withSlash.text()])
    assert.equal(withoutSlashBody, withSlashBody, "GET /workbench and /workbench/ must be byte-equivalent")
    const head = await fetch(`${baseUrl}/workbench/`, { method: "HEAD" })
    assert.equal(head.status, 200)
    assert.equal(Number(head.headers.get("content-length")), Buffer.byteLength(withSlashBody))
    const withProfile = await fetch(`${baseUrl}/workbench/?profile_id=customer_invoice_receipt`)
    assert.equal(withProfile.status, 200, "profile_id remains the only accepted workbench query key")
    for (const query of ["origin=chain_observed", "state=matched", "release=base-erp-public-product-20260814-v5"]) {
      const response = await fetch(`${baseUrl}/workbench/?${query}`)
      assert.equal(response.status, 400, `query binding ${query} must be rejected with 400 and no echo`)
      const body = await response.json()
      assert.equal(body.error, "workbench_input_invalid")
    }
    const workbench = await (await fetch(`${baseUrl}/workbench.json`)).json()
    assert.equal(workbench.contract_version, H215_CONTRACT_VERSION)
    assert.ok(workbench.operator_surface && typeof workbench.operator_surface === "object")
  })
})

test("H218 browser surface renders the shared platform-gates panel without exposing identity or errors", async () => {
  const browser = await launchBrowser()
  try {
    await withServer(async (baseUrl) => {
      for (const vector of VIEWPORT_VECTORS) {
        const { context, page, errors } = await openVectorPage(browser, vector, `${baseUrl}/workbench/`)
        try {
          const panel = page.locator("#platform-gates-panel")
          assert.equal(await panel.count(), 1)
          assert.ok(await panel.isVisible())
          assert.equal(await panel.locator("[data-platform-gate]").count(), 4)
          assert.ok(await panel.getByRole("link", { name: "Platform gates JSON" }).isVisible())
          assert.ok(await panel.getByText(/Native receipt: null · release receipt: false · credit: 0/).count() === 4)
          assert.doesNotMatch(await panel.textContent(), /0x[a-fA-F0-9]{40}|gaysonloser\.base\.eth/)
          const projection = await page.evaluate(async () => (await fetch("/platform-gates.json")).json())
          assert.equal(projection.rows.length, 4)
          assert.deepEqual(errors, [])
        } finally {
          await context.close()
        }
      }
    })
  } finally {
    await browser.close()
  }
})

test("operator workbench browser surface: four named landmarks, dual-origin lanes and aria/live state at every viewport vector", async () => {
  const browser = await launchBrowser()
  try {
    await withServer(async (baseUrl) => {
      for (const vector of VIEWPORT_VECTORS) {
        const { context, page } = await openVectorPage(browser, vector, `${baseUrl}/workbench/`)
        try {
          for (const landmark of WORKBENCH_LANDMARKS) {
            await assertNamedLandmark(page, vector, `#${landmark}`)
          }
          await assertDualOriginLanes(page, vector)
          await assertAriaLiveState(page, vector)
        } finally {
          await context.close()
        }
      }
    })
  } finally {
    await browser.close()
  }
})

test("operator workbench browser surface: ten-state vocabulary is server-owned and renders visible output safely", async () => {
  await withServer(async (baseUrl) => {
    const browser = await launchBrowser()
    try {
      const { context, page, errors } = await openVectorPage(browser, VIEWPORT_VECTORS[0], `${baseUrl}/workbench/`)
      try {
        const catalog = await (await fetch(`${baseUrl}/workbench.json`)).json()
        for (const row of catalog.queue) {
          const body = await (await fetch(`${baseUrl}/workbench.json?profile_id=${row.profile_id}`)).json()
          assert.ok(
            H215_TEN_STATES.includes(body.selected_case.decision_state),
            `server decision_state ${body.selected_case.decision_state} must be part of the H215 ten-state vocabulary`,
          )
        }
        for (const state of H215_TEN_STATES) {
          const workbench = buildOperatorWorkbench({ release: TEST_RELEASE })
          const html = renderOperatorWorkbenchPage({
            ...workbench,
            selected_case: { ...workbench.selected_case, decision_state: state },
          })
          await page.setContent(html, { waitUntil: "domcontentloaded" })
          const stateText = page.locator('[aria-label="Decision state"]')
          assert.equal(await stateText.count(), 1, `state ${state} must render exactly one decision-state output`)
          assert.equal(await stateText.textContent(), state)
          assert.ok(await stateText.isVisible(), `state ${state} must be visibly rendered`)
          assert.equal(await page.locator("#global-control-shell").count(), 1)
          assert.equal(await page.locator("#decision-canvas").count(), 1)
          assert.ok(await page.getByRole("button", { name: "Review evidence" }).isDisabled(), `state ${state} must keep the primary action disabled`)
          assert.ok(await page.getByText(/No wallet request, signature, broadcast, ERP write or platform write is exposed/).isVisible())
        }
        assert.deepEqual(errors, [], "no console or page errors while rendering the ten states")
      } finally {
        await context.close()
      }
    } finally {
      await browser.close()
    }
  })
})

test("operator workbench browser surface: keyboard focus, focus-visible indicator and Escape behavior at every viewport vector", async () => {
  const browser = await launchBrowser()
  try {
    await withServer(async (baseUrl) => {
      for (const vector of VIEWPORT_VECTORS) {
        const { context, page, errors } = await openVectorPage(browser, vector, `${baseUrl}/workbench/`)
        try {
          await page.keyboard.press("Tab")
          const firstFocus = await page.evaluate(() => {
            const element = document.activeElement
            const style = getComputedStyle(element)
            return {
              tag: element.tagName,
              href: element.getAttribute("href") ?? "",
              outlineStyle: style.outlineStyle,
              outlineWidth: style.outlineWidth,
            }
          })
          assert.ok(
            firstFocus.tag === "A" || firstFocus.tag === "BUTTON",
            `[${vector.name}] Tab must focus an interactive control (got ${firstFocus.tag})`,
          )
          const indicator = firstFocus.outlineStyle !== "none" && parseFloat(firstFocus.outlineWidth) > 0
          assert.ok(indicator, `[${vector.name}] keyboard-focused controls must show a visible focus indicator (outline=${firstFocus.outlineStyle} ${firstFocus.outlineWidth})`)
          const focusables = page.locator('nav a[href], #case-queue a[href], #decision-canvas a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])')
          const count = await focusables.count()
          const visited = []
          for (let index = 0; index < count; index += 1) {
            await page.keyboard.press("Tab")
            visited.push(await page.evaluate(() => {
              const element = document.activeElement
              const box = element.getBoundingClientRect()
              const inspector = document.querySelector("#evidence-inspector")
              return {
                tag: element.tagName,
                href: element.getAttribute("href") ?? "",
                inInspector: Boolean(inspector && inspector.contains(element)),
                x: box.x,
              }
            }))
          }
          if (vector.width < 1100) {
            const leaked = visited.find((entry) => entry.inInspector)
            assert.ok(!leaked, `[${vector.name}] keyboard focus must not reach off-canvas drawer content (leaked ${leaked?.href ?? "none"})`)
          }
          const beforeUrl = page.url()
          const activeBeforeEscape = await page.evaluate(() => document.activeElement?.getAttribute("href") ?? document.activeElement?.tagName ?? "body")
          await page.keyboard.press("Escape")
          assert.equal(page.url(), beforeUrl, `[${vector.name}] Escape must not navigate`)
          const activeAfterEscape = await page.evaluate(() => document.activeElement?.getAttribute("href") ?? document.activeElement?.tagName ?? "body")
          assert.equal(activeAfterEscape, activeBeforeEscape, `[${vector.name}] Escape must not move focus`)
          assert.deepEqual(errors, [], `[${vector.name}] no console or page errors on keyboard interaction`)
          if (vector.width < 1100) {
            const inspector = page.locator("#evidence-inspector")
            await page.mouse.move(vector.width - 4, 400)
            await page.waitForFunction(() => document.querySelector("#evidence-inspector").getBoundingClientRect().x <= window.innerWidth - 300)
            const openBox = await inspector.boundingBox()
            assert.ok(openBox.x <= vector.width - 300, "[1024px] drawer must open on hover")
            await page.keyboard.press("Escape")
            const closedBox = await inspector.boundingBox()
            assert.ok(closedBox.x >= vector.width - 60, "[1024px] Escape must close the open evidence drawer")
          }
        } finally {
          await context.close()
        }
      }
    })
  } finally {
    await browser.close()
  }
})

test("operator workbench browser surface: inspector drawer visibility and minimum 44px interactive targets at every viewport vector", async () => {
  const browser = await launchBrowser()
  try {
    await withServer(async (baseUrl) => {
      for (const vector of VIEWPORT_VECTORS) {
        const { context, page } = await openVectorPage(browser, vector, `${baseUrl}/workbench/`)
        try {
          const inspector = page.locator("#evidence-inspector")
          const box = await inspector.boundingBox()
          assert.ok(box, `[${vector.name}] evidence inspector must be present`)
          if (vector.width < 1100) {
            assert.ok(box.x >= vector.width - 60, `[${vector.name}] evidence inspector must rest as a closed off-canvas drawer (x=${box.x})`)
            const transform = await inspector.evaluate((element) => getComputedStyle(element).transform)
            assert.notEqual(transform, "none", `[${vector.name}] closed drawer must be translated off-canvas`)
            await page.mouse.move(vector.width - 4, 400)
            await page.waitForFunction(() => document.querySelector("#evidence-inspector").getBoundingClientRect().x <= window.innerWidth - 300)
            const openBox = await inspector.boundingBox()
            assert.ok(openBox.x <= vector.width - 300, `[${vector.name}] hover must reveal the evidence drawer`)
          } else {
            assert.ok(box.x >= 0 && box.x + box.width <= vector.width, `[${vector.name}] evidence inspector must be visible inside the viewport`)
            assert.ok(box.width >= 100 && box.height >= 100, `[${vector.name}] evidence inspector must have a substantive visible area`)
          }
          const undersized = await page.locator("a[href], button:not([disabled])").evaluateAll((elements, viewportWidth) => elements
            .filter((element) => {
              const rect = element.getBoundingClientRect()
              return rect.width > 0 && rect.height > 0 && rect.x < viewportWidth && rect.x + rect.width > 0
            })
            .map((element) => {
              const rect = element.getBoundingClientRect()
              return { tag: element.tagName, href: element.getAttribute("href") ?? "", width: rect.width, height: rect.height }
            })
            .filter((target) => target.width < 44 || target.height < 44), vector.width)
          assert.deepEqual(undersized, [], `[${vector.name}] every visible interactive target must be at least ${MIN_TARGET_SIZE}px in both dimensions`)
          const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
          assert.ok(overflow <= 0, `[${vector.name}] the operator surface must not overflow horizontally (scrollWidth-innerWidth=${overflow})`)
        } finally {
          await context.close()
        }
      }
    })
  } finally {
    await browser.close()
  }
})
