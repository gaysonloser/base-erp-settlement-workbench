import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { digest } from "./base-neutral-receipt-controls.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const DEFAULT_RELEASE_PATH = resolve(PROJECT_ROOT, "runtime/release_candidate_2026-08-10.json");
const PRIMARY_BASE_ACCOUNT = "0xba36d092db2999bb1fabbaf281ac956a97189c25";
const COMMIT_PATTERN = /^[0-9a-f]{7,40}$/i;
const FULL_COMMIT_PATTERN = /^[0-9a-f]{40}$/i;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/i;
const DEFAULT_COMMIT_PLACEHOLDER = "PENDING_OWNER_PUBLIC_COMMIT";

function readJsonFile(filePath) {
  const resolvedPath = filePath instanceof URL ? filePath : resolve(String(filePath));
  return JSON.parse(readFileSync(resolvedPath, "utf8"));
}

function asNonEmptyString(value, fallback) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function resolveCommit({ candidate, env }) {
  const source = env?.RENDER_GIT_COMMIT ?? env?.RENDER_GIT_COMMIT_SHA ?? env?.GIT_COMMIT_SHA ?? env?.SOURCE_VERSION;
  if (typeof source === "string" && COMMIT_PATTERN.test(source.trim())) {
    return { value: source.trim(), placeholder: !FULL_COMMIT_PATTERN.test(source.trim()), source: "environment" };
  }
  if (typeof candidate?.git_commit === "string" && FULL_COMMIT_PATTERN.test(candidate.git_commit.trim())) {
    return { value: candidate.git_commit.trim(), placeholder: false, source: "release_candidate" };
  }
  return { value: DEFAULT_COMMIT_PLACEHOLDER, placeholder: true, source: "owner_public_commit_pending" };
}

function sha256File(filePath) {
  try {
    return createHash("sha256").update(readFileSync(resolve(PROJECT_ROOT, filePath))).digest("hex");
  } catch {
    return null;
  }
}

function verifyBom(candidate) {
  const entries = Array.isArray(candidate?.immutable_release_bom) ? candidate.immutable_release_bom : [];
  const normalizedBom = entries
    .filter((entry) => entry && typeof entry.path === "string" && typeof entry.digest === "string")
    .map((entry) => ({ path: entry.path, digest: entry.digest.toLowerCase() }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const structureValid = normalizedBom.length === entries.length
    && normalizedBom.length > 0
    && normalizedBom.every((entry) => DIGEST_PATTERN.test(entry.digest))
    && new Set(normalizedBom.map((entry) => entry.path)).size === normalizedBom.length;
  const fingerprintValid = structureValid
    && typeof candidate.bom_fingerprint === "string"
    && candidate.bom_fingerprint.toLowerCase() === digest(normalizedBom);
  const filesVerified = structureValid && normalizedBom.every((entry) => sha256File(entry.path) === entry.digest);
  return {
    bom_verified: Boolean(fingerprintValid && filesVerified),
    bom_fingerprint_valid: Boolean(fingerprintValid),
    bom_files_verified: Boolean(filesVerified),
  };
}

/**
 * Read only the public, non-secret portion of the current release candidate.
 * Runtime cursor, authority details and wallet capabilities are intentionally
 * omitted from this document; /healthz exposes only a bounded writer-idle state.
 */
export function readReleaseDocument({ releasePath = DEFAULT_RELEASE_PATH, env = process.env } = {}) {
  const candidate = readJsonFile(releasePath);
  const commit = resolveCommit({ candidate, env });
  const bomVerification = verifyBom(candidate);
  const bom = Array.isArray(candidate.immutable_release_bom)
    ? candidate.immutable_release_bom.map((entry) => ({ path: entry.path, digest: entry.digest }))
    : [];
  const limitations = Array.from(new Set([
    ...(Array.isArray(candidate.limitations) ? candidate.limitations : []),
    "This local candidate has no Base Mainnet receipt, ERP authoritative readback, or complete eight-surface public receipt.",
    "Public writes and wallet actions are disabled until an owner-visible gate is satisfied.",
  ]));
  return Object.freeze({
    schema_version: "base-erp-public-release-v1",
    project_name: asNonEmptyString(candidate.project_name, "Base ERP Settlement Workbench"),
    release_id: asNonEmptyString(candidate.release_id, "unbound-release"),
    release_fingerprint: asNonEmptyString(candidate.release_fingerprint, ""),
    bom_fingerprint: asNonEmptyString(candidate.bom_fingerprint, ""),
    immutable_bom_sha256: candidate.immutable_bom_sha256 ?? candidate.bom_fingerprint ?? null,
    immutable_release_bom: bom,
    material_outcome: asNonEmptyString(candidate.material_outcome, "Receipt-first ERP settlement preparation"),
    generated_at_cst: candidate.generated_at_cst ?? null,
    network: asNonEmptyString(candidate.network, "Base Mainnet preflight contract only; no chain action"),
    public_identity: Object.freeze({
      basename: asNonEmptyString(candidate.basename, "gaysonloser.base.eth"),
      primary_base_account: asNonEmptyString(candidate.primary_base_account, PRIMARY_BASE_ACCOUNT),
    }),
    git_commit: commit.value,
    commit_placeholder: commit.placeholder,
    commit_source: commit.source,
    ...bomVerification,
    release_identity_valid: typeof candidate.release_id === "string"
      && candidate.release_id.trim() !== ""
      && DIGEST_PATTERN.test(typeof candidate.release_fingerprint === "string" ? candidate.release_fingerprint : "")
      && DIGEST_PATTERN.test(typeof candidate.bom_fingerprint === "string" ? candidate.bom_fingerprint : ""),
    public_write_authorized: false,
    publication_status: "local_candidate_non_public_receipt",
    evidence_level: asNonEmptyString(candidate.evidence_level, "L1_local_tests"),
    limitations,
  });
}

export function readHealth({ release = readReleaseDocument(), runtimeReader = null, observedAt = new Date().toISOString() } = {}) {
  let runtimeStatus = "not_required";
  let runtimeReason;
  if (typeof runtimeReader === "function") {
    try {
      const runtime = runtimeReader();
      runtimeStatus = runtime.writer_idle === true && runtime.writer_idle_authority?.writer_idle === true
        ? "writer_idle_bound"
        : "writer_idle_unbound";
    } catch (error) {
      runtimeStatus = "runtime_binding_unreadable";
      runtimeReason = error instanceof Error ? error.message : "runtime binding unreadable";
    }
  }
  const ready = release.release_identity_valid === true
    && release.bom_verified === true
    && FULL_COMMIT_PATTERN.test(release.git_commit);
  return Object.freeze({
    ready,
    status: ready ? "ok" : "degraded",
    runtime_status: runtimeStatus,
    release_id: release.release_id,
    release_fingerprint: release.release_fingerprint,
    bom_fingerprint: release.bom_fingerprint,
    immutable_bom_sha256: release.immutable_bom_sha256,
    git_commit: release.git_commit,
    commit_placeholder: release.commit_placeholder,
    observed_at: observedAt,
    public_write_authorized: false,
    ...(runtimeReason ? { runtime_reason: runtimeReason } : {}),
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderHomePage(release) {
  const identity = release.public_identity ?? {};
  const limitations = release.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(release.project_name)}</title>
    <style>body{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1.25rem;color:#172033;background:#f7f8fb}main{background:#fff;border:1px solid #dfe4ef;border-radius:16px;padding:2rem;box-shadow:0 8px 30px #17203312}h1{margin-top:0}code{word-break:break-all}a{color:#0052ff}dt{font-weight:700;margin-top:1rem}dd{margin:0}</style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(release.project_name)}</h1>
      <p>Receipt-first Base Smart Wallet and ERP settlement workbench. This page is a public read-only deployment surface for the current release candidate.</p>
      <dl>
        <dt>Release</dt><dd><code>${escapeHtml(release.release_id)}</code></dd>
        <dt>Public identity</dt><dd>${escapeHtml(identity.basename)} · <code>${escapeHtml(identity.primary_base_account)}</code></dd>
        <dt>Material outcome</dt><dd>${escapeHtml(release.material_outcome)}</dd>
        <dt>Network</dt><dd>${escapeHtml(release.network)}</dd>
        <dt>Release fingerprint</dt><dd><code>${escapeHtml(release.release_fingerprint)}</code></dd>
        <dt>BOM fingerprint</dt><dd><code>${escapeHtml(release.bom_fingerprint)}</code></dd>
        <dt>Git commit</dt><dd><code>${escapeHtml(release.git_commit)}</code></dd>
        <dt>Evidence level</dt><dd>${escapeHtml(release.evidence_level)}</dd>
      </dl>
      <h2>Limits</h2>
      <ul>${limitations}</ul>
      <p>Public writes and wallet actions are disabled. See <a href="/release.json">release.json</a> for the bounded public release document and <a href="/healthz">healthz</a> for runtime readiness.</p>
    </main>
  </body>
</html>`;
}

function writeResponse(response, status, body, contentType, { head = false } = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  response.writeHead(status, {
    "content-type": contentType,
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  if (!head) response.end(payload);
  else response.end();
}

export function createAppServer({ releasePath = DEFAULT_RELEASE_PATH, env = process.env, runtimeReader = null } = {}) {
  return createServer((request, response) => {
    const head = request.method === "HEAD";
    if (request.method !== "GET" && !head) {
      writeResponse(response, 405, { error: "method_not_allowed", allowed: ["GET", "HEAD"] }, "application/json; charset=utf-8");
      return;
    }
    let pathname;
    try {
      pathname = new URL(request.url ?? "/", "http://localhost").pathname;
    } catch {
      writeResponse(response, 400, { error: "invalid_request_url" }, "application/json; charset=utf-8", { head });
      return;
    }
    let release;
    try {
      release = readReleaseDocument({ releasePath, env });
    } catch (error) {
      writeResponse(response, 503, { error: "release_unavailable", reason: error instanceof Error ? error.message : "release unavailable" }, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/healthz") {
      const health = readHealth({ release, runtimeReader });
      writeResponse(response, health.ready ? 200 : 503, health, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/release.json") {
      writeResponse(response, 200, release, "application/json; charset=utf-8", { head });
      return;
    }
    if (pathname === "/") {
      writeResponse(response, 200, renderHomePage(release), "text/html; charset=utf-8", { head });
      return;
    }
    writeResponse(response, 404, { error: "not_found", path: pathname }, "application/json; charset=utf-8", { head });
  });
}

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new RangeError("PORT must be an integer between 0 and 65535");
  return port;
}

export function listenServer({ host = process.env.HOST || "0.0.0.0", port = parsePort(process.env.PORT || "3000"), releasePath = DEFAULT_RELEASE_PATH, env = process.env, runtimeReader = null } = {}) {
  const server = createAppServer({ releasePath, env, runtimeReader });
  return new Promise((resolvePromise, rejectPromise) => {
    const onError = (error) => {
      server.removeListener("listening", onListening);
      rejectPromise(error);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      resolvePromise({ server, address: server.address() });
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(parsePort(port), host);
  });
}

async function main() {
  const { server, address } = await listenServer();
  const printableAddress = typeof address === "object" && address !== null ? `http://${address.address}:${address.port}` : String(address);
  process.stdout.write(`Base ERP Settlement Workbench listening at ${printableAddress}\n`);
  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    server.close(() => process.exit(0));
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
}
