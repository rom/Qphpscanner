"use strict";

// qphpscanner web UI. All scan-derived text is inserted with textContent to
// avoid injecting attacker-controlled response data into the DOM. The scan
// endpoint streams NDJSON (progress events then a result line); scan history is
// served by the backend and rendered below the current result.

const $ = (id) => document.getElementById(id);

const form = $("scan-form");
const statusEl = $("status");
const scanBtn = $("scan-btn");
const cancelBtn = $("cancel-btn");
const summaryEl = $("summary");
const resultsEl = $("results");
const failuresEl = $("failures");
const resultTabsEl = $("result-tabs");
const okCountEl = $("ok-count");
const failCountEl = $("fail-count");
const scanErrorEl = $("scan-error");
const downloadsEl = $("downloads");
const progressEl = $("progress");
const progressFill = $("progress-fill");
const progressText = $("progress-text");
const progressLog = $("progress-log");
const historyWrap = $("history-wrap");
const historyEl = $("history");

let controller = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  await runScan();
});
cancelBtn.addEventListener("click", () => {
  if (controller) controller.abort();
});

// Bulk-load a target list from one or more local files (read client-side; the
// file never leaves the browser). Lines are appended to the targets box with
// '#' comments and blank lines stripped.
const targetsFileEl = $("targets-file");
if (targetsFileEl) {
  targetsFileEl.addEventListener("change", async () => {
    const files = Array.from(targetsFileEl.files || []);
    if (!files.length) return;
    let added = 0;
    for (const file of files) {
      let text = "";
      try {
        text = await file.text();
      } catch (_) {
        setStatus("Could not read " + file.name, true);
        continue;
      }
      const lines = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"));
      if (!lines.length) continue;
      const box = $("targets");
      const existing = box.value.trim();
      box.value = (existing ? existing + "\n" : "") + lines.join("\n");
      added += lines.length;
    }
    setStatus(added ? `Loaded ${added} target(s) from file.` : "No targets found in file.");
    targetsFileEl.value = ""; // allow re-loading the same file
  });
}
const targetsClearEl = $("targets-clear");
if (targetsClearEl) {
  targetsClearEl.addEventListener("click", () => {
    $("targets").value = "";
    setStatus("");
  });
}

// ---------- tabs ----------
let overviewCache = null;
for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => showView(tab.dataset.view));
}

// Results / Failures sub-tabs inside the Scan view.
for (const rt of document.querySelectorAll(".rtab")) {
  rt.addEventListener("click", () => showResultTab(rt.dataset.rtab));
}
function showResultTab(which) {
  for (const rt of document.querySelectorAll(".rtab")) {
    rt.classList.toggle("active", rt.dataset.rtab === which);
  }
  resultsEl.classList.toggle("hidden", which !== "ok");
  failuresEl.classList.toggle("hidden", which !== "fail");
}

function showView(name) {
  for (const t of document.querySelectorAll(".tab")) {
    t.classList.toggle("active", t.dataset.view === name);
  }
  for (const v of document.querySelectorAll(".view")) {
    v.classList.toggle("hidden", v.id !== "view-" + name);
  }
  if (name === "compare") refreshCompareList();
  if (name === "stats") loadOverview().then(renderStats);
  if (name === "info") loadOverview().then(renderInfo);
}

async function loadOverview(force) {
  if (overviewCache && !force) return overviewCache;
  try {
    const resp = await fetch("api/overview");
    overviewCache = resp.ok ? await resp.json() : null;
  } catch (_) {
    overviewCache = null;
  }
  return overviewCache;
}

// Invalidate caches after a scan so stats/info/compare reflect new data.
function invalidateOverview() { overviewCache = null; }

const splitList = (s) =>
  (s || "")
    .split(/\r?\n|,/)
    .map((x) => x.trim())
    .filter((x) => x && !x.startsWith("#"));

document.addEventListener("DOMContentLoaded", refreshHistory);
$("cmp-run") && $("cmp-run").addEventListener("click", runCompare);
$("cmp-refresh") && $("cmp-refresh").addEventListener("click", refreshCompareList);
$("stats-refresh") && $("stats-refresh").addEventListener("click", () => loadOverview(true).then(renderStats));
$("info-refresh") && $("info-refresh").addEventListener("click", () => loadOverview(true).then(renderInfo));

async function runScan() {
  const targets = $("targets").value;
  if (!targets.trim()) {
    setStatus("Enter at least one target.", true);
    return;
  }

  const body = {
    targets_text: targets,
    ports: $("ports").value.trim(),
    mode: $("mode").value,
    tls: $("tls").value,
    timeout_seconds: parseInt($("timeout").value, 10) || 10,
    concurrency: parseInt($("concurrency").value, 10) || 50,
    follow_redirects: $("follow").checked,
    security_txt: $("securitytxt").checked,
    insecure: $("insecure").checked,
    include_closed: $("includeclosed").checked,
    resolve_dns: $("resolvedns").checked,
    banners: $("banners").checked,
    host_concurrency: parseInt($("hostconc").value, 10) || 0,
    allow: splitList($("allow").value),
    block: splitList($("block").value),
  };

  scanBtn.disabled = true;
  cancelBtn.classList.remove("hidden");
  setStatus("");
  scanErrorEl.classList.add("hidden");
  downloadsEl.classList.add("hidden");
  startProgress();

  // Prepare a fresh render, but do NOT wipe the existing results yet: they are
  // cleared lazily when the first new service arrives, so a scan that fails
  // before producing anything leaves the previous view intact.
  beginScanRender();

  let openCount = 0;
  let phpCount = 0;
  let errMsg = null;
  let result = null;
  controller = new AbortController();

  try {
    const resp = await fetch("api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!resp.ok) {
      let data = {};
      try { data = await resp.json(); } catch (_) { /* ignore */ }
      throw new Error(data.error || ("HTTP " + resp.status));
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    const handle = (msg) => {
      if (msg.type === "progress") {
        const ev = msg.event;
        if (ev.phase === "enumerate") {
          logLine(ev.message);
        } else {
          if (ev.open) openCount++;
          if (ev.php_verdict && ev.php_verdict !== "none") phpCount++;
          updateProgress(ev, openCount, phpCount);
          if (ev.open) {
            let line = ev.host + ":" + ev.port + " open";
            if (ev.php_verdict && ev.php_verdict !== "none") {
              line += " · PHP " + ev.php_verdict + (ev.version ? " " + ev.version : "");
            }
            logLine(line);
          }
        }
      } else if (msg.type === "service") {
        onServiceMsg(msg.service);
      } else if (msg.type === "result") {
        result = msg.result;
      } else if (msg.type === "error") {
        errMsg = msg.error;
      }
    };

    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (line) handle(JSON.parse(line));
      }
    }
    if (buf.trim()) handle(JSON.parse(buf.trim()));

    if (errMsg) throw new Error(errMsg);
    if (!result) throw new Error("scan ended without a result");

    finishScanRender(result);
    setStatus(`Done in ${result.meta.duration_ms} ms · ${result.summary.hosts_scanned} host(s).`);
    downloadsEl.classList.remove("hidden");
    invalidateOverview();
    refreshHistory();
  } catch (err) {
    // Never wipe results on error: show a banner and keep whatever streamed.
    const aborted = err.name === "AbortError";
    const msg = aborted
      ? "Scan cancelled — results collected so far are shown below."
      : friendlyScanError(err.message);
    setStatus(aborted ? "Scan cancelled." : "Error: " + err.message, !aborted);
    showScanError(msg);
    // History/overview may have gained the partial run on the server side.
    invalidateOverview();
    refreshHistory();
  } finally {
    scanBtn.disabled = false;
    cancelBtn.classList.add("hidden");
    controller = null;
    finishProgress();
  }
}

/* ---------- progress ---------- */

function startProgress() {
  progressEl.classList.remove("hidden");
  progressFill.style.width = "0%";
  progressText.textContent = "Starting…";
  progressLog.replaceChildren();
}

function updateProgress(ev, openCount, phpCount) {
  const pct = ev.total > 0 ? Math.round((ev.done / ev.total) * 100) : 0;
  progressFill.style.width = pct + "%";
  progressText.textContent =
    `probed ${ev.done}/${ev.total} (${pct}%) · open ${openCount} · PHP ${phpCount}`;
}

function finishProgress() {
  setTimeout(() => progressEl.classList.add("hidden"), 600);
}

function logLine(text) {
  if (!text) return;
  const line = el("div", "log-line", text);
  progressLog.appendChild(line);
  while (progressLog.childElementCount > 200) {
    progressLog.removeChild(progressLog.firstChild);
  }
  progressLog.scrollTop = progressLog.scrollHeight;
}

/* ---------- rendering ---------- */

function setStatus(msg, isError) {
  statusEl.textContent = msg;
  statusEl.classList.toggle("error", !!isError);
}

// scanRender tracks the live render of the current scan so results stream in
// and survive an error/timeout instead of being wiped.
let scanRender = null;

function beginScanRender() {
  scanRender = { pendingClear: true, okGroups: new Map(), failGroups: new Map(), ok: 0, fail: 0 };
}

// ensureCleared wipes the pane exactly once — when the first new service (or a
// final result) arrives — so a scan that fails before producing anything keeps
// the previous view on screen.
function ensureCleared() {
  if (!scanRender || !scanRender.pendingClear) return;
  scanRender.pendingClear = false;
  resultsEl.replaceChildren();
  failuresEl.replaceChildren();
  summaryEl.replaceChildren();
  scanRender.okGroups.clear();
  scanRender.failGroups.clear();
  scanRender.ok = 0;
  scanRender.fail = 0;
  resultTabsEl.classList.remove("hidden");
  updateResultCounts();
}

// isProductive marks a service that actually answered HTTP; everything else
// (closed/filtered ports, connect errors, timeouts, open non-HTTP) is a
// "failure" shown on the Failures tab.
function isProductive(svc) {
  return !!(svc && svc.port_open && svc.http);
}

function onServiceMsg(svc) {
  if (!svc) return;
  ensureCleared();
  const ok = isProductive(svc);
  const container = ok ? resultsEl : failuresEl;
  const groups = ok ? scanRender.okGroups : scanRender.failGroups;
  let group = groups.get(svc.host);
  if (!group) {
    group = renderHostHeader(svc.host);
    groups.set(svc.host, group);
    container.appendChild(group.el);
  }
  group.body.appendChild(renderService(svc, null));
  if (ok) scanRender.ok++;
  else scanRender.fail++;
  updateResultCounts();
}

function renderHostHeader(host) {
  const wrap = el("div", "host-group");
  wrap.appendChild(el("h3", null, host));
  const body = el("div");
  wrap.appendChild(body);
  return { el: wrap, body };
}

function updateResultCounts() {
  okCountEl.textContent = String(scanRender ? scanRender.ok : 0);
  failCountEl.textContent = String(scanRender ? scanRender.fail : 0);
}

// finishScanRender runs on a successful result: it re-renders the Results tab
// from the final result (so resolved A/PTR records show) and leaves the
// streamed Failures tab in place.
function finishScanRender(result) {
  ensureCleared();
  renderSummary(result.summary);
  resultsEl.replaceChildren();
  let ok = 0;
  for (const t of result.targets || []) {
    const prod = (t.services || []).filter(isProductive);
    if (!prod.length) continue;
    resultsEl.appendChild(renderHost(Object.assign({}, t, { services: prod })));
    ok += prod.length;
  }
  scanRender.ok = ok;
  updateResultCounts();
  if (scanRender.ok === 0 && scanRender.fail === 0) {
    resultsEl.appendChild(el("p", "empty", "No open services found."));
  }
}

function showScanError(msg) {
  scanErrorEl.textContent = msg;
  scanErrorEl.classList.remove("hidden");
  // If anything streamed, make sure the result tabs are visible.
  if (scanRender && !scanRender.pendingClear) resultTabsEl.classList.remove("hidden");
}

function friendlyScanError(m) {
  if (!m) return "The scan failed. Any results collected so far are shown below.";
  if (/deadline exceeded|timeout|timed out/i.test(m)) {
    return "The scan timed out before completing. The results collected so far are shown below.";
  }
  if (/context canceled|canceled/i.test(m)) {
    return "The scan stopped early. Partial results are shown below.";
  }
  return "The scan failed (" + m + "). Any results collected so far are shown below.";
}

function renderSummary(s) {
  summaryEl.replaceChildren();
  const stats = [
    ["Hosts", s.hosts_scanned],
    ["Open ports", s.open_ports],
    ["HTTP", s.http_services],
    ["PHP confirmed", s.php_confirmed],
    ["PHP likely", s.php_likely],
    ["Vuln leads", s.vulnerabilities],
    ["security.txt", s.security_txt],
  ];
  for (const [label, n] of stats) {
    const box = el("div", "stat");
    box.appendChild(el("div", "n", String(n)));
    box.appendChild(el("div", "l", label));
    summaryEl.appendChild(box);
  }
}

function renderHost(t) {
  const group = el("div", "host-group");
  group.appendChild(el("h3", null, t.host));
  if ((t.addresses && t.addresses.length) || (t.ptr && t.ptr.length)) {
    const dns = el("div", "host-dns");
    if (t.addresses && t.addresses.length) dns.textContent = "addr: " + t.addresses.join(", ");
    if (t.ptr && t.ptr.length) dns.textContent += (dns.textContent ? " · " : "") + "ptr: " + t.ptr.join(", ");
    group.appendChild(dns);
  }
  for (const svc of t.services || []) {
    group.appendChild(renderService(svc, t));
  }
  return group;
}

function isIPHost(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;       // IPv4
  if (host.includes(":") && /^[0-9a-f:]+$/i.test(host)) return true; // IPv6
  return false;
}

function renderService(svc, target) {
  const verdict = svc.php ? svc.php.verdict : "none";
  const card = el("div", "svc v-" + verdict);

  const head = el("div", "svc-head");
  head.appendChild(el("span", "svc-url", svc.url || (svc.host + ":" + svc.port)));
  if (svc.php) {
    head.appendChild(el("span", "badge " + verdict, "PHP: " + verdict + " (" + svc.php.confidence + ")"));
  } else if (!svc.port_open) {
    head.appendChild(el("span", "badge none", "closed"));
  }
  card.appendChild(head);

  // Show the DNS name (and any resolved A/PTR records) at the top of the card
  // whenever the scanned host is a hostname or DNS was resolved.
  const dnsBits = [];
  if (svc.host && !isIPHost(svc.host)) dnsBits.push("DNS name: " + svc.host);
  if (target && target.addresses && target.addresses.length) dnsBits.push("A: " + target.addresses.join(", "));
  if (target && target.ptr && target.ptr.length) dnsBits.push("PTR: " + target.ptr.join(", "));
  if (dnsBits.length) card.appendChild(el("div", "svc-dns", dnsBits.join(" · ")));

  const kv = el("dl", "kv");
  const add = (k, v) => {
    if (v === undefined || v === null || v === "") return;
    kv.appendChild(el("dt", null, k));
    kv.appendChild(el("dd", null, String(v)));
  };

  if (!svc.port_open) {
    add("Port", "closed/filtered");
    if (svc.error) add("Error", svc.error);
    card.appendChild(kv);
    return card;
  }

  if (svc.banner) add("Banner", svc.banner);

  const h = svc.http;
  if (h) {
    add("Status", h.status + (h.proto ? " " + h.proto : ""));
    add("Server", h.server);
    add("X-Powered-By", h.powered_by);
    add("Title", h.title);
    if (h.tls) add("TLS", h.tls.version + " (" + h.tls.cipher_suite + ")");
    if (h.http2) add("HTTP version", "HTTP/2 (negotiated)");
    if (h.alpn) add("ALPN", h.alpn);
    if (h.h2c) add("h2c", "advertised (cleartext HTTP/2)");
    if (h.final_url) add("Redirected to", h.final_url);
  } else {
    add("HTTP", "no response");
    if (svc.error) add("Error", svc.error);
  }

  const ws = svc.server;
  if (ws) {
    if (ws.product) add("Web server", ws.product + (ws.version ? " " + ws.version : ""));
    if (ws.os) add("Server OS hint", ws.os);
  }
  const px = svc.proxy;
  if (px && px.present) {
    kv.appendChild(el("dt", null, "Reverse proxy"));
    kv.appendChild(el("dd", "warn", "YES — origin reply concealed"));
    if (px.cdn && px.cdn.length) add("  CDN", px.cdn.join(", "));
    if (px.waf && px.waf.length) add("  WAF", px.waf.join(", "));
    if (px.load_balancers && px.load_balancers.length) add("  Load balancer", px.load_balancers.join(", "));
    if (px.caches && px.caches.length) add("  Cache/proxy", px.caches.join(", "));
  }

  const php = svc.php;
  if (php) {
    if (php.variant) add("Variant", php.variant);
    if (php.sapi) add("SAPI (guess)", php.sapi);
    if (php.version) add("Version", php.version + (php.version_source ? " (via " + php.version_source + ")" : ""));
    if (php.framework_versions) {
      for (const fw of Object.keys(php.framework_versions)) add(fw + " version", php.framework_versions[fw]);
    }
    if (php.favicon_hash) add("Favicon hash", php.favicon_hash + " (mmh3)");
    if (php.eol_detail) {
      kv.appendChild(el("dt", null, "Lifecycle"));
      const dd = el("dd", null, php.eol_detail);
      if (php.end_of_life) { dd.classList.add("warn"); dd.textContent = "END OF LIFE — " + php.eol_detail; }
      kv.appendChild(dd);
    }
    if (php.phpinfo_exposed) {
      kv.appendChild(el("dt", null, "phpinfo()"));
      kv.appendChild(el("dd", "warn", "exposed at " + php.phpinfo_url));
    }
  }
  card.appendChild(kv);

  if (php) {
    if (php.frameworks && php.frameworks.length) card.appendChild(chips("Frameworks", php.frameworks));
    if (php.addons && php.addons.length) card.appendChild(chips("Addons / tools", php.addons));
    if (php.extensions && php.extensions.length) card.appendChild(chips("PHP extensions", php.extensions));
    if (php.vulnerabilities && php.vulnerabilities.length) card.appendChild(renderVulns(php.vulnerabilities));
    if (php.evidence && php.evidence.length) card.appendChild(renderEvidence(php.evidence));
  }

  if (ws && ws.modules && ws.modules.length) card.appendChild(chips("Server modules", ws.modules));
  if (px && px.present && px.note) card.appendChild(el("p", "note", px.note));

  if (svc.security_txt && svc.security_txt.present) {
    card.appendChild(renderSecurityTxt(svc.security_txt));
  }

  return card;
}

function chips(label, items) {
  const wrap = el("div");
  wrap.appendChild(el("div", "l", label));
  const row = el("div", "chips");
  for (const it of items) row.appendChild(el("span", "chip", it));
  wrap.appendChild(row);
  return wrap;
}

function renderVulns(vulns) {
  const d = el("details");
  d.open = true;
  d.appendChild(el("summary", null, `Vulnerability leads (${vulns.length})`));
  const ul = el("ul", "vulnlist");
  for (const v of vulns) {
    const li = el("li");
    li.appendChild(el("span", "sev " + (v.severity || "low"), (v.severity || "").toUpperCase()));
    li.appendChild(document.createTextNode(v.id + " — " + v.title));
    li.appendChild(el("div", "note", "affects " + v.affected_versions + " · " + v.match_basis));
    ul.appendChild(li);
  }
  d.appendChild(ul);
  d.appendChild(el("p", "note", "Correlated from the detected version only — verify against the live service."));
  return d;
}

function renderEvidence(evidence) {
  const d = el("details");
  d.appendChild(el("summary", null, `Evidence (${evidence.length})`));
  const ul = el("ul", "evlist");
  for (const ev of evidence) {
    const li = el("li");
    li.appendChild(el("span", "ev-weight", String(ev.weight)));
    if (ev.confidence) li.appendChild(el("span", "sev " + evSev(ev.confidence), ev.confidence));
    li.appendChild(document.createTextNode(" " + ev.signal + " — " + ev.detail));
    const meta = [];
    if (ev.where) meta.push("where: " + ev.where);
    if (ev.how) meta.push("how: " + ev.how);
    if (ev.probe) meta.push("probe: " + ev.probe);
    if (ev.status) meta.push("HTTP " + ev.status);
    if (ev.pattern) meta.push("matcher: " + ev.pattern);
    if (ev.line) meta.push("line " + ev.line);
    if (meta.length) li.appendChild(el("div", "ev-meta", meta.join(" · ")));
    if (ev.snippet) li.appendChild(el("div", "ev-snippet", ev.snippet));
    ul.appendChild(li);
  }
  d.appendChild(ul);
  return d;
}

function renderSecurityTxt(st) {
  const box = el("div", "sectxt");
  box.appendChild(el("h4", null, "security.txt" + (st.signed ? " (PGP-signed)" : "")));
  const kv = el("dl", "kv");
  const add = (k, v) => {
    if (!v || (Array.isArray(v) && !v.length)) return;
    kv.appendChild(el("dt", null, k));
    kv.appendChild(el("dd", null, Array.isArray(v) ? v.join(", ") : String(v)));
  };
  add("URL", st.url);
  add("Contact", st.contact);
  if (st.expires) {
    kv.appendChild(el("dt", null, "Expires"));
    const dd = el("dd", null, st.expires + (st.expired ? " (EXPIRED)" : ""));
    if (st.expired) dd.classList.add("warn");
    kv.appendChild(dd);
  }
  add("Policy", st.policy);
  add("Encryption", st.encryption);
  add("Languages", st.preferred_languages);
  box.appendChild(kv);
  return box;
}

/* ---------- history (server-backed) ---------- */

async function refreshHistory() {
  try {
    const resp = await fetch("api/history");
    if (!resp.ok) return;
    const data = await resp.json();
    const scans = data.scans || [];
    renderHistory(scans.slice(1)); // newest is shown as the current result
  } catch (_) {
    /* ignore */
  }
}

function renderHistory(scans) {
  historyEl.replaceChildren();
  if (!scans.length) {
    historyWrap.classList.add("hidden");
    return;
  }
  historyWrap.classList.remove("hidden");
  for (const scan of scans) {
    historyEl.appendChild(renderHistoryEntry(scan));
  }
}

function renderHistoryEntry(scan) {
  const d = el("details", "history-entry");
  const s = scan.summary;
  const when = formatTime(scan.at);
  const label = (scan.hosts || []).slice(0, 3).join(", ") +
    ((scan.hosts || []).length > 3 ? ` +${scan.hosts.length - 3} more` : "");
  d.appendChild(el("summary", null,
    `${when} · ${scan.mode} · ${s.hosts_scanned} host(s) · PHP ${s.php_confirmed + s.php_likely} · vulns ${s.vulnerabilities}`));
  if (label) d.appendChild(el("div", "history-targets", label));

  const dl = el("div", "downloads");
  dl.appendChild(el("span", null, "Download:"));
  for (const fmt of ["json", "csv", "sarif", "html", "pdf"]) {
    const a = el("a", null, fmt.toUpperCase());
    a.href = `api/download?scan=${encodeURIComponent(scan.id)}&format=${fmt}`;
    dl.appendChild(a);
  }
  d.appendChild(dl);

  const body = el("div", "history-body");
  let loaded = false;
  d.addEventListener("toggle", async () => {
    if (!d.open || loaded) return;
    loaded = true;
    try {
      const resp = await fetch(`api/download?scan=${encodeURIComponent(scan.id)}&format=json`);
      const result = await resp.json();
      body.replaceChildren();
      for (const t of result.targets || []) body.appendChild(renderHost(t));
      if (!(result.targets || []).length) body.appendChild(el("p", "empty", "No open services found."));
    } catch (_) {
      body.appendChild(el("p", "error", "Could not load scan details."));
    }
  });
  d.appendChild(body);
  return d;
}

function formatTime(iso) {
  const dt = new Date(iso);
  if (isNaN(dt.getTime())) return iso;
  return dt.toLocaleString();
}

/* ---------- helpers ---------- */

function evSev(tier) {
  if (tier === "high") return "high";
  if (tier === "medium") return "medium";
  return "low";
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

/* ---------- compare ---------- */

let compareScans = [];

async function refreshCompareList() {
  try {
    const resp = await fetch("api/history");
    const data = resp.ok ? await resp.json() : { scans: [] };
    compareScans = data.scans || [];
  } catch (_) {
    compareScans = [];
  }
  const label = (s) => `${formatTime(s.at)} · ${s.mode} · ${s.summary.hosts_scanned} host(s)`;
  for (const [id, pick] of [["cmp-a", 1], ["cmp-b", 0]]) {
    const sel = $(id);
    if (!sel) continue;
    sel.replaceChildren();
    compareScans.forEach((s, i) => {
      const o = el("option", null, label(s));
      o.value = s.id;
      if (i === pick) o.selected = true;
      sel.appendChild(o);
    });
    if (!compareScans.length) {
      const o = el("option", null, "— no scans yet —");
      o.value = "";
      sel.appendChild(o);
    }
  }
}

async function runCompare() {
  const a = $("cmp-a").value;
  const b = $("cmp-b").value;
  const out = $("cmp-result");
  out.replaceChildren();
  if (!a || !b) {
    out.appendChild(el("p", "empty", "Run at least two scans to compare."));
    return;
  }
  try {
    const resp = await fetch(`api/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || ("HTTP " + resp.status));
    renderDiff(out, data.diff);
  } catch (err) {
    out.appendChild(el("p", "error", "Compare failed: " + err.message));
  }
}

function renderDiff(out, diff) {
  if (!diff || (!(diff.added_services || []).length && !(diff.removed_services || []).length && !(diff.changed || []).length)) {
    out.appendChild(el("p", "empty", "No differences between the two scans."));
    return;
  }
  const list = (title, cls, urls) => {
    if (!urls || !urls.length) return;
    const g = el("div", "diff-group");
    g.appendChild(el("h4", cls, `${title} (${urls.length})`));
    const ul = el("ul", "item-list");
    for (const u of urls) ul.appendChild(el("li", null, u));
    g.appendChild(ul);
    out.appendChild(g);
  };
  list("Added services", "diff-added", diff.added_services);
  list("Removed services", "diff-removed", diff.removed_services);
  if ((diff.changed || []).length) {
    const g = el("div", "diff-group");
    g.appendChild(el("h4", null, `Changed (${diff.changed.length})`));
    const ul = el("ul", "item-list");
    for (const c of diff.changed) {
      const li = el("li", null, c.url);
      const bits = [];
      if (c.verdict_change) bits.push("verdict " + c.verdict_change);
      if (c.version_change) bits.push("version " + c.version_change);
      if ((c.new_vulns || []).length) bits.push("+vulns " + c.new_vulns.join(", "));
      if ((c.resolved_vulns || []).length) bits.push("-vulns " + c.resolved_vulns.join(", "));
      if (bits.length) li.appendChild(el("span", "when", bits.join(" · ")));
      ul.appendChild(li);
    }
    g.appendChild(ul);
    out.appendChild(g);
  }
}

/* ---------- statistics ---------- */

function renderStats(ov) {
  const body = $("stats-body");
  body.replaceChildren();
  if (!ov || ov.stats.scans === 0) {
    body.appendChild(el("p", "empty", "No scans yet — run a scan first."));
    return;
  }
  const s = ov.stats;
  const tiles = el("div", "summary");
  const tile = (label, val) => {
    const box = el("div", "stat");
    box.appendChild(el("div", "n", String(val)));
    box.appendChild(el("div", "l", label));
    tiles.appendChild(box);
  };
  tile("Scans", s.scans);
  tile("Services", s.services);
  tile("PHP services", s.php_services);
  tile("Highest severity", (s.highest_severity || "none").toUpperCase());
  tile("Avg scan", s.avg_scan_ms + " ms");
  if (s.oldest_php) tile("Oldest PHP", s.oldest_php.version);
  if (s.oldest_app) tile("Oldest app", s.oldest_app.name + " " + s.oldest_app.version);
  body.appendChild(tiles);

  if (s.oldest_php) body.appendChild(el("p", "note", `Oldest PHP ${s.oldest_php.version} on ${s.oldest_php.host} (${s.oldest_php.url})`));
  if (s.oldest_app) body.appendChild(el("p", "note", `Oldest application ${s.oldest_app.name} ${s.oldest_app.version} on ${s.oldest_app.host}`));

  body.appendChild(topList("Top vulnerabilities", s.top_vulns, true));
  body.appendChild(topList("Top applications", s.top_apps, false));
  body.appendChild(topList("Top networks", s.top_networks, false));
}

function topList(title, rows, withSev) {
  const g = el("div", "tag-section");
  g.appendChild(el("h3", null, title));
  if (!rows || !rows.length) {
    g.appendChild(el("p", "empty", "—"));
    return g;
  }
  const ul = el("ul", "item-list");
  for (const r of rows) {
    const li = el("li");
    if (withSev && r.severity) li.appendChild(el("span", "sev " + (r.severity || "low"), (r.severity || "").toUpperCase()));
    li.appendChild(document.createTextNode(" " + r.key));
    li.appendChild(el("span", "when", "×" + r.count));
    ul.appendChild(li);
  }
  g.appendChild(ul);
  return g;
}

/* ---------- info / findings explorer ---------- */

function renderInfo(ov) {
  const tagsEl = $("info-tags");
  const itemsEl = $("info-items");
  tagsEl.replaceChildren();
  itemsEl.replaceChildren();
  if (!ov || ov.stats.scans === 0) {
    tagsEl.appendChild(el("p", "empty", "No scans yet — run a scan first."));
    return;
  }

  const showItems = (group) => {
    itemsEl.replaceChildren();
    for (const t of tagsEl.querySelectorAll(".tag")) t.classList.remove("active");
    const h = el("h3", null, `${group.name} — ${group.count} item(s)`);
    itemsEl.appendChild(h);
    const ul = el("ul", "item-list");
    for (const it of group.items || []) {
      const li = el("li", null, it.host + "  " + it.url);
      li.appendChild(el("span", "when", it.at));
      ul.appendChild(li);
    }
    itemsEl.appendChild(ul);
  };

  const section = (title, groups, severityClass) => {
    if (!groups || !groups.length) return;
    const sec = el("div", "tag-section");
    sec.appendChild(el("h3", null, title));
    for (const g of groups) {
      let cls = "tag";
      if (severityClass && g.severity) cls += " sev-" + g.severity;
      const chip = el("span", cls);
      chip.appendChild(document.createTextNode(g.name));
      chip.appendChild(el("span", "tag-count", "×" + g.count));
      chip.addEventListener("click", () => {
        showItems(g);
        chip.classList.add("active");
      });
      sec.appendChild(chip);
    }
    tagsEl.appendChild(sec);
  };

  section("Frameworks / applications", ov.frameworks, false);
  section("Addons / tools", ov.addons, false);
  section("Vulnerabilities", ov.vulns, true);
}
