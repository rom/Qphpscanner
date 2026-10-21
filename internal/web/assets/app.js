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

document.addEventListener("DOMContentLoaded", refreshHistory);

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
  };

  scanBtn.disabled = true;
  cancelBtn.classList.remove("hidden");
  setStatus("");
  resultsEl.replaceChildren();
  summaryEl.replaceChildren();
  downloadsEl.classList.add("hidden");
  startProgress();

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

    render(result);
    setStatus(`Done in ${result.meta.duration_ms} ms · ${result.summary.hosts_scanned} host(s).`);
    downloadsEl.classList.remove("hidden");
    refreshHistory();
  } catch (err) {
    if (err.name === "AbortError") {
      setStatus("Scan cancelled.");
    } else {
      setStatus("Error: " + err.message, true);
    }
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

function render(result) {
  renderSummary(result.summary);
  const targets = result.targets || [];
  if (targets.length === 0) {
    resultsEl.appendChild(el("p", "empty", "No open services found."));
    return;
  }
  for (const t of targets) {
    resultsEl.appendChild(renderHost(t));
  }
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
    group.appendChild(renderService(svc));
  }
  return group;
}

function renderService(svc) {
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
