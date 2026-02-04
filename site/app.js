/* LogWatch TDAS static dashboard
   - Loads outputs/alerts.json via fetch when served over HTTP
   - Also supports file upload + drag/drop
*/

const state = {
  raw: [],
  items: [],
  selectedId: null,
  filters: {
    q: "",
    severity: new Set(["low", "medium", "high"]),
    rules: new Set(),
    etypes: new Set(),
  },
};

const SEVERITY_ORDER = ["low", "medium", "high"];
const SEVERITY_COLOR = {
  low: getCssVar("--low"),
  medium: getCssVar("--medium"),
  high: getCssVar("--high"),
};

function getCssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function $(id) {
  return document.getElementById(id);
}

function setStatus(msg, kind = "info") {
  const el = $("status");
  if (!el) return;

  const prefix = kind === "error" ? "Error: " : kind === "ok" ? "OK: " : "";
  el.textContent = `${prefix}${msg}`;
  el.style.color = kind === "error" ? "rgba(255, 92, 115, 0.95)" : kind === "ok" ? "rgba(61, 220, 151, 0.95)" : "";
}

function severityFromScore(score) {
  const s = Number(score);
  if (!Number.isFinite(s)) return "low";
  if (s >= 7) return "high";
  if (s >= 3) return "medium";
  return "low";
}

function parseTimestamp(item) {
  // Supports finding.ts or finding.event.ts (ISO8601 strings)
  const candidate =
    (typeof item.ts === "string" && item.ts) ||
    (item.event && typeof item.event.ts === "string" && item.event.ts) ||
    null;
  if (!candidate) return null;
  const d = new Date(candidate);
  return Number.isNaN(d.getTime()) ? null : d;
}

function normalizeFindings(raw) {
  if (!Array.isArray(raw)) throw new Error("alerts.json must be a JSON array");

  return raw
    .filter((x) => x && typeof x === "object")
    .map((finding, idx) => {
      const score = Number(finding.score);
      const normScore = Number.isFinite(score) ? score : 0;
      const ts = parseTimestamp(finding);
      const severity = severityFromScore(normScore);

      return {
        id: idx,
        ts,
        tsText: ts ? ts.toISOString() : "—",
        severity,
        rule: typeof finding.rule === "string" ? finding.rule : "unknown",
        etype: typeof finding.etype === "string" ? finding.etype : "unknown",
        entity: typeof finding.entity === "string" ? finding.entity : String(finding.entity ?? "unknown"),
        score: normScore,
        event: finding.event && typeof finding.event === "object" ? finding.event : {},
        raw: finding,
      };
    });
}

function computeUniqueSets(items) {
  const rules = new Set();
  const etypes = new Set();
  for (const it of items) {
    rules.add(it.rule);
    etypes.add(it.etype);
  }
  return {
    rules: [...rules].sort(),
    etypes: [...etypes].sort(),
  };
}

function renderSeverityChips() {
  const host = $("severity-chips");
  host.innerHTML = "";

  for (const sev of SEVERITY_ORDER) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip";
    chip.dataset.on = state.filters.severity.has(sev) ? "true" : "false";

    const dot = document.createElement("span");
    dot.className = "dot";
    dot.style.background = SEVERITY_COLOR[sev] || "rgba(255,255,255,0.7)";

    const text = document.createElement("span");
    text.textContent = sev;

    chip.append(dot, text);

    chip.addEventListener("click", () => {
      if (state.filters.severity.has(sev)) state.filters.severity.delete(sev);
      else state.filters.severity.add(sev);
      renderAll();
    });

    host.appendChild(chip);
  }
}

function renderChecklist(hostId, items, selectedSet, onChange) {
  const host = $(hostId);
  host.innerHTML = "";

  const topRow = document.createElement("div");
  topRow.className = "check";

  const toggleAll = document.createElement("input");
  toggleAll.type = "checkbox";
  toggleAll.checked = selectedSet.size === items.length && items.length > 0;

  const allLabel = document.createElement("label");
  allLabel.textContent = "(select all)";

  topRow.append(toggleAll, allLabel);
  host.appendChild(topRow);

  toggleAll.addEventListener("change", () => {
    selectedSet.clear();
    if (toggleAll.checked) {
      for (const v of items) selectedSet.add(v);
    }
    onChange();
  });

  for (const v of items) {
    const row = document.createElement("div");
    row.className = "check";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = selectedSet.has(v);

    const label = document.createElement("label");
    label.textContent = v;

    cb.addEventListener("change", () => {
      if (cb.checked) selectedSet.add(v);
      else selectedSet.delete(v);
      onChange();
    });

    row.append(cb, label);
    host.appendChild(row);
  }
}

function filteredItems() {
  const q = state.filters.q.trim().toLowerCase();
  const sev = state.filters.severity;
  const rules = state.filters.rules;
  const etypes = state.filters.etypes;

  return state.items.filter((it) => {
    if (sev.size > 0 && !sev.has(it.severity)) return false;
    if (rules.size > 0 && !rules.has(it.rule)) return false;
    if (etypes.size > 0 && !etypes.has(it.etype)) return false;
    if (q && !String(it.entity).toLowerCase().includes(q)) return false;
    return true;
  });
}

function computeTimeSpan(items) {
  const times = items.map((x) => x.ts).filter(Boolean);
  if (times.length === 0) return "n/a";
  times.sort((a, b) => a - b);

  const fmt = (d) => {
    const y = d.getUTCFullYear();
    const m = String(d.getUTCMonth() + 1).padStart(2, "0");
    const day = String(d.getUTCDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
  };

  return `${fmt(times[0])} → ${fmt(times[times.length - 1])}`;
}

function renderKpis(items) {
  $("kpi-total").textContent = String(state.items.length);
  $("kpi-filtered").textContent = String(items.length);

  const uniq = new Set(items.map((x) => `${x.etype}:${x.entity}`));
  $("kpi-entities").textContent = String(uniq.size);
  $("kpi-timespan").textContent = computeTimeSpan(items);
}

function renderSeverityBars(items) {
  const counts = { low: 0, medium: 0, high: 0 };
  for (const it of items) counts[it.severity] = (counts[it.severity] || 0) + 1;

  const host = $("sevbar");
  const legend = $("sevlegend");
  host.innerHTML = "";
  legend.innerHTML = "";

  for (const sev of SEVERITY_ORDER) {
    const seg = document.createElement("div");
    seg.className = "sevbar__seg";

    const count = document.createElement("div");
    count.className = "sevbar__count";
    count.textContent = String(counts[sev] || 0);

    const label = document.createElement("div");
    label.className = "sevbar__label";
    label.textContent = sev;

    seg.style.borderColor = `${SEVERITY_COLOR[sev]}55`;
    seg.style.background = `linear-gradient(135deg, ${SEVERITY_COLOR[sev]}22, rgba(255,255,255,0.03))`;

    seg.append(count, label);
    host.appendChild(seg);

    const l = document.createElement("div");
    l.innerHTML = `<span class="dot" style="background:${SEVERITY_COLOR[sev]}"></span> ${sev}`;
    legend.appendChild(l);
  }
}

function renderRankTable(items) {
  const map = new Map();
  for (const it of items) {
    const k = `${it.etype}::${it.entity}`;
    const cur = map.get(k) || { etype: it.etype, entity: it.entity, score: 0, events: 0 };
    cur.score += it.score;
    cur.events += 1;
    map.set(k, cur);
  }

  const ranked = [...map.values()].sort((a, b) => b.score - a.score);
  const tbody = $("rank-table").querySelector("tbody");
  tbody.innerHTML = "";

  for (const row of ranked.slice(0, 15)) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(row.etype)}</td>
      <td>${escapeHtml(row.entity)}</td>
      <td class="right">${row.score.toFixed(1)}</td>
      <td class="right">${row.events}</td>
    `;
    tbody.appendChild(tr);
  }

  if (ranked.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="4" class="muted">No entities</td>`;
    tbody.appendChild(tr);
  }
}

function renderFindingsTable(items) {
  const tbody = $("findings-table").querySelector("tbody");
  tbody.innerHTML = "";

  const sorted = [...items].sort((a, b) => {
    const at = a.ts ? a.ts.getTime() : -Infinity;
    const bt = b.ts ? b.ts.getTime() : -Infinity;
    if (at !== bt) return bt - at;
    return b.score - a.score;
  });

  for (const it of sorted) {
    const tr = document.createElement("tr");
    tr.dataset.id = String(it.id);

    tr.innerHTML = `
      <td class="mono">${escapeHtml(it.tsText)}</td>
      <td>${severityPill(it.severity)}</td>
      <td>${escapeHtml(it.rule)}</td>
      <td>${escapeHtml(it.etype)}</td>
      <td>${escapeHtml(it.entity)}</td>
      <td class="right">${it.score.toFixed(1)}</td>
    `;

    tr.addEventListener("click", () => selectFinding(it.id));

    if (state.selectedId === it.id) tr.classList.add("is-selected");

    tbody.appendChild(tr);
  }

  if (sorted.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" class="muted">No findings match your filters</td>`;
    tbody.appendChild(tr);
  }
}

function severityPill(sev) {
  const c = SEVERITY_COLOR[sev] || "rgba(255,255,255,0.7)";
  const style = `display:inline-flex;align-items:center;gap:8px;` +
    `padding:5px 10px;border-radius:999px;` +
    `border:1px solid ${c}55;background:${c}14;font-weight:800;font-size:12px;`;

  return `<span style="${style}"><span class="dot" style="background:${c}"></span>${escapeHtml(sev)}</span>`;
}

function selectFinding(id) {
  state.selectedId = id;
  const found = state.items.find((x) => x.id === id);
  const el = $("inspect-json");
  if (!found) {
    el.textContent = JSON.stringify({ note: "No finding selected" }, null, 2);
  } else {
    el.textContent = JSON.stringify(found.raw, null, 2);
  }
  renderAll();
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderAll() {
  renderSeverityChips();
  // Update chip on/off state without rebuilding listeners (simple enough to rebuild).

  const filtered = filteredItems();
  renderKpis(filtered);
  renderSeverityBars(filtered);
  renderRankTable(filtered);
  renderFindingsTable(filtered);

  // Re-render checklists
  const uniq = computeUniqueSets(state.items);
  renderChecklist("rule-list", uniq.rules, state.filters.rules, renderAll);
  renderChecklist("etype-list", uniq.etypes, state.filters.etypes, renderAll);
}

function resetFilters() {
  state.filters.q = "";
  state.filters.severity = new Set(["low", "medium", "high"]);

  // Default: select all rules + etypes (once data is loaded)
  const uniq = computeUniqueSets(state.items);
  state.filters.rules = new Set(uniq.rules);
  state.filters.etypes = new Set(uniq.etypes);

  $("search").value = "";
  renderAll();
}

async function tryLoadFromOutputs() {
  const urlCandidates = [
    // When served from repo root: http://localhost:8000/site/
    "../outputs/alerts.json",
    // When hosted at /site/ path with absolute root
    "/outputs/alerts.json",
  ];

  let lastErr = null;
  for (const url of urlCandidates) {
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      loadJson(json, `Loaded ${url}`);
      return;
    } catch (e) {
      lastErr = e;
    }
  }

  throw new Error(`Could not fetch outputs/alerts.json (${lastErr ? lastErr.message : "unknown"}).\nServe the repo via http.server, or upload alerts.json.`);
}

function loadJson(raw, statusMsg = "Loaded") {
  state.raw = raw;
  state.items = normalizeFindings(raw);

  // Initialize checklist selections to all
  const uniq = computeUniqueSets(state.items);
  state.filters.rules = new Set(uniq.rules);
  state.filters.etypes = new Set(uniq.etypes);

  state.selectedId = null;
  $("inspect-json").textContent = JSON.stringify({ note: "No finding selected" }, null, 2);

  setStatus(`${statusMsg} (${state.items.length} findings)`, "ok");
  renderAll();
}

function loadFromFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = String(reader.result || "");
        resolve(JSON.parse(text));
      } catch (e) {
        reject(new Error("Invalid JSON file"));
      }
    };
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.readAsText(file);
  });
}

function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function wireUi() {
  $("btn-load-default").addEventListener("click", async () => {
    setStatus("Loading outputs/alerts.json…");
    try {
      await tryLoadFromOutputs();
    } catch (e) {
      setStatus(e.message, "error");
    }
  });

  $("file-input").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    setStatus(`Reading ${file.name}…`);
    try {
      const json = await loadFromFile(file);
      loadJson(json, `Loaded ${file.name}`);
    } catch (e) {
      setStatus(e.message, "error");
    } finally {
      ev.target.value = "";
    }
  });

  $("search").addEventListener("input", (ev) => {
    state.filters.q = ev.target.value || "";
    renderAll();
  });

  $("btn-reset").addEventListener("click", resetFilters);

  $("btn-export").addEventListener("click", () => {
    const filtered = filteredItems().map((x) => x.raw);
    downloadJson("alerts.filtered.json", filtered);
  });

  const dropzone = $("dropzone");
  dropzone.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    dropzone.classList.add("is-dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("is-dragover");
  });

  dropzone.addEventListener("drop", async (ev) => {
    ev.preventDefault();
    dropzone.classList.remove("is-dragover");

    const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (!file) return;

    setStatus(`Reading ${file.name}…`);
    try {
      const json = await loadFromFile(file);
      loadJson(json, `Loaded ${file.name}`);
    } catch (e) {
      setStatus(e.message, "error");
    }
  });
}

function bootstrap() {
  wireUi();

  // If the page is served over HTTP, try best-effort autoload.
  if (location.protocol === "http:" || location.protocol === "https:") {
    setStatus("Attempting to auto-load outputs/alerts.json…");
    tryLoadFromOutputs().catch(() => {
      setStatus("Auto-load failed. Click 'Load from outputs' or upload alerts.json.");
    });
  } else {
    setStatus("Open via a local server for auto-load, or upload alerts.json.");
  }
}

bootstrap();
