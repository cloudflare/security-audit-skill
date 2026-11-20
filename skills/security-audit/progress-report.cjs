"use strict";

/**
 * Renders progress.html: a self-contained, offline, human-readable view of a
 * full-audit run (knowledge, coverage, candidates, findings, agents, gaps, and
 * activity). Every value is HTML-escaped at render time and the page's only
 * script and style are pinned by hash in a Content-Security-Policy, so text
 * that agents copied from the target can never execute in the browser.
 *
 * renderProgressHtml() accepts whatever exists, so it also renders runs that
 * predate audit-state.cjs (metadata, ledger, and findings only).
 */

const crypto = require("crypto");

const PHASES = ["Reconnaissance", "Hunting waves", "Candidate validation", "Structured output", "Record verification", "Reporting"];
const UNIT_STATUSES = ["planned", "in_progress", "covered", "candidate", "blocked", "deferred", "out_of_scope", "not_applicable"];
const CANDIDATE_STATUSES = ["proposed", "validating", "validated", "final_review", "replacement_pending", "verified", "duplicate", "removed"];
const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const VERDICTS = ["confirmed", "needs_validation", "rejected"];
const INVISIBLE = /(?![\t\n\r])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Default_Ignorable_Code_Point}]/gu;

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function esc(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return text.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[character]));
}

/** Escapes text and makes invisible or direction-changing characters visible. */
function txt(value) {
  const text = value === null || value === undefined ? "" : String(value);
  let out = "";
  let last = 0;
  text.replace(INVISIBLE, (character, offset) => {
    out += esc(text.slice(last, offset));
    const code = character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    out += `<span class="cc" title="invisible character">U+${code}</span>`;
    last = offset + character.length;
    return character;
  });
  return out + esc(text.slice(last));
}

/** Escapes an attribute value and drops invisible or direction-changing characters. */
function attr(value) {
  return esc(value === null || value === undefined ? "" : String(value).replace(INVISIBLE, ""));
}

function slug(value) {
  const base = String(value).replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "item";
  const hash = crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 8);
  return `${base}-${hash}`;
}

function label(value) {
  return String(value).replace(/_/g, " ");
}

function pill(kind, value, extra = "") {
  if (value === null || value === undefined || value === "") return "";
  return `<span class="pill ${kind}-${esc(String(value).replace(/[^a-z_-]/gi, ""))}${extra ? ` ${extra}` : ""}">${esc(label(value))}</span>`;
}

function time(iso) {
  if (!iso) return "";
  return `<time datetime="${esc(iso)}">${esc(String(iso).replace("T", " ").replace(/\.\d+Z$/, "Z"))}</time>`;
}

function duration(start, end) {
  if (!start) return "";
  const ms = (end ? Date.parse(end) : Date.now()) - Date.parse(start);
  if (!Number.isFinite(ms) || ms < 0) return "";
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function code(value) {
  return `<code>${txt(value)}</code>`;
}

function list(items, render = (item) => txt(item), empty = "") {
  if (!Array.isArray(items) || items.length === 0) return empty ? `<p class="muted">${esc(empty)}</p>` : "";
  return `<ul class="plain">${items.map((item) => `<li>${render(item)}</li>`).join("")}</ul>`;
}

function dl(rows) {
  const body = rows.filter(([, value]) => value !== null && value !== undefined && value !== "").map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`).join("");
  return body ? `<dl class="kv">${body}</dl>` : "";
}

function countBy(items, key) {
  const counts = {};
  for (const item of items || []) {
    const value = typeof key === "function" ? key(item) : item[key];
    counts[value] = (counts[value] || 0) + 1;
  }
  return counts;
}

function alias(unit) {
  return (unit && unit.bookkeeping && unit.bookkeeping.alias) || "";
}

// ---------------------------------------------------------------------------
// Markdown (architecture.md): a small, escaping subset
// ---------------------------------------------------------------------------

function inlineMarkdown(text) {
  return txt(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    // Links render as text only: no target-supplied URL ever becomes an attribute.
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, "<span class=\"mdlink\">$1</span>");
}

function renderMarkdown(source) {
  const lines = String(source).replace(/\r\n?/g, "\n").split("\n");
  const out = [];
  let paragraph = [];
  let listType = null;
  let items = [];
  let fence = null;
  const flushParagraph = () => {
    if (paragraph.length) out.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (listType) out.push(`<${listType}>${items.map((item) => `<li>${inlineMarkdown(item)}</li>`).join("")}</${listType}>`);
    listType = null;
    items = [];
  };
  for (const line of lines) {
    if (fence !== null) {
      if (/^\s*```/.test(line)) {
        out.push(`<pre><code>${txt(fence.join("\n"))}</code></pre>`);
        fence = null;
      } else {
        fence.push(line);
      }
      continue;
    }
    if (/^\s*```/.test(line)) {
      flushParagraph();
      flushList();
      fence = [];
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      const level = Math.min(6, heading[1].length + 2);
      out.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet || ordered) {
      flushParagraph();
      const type = bullet ? "ul" : "ol";
      if (listType !== type) flushList();
      listType = type;
      items.push((bullet || ordered)[1]);
      continue;
    }
    if (line.trim() === "") {
      flushParagraph();
      flushList();
      continue;
    }
    if (listType && /^\s{2,}\S/.test(line)) {
      items[items.length - 1] += ` ${line.trim()}`;
      continue;
    }
    flushList();
    paragraph.push(line.trim());
  }
  if (fence !== null) out.push(`<pre><code>${txt(fence.join("\n"))}</code></pre>`);
  flushParagraph();
  flushList();
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

function location(entry) {
  return `${code(`${entry.file}${entry.line ? `:${entry.line}` : ""}`)}`;
}

function renderRecord(record) {
  if (!record || typeof record !== "object") return "<p class=\"muted\">No record.</p>";
  const parts = [];
  if (record.description) parts.push(`<p>${txt(record.description)}</p>`);
  parts.push(dl([
    ["Root cause", record.root_cause ? txt(record.root_cause) : null],
    ["Claimed root cause", record.claimed_root_cause ? txt(record.claimed_root_cause) : null],
    ["Intended behavior", record.intended_behavior ? txt(record.intended_behavior) : null],
    ["Rejection reason", record.reason ? txt(record.reason) : null],
  ]));
  if (Array.isArray(record.trace) && record.trace.length) {
    parts.push(`<h4>Trace</h4><ol class="trace">${record.trace.map((step) => `<li>${pill("kind", step.kind)} ${location(step)} <span class="scope">${txt(step.scope)}</span><div>${txt(step.description)}</div></li>`).join("")}</ol>`);
  }
  if (Array.isArray(record.evidence) && record.evidence.length) {
    parts.push(`<h4>Evidence</h4>${list(record.evidence, (entry) => `${location(entry)} — ${txt(entry.description)}`)}`);
  }
  if (Array.isArray(record.conditions) && record.conditions.length) {
    parts.push(`<h4>Conditions</h4>${list(record.conditions, (entry) => `${pill("cond", entry.kind)} ${txt(entry.description)}`)}`);
  }
  if (Array.isArray(record.blockers) && record.blockers.length) {
    parts.push(`<h4>Blockers</h4>${list(record.blockers)}`);
  }
  if (record.validation_plan) {
    parts.push(`<h4>Validation plan</h4>${dl([["Local", record.validation_plan.local ? txt(record.validation_plan.local) : null], ["Owner-observed deployment", record.validation_plan.deployment ? txt(record.validation_plan.deployment) : null]])}`);
  }
  if (record.execution) {
    const execution = record.execution;
    parts.push("<h4>Bounded local reproduction</h4>" + dl([
      ["Attacker perspective", execution.attacker_perspective ? txt(execution.attacker_perspective) : null],
      ["Payloads", Array.isArray(execution.payloads) ? execution.payloads.map((payload) => `<pre>${txt(payload) || "<span class=\"muted\">(empty)</span>"}</pre>`).join("") : null],
      ["Instructions", Array.isArray(execution.instructions) ? `<ol>${execution.instructions.map((step) => `<li>${txt(step)}</li>`).join("")}</ol>` : null],
      ["Observed result", execution.observed_result ? `<strong>${txt(execution.observed_result)}</strong>` : null],
    ]));
  }
  if (record.remediation) {
    const changes = Array.isArray(record.remediation.code_changes) ? record.remediation.code_changes.map((change) => `<div class="change">${code(change.file_name)}<pre>${txt(change.fixed_code)}</pre></div>`).join("") : "";
    parts.push(`<h4>Remediation</h4><p>${txt(record.remediation.strategy)}</p>${changes}`);
  }
  if (record.severity) {
    const severity = record.severity;
    parts.push("<h4>Priority</h4>" + dl([
      ["Overall", pill("sev", severity.overall_severity)],
      ["Likelihood", severity.likelihood ? `${pill("sev", severity.likelihood.score)} ${txt(severity.likelihood.reason)}` : null],
      ["Impact", severity.impact ? `${pill("sev", severity.impact.score)} ${txt(severity.impact.reason)}` : null],
      ["Confidence", record.confidence ? `${pill("conf", record.confidence.score)} ${txt(record.confidence.reason)}` : null],
    ]));
  } else if (record.confidence) {
    parts.push(dl([["Confidence", `${pill("conf", record.confidence.score)} ${txt(record.confidence.reason)}`]]));
  }
  return parts.join("");
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function stackedBar(counts, order, kind) {
  const total = order.reduce((sum, key) => sum + (counts[key] || 0), 0);
  if (total === 0) return "<div class=\"bar empty\"></div>";
  let x = 0;
  const rects = order.filter((key) => counts[key]).map((key) => {
    const width = (counts[key] / total) * 1000;
    const rect = `<rect class="fill ${kind}-${key}" x="${x.toFixed(2)}" y="0" width="${width.toFixed(2)}" height="12"><title>${esc(label(key))}: ${counts[key]}</title></rect>`;
    x += width;
    return rect;
  }).join("");
  return `<svg class="bar" viewBox="0 0 1000 12" preserveAspectRatio="none" role="img" aria-label="distribution">${rects}</svg>`;
}

function legend(counts, order, kind) {
  return `<div class="legend">${order.filter((key) => counts[key]).map((key) => `<span><i class="dot ${kind}-${key}"></i>${esc(label(key))} <b>${counts[key]}</b></span>`).join("")}</div>`;
}

function phaseStepper(phase, runStatus) {
  return `<ol class="phases">${PHASES.map((name, index) => {
    const number = index + 1;
    const state = runStatus === "complete" || number < phase ? "done" : number === phase ? "current" : "todo";
    return `<li class="${state}"><span class="num">${number}</span><span class="name">${esc(name)}</span></li>`;
  }).join("")}</ol>`;
}

function tile(title, value, detail = "", extra = "") {
  return `<div class="tile ${extra}"><div class="tile-title">${esc(title)}</div><div class="tile-value">${value}</div>${detail ? `<div class="tile-detail">${detail}</div>` : ""}</div>`;
}

function overview(data) {
  const { metadata = {}, ledger, findings, state } = data;
  const units = ledger || [];
  const unitCounts = countBy(units, "status");
  const closed = units.filter((unit) => !["planned", "in_progress"].includes(unit.status)).length;
  const candidates = (state && state.candidates) || [];
  const candidateCounts = countBy(candidates, "status");
  const records = findings || [];
  const verdictCounts = countBy(records, "verdict");
  const severityCounts = countBy(records.filter((record) => record.verdict === "confirmed"), (record) => record.severity && record.severity.overall_severity);
  const agents = (state && state.agents) || [];
  const running = agents.filter((agent) => agent.status === "running").length;
  const budget = Number.isInteger(metadata.budget) ? metadata.budget : null;
  const validation = (state && state.validation) || {};
  const verdictOf = (present, entry) => (!present ? "<span class=\"muted\">not written</span>" : entry && entry.ok === false ? "<b class=\"bad\">FAIL</b>" : "<b class=\"good\">PASS</b>");
  const validatorLine = `<span class="vrow">coverage-ledger ${verdictOf(ledger, validation.ledger)}</span><span class="vrow">findings ${verdictOf(findings, validation.findings)}</span>`;
  const severityDetail = SEVERITIES.filter((key) => severityCounts[key]).map((key) => `${pill("sev", key)} ${severityCounts[key]}`).join(" ");
  const tiles = [
    tile("Coverage units", `${closed}<small>/${units.length} closed</small>`, `${unitCounts.in_progress || 0} in progress · ${unitCounts.planned || 0} planned`),
    tile("Candidates", `${candidates.length}`, `${(candidateCounts.proposed || 0) + (candidateCounts.validating || 0)} awaiting validation`),
    tile("Confirmed", `${verdictCounts.confirmed || 0}`, severityDetail || (findings ? "none confirmed" : "findings.json not written"), "accent-confirmed"),
    tile("Needs validation", `${verdictCounts.needs_validation || 0}`, `${verdictCounts.rejected || 0} rejected`),
    tile("Agents", `${agents.length}${budget !== null ? `<small>/${budget}</small>` : ""}`, `${running} running${budget !== null ? ` · ${Math.max(0, budget - agents.length)} left` : ""}`),
    tile("Validators", validatorLine),
  ].join("");
  const steps = data.nextSteps || [];
  const alerts = [];
  if (metadata.run_status === "incomplete") alerts.push(`<li class="alert">Run incomplete: ${txt(metadata.incomplete_reason || "no reason recorded")}</li>`);
  for (const agent of agents) {
    if (agent.status === "running" && (agent.last_errors || []).length) alerts.push(`<li class="alert">Result from ${code(agent.id)} was rejected (${agent.last_errors.length} problem(s)); see Agents.</li>`);
  }
  for (const candidate of candidates) {
    if (candidate.status === "replacement_pending") alerts.push(`<li class="warn">${code(candidate.fingerprint)} has a material Phase 5 replacement awaiting fresh verification.</li>`);
    if (candidate.status === "removed") alerts.push(`<li class="alert">${code(candidate.fingerprint)} was removed from findings: ${txt(candidate.removed_reason)}</li>`);
  }
  return `<section id="overview" class="card">
    ${phaseStepper((state && state.phase) || 1, metadata.run_status)}
    <div class="tiles">${tiles}</div>
    <div class="dist"><div class="dist-title">Coverage ledger</div>${stackedBar(unitCounts, UNIT_STATUSES, "st")}${legend(unitCounts, UNIT_STATUSES, "st")}</div>
    ${candidates.length ? `<div class="dist"><div class="dist-title">Candidates</div>${stackedBar(candidateCounts, CANDIDATE_STATUSES, "cs")}${legend(candidateCounts, CANDIDATE_STATUSES, "cs")}</div>` : ""}
    ${alerts.length || steps.length ? `<div class="next"><h3>Attention and next steps</h3><ul class="plain">${alerts.join("")}${steps.map((step) => `<li>${txt(step)}</li>`).join("")}</ul></div>` : ""}
  </section>`;
}

function knowledge(data) {
  const meta = data.metadata || {};
  const sourceRef = meta.source_ref && typeof meta.source_ref === "object"
    ? `${code(meta.source_ref.commit || "")}${meta.source_ref.dirty ? " <span class=\"pill warn-dirty\">dirty worktree</span>" : ""}`
    : meta.source_ref ? code(meta.source_ref) : null;
  const known = new Set(["run_id", "repo", "target", "source_ref", "profile", "scope_paths", "budget", "execution_policy", "selected_companions", "prior_runs", "shared_file_owners", "run_status", "incomplete_reason"]);
  const extra = Object.entries(meta).filter(([key]) => !known.has(key)).map(([key, value]) => [label(key), txt(typeof value === "object" ? JSON.stringify(value) : value)]);
  const files = Object.entries(data.files || {}).map(([name, exists]) => (exists ? `<a href="${esc(name)}">${esc(name)}</a>` : `<span class="muted">${esc(name)}</span>`)).join(" · ");
  return `<section id="knowledge" class="card">
    <h2>Knowledge</h2>
    <div class="cols">
      <div>${dl([
        ["Run", meta.run_id ? txt(meta.run_id) : null],
        ["Repository", meta.repo ? txt(meta.repo) : null],
        ["Target", meta.target ? code(meta.target) : null],
        ["Source ref", sourceRef],
        ["Profile", meta.profile ? pill("profile", meta.profile) : null],
        ["Scope", Array.isArray(meta.scope_paths) ? (meta.scope_paths.length ? meta.scope_paths.map(code).join(" ") : "whole repository") : null],
        ["Budget", meta.budget === null || meta.budget === undefined ? "unset" : txt(meta.budget)],
        ["Execution policy", meta.execution_policy ? code(meta.execution_policy) : null],
        ["Companions", Array.isArray(meta.selected_companions) ? (meta.selected_companions.map(code).join(" ") || "none") : null],
        ["Prior runs", Array.isArray(meta.prior_runs) ? (meta.prior_runs.map(code).join("<br>") || "none") : null],
        ["Run status", pill("run", meta.run_status)],
        ...extra,
      ])}
      <p class="files">Files: ${files}</p></div>
      <div class="arch">${data.architecture ? `<details open><summary><b>architecture.md</b></summary><div class="md">${renderMarkdown(data.architecture)}</div></details>` : "<p class=\"muted\">architecture.md has not been written yet.</p>"}</div>
    </div>
  </section>`;
}

function filterBar(group, statuses, counts) {
  const chips = [`<button type="button" class="chip on" data-value="*">all</button>`]
    .concat(statuses.filter((status) => counts[status]).map((status) => `<button type="button" class="chip" data-value="${esc(status)}">${esc(label(status))} ${counts[status]}</button>`))
    .join("");
  return `<div class="filters" data-filter-group="${esc(group)}">${chips}<input type="search" placeholder="Filter…" aria-label="Filter ${esc(group)}"></div>`;
}

function renderCheck(check) {
  return `<li>${pill("method", check.method)} ${code(check.agent_id)} <b>${txt(check.invariant)}</b><div>${txt(check.result)}</div><div class="muted">${(check.reviewed_paths || []).map(code).join(" ")}${check.artifact ? ` · artifact ${code(check.artifact)}` : ""}</div></li>`;
}

function coverage(data) {
  const units = data.ledger || [];
  if (!data.ledger) return `<section id="coverage" class="card"><h2>Coverage</h2><p class="muted">coverage-ledger.json has not been seeded yet.</p></section>`;
  const counts = countBy(units, "status");
  const aliasNumber = (unit) => {
    const match = /^U(\d+)$/.exec(alias(unit));
    return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
  };
  const ordered = units.slice().sort((left, right) => aliasNumber(left) - aliasNumber(right));
  const rows = ordered.map((unit) => {
    const book = unit.bookkeeping || {};
    const hardening = Array.isArray(book.hardening) ? book.hardening : [];
    const decisions = Array.isArray(book.decisions) ? book.decisions : [];
    const body = [
      dl([
        ["Coverage ID", code(unit.coverage_id)],
        ["Canonical refs", unit.canonical_refs ? Object.entries(unit.canonical_refs).map(([key, value]) => `${esc(label(key))}: ${code(value)}`).join("<br>") : null],
        ["Lifecycle", unit.lifecycle ? txt(unit.lifecycle) : null],
        ["Starting paths", (unit.starting_paths || []).map(code).join(" ")],
        ["Ordinary block", unit.ordinary_attack_class_block ? code(unit.ordinary_attack_class_block) : "none"],
        ["Companion blocks", (unit.selected_companion_blocks || []).map(code).join(" ") || "none"],
        ["Excluded blocks", (unit.excluded_blocks || []).length ? list(unit.excluded_blocks, (entry) => `${code(entry.block)} — ${txt(entry.reason)}`) : null],
        ["Prior status", txt(unit.prior_status)],
        ["Priority rationale", book.priority_rationale ? txt(book.priority_rationale) : null],
        ["Fingerprints", (unit.result_fingerprints || []).map(code).join(" ") || null],
        ["Carried", (book.carried_fingerprints || []).map(code).join(" ") || null],
        ["Unresolved", (unit.unresolved || []).length ? list(unit.unresolved) : null],
      ]),
      (unit.local_checks || []).length ? `<h4>Checks</h4><ul class="checks">${unit.local_checks.map(renderCheck).join("")}</ul>` : "",
      decisions.length ? `<h4>Validation decisions</h4>${list(decisions, (entry) => `Phase ${txt(entry.phase)} ${code(entry.agent_id)} → ${pill("dec", entry.decision)} ${code(entry.fingerprint)}`)}` : "",
      hardening.length ? `<h4>Hardening notes</h4>${list(hardening, (entry) => `${txt(entry.note)} <span class="muted">(${esc(entry.agent_id)})</span>`)}` : "",
      (unit.attempts || []).length ? `<h4>Archived attempts</h4>${list(unit.attempts, (attempt) => `wave ${txt(attempt.wave)} ${pill("st", attempt.status)} ${code(attempt.agent_id)} — ${txt(attempt.reassignment_reason)}<ul class="checks">${(attempt.local_checks || []).map(renderCheck).join("")}</ul>`)}` : "",
      Array.isArray(book.notes) && book.notes.length ? `<h4>Notes</h4>${list(book.notes, (entry) => `${txt(entry.note)} <span class="muted">${time(entry.at)}</span>`)}` : "",
    ].join("");
    const search = [alias(unit), unit.coverage_id, unit.surface, unit.boundary, unit.subsystem, unit.attack_class, unit.lifecycle, unit.agent_id, ...(unit.result_fingerprints || [])].filter(Boolean).join(" ").toLowerCase();
    return `<details class="row" id="u-${slug(unit.coverage_id)}" data-status="${esc(unit.status)}" data-search="${attr(search)}">
      <summary class="grid unit-grid"><span class="id">${esc(alias(unit) || "—")}</span>${pill("st", unit.status)}<span class="main"><b>${txt(unit.surface)}</b><span class="sub">${txt(unit.boundary)}</span></span><span>${txt(unit.attack_class)}<span class="sub">${txt(unit.subsystem)}${unit.lifecycle ? ` · ${txt(unit.lifecycle)}` : ""}</span></span><span class="meta">w${esc(unit.wave)}</span><span class="meta">${unit.agent_id ? code(unit.agent_id) : "—"}</span><span class="meta">${(unit.local_checks || []).length} chk${(unit.result_fingerprints || []).length ? ` · ${unit.result_fingerprints.length} fp` : ""}</span></summary>
      <div class="body">${body}</div></details>`;
  }).join("");
  return `<section id="coverage" class="card"><h2>Coverage <span class="count">${units.length}</span></h2>${filterBar("coverage", UNIT_STATUSES, counts)}<div class="rows" data-filter-target="coverage">${rows}</div></section>`;
}

function candidatesSection(data) {
  const candidates = (data.state && data.state.candidates) || [];
  const units = data.ledger || [];
  if (!data.state) return "";
  if (candidates.length === 0) return `<section id="candidates" class="card"><h2>Candidates</h2><p class="muted">No candidates yet.</p></section>`;
  const linked = (fingerprint) => units.filter((unit) => (unit.result_fingerprints || []).includes(fingerprint) || (unit.attempts || []).some((attempt) => (attempt.result_fingerprints || []).includes(fingerprint)) || ((unit.bookkeeping && unit.bookkeeping.carried_fingerprints) || []).includes(fingerprint));
  const counts = countBy(candidates, "status");
  const rows = candidates.map((candidate) => {
    const latest = candidate.pending ? candidate.pending.record : candidate.record || (candidate.proposals[candidate.proposals.length - 1] || {}).record;
    const history = [
      ...candidate.proposals.map((proposal) => ({ at: proposal.at, text: `${proposal.source === "prior" ? "carried from a prior run" : `proposed by ${esc(proposal.agent_id)}`} as ${pill("verdict", proposal.proposed_verdict)}` })),
      ...candidate.validation.map((entry) => ({ at: entry.at, text: `Phase 3 ${code(entry.agent_id)} → ${pill("verdict", entry.decision)}` })),
      ...candidate.final.map((entry) => ({ at: entry.at, text: `Phase 5 ${code(entry.agent_id)} → ${pill("dec", entry.decision)}${entry.reason ? ` — ${txt(entry.reason)}` : ""}${(entry.material || []).length ? ` <span class="warn-text">(material: ${txt(entry.material.join("; "))})</span>` : ""}` })),
    ].sort((left, right) => String(left.at).localeCompare(String(right.at)));
    const linkedUnits = linked(candidate.fingerprint);
    const search = [candidate.fingerprint, candidate.title, candidate.verdict, ...candidate.proposals.map((proposal) => proposal.agent_id)].filter(Boolean).join(" ").toLowerCase();
    return `<details class="row" id="c-${slug(candidate.fingerprint)}" data-status="${esc(candidate.status)}" data-search="${attr(search)}">
      <summary class="grid cand-grid">${pill("cs", candidate.status)}<span class="main"><b>${txt(candidate.title || candidate.fingerprint)}</b><span class="sub">${code(candidate.fingerprint)}</span></span><span>${pill("verdict", candidate.verdict || (candidate.proposals[0] || {}).proposed_verdict, candidate.verdict ? "" : "ghost")}</span><span class="meta">${linkedUnits.map((unit) => esc(alias(unit))).join(" ") || "—"}</span><span class="meta">${candidate.proposals.map((proposal) => esc(proposal.agent_id)).join(", ")}</span></summary>
      <div class="body">
        ${candidate.duplicate_of ? `<p>Duplicate of ${code(candidate.duplicate_of)}${candidate.duplicate_reason ? ` — ${txt(candidate.duplicate_reason)}` : ""}</p>` : ""}
        ${candidate.removed_reason ? `<p class="bad">Removed: ${txt(candidate.removed_reason)}</p>` : ""}
        <h4>History</h4><ul class="plain timeline">${history.map((entry) => `<li>${time(entry.at)} ${entry.text}</li>`).join("")}</ul>
        ${candidate.pending ? `<h4>Pending replacement (${esc(candidate.pending.agent_id)})</h4><p>${txt(candidate.pending.reason)}</p>` : ""}
        <h4>${candidate.pending ? "Proposed replacement record" : candidate.record ? "Current record" : "Proposed record"}</h4>
        <div class="record">${renderRecord(latest)}</div>
      </div></details>`;
  }).join("");
  return `<section id="candidates" class="card"><h2>Candidates <span class="count">${candidates.length}</span></h2>${filterBar("candidates", CANDIDATE_STATUSES, counts)}<div class="rows" data-filter-target="candidates">${rows}</div></section>`;
}

function findingsSection(data) {
  if (!data.findings) return `<section id="findings" class="card"><h2>Findings</h2><p class="muted">findings.json is written in Phase 4, after independent candidate validation.</p></section>`;
  const records = data.findings.slice().sort((left, right) => {
    const verdictOrder = VERDICTS.indexOf(left.verdict) - VERDICTS.indexOf(right.verdict);
    if (verdictOrder) return verdictOrder;
    const severity = (record) => SEVERITIES.indexOf(record.severity ? record.severity.overall_severity : "informational");
    return severity(left) - severity(right) || String(left.fingerprint).localeCompare(String(right.fingerprint));
  });
  const candidates = new Map(((data.state && data.state.candidates) || []).map((candidate) => [candidate.fingerprint, candidate]));
  const counts = countBy(records, "verdict");
  const rows = records.map((record) => {
    const candidate = candidates.get(record.fingerprint);
    const review = candidate ? pill("cs", candidate.status) : "";
    const headline = record.verdict === "confirmed" ? record.execution && record.execution.observed_result : record.verdict === "needs_validation" ? (record.blockers || [])[0] : record.reason;
    const search = [record.fingerprint, record.title, record.verdict, record.severity && record.severity.overall_severity].filter(Boolean).join(" ").toLowerCase();
    return `<details class="row" id="f-${slug(record.fingerprint)}" data-status="${esc(record.verdict)}" data-search="${attr(search)}">
      <summary class="grid find-grid">${record.verdict === "confirmed" ? pill("sev", record.severity && record.severity.overall_severity) : pill("verdict", record.verdict)}<span class="main"><b>${txt(record.title)}</b><span class="sub">${txt(headline || "")}</span></span><span class="meta">${code(record.fingerprint)}</span><span class="meta">${review}</span></summary>
      <div class="body record">${renderRecord(record)}</div></details>`;
  }).join("");
  return `<section id="findings" class="card"><h2>Findings <span class="count">${records.length}</span></h2>${filterBar("findings", VERDICTS, counts)}<div class="rows" data-filter-target="findings">${rows || "<p class=\"muted\">No records.</p>"}</div></section>`;
}

function agentsSection(data) {
  const agents = (data.state && data.state.agents) || [];
  if (!data.state) return "";
  const units = new Map((data.ledger || []).map((unit) => [unit.coverage_id, unit]));
  const budget = data.metadata && Number.isInteger(data.metadata.budget) ? data.metadata.budget : null;
  const roleCounts = countBy(agents, "role");
  const rows = agents.slice().reverse().map((agent) => {
    const work = [
      ...(agent.units || []).map((id) => esc(alias(units.get(id)) || id)),
      ...(agent.fingerprints || []).map(code),
    ].join(" ");
    const status = agent.status === "running" && (agent.last_errors || []).length ? pill("ag", "rejected") : pill("ag", agent.status);
    const errors = (agent.last_errors || []).length ? `<details class="errs"><summary>${agent.last_errors.length} problem(s) in the result file</summary><pre>${txt(agent.last_errors.join("\n"))}</pre></details>` : "";
    return `<tr data-status="${esc(agent.status)}"><td>${code(agent.id)}</td><td>${esc(agent.role)}</td><td>${esc(agent.phase || "")}${agent.wave ? ` · w${esc(agent.wave)}` : ""}</td><td>${status}</td><td>${work || "—"}</td><td>${time(agent.started_at)}</td><td>${esc(duration(agent.started_at, agent.ended_at))}</td><td>${txt(agent.summary || agent.note || "")}${agent.critic ? ` ${agent.critic.stop ? pill("ag", "stop") : ""}` : ""}${errors}</td></tr>`;
  }).join("");
  const bar = budget !== null ? `<div class="dist"><div class="dist-title">Budget: ${agents.length} of ${budget} agent invocations</div>${stackedBar({ used: Math.min(agents.length, budget), left: Math.max(0, budget - agents.length) }, ["used", "left"], "bud")}</div>` : "";
  return `<section id="agents" class="card"><h2>Agents <span class="count">${agents.length}</span></h2>${bar}<p class="muted">${Object.entries(roleCounts).map(([role, count]) => `${esc(role)} ${count}`).join(" · ")}</p>
    <div class="table-wrap"><table><thead><tr><th>Agent</th><th>Role</th><th>Phase</th><th>Status</th><th>Work</th><th>Started</th><th>Time</th><th>Summary</th></tr></thead><tbody>${rows || "<tr><td colspan=\"8\" class=\"muted\">No agents started yet.</td></tr>"}</tbody></table></div></section>`;
}

function gapsSection(data) {
  const proposals = (data.state && data.state.proposals) || [];
  const units = data.ledger || [];
  const open = proposals.filter((proposal) => proposal.status === "open");
  const closed = proposals.filter((proposal) => proposal.status !== "open");
  const renderProposal = (proposal) => {
    const body = proposal.type === "reassign"
      ? `reassign ${esc(proposal.data.unit)} (${esc(proposal.data.status)})`
      : `${txt(proposal.data.surface)} × ${txt(proposal.data.boundary)} × ${txt(proposal.data.attack_class)} <span class="muted">(${txt(proposal.data.subsystem)})</span><div>${txt(proposal.data.reason)}</div><div class="muted">${(proposal.data.starting_paths || []).map(code).join(" ")}</div>`;
    return `<li>${code(proposal.id)} ${pill("prop", proposal.type)} from ${code(proposal.from_agent)} ${body}${proposal.resolution ? `<div class="muted">${esc(proposal.status)}: ${txt(proposal.resolution)}</div>` : ""}</li>`;
  };
  const hardening = new Map();
  for (const unit of units) {
    for (const entry of (unit.bookkeeping && unit.bookkeeping.hardening) || []) {
      const key = entry.note;
      if (!hardening.has(key)) hardening.set(key, { note: entry.note, agents: new Set(), units: new Set() });
      hardening.get(key).agents.add(entry.agent_id);
      hardening.get(key).units.add(alias(unit));
    }
  }
  const unresolved = units.filter((unit) => (unit.unresolved || []).length && ["blocked", "deferred", "out_of_scope", "not_applicable", "candidate"].includes(unit.status));
  return `<section id="gaps" class="card"><h2>Gaps and notes</h2>
    <div class="cols">
      <div><h3>Open proposals <span class="count">${open.length}</span></h3>${open.length ? `<ul class="plain props">${open.map(renderProposal).join("")}</ul>` : "<p class=\"muted\">None.</p>"}
      ${closed.length ? `<details><summary>${closed.length} resolved proposal(s)</summary><ul class="plain props">${closed.map(renderProposal).join("")}</ul></details>` : ""}</div>
      <div><h3>Unresolved facts <span class="count">${unresolved.length}</span></h3>${unresolved.length ? `<ul class="plain">${unresolved.map((unit) => `<li>${esc(alias(unit))} ${pill("st", unit.status)} ${txt(unit.surface)} × ${txt(unit.attack_class)}${list(unit.unresolved)}</li>`).join("")}</ul>` : "<p class=\"muted\">None.</p>"}</div>
    </div>
    <h3>Hardening notes <span class="count">${hardening.size}</span></h3>${hardening.size ? `<ul class="plain">${[...hardening.values()].map((entry) => `<li>${txt(entry.note)} <span class="muted">— ${[...entry.agents].map(esc).join(", ")} on ${[...entry.units].map(esc).join(", ")}</span></li>`).join("")}</ul>` : "<p class=\"muted\">None.</p>"}
  </section>`;
}

function activitySection(data) {
  const events = (data.events || []).slice().reverse();
  if (events.length === 0) return "";
  return `<section id="activity" class="card"><h2>Activity</h2><ol class="plain activity">${events.slice(0, 300).map((entry) => `<li class="${esc(entry.level || "")}">${time(entry.at)} <b>${esc(entry.command)}</b> ${txt(entry.message)}</li>`).join("")}</ol></section>`;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const STYLE = `
:root{--bg:#f6f7f9;--card:#fff;--ink:#17202a;--muted:#5d6b7a;--line:#e3e7ec;--soft:#eef1f5;--accent:#2f6fde;--good:#1e8e4f;--bad:#c62f3a;--warn:#c27100;--code:#f1f3f6;
--st-planned:#9aa5b1;--st-in_progress:#2f6fde;--st-covered:#1e8e4f;--st-candidate:#7b4ddb;--st-blocked:#d9731a;--st-deferred:#c9a227;--st-out_of_scope:#6b7785;--st-not_applicable:#b5bec8;
--sev-critical:#8e1b4f;--sev-high:#c62f3a;--sev-medium:#d9731a;--sev-low:#2f6fde;--sev-informational:#6b7785;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--ink:#e6ebf0;--muted:#98a4b1;--line:#2a313b;--soft:#1f252e;--accent:#6b9cff;--good:#3fbf74;--bad:#ff6b74;--warn:#f0a43a;--code:#222933;--st-planned:#6b7785;--st-in_progress:#5b8ff0;--st-covered:#3fbf74;--st-candidate:#a07ef0;--st-blocked:#f08c3a;--st-deferred:#e0bd3d;--st-out_of_scope:#7c8794;--st-not_applicable:#4d5661;--sev-critical:#e0569a;--sev-high:#ff6b74;--sev-medium:#f08c3a;--sev-low:#6b9cff;--sev-informational:#8a96a3;color-scheme:dark}}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:64px}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header.top{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
.bar-inner,main{max-width:1280px;margin:0 auto;padding:0 16px}
.bar-inner{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding-top:10px;padding-bottom:10px}
.brand{font-weight:650;font-size:15px}.brand small{color:var(--muted);font-weight:400}
nav{display:flex;flex-wrap:wrap;gap:4px}nav a{color:var(--muted);text-decoration:none;padding:3px 9px;border-radius:999px}nav a:hover{background:var(--soft);color:var(--ink)}
.updated{margin-left:auto;color:var(--muted);font-size:12px;display:flex;gap:10px;align-items:center}
main{padding-top:16px;padding-bottom:48px;display:grid;gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;min-width:0}
h2{font-size:17px;margin:0 0 12px}h3{font-size:14px;margin:14px 0 8px}h4{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:14px 0 6px}
.count{color:var(--muted);font-weight:400;font-size:13px}
.muted{color:var(--muted)}.good{color:var(--good)}.bad{color:var(--bad)}.warn-text{color:var(--warn)}
code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
pre{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:8px 10px;border-radius:6px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;margin:4px 0}
.cc{font:10px ui-monospace,monospace;background:var(--warn);color:#fff;border-radius:3px;padding:0 3px;margin:0 1px}
.phases{display:grid;grid-template-columns:repeat(6,1fr);gap:6px;list-style:none;margin:0 0 16px;padding:0}
.phases li{display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:8px;background:var(--soft);color:var(--muted);font-size:12.5px;min-width:0}
.phases .num{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;background:var(--line);color:var(--ink);font-weight:600;font-size:12px}
.phases .name{line-height:1.25}
.phases .done{color:var(--ink)}.phases .done .num{background:var(--good);color:#fff}
.phases .current{background:color-mix(in srgb,var(--accent) 14%,var(--card));color:var(--ink);font-weight:600;box-shadow:inset 0 0 0 1px var(--accent)}.phases .current .num{background:var(--accent);color:#fff}
.tiles{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-bottom:14px}.vrow{display:block}
.tile{border:1px solid var(--line);border-radius:10px;padding:10px 12px}.tile-title{color:var(--muted);font-size:12px}.tile-value{font-size:24px;font-weight:650;line-height:1.3}.tile-value small{font-size:13px;color:var(--muted);font-weight:400}.tile-detail{font-size:12px;color:var(--muted)}
.tile:last-child .tile-value{font-size:13px;font-weight:400;padding-top:4px;line-height:1.6}
.accent-confirmed .tile-value{color:var(--sev-high)}
.dist{margin:10px 0}.dist-title{font-size:12px;color:var(--muted);margin-bottom:4px}
svg.bar,.bar.empty{display:block;width:100%;height:12px;border-radius:6px;background:var(--soft);overflow:hidden}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:6px;font-size:12px;color:var(--muted)}.legend b{color:var(--ink)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:baseline}
.next{border-top:1px solid var(--line);margin-top:14px}.next li{padding:3px 0}.next li::before{content:"→ ";color:var(--accent)}
.next li.alert{color:var(--bad)}.next li.alert::before{content:"! ";color:var(--bad)}.next li.warn{color:var(--warn)}
ul.plain,ol.plain{list-style:none;margin:0;padding:0}ul.plain li{padding:2px 0}
.cols{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.3fr);gap:20px}
dl.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:4px 14px;margin:0}dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}
.files a{color:var(--accent)}
.arch .md{max-height:520px;overflow:auto;border-top:1px solid var(--line);margin-top:8px;padding-top:4px}.md h3,.md h4,.md h5{color:var(--ink);text-transform:none;letter-spacing:0;font-size:14px}.md p,.md ul,.md ol{margin:6px 0}.mdlink{text-decoration:underline dotted}
.filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center}
.chip{font:inherit;font-size:12px;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:3px 10px;cursor:pointer}.chip.on{background:var(--ink);color:var(--card);border-color:var(--ink)}
.filters input{font:inherit;font-size:13px;margin-left:auto;padding:4px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);min-width:180px}
.rows{display:grid;gap:6px}
details.row{border:1px solid var(--line);border-radius:8px;background:var(--card)}details.row[open]{border-color:color-mix(in srgb,var(--accent) 45%,var(--line))}
details.row>summary{list-style:none;cursor:pointer;padding:8px 12px}details.row>summary::-webkit-details-marker{display:none}
details.row>summary:hover{background:var(--soft);border-radius:8px}
.grid{display:grid;gap:10px;align-items:center}
.unit-grid{grid-template-columns:44px 104px minmax(0,2fr) minmax(0,1.3fr) 34px 120px 80px}
.cand-grid{grid-template-columns:132px minmax(0,2.5fr) 120px 110px minmax(0,1fr)}
.find-grid{grid-template-columns:120px minmax(0,3fr) minmax(0,1.3fr) 120px}
.main,.grid>span{min-width:0}.main b{display:block;overflow:hidden;text-overflow:ellipsis}.sub{display:block;color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.id{font-weight:650;font-variant-numeric:tabular-nums}.meta{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.body{padding:4px 14px 14px;border-top:1px solid var(--line)}
.checks{list-style:none;margin:0;padding:0;display:grid;gap:6px}.checks>li{border-left:3px solid var(--line);padding:2px 0 2px 10px}
ol.trace{margin:0;padding-left:20px}ol.trace li{margin:4px 0}.scope{font-weight:600}
.record h4:first-child{margin-top:4px}.change{margin:6px 0}
.timeline li{font-size:13px}
.pill{display:inline-block;font-size:11.5px;line-height:18px;padding:0 8px;border-radius:999px;background:var(--soft);color:var(--ink);white-space:nowrap;font-weight:550}
.pill.ghost{opacity:.6;font-style:italic}
${UNIT_STATUSES.map((status) => `.st-${status}{--c:var(--st-${status})}`).join("")}
${SEVERITIES.map((severity) => `.sev-${severity}{--c:var(--sev-${severity})}`).join("")}
.pill[class*="st-"],.pill[class*="sev-"],.pill[class*="cs-"],.pill[class*="verdict-"],.pill[class*="ag-"],.pill[class*="dec-"],.pill[class*="kind-"],.pill[class*="run-"]{background:color-mix(in srgb,var(--c,var(--muted)) 16%,var(--card));color:var(--c,var(--ink));box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--c,var(--muted)) 35%,transparent)}
.cs-proposed,.ag-stop{--c:var(--st-planned)}.cs-validating,.cs-final_review,.ag-running,.run-in_progress,.kind-propagation{--c:var(--st-in_progress)}.cs-validated{--c:#13867f}.cs-replacement_pending,.ag-rejected{--c:var(--warn)}.cs-verified,.ag-done,.run-complete,.dec-verified,.kind-entrypoint{--c:var(--good)}.cs-duplicate{--c:var(--st-out_of_scope)}.cs-removed,.ag-failed,.run-incomplete,.kind-sink{--c:var(--bad)}
.verdict-confirmed,.dec-confirmed{--c:var(--sev-high)}.verdict-needs_validation,.dec-needs_validation,.dec-replace{--c:var(--warn)}.verdict-rejected,.dec-rejected{--c:var(--st-out_of_scope)}
svg .fill{fill:var(--c)}.bud-used{--c:var(--accent)}.bud-left{--c:var(--soft)}
.dot{background:var(--c)}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:550;font-size:12px}
details.errs summary{color:var(--warn);cursor:pointer}
.props>li{border-left:3px solid var(--line);padding:4px 0 4px 10px;margin-bottom:6px}
.activity li{padding:3px 0;border-bottom:1px dashed var(--line);font-size:13px}.activity li.error{color:var(--bad)}.activity li.warn{color:var(--warn)}
.activity time,.timeline time{color:var(--muted);font-size:12px;margin-right:6px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:0 16px 24px}
label.toggle{display:flex;gap:4px;align-items:center;cursor:pointer}
[hidden]{display:none!important}
@media (max-width:1100px){.tiles{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:900px){.cols{grid-template-columns:1fr}.phases{grid-template-columns:repeat(3,1fr)}
.unit-grid{grid-template-columns:44px 1fr;grid-auto-flow:row}.unit-grid>:nth-child(n+3){grid-column:1/-1}
.cand-grid,.find-grid{grid-template-columns:1fr}.updated{margin-left:0}.filters input{margin-left:0;flex:1}}
@media (max-width:520px){.phases,.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}.tile-value{font-size:20px}dl.kv{grid-template-columns:minmax(0,1fr);gap:0}dl.kv dd{margin-bottom:8px}}
`;

const SCRIPT = `(function(){
var KEY="audit-progress:"+location.pathname;
function load(){try{return JSON.parse(sessionStorage.getItem(KEY)||"{}")}catch(e){return {}}}
function save(s){try{sessionStorage.setItem(KEY,JSON.stringify(s))}catch(e){}}
var saved=load();
document.querySelectorAll("time[datetime]").forEach(function(t){var d=new Date(t.getAttribute("datetime"));if(!isNaN(d))t.textContent=d.toLocaleString();});
var groups={};
document.querySelectorAll("[data-filter-group]").forEach(function(bar){
  var name=bar.getAttribute("data-filter-group");var target=document.querySelector('[data-filter-target="'+name+'"]');if(!target)return;
  var chips=bar.querySelectorAll(".chip");var input=bar.querySelector("input");var st=(saved.filters||{})[name]||{v:"*",q:""};
  function apply(){var q=(input.value||"").toLowerCase().trim();target.querySelectorAll("[data-status]").forEach(function(el){
    var ok=(st.v==="*"||el.getAttribute("data-status")===st.v)&&(!q||(el.getAttribute("data-search")||"").indexOf(q)!==-1);el.hidden=!ok;});
    chips.forEach(function(c){c.classList.toggle("on",c.getAttribute("data-value")===st.v)});st.q=input.value;groups[name]=st;}
  chips.forEach(function(c){c.addEventListener("click",function(){st.v=c.getAttribute("data-value");apply();remember();})});
  input.value=st.q||"";input.addEventListener("input",function(){apply();remember();});apply();
});
(saved.open||[]).forEach(function(id){var el=document.getElementById(id);if(el&&el.tagName==="DETAILS")el.open=true;});
if(typeof saved.y==="number")window.scrollTo(0,saved.y);
function remember(){var open=[];document.querySelectorAll("details[open][id]").forEach(function(d){open.push(d.id)});save({y:window.scrollY,open:open,filters:groups,auto:box?box.checked:undefined});}
var box=document.getElementById("autorefresh");
if(box){var def=box.getAttribute("data-default")==="on";box.checked=typeof saved.auto==="boolean"?saved.auto:def;box.addEventListener("change",remember);}
document.addEventListener("toggle",remember,true);window.addEventListener("scroll",function(){clearTimeout(window.__t);window.__t=setTimeout(remember,200)});
setInterval(function(){if(box&&box.checked&&document.visibilityState==="visible"&&!(document.activeElement&&document.activeElement.tagName==="INPUT"&&document.activeElement.type==="search")){remember();location.reload();}},15000);
})();`;

function sha256(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64");
}

function renderProgressHtml(data) {
  const metadata = data.metadata || {};
  const state = data.state || null;
  const title = `${metadata.repo || "audit"} · ${metadata.run_id || "run"}`;
  const phase = (state && state.phase) || 1;
  const runStatus = metadata.run_status || "in_progress";
  const csp = `default-src 'none'; style-src 'sha256-${sha256(STYLE)}'; script-src 'sha256-${sha256(SCRIPT)}'; img-src data:; base-uri 'none'; form-action 'none'`;
  const sections = [
    overview({ ...data, metadata }),
    knowledge({ ...data, metadata }),
    coverage(data),
    candidatesSection(data),
    findingsSection(data),
    agentsSection(data),
    gapsSection(data),
    activitySection(data),
  ].filter(Boolean).join("\n");
  const navItems = [["overview", "Overview"], ["knowledge", "Knowledge"], ["coverage", "Coverage"], ...(state ? [["candidates", "Candidates"]] : []), ["findings", "Findings"], ...(state ? [["agents", "Agents"], ["gaps", "Gaps"], ["activity", "Activity"]] : [])];
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<title>${esc(`Audit progress — ${title}`)}</title>
<style>${STYLE}</style>
</head>
<body>
<header class="top"><div class="bar-inner">
  <div class="brand">Security audit progress <small>${txt(title)}</small></div>
  ${pill("run", runStatus)} <span class="pill">phase ${esc(phase)} · ${esc(PHASES[phase - 1] || "")}</span>
  <nav>${navItems.map(([id, name]) => `<a href="#${id}">${name}</a>`).join("")}</nav>
  <div class="updated">Updated ${time(data.generatedAt)}<label class="toggle"><input type="checkbox" id="autorefresh" data-default="${runStatus === "in_progress" ? "on" : "off"}"> auto-refresh</label></div>
</div></header>
<main>
${sections}
</main>
<footer>Generated by audit-state.cjs from run-metadata.json, coverage-ledger.json, findings.json, architecture.md, and state/. This page never changes the run; regenerate it with <code>audit-state.cjs report</code>.</footer>
<script>${SCRIPT}</script>
</body>
</html>
`;
}

module.exports = { renderProgressHtml, renderMarkdown, esc, txt };
