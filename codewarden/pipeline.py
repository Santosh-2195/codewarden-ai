"""End-to-end scan pipeline.

    collect -> rules (candidates) -> redact secrets -> AI per-file review (triage + discovery)
            -> evidence grounding -> merge & de-duplicate -> AI executive synthesis -> report
"""
from __future__ import annotations

import datetime as _dt
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import __version__
from .ai.providers import LLMClient, ProviderError
from .ai.reviewer import AIReviewer, FileReview, select_files
from .collector import load_target
from .models import (SEV_RANK, SEV_WEIGHT, SEVERITIES, Finding, Location, ScanMetrics, SourceFile,
                     lower_confidence, norm_confidence, norm_severity)
from .rules import RULES_BY_ID, ProjectContext, run_rules
from .rules.secrets import redact

CWE_FAMILIES = [
    {"CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-639", "CWE-306", "CWE-287", "CWE-288", "CWE-566", "CWE-425"},
    {"CWE-89", "CWE-564", "CWE-943"},
    {"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
    {"CWE-798", "CWE-259", "CWE-321", "CWE-312", "CWE-522", "CWE-540"},
    {"CWE-209", "CWE-200", "CWE-497", "CWE-210", "CWE-211"},
    {"CWE-489", "CWE-215", "CWE-11", "CWE-1188"},
    {"CWE-942", "CWE-346", "CWE-1385"},
    {"CWE-915", "CWE-20"},
    {"CWE-78", "CWE-77", "CWE-88"},
    {"CWE-269", "CWE-266", "CWE-250"},
]
GROUP_ACROSS_FILES = {"CWE-209", "CWE-200", "CWE-497", "CWE-489", "CWE-215", "CWE-942", "CWE-346"}


def cwe_family(cwe: str) -> int:
    for i, fam in enumerate(CWE_FAMILIES):
        if cwe in fam:
            return i
    return -1 - abs(hash(cwe)) % 100000


@dataclass
class ScanOptions:
    provider: Optional[str] = None      # None / "none" -> rules only
    model: Optional[str] = None
    api_key: Optional[str] = None
    max_files: int = 60
    workers: int = 3
    cache_dir: Optional[Path] = Path(".codewarden/cache")
    min_severity: str = "Low"
    project_name: Optional[str] = None  # display name override


@dataclass
class ScanResult:
    project: str
    files: List[SourceFile]
    findings: List[Finding]
    metrics: ScanMetrics
    summary: Dict
    ai_label: str
    ai_enabled: bool
    started: str
    duration_s: float
    frameworks: List[str]
    tool_version: str = __version__
    file_summaries: Dict[str, str] = field(default_factory=dict)

    def counts(self) -> Dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c


# ------------------------------------------------------------------ grounding

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def ground_line(d: Dict, f: SourceFile):
    """Return (start_line, end_line, verified, relocated) or None when the evidence is hallucinated."""
    lines = f.lines
    red = (f.redacted_text or f.text).splitlines()
    ev = _norm(str(d.get("evidence") or ""))
    ev = re.sub(r"^\d+\s*\|\s?", "", ev)
    ev_first = _norm(str(d.get("evidence") or "").splitlines()[0] if d.get("evidence") else "")
    ev_first = re.sub(r"^\d+\s*\|\s?", "", ev_first)
    try:
        claimed = int(d.get("start_line") or 0)
    except (TypeError, ValueError):
        claimed = 0
    try:
        claimed_end = int(d.get("end_line") or claimed)
    except (TypeError, ValueError):
        claimed_end = claimed
    span = max(0, min(30, claimed_end - claimed)) if claimed_end >= claimed else 0
    hits = []
    probes = [p for p in {ev, ev_first} if len(p) >= 4]
    for i, (a, b) in enumerate(zip(lines, red), start=1):
        na, nb = _norm(a), _norm(b)
        if not na:
            continue
        for p in probes:
            if p == na or p == nb or (len(p) >= 10 and (p in na or p in nb)) or (len(na) >= 12 and na in p):
                hits.append(i)
                break
    if hits:
        best = min(hits, key=lambda i: abs(i - claimed)) if claimed else hits[0]
        return best, min(len(lines), best + span), True, bool(claimed) and best != claimed
    if 1 <= claimed <= len(lines) and not probes:
        return claimed, min(len(lines), claimed + span), False, False
    if 1 <= claimed <= len(lines) and probes:
        return claimed, min(len(lines), claimed + span), False, False
    return None


def _snip(f: SourceFile, s: int, e: int) -> str:
    return "\n".join(f.lines[s - 1:e])


def _str(d: Dict, k: str) -> str:
    v = d.get(k)
    if v is None:
        return ""
    if isinstance(v, list):
        return "\n".join(str(x) for x in v)
    return str(v).strip()


def _status(v: str, default="Needs validation") -> str:
    v = (v or "").lower().replace("_", " ")
    if v.startswith("confirm"):
        return "Confirmed"
    if "valid" in v or "likely" in v:
        return "Needs validation"
    return default


def _extra_locations(d: Dict, f: SourceFile, existing: List[Location]) -> List[Location]:
    out = []
    have = {(l.file, l.start_line) for l in existing}
    for ln in d.get("additional_lines") or []:
        try:
            ln = int(ln)
        except (TypeError, ValueError):
            continue
        if 1 <= ln <= f.line_count and (f.path, ln) not in have and all(abs(ln - l.start_line) > 1 for l in existing if l.file == f.path):
            out.append(Location(f.path, ln, ln, f.lines[ln - 1].strip()))
            have.add((f.path, ln))
    return out[:5]


def enrich(c: Finding, d: Dict, f: SourceFile, verdict: Optional[Dict], metrics: ScanMetrics) -> Finding:
    sev = norm_severity(_str(d, "severity") or (verdict or {}).get("severity"), c.severity)
    if sev != c.severity:
        c.ai_severity_change = f"{c.severity} -> {sev}"
        metrics.ai_severity_adjusted += 1
    c.severity = sev
    c.title = _str(d, "title") or c.title
    for attr in ("description", "impact", "recommendation", "secure_code"):
        val = _str(d, attr)
        if val and len(val) > 15:
            setattr(c, attr, val)
    if _str(d, "secure_code"):
        c.secure_code_lang = c.secure_code_lang or f.language
    vstat = (verdict or {}).get("verdict", "")
    c.status = _status(_str(d, "status") or vstat, c.status)
    c.confidence = norm_confidence(_str(d, "confidence"), c.confidence)
    notes = _str(d, "validation_notes")
    reason = _str(verdict or {}, "reason")
    c.validation_notes = notes or c.validation_notes or reason
    c.locations += _extra_locations(d, f, c.locations)
    c.source = "rule+ai"
    c.ai_reviewed = True
    return c


def new_ai_finding(d: Dict, f: SourceFile, metrics: ScanMetrics) -> Optional[Finding]:
    g = ground_line(d, f)
    if g is None:
        metrics.grounding_dropped += 1
        return None
    s, e, verified, relocated = g
    if relocated:
        metrics.grounding_relocated += 1
    conf = norm_confidence(_str(d, "confidence"), "Medium")
    notes = _str(d, "validation_notes")
    if not verified:
        conf = lower_confidence(conf)
        notes = (notes + " " if notes else "") + "(Evidence line could not be matched verbatim; location taken from the model.)"
    cwe = _str(d, "cwe").upper().replace(" ", "")
    m = re.search(r"CWE-?(\d+)", cwe)
    cwe = f"CWE-{m.group(1)}" if m else "CWE-Other"
    title = _str(d, "title") or "Potential security issue"
    desc = _str(d, "description")
    if not desc:
        metrics.grounding_dropped += 1
        return None
    fd = Finding(
        title=title, category=_str(d, "category") or "Security Weakness", cwe=cwe,
        severity=norm_severity(_str(d, "severity"), "Medium"), confidence=conf,
        status=_status(_str(d, "status")),
        locations=[Location(f.path, s, e, _snip(f, s, e).strip())],
        description=desc, impact=_str(d, "impact"), recommendation=_str(d, "recommendation"),
        secure_code=_str(d, "secure_code"), secure_code_lang=f.language, validation_notes=notes,
        source="ai", ai_reviewed=True,
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"] if m else [],
    )
    fd.locations += _extra_locations(d, f, fd.locations)
    return fd


def combine(candidates: List[Finding], reviews: Dict[str, FileReview], files: Dict[str, SourceFile],
            metrics: ScanMetrics) -> List[Finding]:
    by_id = {c.temp_id: c for c in candidates}
    verdicts: Dict[str, Dict] = {}
    for r in reviews.values():
        for cr in r.candidate_reviews:
            verdicts[str(cr.get("candidate_id"))] = cr
    out: List[Finding] = []
    consumed = set()
    for path, r in reviews.items():
        f = files[path]
        for d in r.findings:
            cid = d.get("candidate_id")
            cid = str(cid).strip() if cid not in (None, "", "null", "None") else None
            if cid and cid in by_id:
                if cid in consumed:
                    continue
                v = verdicts.get(cid)
                if v and str(v.get("verdict", "")).lower().startswith("false"):
                    continue
                consumed.add(cid)
                out.append(enrich(by_id[cid], d, files[by_id[cid].primary.file], v, metrics))
            else:
                nf = new_ai_finding(d, f, metrics)
                if nf:
                    out.append(nf)
    reviewed_files = {p for p, r in reviews.items() if not r.error or r.candidate_reviews}
    for c in candidates:
        if c.temp_id in consumed:
            continue
        v = verdicts.get(c.temp_id)
        if v:
            verdict = str(v.get("verdict", "")).lower()
            if verdict.startswith("false"):
                metrics.ai_rejected += 1
                continue
            sev = norm_severity(v.get("severity"), c.severity)
            if sev != c.severity:
                c.ai_severity_change = f"{c.severity} -> {sev}"
                metrics.ai_severity_adjusted += 1
                c.severity = sev
            c.status = _status(verdict, c.status)
            if v.get("reason"):
                c.validation_notes = (c.validation_notes + " AI review: " + str(v["reason"])).strip()
            c.ai_reviewed = True
            c.source = "rule+ai"
        elif c.primary.file in reviewed_files:
            c.validation_notes = (c.validation_notes + " (Not explicitly triaged by the AI reviewer.)").strip()
        out.append(c)
    return out


# ------------------------------------------------------------------ de-duplication

def _tokens(s: str) -> set:
    return {w for w in re.findall(r"[a-z]{4,}", s.lower())} - {"with", "from", "that", "this", "user", "users", "data"}


def _similar(a: Finding, b: Finding) -> float:
    ta, tb = _tokens(a.title + " " + a.category), _tokens(b.title + " " + b.category)
    return len(ta & tb) / max(1, len(ta | tb))


def _merge_into(base: Finding, other: Finding) -> None:
    have = {(l.file, l.start_line) for l in base.locations}
    for l in other.locations:
        if (l.file, l.start_line) not in have and not any(
                l.file == b.file and abs(l.start_line - b.start_line) <= 1 for b in base.locations):
            base.locations.append(l)
            have.add((l.file, l.start_line))
    if SEV_RANK[other.severity] < SEV_RANK[base.severity]:
        base.severity = other.severity
    if other.status == "Confirmed":
        base.status = "Confirmed"
    if not base.secure_code and other.secure_code:
        base.secure_code = other.secure_code
    if other.ai_reviewed:
        base.ai_reviewed = True
        if base.source == "rule":
            base.source = "rule+ai"


def _rank_base(f: Finding) -> tuple:
    return ({"rule+ai": 0, "rule": 1, "ai": 2}.get(f.source, 3), SEV_RANK[f.severity])


def deduplicate(findings: List[Finding], files: Dict[str, SourceFile], metrics: ScanMetrics) -> List[Finding]:
    items = sorted(findings, key=_rank_base)
    kept: List[Finding] = []
    for f in items:
        target = None
        for k in kept:
            if k.primary.file != f.primary.file:
                continue
            same_family = cwe_family(k.cwe) == cwe_family(f.cwe)
            near = any(abs(a.start_line - b.start_line) <= 2 for a in k.locations for b in f.locations if a.file == b.file)
            close = any(abs(a.start_line - b.start_line) <= 25 for a in k.locations for b in f.locations if a.file == b.file)
            is_sql = files.get(f.primary.file) and files[f.primary.file].language == "sql"
            if same_family and (near or (not is_sql and (close or _similar(k, f) >= 0.3))):
                target = k
                break
            if near and _similar(k, f) >= 0.5:
                target = k
                break
        if target:
            _merge_into(target, f)
            metrics.merged_duplicates += 1
        else:
            kept.append(f)
    # cross-file grouping of hygiene-type issues with a single shared fix
    grouped: List[Finding] = []
    for f in kept:
        rule = RULES_BY_ID.get(f.rule_id or "")
        groupable = (rule and rule.group_across_files) or f.cwe in GROUP_ACROSS_FILES
        target = None
        if groupable:
            for g in grouped:
                if (g.rule_id and g.rule_id == f.rule_id) or (cwe_family(g.cwe) == cwe_family(f.cwe) and g.cwe in GROUP_ACROSS_FILES):
                    target = g
                    break
        if target:
            _merge_into(target, f)
            metrics.merged_duplicates += 1
        else:
            grouped.append(f)
    return grouped


# ------------------------------------------------------------------ summary fallback

def risk_rating(findings: List[Finding]) -> str:
    if any(f.severity == "Critical" for f in findings):
        return "Critical"
    highs = sum(1 for f in findings if f.severity == "High")
    if highs:
        return "High"
    if any(f.severity == "Medium" for f in findings):
        return "Medium"
    return "Low" if findings else "Low"


def deterministic_summary(project: str, findings: List[Finding], counts: Dict[str, int]) -> Dict:
    total = len(findings)
    rating = risk_rating(findings)
    top = [f for f in findings if f.severity in ("Critical", "High")][:4]
    top_txt = "; ".join(f"{f.id} {f.title}" for f in top)
    cats = sorted({f.category for f in findings})
    summary = (f"The static review of {project} produced {total} finding(s): "
               + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts.get(s)) + ". "
               + (f"The most serious issues are: {top_txt}. " if top else "")
               + f"Overall risk is rated {rating}. Findings should be validated and remediated in severity order.")
    actions = []
    for f in findings[:6]:
        first = re.split(r"(?<=[.!?])\s", f.recommendation.strip())[0] if f.recommendation else f.title
        actions.append({"action": first, "finding_ids": [f.id], "effort": "Medium"})
    return {
        "executive_summary": summary,
        "risk_rating": rating,
        "overall_assessment": ("Issues span the following areas: " + ", ".join(cats) + ". "
                               "Address authorisation and injection weaknesses first, then data-exposure and "
                               "configuration hardening.") if cats else "No significant issues were identified.",
        "attack_chains": [],
        "prioritized_actions": actions,
        "positive_observations": [],
        "generated_by": "deterministic",
    }


def _clean_summary(data: Dict, ids: set, findings: List[Finding]) -> Dict:
    def fid(lst):
        return [x for x in (lst or []) if isinstance(x, str) and x in ids]
    chains = []
    for c in data.get("attack_chains") or []:
        if isinstance(c, dict) and len(fid(c.get("finding_ids"))) >= 1 and c.get("narrative"):
            chains.append({"title": str(c.get("title", "Attack chain")), "finding_ids": fid(c.get("finding_ids")),
                           "narrative": str(c["narrative"])})
    actions = []
    for a in data.get("prioritized_actions") or []:
        if isinstance(a, dict) and a.get("action"):
            actions.append({"action": str(a["action"]), "finding_ids": fid(a.get("finding_ids")),
                            "effort": str(a.get("effort", "Medium"))})
    rating = norm_severity(data.get("risk_rating"), risk_rating(findings))
    # never let the narrative rating contradict the evidence
    computed = risk_rating(findings)
    if SEV_RANK[rating] > SEV_RANK[computed]:
        rating = computed
    return {
        "executive_summary": str(data.get("executive_summary") or "").strip(),
        "risk_rating": rating,
        "overall_assessment": str(data.get("overall_assessment") or "").strip(),
        "attack_chains": chains[:3],
        "prioritized_actions": actions[:8],
        "positive_observations": [str(x) for x in (data.get("positive_observations") or []) if isinstance(x, str)][:5],
        "generated_by": "ai",
    }


# ------------------------------------------------------------------ main entry

def run_scan(target: str = None, options: ScanOptions = None, progress: Callable[[str], None] = None,
             preloaded: Optional[tuple] = None) -> ScanResult:
    options = options or ScanOptions()
    progress = progress or (lambda m: None)
    t0 = time.time()
    started = _dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z").strip()
    metrics = ScanMetrics()
    tmp = None
    if preloaded:
        project, files, tmp = preloaded
    else:
        progress(f"Loading {target} ...")
        project, files, tmp = load_target(target, metrics.skipped_files)
    if options.project_name:
        project = options.project_name
    try:
        return _run(project, files, options, progress, metrics, started, t0)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _run(project, files, options, progress, metrics, started, t0) -> ScanResult:
    metrics.files_collected = len(files)
    metrics.lines_scanned = sum(f.line_count for f in files)
    progress(f"Collected {len(files)} source files ({metrics.lines_scanned} lines).")
    if not files:
        raise ValueError("No supported source files were found in the target.")
    ctx = ProjectContext(files)
    by_path = {f.path: f for f in files}
    progress(f"Detected stack: {', '.join(ctx.frameworks) or 'unknown'}")

    candidates = run_rules(files, ctx)
    metrics.rule_candidates = len(candidates)
    progress(f"Rule engine produced {len(candidates)} candidate finding(s).")

    for f in files:
        f.redacted_text, n = redact(f)
        metrics.secrets_redacted += n

    ai_enabled = bool(options.provider and options.provider.lower() not in ("none", "off", "rules"))
    ai_label = "disabled (rules-only mode)"
    reviewer = None
    if ai_enabled:
        client = LLMClient.create(options.provider, options.model, options.api_key)
        ai_label = client.label
        reviewer = AIReviewer(client, project, ctx, metrics, options.cache_dir, options.workers, progress)
        targets = select_files(files, candidates, options.max_files)
        skipped = len([f for f in files if f not in targets])
        progress(f"AI reviewing {len(targets)} file(s) with {client.label}"
                 + (f" ({skipped} lower-priority/non-code files skipped)" if skipped else "") + " ...")
        if secrets_count := metrics.secrets_redacted:
            progress(f"Privacy: {secrets_count} secret value(s) masked before sending code to the AI provider.")
        reviews = reviewer.review_all(targets, candidates)
        file_summaries = {p: r.summary for p, r in reviews.items() if r.summary}
        if metrics.ai_errors and metrics.ai_errors >= len(targets):
            progress("WARNING: every AI request failed - falling back to rule findings only. "
                     + (metrics.ai_error_messages[0] if metrics.ai_error_messages else ""))
        findings = combine(candidates, reviews, by_path, metrics)
    else:
        file_summaries = {}
        findings = list(candidates)

    findings = deduplicate(findings, by_path, metrics)
    min_rank = SEV_RANK[norm_severity(options.min_severity, "Low")]
    findings = [f for f in findings if SEV_RANK[f.severity] <= min_rank]
    findings.sort(key=lambda f: (SEV_RANK[f.severity], 0 if f.status == "Confirmed" else 1, f.primary.file, f.primary.start_line))
    for i, f in enumerate(findings, start=1):
        f.id = f"CW-{i:03d}"
        first_file = f.locations[0].file
        f.locations = [f.locations[0]] + sorted(f.locations[1:], key=lambda l: (l.file != first_file, l.file, l.start_line))
    metrics.ai_new_findings = sum(1 for f in findings if f.source == "ai")
    metrics.ai_confirmed = sum(1 for f in findings if f.ai_reviewed and f.status == "Confirmed")
    metrics.ai_needs_validation = sum(1 for f in findings if f.ai_reviewed and f.status != "Confirmed")

    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    summary = None
    if reviewer and findings:
        progress("AI synthesising executive summary, attack chains and remediation plan ...")
        raw = reviewer.summarize(findings, counts, metrics.files_collected, metrics.lines_scanned)
        if raw:
            summary = _clean_summary(raw, {f.id for f in findings}, findings)
            if not summary["executive_summary"]:
                summary = None
    if not summary:
        summary = deterministic_summary(project, findings, counts)
    summary["risk_score"] = sum(SEV_WEIGHT[f.severity] for f in findings)

    return ScanResult(project=project, files=files, findings=findings, metrics=metrics, summary=summary,
                      ai_label=ai_label, ai_enabled=ai_enabled, started=started,
                      duration_s=round(time.time() - t0, 1), frameworks=ctx.frameworks,
                      file_summaries=file_summaries)
