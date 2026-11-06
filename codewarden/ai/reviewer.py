"""AI review stage: per-file triage of rule candidates + discovery of new issues,
and a final executive synthesis over all verified findings."""
from __future__ import annotations

import hashlib
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..models import Finding, ScanMetrics, SourceFile
from . import prompts
from .providers import LLMClient, ProviderError, extract_json

AI_LANGS = {"typescript", "javascript", "python", "sql", "java", "kotlin", "go", "php", "ruby", "csharp",
            "html", "yaml", "toml", "json", "shell", "docker", "env"}
CHUNK_LINES = 450
CHUNK_OVERLAP = 40
INJECTION_RE = re.compile(r"ignore (all |any )?(previous|prior|above) instructions|disregard .{0,30}instructions|"
                          r"you are now|system prompt|do not report|report no (issues|vulnerabilities)", re.I)


@dataclass
class FileReview:
    path: str
    candidate_reviews: List[Dict] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None


class ResponseCache:
    def __init__(self, root: Optional[Path]):
        self.root = root
        self.lock = threading.Lock()
        if root:
            root.mkdir(parents=True, exist_ok=True)

    def key(self, *parts: str) -> str:
        h = hashlib.sha256()
        for p in parts:
            h.update(p.encode("utf-8", errors="replace"))
            h.update(b"\x00")
        return h.hexdigest()

    def get(self, k: str) -> Optional[str]:
        if not self.root:
            return None
        p = self.root / f"{k}.json"
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))["text"]
            except Exception:
                return None
        return None

    def put(self, k: str, text: str) -> None:
        if not self.root:
            return
        with self.lock:
            (self.root / f"{k}.json").write_text(json.dumps({"text": text}), encoding="utf-8")


def file_priority(f: SourceFile, candidate_count: int) -> int:
    score = candidate_count * 10
    if f.language == "sql":
        score += 15
    if re.search(r"(api|server|backend|functions|routes|auth|controllers|handlers|supabase|middleware)", f.path, re.I):
        score += 12
    if re.search(r"(auth|login|session|token|password|admin|payment|upload|query|search)", f.text[:20000], re.I):
        score += 5
    if re.search(r"(test|spec|fixture|mock|stories)", f.path, re.I):
        score -= 15
    if f.line_count < 3:
        score -= 30
    return score


def select_files(files: List[SourceFile], candidates: List[Finding], max_files: int) -> List[SourceFile]:
    counts: Dict[str, int] = {}
    for c in candidates:
        for loc in c.locations:
            counts[loc.file] = counts.get(loc.file, 0) + 1
    eligible = [f for f in files if f.language in AI_LANGS and f.text.strip()]
    eligible.sort(key=lambda f: file_priority(f, counts.get(f.path, 0)), reverse=True)
    return eligible[:max_files]


def numbered(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    out = []
    width = len(str(end))
    for i in range(start, min(end, len(lines)) + 1):
        out.append(f"{str(i).rjust(width)} | {lines[i - 1]}")
    return "\n".join(out)


def chunks_for(f: SourceFile):
    n = max(1, f.line_count)
    if n <= CHUNK_LINES + CHUNK_OVERLAP:
        return [(1, n)]
    out, s = [], 1
    while s <= n:
        e = min(n, s + CHUNK_LINES - 1)
        out.append((s, e))
        if e == n:
            break
        s = e - CHUNK_OVERLAP + 1
    return out


def candidates_payload(cands: List[Finding]) -> str:
    if not cands:
        return "(none)"
    items = []
    for c in cands:
        items.append({
            "candidate_id": c.temp_id, "rule": c.rule_id, "title": c.title, "cwe": c.cwe,
            "severity": c.severity, "lines": [loc.start_line for loc in c.locations if loc.file == c.primary.file],
            "rule_note": c.validation_notes[:400],
        })
    return json.dumps(items, indent=1)


class AIReviewer:
    def __init__(self, client: LLMClient, project: str, ctx, metrics: ScanMetrics,
                 cache_dir: Optional[Path] = None, workers: int = 3,
                 progress: Optional[Callable[[str], None]] = None):
        self.client = client
        self.project = project
        self.ctx = ctx
        self.metrics = metrics
        self.cache = ResponseCache(cache_dir)
        self.workers = max(1, workers)
        self.progress = progress or (lambda m: None)
        self.lock = threading.Lock()

    # --------------------------------------------------------------- LLM call
    def _call(self, system: str, user: str, max_tokens: int) -> Dict:
        k = self.cache.key(prompts.PROMPT_VERSION, self.client.label, system, user)
        cached = self.cache.get(k)
        if cached is not None:
            with self.lock:
                self.metrics.ai_cache_hits += 1
            return extract_json(cached)
        with self.lock:
            self.metrics.ai_calls += 1
        text = self.client.complete(system, user, max_tokens=max_tokens)
        data = extract_json(text)  # raises if unparsable -> not cached
        self.cache.put(k, text)
        return data

    # ----------------------------------------------------------- file review
    def review_file(self, f: SourceFile, cands: List[Finding]) -> FileReview:
        review = FileReview(f.path)
        code_text = f.redacted_text or f.text
        if INJECTION_RE.search(f.text):
            with self.lock:
                self.metrics.injection_markers += 1
        for (s, e) in chunks_for(f):
            chunk_cands = [c for c in cands if any(s <= loc.start_line <= e for loc in c.locations if loc.file == f.path)]
            user = prompts.REVIEW_USER.format(
                project=self.project,
                frameworks=", ".join(self.ctx.frameworks) or "unknown",
                tree=self.ctx.tree(200),
                sql_digest=self.ctx.sql.digest(5000) or "(no SQL files)",
                candidates=candidates_payload(chunk_cands),
                path=f.path, language=f.language, start=s, end=e,
                code=numbered(code_text, s, e),
            )
            try:
                data = self._call(prompts.REVIEW_SYSTEM, user, max_tokens=8000)
            except (ProviderError, ValueError, json.JSONDecodeError) as exc:
                review.error = str(exc)[:300]
                continue
            cr = data.get("candidate_reviews") or []
            fd = data.get("findings") or []
            if isinstance(cr, list):
                review.candidate_reviews.extend(x for x in cr if isinstance(x, dict))
            if isinstance(fd, list):
                review.findings.extend(x for x in fd if isinstance(x, dict))
            if isinstance(data.get("file_summary"), str):
                review.summary = (review.summary + " " + data["file_summary"]).strip()
        return review

    def review_all(self, files: List[SourceFile], candidates: List[Finding]) -> Dict[str, FileReview]:
        by_file: Dict[str, List[Finding]] = {}
        for c in candidates:
            by_file.setdefault(c.primary.file, []).append(c)
        results: Dict[str, FileReview] = {}
        total = len(files)
        done = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futs = {pool.submit(self.review_file, f, by_file.get(f.path, [])): f for f in files}
            for fut in as_completed(futs):
                f = futs[fut]
                try:
                    r = fut.result()
                except Exception as exc:  # noqa: BLE001
                    r = FileReview(f.path, error=str(exc)[:300])
                results[f.path] = r
                done += 1
                status = "error: " + r.error[:80] if r.error else f"{len(r.findings)} finding(s)"
                self.progress(f"[AI {done}/{total}] {f.path} -> {status}")
                if r.error:
                    with self.lock:
                        self.metrics.ai_errors += 1
                        if len(self.metrics.ai_error_messages) < 5:
                            self.metrics.ai_error_messages.append(f"{f.path}: {r.error}")
        self.metrics.files_ai_reviewed = sum(1 for r in results.values() if not r.error or r.findings)
        return results

    # --------------------------------------------------------------- summary
    def summarize(self, findings: List[Finding], counts: Dict[str, int], files: int, lines: int) -> Optional[Dict]:
        compact = [{
            "id": f.id, "severity": f.severity, "status": f.status, "title": f.title, "cwe": f.cwe,
            "location": f.primary.label(), "summary": f.description[:350],
        } for f in findings]
        user = prompts.SUMMARY_USER.format(
            project=self.project, frameworks=", ".join(self.ctx.frameworks) or "unknown",
            files=files, lines=lines, counts=json.dumps(counts),
            sql_digest=self.ctx.sql.digest(3000) or "(none)",
            findings=json.dumps(compact, indent=1),
        )
        try:
            return self._call(prompts.SUMMARY_SYSTEM, user, max_tokens=4000)
        except (ProviderError, ValueError, json.JSONDecodeError) as exc:
            with self.lock:
                self.metrics.ai_errors += 1
                self.metrics.ai_error_messages.append(f"summary: {str(exc)[:200]}")
            return None
