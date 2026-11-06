"""Rule engine: runs all generic candidate rules over the collected files."""
from __future__ import annotations

from typing import List

from ..models import Finding, SourceFile
from . import javascript, python_rules, secrets, sql_rules
from .base import ProjectContext, Rule

ALL_RULES: List[Rule] = secrets.RULES + javascript.RULES + python_rules.RULES + sql_rules.RULES
RULES_BY_ID = {r.id: r for r in ALL_RULES}


def run_rules(files: List[SourceFile], ctx: ProjectContext) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for rule in ALL_RULES:
        if rule.check:
            for f in files:
                if not rule.applies_to(f):
                    continue
                try:
                    matches = rule.check(f, ctx)
                except Exception:  # a broken heuristic must never stop the scan
                    continue
                for m in matches:
                    key = (rule.id, f.path, m.start_line)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(rule.to_finding(f, m))
        if rule.project_check:
            try:
                pairs = rule.project_check(ctx)
            except Exception:
                pairs = []
            for path, m in pairs:
                f = ctx.by_path.get(path)
                if not f:
                    continue
                key = (rule.id, path, m.start_line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(rule.to_finding(f, m))
    for i, fd in enumerate(findings, start=1):
        fd.temp_id = f"R{i}"
    return findings


__all__ = ["ALL_RULES", "RULES_BY_ID", "run_rules", "ProjectContext"]
