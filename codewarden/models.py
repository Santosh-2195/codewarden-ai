"""Core data structures shared by the rule engine, AI layer and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower number = more severe
SEV_WEIGHT = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "Info": 0}

CONFIDENCES = ["High", "Medium", "Low"]
STATUSES = ["Confirmed", "Needs validation"]


def norm_severity(value: Optional[str], default: str = "Medium") -> str:
    if not value:
        return default
    v = str(value).strip().lower()
    for s in SEVERITIES:
        if v == s.lower():
            return s
    if v in ("informational", "information", "note"):
        return "Info"
    if v in ("crit",):
        return "Critical"
    if v in ("moderate", "med"):
        return "Medium"
    return default


def norm_confidence(value: Optional[str], default: str = "Medium") -> str:
    if not value:
        return default
    v = str(value).strip().lower()
    for c in CONFIDENCES:
        if v == c.lower():
            return c
    return default


def lower_confidence(value: str) -> str:
    idx = CONFIDENCES.index(norm_confidence(value))
    return CONFIDENCES[min(idx + 1, len(CONFIDENCES) - 1)]


def lower_severity(value: str) -> str:
    idx = SEV_RANK[norm_severity(value)]
    return SEVERITIES[min(idx + 1, len(SEVERITIES) - 2)]  # never drop below Low


@dataclass
class SourceFile:
    path: str               # relative, POSIX-style path
    language: str
    text: str
    redacted_text: str = ""  # text with secret values masked (sent to AI)

    @property
    def lines(self) -> List[str]:
        return self.text.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)


@dataclass
class Location:
    file: str
    start_line: int
    end_line: int
    snippet: str = ""

    def label(self) -> str:
        if self.start_line == self.end_line:
            return f"{self.file}:{self.start_line}"
        return f"{self.file}:{self.start_line}-{self.end_line}"


@dataclass
class Finding:
    title: str
    category: str
    cwe: str
    severity: str
    confidence: str
    status: str
    locations: List[Location]
    description: str
    impact: str
    recommendation: str
    secure_code: str = ""
    secure_code_lang: str = ""
    validation_notes: str = ""
    owasp: str = ""
    rule_id: Optional[str] = None
    source: str = "rule"          # rule | ai | rule+ai
    ai_reviewed: bool = False
    ai_severity_change: str = ""  # e.g. "High -> Medium" when the AI recalibrated
    references: List[str] = field(default_factory=list)
    temp_id: str = ""             # candidate id used during triage
    id: str = ""                  # final id, e.g. CW-001

    @property
    def primary(self) -> Location:
        return self.locations[0]

    def to_dict(self) -> Dict:
        d = asdict(self)
        d.pop("temp_id", None)
        return d


@dataclass
class ScanMetrics:
    files_collected: int = 0
    files_ai_reviewed: int = 0
    lines_scanned: int = 0
    rule_candidates: int = 0
    ai_confirmed: int = 0
    ai_needs_validation: int = 0
    ai_rejected: int = 0
    ai_new_findings: int = 0
    ai_severity_adjusted: int = 0
    grounding_dropped: int = 0
    grounding_relocated: int = 0
    merged_duplicates: int = 0
    ai_calls: int = 0
    ai_cache_hits: int = 0
    ai_errors: int = 0
    secrets_redacted: int = 0
    injection_markers: int = 0
    skipped_files: List[str] = field(default_factory=list)
    ai_error_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)
