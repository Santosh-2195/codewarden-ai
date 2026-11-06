"""Hard-coded secret detection and redaction.

The same detector is used for two jobs:
  1. producing candidate findings (CWE-798), and
  2. masking secret values *before* any code is sent to an external AI provider.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List

from ..models import SourceFile
from .base import Match, Rule, is_client_file, is_comment, is_test_file

PROVIDER_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "High"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "Critical"),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), "High"),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "High"),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "High"),
    ("Stripe live secret key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"), "Critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Medium"),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "High"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"), "High"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "Medium"),
    ("Database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@'\"]+:[^\s@'\"]{3,}@"), "High"),
]

KEY_NAMES = (
    r"api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"bearer[_-]?token|private[_-]?key|password|passwd|pwd|service[_-]?role(?:[_-]?key)?|signing[_-]?key|"
    r"encryption[_-]?key|webhook[_-]?secret|jwt[_-]?secret|db[_-]?pass(?:word)?"
)
ASSIGN_RE = re.compile(
    r"(?P<key>[\"']?[A-Za-z0-9_.\-]*(?:" + KEY_NAMES + r")[A-Za-z0-9_\-]*[\"']?)\s*(?::|=|=>|:=)\s*"
    r"(?P<q>[\"'`])(?P<val>[^\"'`\n]{6,})(?P=q)", re.I)
ENV_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Z0-9_]*(?:" + KEY_NAMES + r")[A-Z0-9_]*)\s*=\s*(?P<val>[^\s#]{6,})", re.I)

PUBLIC_KEY_NAMES = re.compile(r"anon|publishable|public|pk_|site[_-]?key|client[_-]?id|label|placeholder|field|"
                              r"input|hint|message|error|text|title|_url|url$|type|path|route|header|policy|reset", re.I)
PLACEHOLDER_RE = re.compile(r"not[_-]?real|dummy|example|sample|placeholder|changeme|change[_-]?me|your[_-]|xxx+|"
                            r"\*\*\*|<[^>]+>|\$\{|todo|fake|test|demo|redacted|replace", re.I)
NOT_SECRET_VALUE = re.compile(r"^(process\.env|import\.meta|os\.environ|Deno\.env|env\(|getenv|config\.|settings\.)", re.I)


@dataclass
class SecretHit:
    line: int
    start: int
    end: int
    kind: str
    key: str
    value: str
    placeholder: bool
    severity: str


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def find_secrets(f: SourceFile) -> List[SecretHit]:
    hits: List[SecretHit] = []
    for i, line in enumerate(f.lines, start=1):
        if len(line) > 2000:
            continue
        taken = []
        for kind, pat, sev in PROVIDER_PATTERNS:
            for m in pat.finditer(line):
                val = m.group(0)
                hits.append(SecretHit(i, m.start(), m.end(), kind, "", val, bool(PLACEHOLDER_RE.search(val)), sev))
                taken.append((m.start(), m.end()))
        regex = ENV_ASSIGN_RE if f.language == "env" else ASSIGN_RE
        for m in regex.finditer(line):
            key = m.group("key").strip("\"'")
            val = m.group("val")
            s, e = m.span("val")
            if any(a <= s < b for a, b in taken):
                continue
            if PUBLIC_KEY_NAMES.search(key) or NOT_SECRET_VALUE.search(val):
                continue
            if " " in val.strip() and not val.startswith("-----"):
                continue  # prose / UI text, not a credential
            if re.fullmatch(r"[a-z_]+|[A-Z_]+", val) and len(val) < 20:
                continue  # identifiers such as "password_hash"
            placeholder = bool(PLACEHOLDER_RE.search(val))
            if not placeholder and _entropy(val) < 2.5 and len(val) < 12:
                continue
            hits.append(SecretHit(i, s, e, "Hard-coded credential", key, val, placeholder, "High"))
    return hits


def mask_value(v: str) -> str:
    if len(v) <= 6:
        return "*" * len(v)
    return v[:4] + "*" * min(12, len(v) - 4)


def redact(f: SourceFile) -> (str, int):
    """Return text with secret values replaced, plus the number of redactions."""
    hits = find_secrets(f)
    if not hits:
        return f.text, 0
    lines = f.lines
    by_line = {}
    for h in hits:
        by_line.setdefault(h.line, []).append(h)
    for ln, hs in by_line.items():
        s = lines[ln - 1]
        for h in sorted(hs, key=lambda x: x.start, reverse=True):
            tag = "[REDACTED_SECRET:placeholder-like value]" if h.placeholder else "[REDACTED_SECRET]"
            s = s[:h.start] + tag + s[h.end:]
        lines[ln - 1] = s
    return "\n".join(lines), len(hits)


def _check(f: SourceFile, ctx) -> List[Match]:
    out: List[Match] = []
    client = is_client_file(f)
    test = is_test_file(f)
    for h in find_secrets(f):
        line = f.lines[h.line - 1]
        if is_comment(line) and h.kind == "Hard-coded credential":
            continue
        notes = []
        sev = h.severity
        status = "Confirmed"
        conf = "High"
        if h.placeholder:
            sev = "Medium" if sev in ("Critical", "High") else "Low"
            status = "Needs validation"
            conf = "Medium"
            notes.append("The value appears to be a fabricated/placeholder string, so this is reported as an insecure "
                         "secret-handling pattern rather than a confirmed leaked production credential.")
        if client:
            notes.append("The file is part of client-side code, so any value here is shipped to every browser "
                         "and cannot be kept secret.")
            if not h.placeholder and sev == "High":
                sev = "Critical" if "private" in (h.key + h.kind).lower() or "service" in h.key.lower() else "High"
        if test:
            sev = "Low"
            notes.append("Located in a test/fixture path; verify it is not a real credential.")
        if f.language == "env":
            notes.append("A populated .env file is committed to the repository; .env files should be git-ignored.")
        masked = line.replace(h.value, mask_value(h.value))
        title = f"Hard-coded secret in source ({h.kind}{': ' + h.key if h.key else ''})"
        out.append(Match(h.line, h.line, masked.strip(), " ".join(notes), severity=sev,
                         confidence=conf, status=status, title=title))
    return out


SECRET_RULE = Rule(
    id="CW-SECRET-001",
    title="Hard-coded secret in source",
    category="Hardcoded Secrets",
    cwe="CWE-798",
    owasp="A07:2021 Identification and Authentication Failures",
    severity="High",
    confidence="High",
    languages=["*"],
    description="A credential-like value (API key, token, password or private key) is embedded directly in "
                "source code instead of being loaded from a secret store or server-side environment variable.",
    impact="Anyone with access to the repository, build artefacts or (for frontend code) the browser bundle can "
           "read the value and impersonate the application against the related service. Secrets in git history "
           "persist even after the line is deleted.",
    recommendation="Remove the value from source, rotate it if it was ever real, and load it at runtime from a "
                   "server-side secret store or environment variable. Never place private keys in frontend code; "
                   "move the privileged call behind a backend endpoint that holds the secret.",
    secure_code={
        "typescript": "// Server-side only (e.g. edge function / API route):\n"
                      "const analyticsKey = Deno.env.get(\"ANALYTICS_API_KEY\"); // or process.env.ANALYTICS_API_KEY\n"
                      "if (!analyticsKey) throw new Error(\"ANALYTICS_API_KEY is not configured\");\n\n"
                      "// Frontend: keep only public, non-secret settings\n"
                      "export const appConfig = {\n  analytics: { enabled: true }, // the key itself lives on the server\n};",
        "javascript": "const apiKey = process.env.API_KEY;\nif (!apiKey) throw new Error(\"API_KEY is not configured\");",
        "python": "import os\n\napi_key = os.environ[\"API_KEY\"]  # fails fast if missing",
        "env": "# Commit only a template (.env.example) with empty values and add .env to .gitignore\nAPI_KEY=",
    },
    references=["https://cwe.mitre.org/data/definitions/798.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    status="Confirmed",
    check=_check,
)

RULES = [SECRET_RULE]
