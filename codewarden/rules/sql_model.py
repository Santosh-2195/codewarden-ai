"""A small, dependency-free PostgreSQL/Supabase schema model.

It is not a full SQL parser; it extracts just enough structure (tables, columns,
foreign keys, RLS state, policies, grants, functions, triggers) to reason about
database access control across migration files.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import SourceFile


@dataclass
class Statement:
    file: str
    text: str           # comment-stripped statement text
    offset: int         # offset in the file text
    line: int           # line where the statement starts
    file_text: str      # whole (comment-stripped) file text

    def line_at(self, rel_offset: int) -> int:
        return self.file_text.count("\n", 0, self.offset + rel_offset) + 1


@dataclass
class Table:
    name: str
    file: str
    line: int
    columns: Dict[str, str] = field(default_factory=dict)
    fks: Dict[str, str] = field(default_factory=dict)  # column -> referenced table
    rls_enabled: bool = False
    rls_line: Optional[int] = None


@dataclass
class Policy:
    name: str
    table: str
    cmd: str
    roles: List[str]
    using: Optional[str]
    check: Optional[str]
    file: str
    line: int
    using_line: Optional[int]
    check_line: Optional[int]
    permissive: bool = True

    @property
    def evidence_line(self) -> int:
        return self.using_line or self.check_line or self.line


@dataclass
class Grant:
    privileges: str
    obj: str
    roles: List[str]
    file: str
    line: int
    revoke: bool = False
    columns: List[str] = field(default_factory=list)


@dataclass
class Function:
    name: str
    file: str
    line: int
    security_definer: bool
    has_search_path: bool
    body: str


def canon(name: str) -> str:
    n = name.strip().strip('"').replace('"', "")
    if n.lower().startswith("public."):
        n = n[7:]
    return n.lower()


def strip_sql_comments(text: str) -> str:
    """Blank out comments while keeping offsets/line numbers stable."""
    out = list(text)
    i, n = 0, len(text)
    in_str = None
    while i < n:
        c = text[i]
        if in_str:
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == "'":
            in_str = "'"
            i += 1
            continue
        if text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def split_statements(f: SourceFile) -> List[Statement]:
    text = strip_sql_comments(f.text)
    stmts: List[Statement] = []
    i, n, start = 0, len(text), 0
    in_str = False
    dollar: Optional[str] = None
    while i < n:
        c = text[i]
        if dollar:
            if text.startswith(dollar, i):
                i += len(dollar)
                dollar = None
                continue
            i += 1
            continue
        if in_str:
            if c == "'":
                in_str = False
            i += 1
            continue
        if c == "'":
            in_str = True
        elif c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", text[i:])
            if m:
                dollar = m.group(0)
                i += len(dollar)
                continue
        elif c == ";":
            _push(stmts, f, text, start, i)
            start = i + 1
        i += 1
    _push(stmts, f, text, start, n)
    return stmts


def _push(stmts, f, text, start, end):
    chunk = text[start:end]
    stripped = chunk.lstrip()
    if not stripped.strip():
        return
    lead = len(chunk) - len(stripped)
    offset = start + lead
    stmts.append(Statement(f.path, stripped.rstrip(), offset, text.count("\n", 0, offset) + 1, text))


def _split_top_level(body: str) -> List[str]:
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _balanced_after(text: str, keyword_re: str) -> Tuple[Optional[str], Optional[int]]:
    m = re.search(keyword_re + r"\s*\(", text, re.I | re.S)
    if not m:
        return None, None
    i = m.end() - 1
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j].strip(), m.start()
    return text[i + 1:].strip(), m.start()


class SqlModel:
    def __init__(self, sql_files: List[SourceFile]):
        self.tables: Dict[str, Table] = {}
        self.policies: List[Policy] = []
        self.grants: List[Grant] = []
        self.functions: List[Function] = []
        self.triggers: Dict[str, List[str]] = {}  # table -> trigger statement texts
        self.statements: List[Statement] = []
        self.has_sql = bool(sql_files)
        for f in sql_files:
            for st in split_statements(f):
                self.statements.append(st)
                self._parse(st)

    # ------------------------------------------------------------ parsing
    def _parse(self, st: Statement) -> None:
        t = st.text
        m = re.match(r"CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)\s*\((.*)\)", t, re.I | re.S)
        if m:
            self._parse_table(st, canon(m.group(1)), m.group(2))
            return
        m = re.match(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w.\"]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", t, re.I)
        if m:
            name = canon(m.group(1))
            tbl = self.tables.get(name)
            if tbl:
                tbl.rls_enabled = True
                tbl.rls_line = st.line
            else:
                self.tables[name] = Table(name, st.file, st.line, rls_enabled=True, rls_line=st.line)
            return
        m = re.match(r"CREATE\s+POLICY\s+(\"[^\"]+\"|[\w]+)\s+ON\s+([\w.\"]+)(.*)", t, re.I | re.S)
        if m:
            self._parse_policy(st, m.group(1).strip('"'), canon(m.group(2)), m.group(3), m.start(3))
            return
        m = re.match(r"(GRANT|REVOKE)\s+(.+?)\s+ON\s+(?:TABLE\s+|ALL\s+TABLES\s+IN\s+SCHEMA\s+)?(.+?)\s+(TO|FROM)\s+(.+)", t, re.I | re.S)
        if m:
            privs = m.group(2)
            cols = []
            cm = re.search(r"\(([^)]*)\)", privs)
            if cm:
                cols = [c.strip().strip('"').lower() for c in cm.group(1).split(",")]
            roles = [r.strip().lower() for r in re.split(r",", m.group(5)) if r.strip()]
            self.grants.append(Grant(privs.lower(), canon(m.group(3)), roles, st.file, st.line,
                                     revoke=m.group(1).upper() == "REVOKE", columns=cols))
            return
        m = re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.\"]+)", t, re.I)
        if m:
            self.functions.append(Function(
                canon(m.group(1)), st.file, st.line,
                security_definer=bool(re.search(r"SECURITY\s+DEFINER", t, re.I)),
                has_search_path=bool(re.search(r"SET\s+search_path", t, re.I)),
                body=t))
            return
        m = re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+.*?\s+ON\s+([\w.\"]+)", t, re.I | re.S)
        if m:
            self.triggers.setdefault(canon(m.group(1)), []).append(t)

    def _parse_table(self, st: Statement, name: str, body: str) -> None:
        tbl = self.tables.get(name) or Table(name, st.file, st.line)
        tbl.file, tbl.line = st.file, st.line
        for part in _split_top_level(body):
            first = part.split()[0].strip('"').lower() if part.split() else ""
            if first in ("constraint", "primary", "unique", "check", "exclude", "foreign"):
                fk = re.search(r"FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+([\w.\"]+)", part, re.I)
                if fk:
                    for col in fk.group(1).split(","):
                        tbl.fks[col.strip().strip('"').lower()] = canon(fk.group(2))
                continue
            tbl.columns[first] = part
            ref = re.search(r"REFERENCES\s+([\w.\"]+)", part, re.I)
            if ref:
                tbl.fks[first] = canon(ref.group(1))
        self.tables[name] = tbl

    def _parse_policy(self, st: Statement, pname: str, table: str, rest: str, rest_off: int) -> None:
        cmd_m = re.search(r"\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b", rest, re.I)
        cmd = cmd_m.group(1).upper() if cmd_m else "ALL"
        to_m = re.search(r"\bTO\s+(.+?)(?=\bUSING\b|\bWITH\s+CHECK\b|$)", rest, re.I | re.S)
        roles = [r.strip().lower() for r in to_m.group(1).split(",")] if to_m else ["public"]
        using, u_off = _balanced_after(rest, r"\bUSING")
        check, c_off = _balanced_after(rest, r"\bWITH\s+CHECK")
        permissive = not re.search(r"\bAS\s+RESTRICTIVE\b", rest, re.I)
        self.policies.append(Policy(
            pname, table, cmd, roles, using, check, st.file, st.line,
            using_line=st.line_at(rest_off + u_off) if u_off is not None else None,
            check_line=st.line_at(rest_off + c_off) if c_off is not None else None,
            permissive=permissive))

    # ------------------------------------------------------------ queries
    def policies_for(self, table: str, cmds=("SELECT",)) -> List[Policy]:
        return [p for p in self.policies if p.table == table and (p.cmd in cmds or p.cmd == "ALL")]

    def uses_supabase_auth(self) -> bool:
        return any("auth.uid()" in (p.using or "") + (p.check or "") for p in self.policies) or any(
            "auth.users" in t.fks.values() for t in self.tables.values())

    def owner_columns(self, table: str) -> List[str]:
        t = self.tables.get(table)
        if not t:
            return []
        out = []
        for col, ref in t.fks.items():
            if ref in ("auth.users", "users", "profiles", "accounts"):
                out.append(col)
        for col in t.columns:
            if col in ("owner_id", "user_id", "author_id", "created_by", "account_id", "tenant_id", "org_id") and col not in out:
                out.append(col)
        return out

    def digest(self, limit: int = 6000) -> str:
        """Compact human-readable summary used as AI context."""
        lines = []
        for t in self.tables.values():
            cols = ", ".join(t.columns.keys())
            fks = ", ".join(f"{c}->{r}" for c, r in t.fks.items())
            lines.append(f"TABLE {t.name} ({cols}) FK[{fks}] RLS={'on' if t.rls_enabled else 'OFF'}  [{t.file}:{t.line}]")
        for p in self.policies:
            lines.append(f"POLICY \"{p.name}\" ON {p.table} FOR {p.cmd} TO {','.join(p.roles)} "
                         f"USING({_squash(p.using)}) CHECK({_squash(p.check)})  [{p.file}:{p.line}]")
        for g in self.grants:
            lines.append(f"{'REVOKE' if g.revoke else 'GRANT'} {g.privileges} ON {g.obj} {'FROM' if g.revoke else 'TO'} {','.join(g.roles)}  [{g.file}:{g.line}]")
        for fn in self.functions:
            lines.append(f"FUNCTION {fn.name} security_definer={fn.security_definer} search_path_set={fn.has_search_path}  [{fn.file}:{fn.line}]")
        for tbl, trigs in self.triggers.items():
            lines.append(f"TRIGGERS on {tbl}: {len(trigs)}")
        out = "\n".join(lines)
        return out[:limit]


def _squash(expr: Optional[str]) -> str:
    if expr is None:
        return "-"
    return re.sub(r"\s+", " ", expr).strip()
