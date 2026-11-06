"""Cross-file database access-control rules for PostgreSQL / Supabase migrations."""
from __future__ import annotations

import re
from typing import List, Tuple

from ..models import Location
from .base import Match, Rule, regex_lines
from .sql_model import Policy, SqlModel

TRUE_EXPR = re.compile(r"^\(*\s*(true|1\s*=\s*1|'t'|'true')\s*\)*$", re.I)
USER_SCOPE = re.compile(r"auth\.uid\(\)|auth\.jwt\(\)|auth\.role\(\)|current_user|session_user|current_setting\(", re.I)
PRIV_COLUMNS = {"role", "roles", "is_admin", "admin", "is_superuser", "permissions", "plan", "tier", "credits",
                "balance", "is_verified", "verified", "approved", "is_staff", "user_role", "account_type"}


def _is_true(expr) -> bool:
    return expr is not None and bool(TRUE_EXPR.match(re.sub(r"\s+", " ", expr).strip()))


def _policy_snippet(ctx, p: Policy) -> str:
    f = ctx.by_path.get(p.file)
    if not f:
        return ""
    lines = f.lines
    end = max(p.evidence_line, p.line)
    # include the full USING / WITH CHECK clause (up to closing paren on following lines)
    j = end
    while j < len(lines) and j - p.line < 14 and not lines[j - 1].rstrip().endswith(";"):
        j += 1
    return "\n".join(lines[p.line - 1:j])


def _restrictive_parent(sql: SqlModel, parent: str) -> bool:
    pols = sql.policies_for(parent, ("SELECT",))
    return bool(pols) and all(USER_SCOPE.search(p.using or "") for p in pols)


# ---------------------------------------------------------------- context-aware fix generation
NON_EDITABLE = {"id", "created_at", "updated_at", "inserted_at"}


def _q(name: str) -> str:
    return name if "." in name else f"public.{name}"


def _owner_pred(sql: SqlModel, table: str, alias: str) -> str:
    owners = [c for c in sql.owner_columns(table) if c != "id"] or sql.owner_columns(table)
    col = owners[0] if owners else "owner_id"
    return f"{alias}.{col} = (SELECT auth.uid())"


def _parent_link(sql: SqlModel, table: str):
    t = sql.tables.get(table)
    if not t:
        return None
    for col, parent in t.fks.items():
        if parent not in ("auth.users", "users") and parent in sql.tables and parent != table:
            return col, parent
    return None


def fix_read(sql: SqlModel, p: Policy) -> str:
    t = p.table
    owners = sql.owner_columns(t)
    lines = [f'DROP POLICY IF EXISTS "{p.name}" ON {_q(t)};',
             f'CREATE POLICY "{p.name} (scoped)"', f"ON {_q(t)}", "FOR SELECT", "TO authenticated", "USING ("]
    if owners == ["id"]:
        lines.append("  id = (SELECT auth.uid())")
        lines.append(");")
        lines.append("")
        lines.append(f"-- If other users genuinely need some fields, expose only those via a view:")
        safe_cols = [c for c in sql.tables[t].columns if c not in PRIV_COLUMNS][:4] if t in sql.tables else ["id"]
        lines.append(f"-- CREATE VIEW public.{t}_public AS SELECT {', '.join(safe_cols)} FROM {_q(t)};")
        return "\n".join(lines)
    preds = [f"  {_owner_pred(sql, t, t).split('.', 1)[1] if owners else 'owner_id = (SELECT auth.uid())'}"]
    link = _parent_link(sql, t)
    if link:
        col, parent = link
        preds.append(f"  OR EXISTS (\n    SELECT 1 FROM {_q(parent)} parent\n    WHERE parent.id = {t}.{col}\n"
                     f"      AND {_owner_pred(sql, parent, 'parent')}\n  )")
    lines += preds + [");"]
    return "\n".join(lines)


def fix_subquery(sql: SqlModel, p: Policy, parent: str) -> str:
    t = p.table
    t_tbl = sql.tables.get(t)
    link_col = next((c for c, ref in (t_tbl.fks.items() if t_tbl else []) if ref == parent), f"{parent.rstrip('s')}_id")
    pred = f"({_owner_pred(sql, parent, 'x')}"
    up = _parent_link(sql, parent)
    join = ""
    if up:
        ucol, uparent = up
        join = f"\n    JOIN {_q(uparent)} gp ON gp.id = x.{ucol}"
        pred += f" OR {_owner_pred(sql, uparent, 'gp')}"
    pred += ")"
    return "\n".join([
        f'DROP POLICY IF EXISTS "{p.name}" ON {_q(t)};',
        f'CREATE POLICY "{p.name} (scoped)"', f"ON {_q(t)}", "FOR SELECT", "TO authenticated", "USING (",
        "  EXISTS (", f"    SELECT 1", f"    FROM {_q(parent)} x{join}",
        f"    WHERE x.id = {t}.{link_col}", f"      AND {pred}", "  )", ");"])


def fix_priv_columns(sql: SqlModel, p: Policy, priv) -> str:
    t = p.table
    tbl = sql.tables[t]
    editable = [c for c in tbl.columns if c not in PRIV_COLUMNS and c not in NON_EDITABLE
                and c not in sql.owner_columns(t)] or ["<editable_columns>"]
    pc = priv[0]
    fn = f"prevent_{t}_{pc}_change"
    return "\n".join([
        "-- Clients may edit only their own non-privileged fields",
        f"REVOKE UPDATE ON {_q(t)} FROM authenticated;",
        f"GRANT UPDATE ({', '.join(editable)}) ON {_q(t)} TO authenticated;",
        "",
        "-- Defence in depth: block privileged-column changes from client sessions",
        f"CREATE OR REPLACE FUNCTION public.{fn}()", "RETURNS trigger", "LANGUAGE plpgsql",
        "SET search_path = ''", "AS $$", "BEGIN",
        f"  IF NEW.{pc} IS DISTINCT FROM OLD.{pc}", "     AND current_user <> 'service_role' THEN",
        f"    RAISE EXCEPTION '{pc} cannot be changed by clients';", "  END IF;", "  RETURN NEW;", "END;", "$$;", "",
        f"CREATE TRIGGER {t}_prevent_{pc}_change", f"BEFORE UPDATE ON {_q(t)}",
        f"FOR EACH ROW EXECUTE FUNCTION public.{fn}();"])


def fix_parent_check(sql: SqlModel, p: Policy, col: str, parent: str) -> str:
    t = p.table
    own = p.check or p.using or "owner_id = auth.uid()"
    own = re.sub(r"\s+", " ", own).strip()
    return "\n".join([
        f'DROP POLICY IF EXISTS "{p.name}" ON {_q(t)};',
        f'CREATE POLICY "{p.name} (parent-checked)"', f"ON {_q(t)}", f"FOR {p.cmd}", "TO authenticated",
        "WITH CHECK (", f"  {own}", "  AND EXISTS (", f"    SELECT 1 FROM {_q(parent)} x",
        f"    WHERE x.id = {t}.{col}", f"      AND {_owner_pred(sql, parent, 'x')}", "  )", ");",
        "-- Apply the same parent check to any UPDATE policy (in both USING and WITH CHECK)."])


def _permissive_read(ctx) -> List[Tuple[str, Match]]:
    sql: SqlModel = ctx.sql
    out = []
    for p in sql.policies:
        if p.cmd not in ("SELECT", "ALL") or not _is_true(p.using) or not p.permissive:
            continue
        owners = sql.owner_columns(p.table)
        tbl = sql.tables.get(p.table)
        pk_owner = tbl and owners == ["id"]
        public_roles = any(r in ("anon", "public") for r in p.roles)
        notes = [f"Policy \"{p.name}\" lets every {'visitor' if public_roles else 'signed-in user'} read every row of "
                 f"`{p.table}` (USING (true))."]
        sev = "Medium"
        status = "Needs validation"
        if owners and not pk_owner:
            sev, status = "High", "Confirmed"
            notes.append(f"The table records ownership in `{', '.join(owners)}`, but the policy ignores it, so users can "
                         "read records that belong to other users.")
        elif pk_owner:
            notes.append("Rows are per-user records; confirm that exposing all of them (including every column) to all "
                         "users is an intended product decision (e.g. a public directory).")
        if tbl:
            for col, parent in tbl.fks.items():
                if parent in sql.tables and _restrictive_parent(sql, parent):
                    sev, status = "High", "Confirmed"
                    notes.append(f"This is inconsistent with the parent table `{parent}`, whose SELECT policy is restricted "
                                 f"to the owner: rows of `{p.table}` leak data about {parent} the user cannot otherwise see.")
                    break
        if public_roles:
            sev = "Critical" if sev == "High" else "High"
        title = f"Over-permissive RLS read policy on `{p.table}` (USING true)"
        out.append((p.file, Match(p.evidence_line, p.evidence_line, _policy_snippet(ctx, p), " ".join(notes),
                                  severity=sev, status=status, title=title,
                                  confidence="High" if status == "Confirmed" else "Medium",
                                  secure_code=fix_read(sql, p))))
    return out


def _permissive_write(ctx) -> List[Tuple[str, Match]]:
    out = []
    for p in ctx.sql.policies:
        if p.cmd in ("INSERT", "UPDATE", "DELETE", "ALL") and p.permissive and (
                _is_true(p.check) or (p.cmd in ("UPDATE", "DELETE", "ALL") and _is_true(p.using))):
            if p.cmd == "ALL" and _is_true(p.using) and p.check is None:
                pass  # covered as both read and write
            out.append((p.file, Match(p.evidence_line, p.evidence_line, _policy_snippet(ctx, p),
                                      f"Policy \"{p.name}\" allows {p.cmd} on any row of `{p.table}`.",
                                      title=f"Over-permissive RLS write policy on `{p.table}` ({p.cmd} with true)",
                                      status="Confirmed", confidence="High")))
    return out


def _unscoped_subquery(ctx) -> List[Tuple[str, Match]]:
    sql: SqlModel = ctx.sql
    out = []
    for p in sql.policies:
        expr = p.using if p.cmd in ("SELECT", "ALL", "UPDATE", "DELETE") else p.check
        if not expr or not re.search(r"\bEXISTS\s*\(|\bIN\s*\(\s*SELECT", expr, re.I):
            continue
        if USER_SCOPE.search(expr):
            continue
        ref = re.search(r"FROM\s+([\w.\"]+)", expr, re.I)
        parent = ref.group(1).strip('"').replace("public.", "").lower() if ref else "the parent table"
        note = (f"The subquery in policy \"{p.name}\" only checks that a related `{parent}` row exists; it never "
                "compares anything with auth.uid(), so it does not restrict access to the current user.")
        parent_pols = sql.policies_for(parent, ("SELECT",))
        if parent_pols and any(_is_true(pp.using) for pp in parent_pols):
            note += (f" Because `{parent}` is itself readable by every authenticated user, this policy effectively "
                     f"exposes every row of `{p.table}`.")
        line = p.using_line or p.check_line or p.line
        out.append((p.file, Match(line, line, _policy_snippet(ctx, p), note,
                                  title=f"RLS policy on `{p.table}` does not scope rows to the current user",
                                  status="Confirmed", confidence="High",
                                  secure_code=fix_subquery(sql, p, parent) if parent in sql.tables else None)))
    return out


def _privileged_column_update(ctx) -> List[Tuple[str, Match]]:
    sql: SqlModel = ctx.sql
    out = []
    for p in sql.policies:
        if p.cmd not in ("UPDATE", "ALL"):
            continue
        tbl = sql.tables.get(p.table)
        if not tbl:
            continue
        priv = sorted(c for c in tbl.columns if c in PRIV_COLUMNS)
        if not priv:
            continue
        expr = (p.check or "") + " " + (p.using or "")
        if any(re.search(rf"\b{c}\b", expr) for c in priv):
            continue  # the policy constrains the privileged column itself
        protected = any(g.obj == p.table and (g.revoke and "update" in g.privileges or
                        (not g.revoke and g.columns and "update" in g.privileges))
                        for g in sql.grants)
        if protected or sql.triggers.get(p.table):
            continue
        cols = ", ".join(f"`{c}`" for c in priv)
        note = (f"Policy \"{p.name}\" lets a user update their own row in `{p.table}`, but RLS is row-level only: "
                f"nothing prevents them from changing the privileged column(s) {cols} (e.g. setting role = 'admin'). "
                "No column-level REVOKE/GRANT or trigger protecting these columns was found.")
        line = p.check_line or p.using_line or p.line
        out.append((p.file, Match(line, line, _policy_snippet(ctx, p), note,
                                  title=f"Privilege escalation: users can modify {cols} on `{p.table}`",
                                  status="Confirmed", confidence="High",
                                  secure_code=fix_priv_columns(sql, p, priv))))
    return out


def _parent_not_checked(ctx) -> List[Tuple[str, Match]]:
    sql: SqlModel = ctx.sql
    grouped = {}
    for p in sql.policies:
        if p.cmd not in ("INSERT", "UPDATE", "ALL"):
            continue
        expr = p.check if p.check is not None else p.using
        if not expr or _is_true(expr) or not USER_SCOPE.search(expr):
            continue
        tbl = sql.tables.get(p.table)
        if not tbl:
            continue
        for col, parent in tbl.fks.items():
            if parent in ("auth.users", "users") or parent == p.table or parent not in sql.tables:
                continue
            if not (sql.owner_columns(parent) or sql.policies_for(parent, ("SELECT",))):
                continue
            if re.search(rf"\b{re.escape(col)}\b", expr):
                continue
            grouped.setdefault((p.table, col, parent), []).append(p)
    out = []
    for (table, col, parent), pols in grouped.items():
        first = pols[0]
        line = first.check_line or first.using_line or first.line
        extras = [Location(pp.file, pp.check_line or pp.line, pp.check_line or pp.line, _policy_snippet(ctx, pp))
                  for pp in pols[1:]]
        cmds = "/".join(sorted({pp.cmd for pp in pols}))
        plural = len(pols) > 1
        note = (f"The {cmds} polic{'ies' if plural else 'y'} on `{table}` only check{'' if plural else 's'} the row's own "
                f"owner column. {'They never verify' if plural else 'It never verifies'} that `{col}` points to a "
                f"`{parent}` row the user is allowed to access, so a user can create "
                f"{'or move ' if 'UPDATE' in cmds else ''}`{table}` rows under another user's `{parent}`.")
        out.append((first.file, Match(line, line, _policy_snippet(ctx, first), note,
                                      title=f"RLS write policy on `{table}` does not verify access to parent `{parent}`",
                                      extra_locations=extras, status="Confirmed", confidence="Medium",
                                      secure_code=fix_parent_check(sql, first, col, parent))))
    return out


def _rls_missing(ctx) -> List[Tuple[str, Match]]:
    sql: SqlModel = ctx.sql
    if not sql.tables or not (sql.uses_supabase_auth() or any(t.rls_enabled for t in sql.tables.values())):
        return []
    out = []
    for t in sql.tables.values():
        if "." in t.name or t.rls_enabled or not t.columns:
            continue
        f = ctx.by_path.get(t.file)
        snip = f.lines[t.line - 1].strip() if f else ""
        out.append((t.file, Match(t.line, t.line, snip,
                                  f"Table `{t.name}` is created in the exposed schema but Row Level Security is never "
                                  "enabled, while other tables rely on RLS.", status="Confirmed", confidence="High",
                                  title=f"Row Level Security not enabled on `{t.name}`")))
    return out


def _grants(ctx) -> List[Tuple[str, Match]]:
    out = []
    for g in ctx.sql.grants:
        if g.revoke or not any(r in ("anon", "public") for r in g.roles):
            continue
        if re.search(r"\b(all|insert|update|delete|truncate)\b", g.privileges):
            f = ctx.by_path.get(g.file)
            out.append((g.file, Match(g.line, g.line, f.lines[g.line - 1].strip() if f else "",
                                      f"Write privileges on `{g.obj}` are granted to {', '.join(g.roles)}.",
                                      status="Confirmed", confidence="High")))
    return out


def _secdef(ctx) -> List[Tuple[str, Match]]:
    out = []
    for fn in ctx.sql.functions:
        if fn.security_definer and not fn.has_search_path:
            f = ctx.by_path.get(fn.file)
            out.append((fn.file, Match(fn.line, fn.line, f.lines[fn.line - 1].strip() if f else "",
                                       f"Function `{fn.name}` runs with its owner's privileges but does not pin search_path.")))
    return out


def _dynamic_sql(ctx) -> List[Tuple[str, Match]]:
    out = []
    for fn in ctx.sql.functions:
        if re.search(r"\bEXECUTE\s+[^;]*\|\||\bEXECUTE\s+format\([^)]*%s", fn.body, re.I):
            f = ctx.by_path.get(fn.file)
            if not f:
                continue
            for m in regex_lines(f, re.compile(r"\bEXECUTE\b", re.I)):
                if m.start_line >= fn.line:
                    out.append((fn.file, m))
                    break
    return out


DB_REFS = ["https://supabase.com/docs/guides/database/postgres/row-level-security",
           "https://cwe.mitre.org/data/definitions/284.html"]

POLICY_FIX_SELECT = (
    "-- Scope reads to the caller (adjust to your membership model)\n"
    "DROP POLICY IF EXISTS \"Users can view tasks\" ON public.items;\n"
    "CREATE POLICY \"Users can view tasks in their projects\"\nON public.items\nFOR SELECT\nTO authenticated\nUSING (\n"
    "  owner_id = (SELECT auth.uid())\n  OR EXISTS (\n    SELECT 1 FROM public.projects p\n"
    "    WHERE p.id = tasks.project_id\n      AND p.owner_id = (SELECT auth.uid())\n  )\n);")

RULES = [
    Rule(
        id="CW-SQL-RLS-001", title="Over-permissive RLS read policy (USING true)",
        category="Database Access Control", cwe="CWE-284", owasp="A01:2021 Broken Access Control",
        severity="Medium", confidence="Medium", languages=["sql"],
        description="A Row Level Security SELECT policy uses `USING (true)`, which makes every row visible to every "
                    "user in the granted role, regardless of who owns the data.",
        impact="Any authenticated user can query the table directly through the auto-generated API and read other "
               "users' records (horizontal privilege escalation / data exposure).",
        recommendation="Replace `true` with a predicate that ties rows to the caller (ownership or project/team "
                       "membership via auth.uid()). If some data must be public, expose it through a view containing "
                       "only the non-sensitive columns.",
        secure_code={"sql": POLICY_FIX_SELECT},
        references=DB_REFS, project_check=_permissive_read),
    Rule(
        id="CW-SQL-RLS-002", title="Over-permissive RLS write policy",
        category="Database Access Control", cwe="CWE-284", owasp="A01:2021 Broken Access Control",
        severity="High", confidence="High", languages=["sql"],
        description="An INSERT/UPDATE/DELETE policy uses a constant-true expression.",
        impact="Any user in the granted role can create, modify or delete arbitrary rows.",
        recommendation="Constrain WITH CHECK / USING to rows the caller owns or is a member of.",
        secure_code={"sql": "CREATE POLICY \"Owners can update\" ON public.items FOR UPDATE TO authenticated\n"
                            "USING (owner_id = (SELECT auth.uid()))\nWITH CHECK (owner_id = (SELECT auth.uid()));"},
        references=DB_REFS, project_check=_permissive_write),
    Rule(
        id="CW-SQL-RLS-003", title="RLS policy subquery does not scope rows to the current user",
        category="Database Access Control", cwe="CWE-863", owasp="A01:2021 Broken Access Control",
        severity="Medium", confidence="High", languages=["sql"],
        description="The policy relies on an EXISTS/IN subquery that only checks that a related row exists, without "
                    "comparing it to the authenticated user. It looks restrictive but filters nothing user-specific.",
        impact="Users can read rows (e.g. comments) attached to records they should not have access to.",
        recommendation="Make the subquery join to the parent and compare the parent's owner/membership with auth.uid().",
        secure_code={"sql": "DROP POLICY IF EXISTS \"Users can view task comments\" ON public.comments;\n"
                            "CREATE POLICY \"Users can view comments on accessible tasks\"\nON public.comments\n"
                            "FOR SELECT\nTO authenticated\nUSING (\n  EXISTS (\n    SELECT 1\n    FROM public.items t\n"
                            "    JOIN public.projects p ON p.id = t.project_id\n    WHERE t.id = comments.task_id\n"
                            "      AND (t.owner_id = (SELECT auth.uid()) OR p.owner_id = (SELECT auth.uid()))\n  )\n);"},
        references=DB_REFS, project_check=_unscoped_subquery),
    Rule(
        id="CW-SQL-RLS-004", title="Privilege escalation through self-service row update",
        category="Database Access Control", cwe="CWE-269", owasp="A01:2021 Broken Access Control",
        severity="High", confidence="High", languages=["sql"],
        description="An UPDATE policy allows users to edit their own row, and that row contains an authorisation "
                    "column (e.g. `role`). RLS restricts which rows can be changed, not which columns.",
        impact="A regular user can promote themselves (e.g. `role = 'admin'`) with a single API call and gain "
               "administrative capabilities wherever the application trusts that column.",
        recommendation="Revoke UPDATE on the privileged column(s) from client roles and grant UPDATE only on "
                       "user-editable columns, or enforce immutability with a BEFORE UPDATE trigger. Store roles in a "
                       "separate table writable only by the service role.",
        secure_code={"sql": "-- Clients may edit only their own non-privileged fields\n"
                            "REVOKE UPDATE ON public.profiles FROM authenticated;\n"
                            "GRANT UPDATE (full_name, bio) ON public.profiles TO authenticated;\n\n"
                            "-- Defence in depth: block role changes from client sessions\n"
                            "CREATE OR REPLACE FUNCTION public.prevent_role_change()\nRETURNS trigger\nLANGUAGE plpgsql\n"
                            "SET search_path = ''\nAS $$\nBEGIN\n  IF NEW.role IS DISTINCT FROM OLD.role\n"
                            "     AND current_user <> 'service_role' THEN\n"
                            "    RAISE EXCEPTION 'role cannot be changed by clients';\n  END IF;\n  RETURN NEW;\nEND;\n$$;\n\n"
                            "CREATE TRIGGER profiles_prevent_role_change\nBEFORE UPDATE ON public.profiles\n"
                            "FOR EACH ROW EXECUTE FUNCTION public.prevent_role_change();"},
        references=DB_REFS + ["https://cwe.mitre.org/data/definitions/269.html"],
        project_check=_privileged_column_update),
    Rule(
        id="CW-SQL-RLS-005", title="RLS write policy does not verify access to the parent record",
        category="Database Access Control", cwe="CWE-639", owasp="A01:2021 Broken Access Control",
        severity="Medium", confidence="Medium", languages=["sql"],
        description="INSERT/UPDATE policies check only the new row's owner column; the foreign key that links the row "
                    "to a parent (project, task, organisation) is not validated against the caller's access.",
        impact="Users can attach records to resources owned by others (e.g. inject tasks or comments into another "
               "user's project), polluting data and enabling spam, phishing content or confused-deputy issues.",
        recommendation="Add a membership/ownership check on the parent in WITH CHECK (and USING for updates).",
        secure_code={"sql": "DROP POLICY IF EXISTS \"Users can create tasks\" ON public.items;\n"
                            "CREATE POLICY \"Users can create tasks in own projects\"\nON public.items\nFOR INSERT\n"
                            "TO authenticated\nWITH CHECK (\n  owner_id = (SELECT auth.uid())\n  AND EXISTS (\n"
                            "    SELECT 1 FROM public.projects p\n    WHERE p.id = tasks.project_id\n"
                            "      AND p.owner_id = (SELECT auth.uid())\n  )\n);"},
        references=DB_REFS, project_check=_parent_not_checked),
    Rule(
        id="CW-SQL-RLS-006", title="Row Level Security not enabled on table",
        category="Database Access Control", cwe="CWE-284", owasp="A01:2021 Broken Access Control",
        severity="High", confidence="High", languages=["sql"],
        description="A table in the API-exposed schema has no Row Level Security.",
        impact="With Supabase/PostgREST, every row is readable and writable by any client holding the public anon key.",
        recommendation="Enable RLS and add explicit least-privilege policies.",
        secure_code={"sql": "ALTER TABLE public.my_table ENABLE ROW LEVEL SECURITY;"},
        references=DB_REFS, project_check=_rls_missing),
    Rule(
        id="CW-SQL-GRANT-001", title="Write privileges granted to anonymous/public role",
        category="Database Access Control", cwe="CWE-732", owasp="A01:2021 Broken Access Control",
        severity="High", confidence="High", languages=["sql"],
        description="GRANT gives INSERT/UPDATE/DELETE/ALL to `anon` or `public`.",
        impact="Unauthenticated clients may modify data (subject only to RLS, if enabled).",
        recommendation="Grant only the minimum privileges to authenticated roles.",
        secure_code={"sql": "REVOKE ALL ON public.my_table FROM anon, public;\nGRANT SELECT ON public.my_table TO authenticated;"},
        references=DB_REFS, project_check=_grants),
    Rule(
        id="CW-SQL-FUNC-001", title="SECURITY DEFINER function without fixed search_path",
        category="Database Access Control", cwe="CWE-427", owasp="A05:2021 Security Misconfiguration",
        severity="Medium", confidence="High", languages=["sql"],
        description="SECURITY DEFINER functions run with elevated privileges; without a fixed search_path, objects can "
                    "be shadowed by a malicious schema.",
        impact="Privilege escalation by hijacking unqualified function/table references.",
        recommendation="Add `SET search_path = ''` and schema-qualify all references.",
        secure_code={"sql": "CREATE OR REPLACE FUNCTION public.fn()\nRETURNS void\nLANGUAGE plpgsql\nSECURITY DEFINER\n"
                            "SET search_path = ''\nAS $$ BEGIN /* use public.table names */ END; $$;"},
        references=["https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY"],
        project_check=_secdef),
    Rule(
        id="CW-SQL-DYN-001", title="Dynamic SQL built by concatenation in database function",
        category="SQL Injection", cwe="CWE-89", owasp="A03:2021 Injection",
        severity="High", confidence="Medium", languages=["sql"],
        description="EXECUTE runs a statement assembled with || or format('%s').",
        impact="Function arguments can inject SQL that runs with the function's privileges.",
        recommendation="Use format() with %I/%L placeholders or EXECUTE ... USING parameters.",
        secure_code={"sql": "EXECUTE format('SELECT * FROM %I WHERE id = $1', tbl) USING row_id;"},
        references=["https://cwe.mitre.org/data/definitions/89.html"], project_check=_dynamic_sql),
]
