"""Candidate rules for JavaScript / TypeScript (React, Node, Express, Deno, Supabase edge functions)."""
from __future__ import annotations

import re
from typing import List

from ..models import Location, SourceFile
from .base import Match, Rule, has_taint_source, is_comment, line_of_offset, regex_lines, window

JS = ["typescript", "javascript", "html"]

# ----------------------------------------------------------------- XSS

def _check_dangerous_html(f: SourceFile, ctx) -> List[Match]:
    out = []
    for m in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{", f.text):
        seg = f.text[m.end(): m.end() + 300]
        ln = line_of_offset(f.text, m.start())
        if is_comment(f.lines[ln - 1]):
            continue
        val = re.search(r"__html\s*:\s*([^}]+)", seg)
        value = val.group(1).strip().rstrip(",").strip() if val else ""
        if re.search(r"sanitize|DOMPurify|purify|xss\(|escape", seg, re.I):
            continue
        if re.fullmatch(r"([\"'`])[^$\"'`]*\1,?", value):
            continue  # static literal markup
        end = line_of_offset(f.text, m.end() + (val.end() if val else 0))
        snip = "\n".join(f.lines[ln - 1:end]).strip()
        note = f"The HTML comes from `{value[:80]}` and is inserted without sanitisation." if value else ""
        out.append(Match(ln, end, snip, note))
    return out


def _check_dom_sinks(f: SourceFile, ctx) -> List[Match]:
    pat = re.compile(
        r"\.(innerHTML|outerHTML)\s*\+?=\s*(?![\"'][^\"'$]*[\"']\s*;?\s*$)|"
        r"document\.write(ln)?\s*\(|\.insertAdjacentHTML\s*\(|\bv-html\s*=|\[innerHTML\]\s*=|"
        r"bypassSecurityTrust(Html|Script|Url|ResourceUrl)\s*\(|\$\([^)]*\)\.html\(\s*[^)\s]")
    safe = re.compile(r"sanitize|DOMPurify|escapeHtml|textContent|=\s*['\"]{2}\s*;?$")
    return list(regex_lines(f, pat, safe))


# ----------------------------------------------------------------- injection

SQL_KW = re.compile(r"\b(SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\s+[\w.\"]+\s+SET|DELETE\s+FROM)\b", re.I)


def _check_sql_injection(f: SourceFile, ctx) -> List[Match]:
    out = []
    text = f.text
    tainted = has_taint_source(text)
    unsafe_sink = re.search(r"\.unsafe\(|\$queryRawUnsafe|\$executeRawUnsafe|\.raw\(|\.query\(|\.execute\(|knex\.raw|sequelize\.query", text)
    for m in re.finditer(r"`(?:\\.|[^`\\])*`", text, re.S):
        lit = m.group(0)
        if "${" not in lit or not SQL_KW.search(lit):
            continue
        before = text[max(0, m.start() - 40):m.start()]
        if re.search(r"[\w.)\]]\s*$", before) and not re.search(r"(=|\(|,|return|:)\s*$", before):
            continue  # tagged template (e.g. sql`...`) -> parameterised by the driver
        interp = lit.index("${")
        ln = line_of_offset(text, m.start() + interp)
        start_ln = line_of_offset(text, m.start())
        sev = "Critical" if (tainted and unsafe_sink) else ("High" if tainted or unsafe_sink else "Medium")
        status = "Confirmed" if tainted and unsafe_sink else "Needs validation"
        note = ("User-controlled request input is present in this handler and the query is executed through a raw/unsafe "
                "API, so the interpolated value reaches the database unescaped." if status == "Confirmed" else
                "Confirm whether the interpolated value can be influenced by a user.")
        out.append(Match(ln, ln, f.lines[ln - 1].strip(), note, severity=sev, status=status,
                         confidence="High" if status == "Confirmed" else "Medium",
                         extra_locations=[] if start_ln == ln else []))
    concat = re.compile(r"(\"[^\"\n]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\"\n]*\"|"
                        r"'[^'\n]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^'\n]*')\s*\+\s*[A-Za-z_$]", re.I)
    for mt in regex_lines(f, concat):
        mt.severity = "High" if tainted else "Medium"
        out.append(mt)
    return out


def _check_cmd_injection(f: SourceFile, ctx) -> List[Match]:
    if not re.search(r"child_process|execa|shelljs|Deno\.Command|Deno\.run", f.text):
        return []
    pat = re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(`[^`]*\$\{|[^,)]*\+\s*\w)")
    pat2 = re.compile(r"\bshell\s*:\s*true")
    return list(regex_lines(f, pat)) + list(regex_lines(f, pat2))


def _check_eval(f: SourceFile, ctx) -> List[Match]:
    pat = re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bset(Timeout|Interval)\s*\(\s*[\"'`]")
    return list(regex_lines(f, pat))


def _check_path_traversal(f: SourceFile, ctx) -> List[Match]:
    pat = re.compile(r"(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|sendFile|download|"
                     r"Deno\.readTextFile|Deno\.readFile)\s*\([^)]*(req\.(params|query|body)|searchParams|params\.|\bfilename\b|\bfilePath\b)")
    safe = re.compile(r"basename\(|allowlist|allowed|whitelist")
    return list(regex_lines(f, pat, safe))


def _check_open_redirect(f: SourceFile, ctx) -> List[Match]:
    pat = re.compile(r"res\.redirect\(\s*(req\.(query|body|params)|[^)]*searchParams)|"
                     r"(window\.)?location(\.href)?\s*=\s*[^;]*(searchParams\.get|req\.query|params\.get)")
    return list(regex_lines(f, pat))


# ----------------------------------------------------------------- access control

AUTH_MARKERS = re.compile(
    r"auth\.getUser\(|getUser\(|getClaims\(|jwtVerify|jwt\.verify|verifyToken|verifyIdToken|requireAuth|"
    r"isAuthenticated|ensureAuth|passport\.authenticate|authMiddleware|withAuth|getServerSession|getSession\(|"
    r"currentUser|req\.user\b|ctx\.state\.user|headers\.get\(\s*[\"']authorization[\"']\s*\)", re.I)
HANDLER_MARKERS = re.compile(r"Deno\.serve\(|\bserve\(\s*async|export\s+(default\s+)?async\s+function\s+(handler|GET|POST|PUT|PATCH|DELETE)\b|"
                             r"\b(app|router)\.(get|post|put|patch|delete)\s*\(|exports\.handler|export\s+const\s+handler")
PRIVILEGED_CLIENT = re.compile(r"SERVICE_ROLE|service_role|serviceRole|ADMIN_KEY|admin\.firestore|firebase-admin")
DIRECT_DB = re.compile(r"\b(postgres|new\s+Pool|new\s+Client|createPool|mysql\.createConnection|new\s+PrismaClient)\s*\(")
WRITE_OPS = re.compile(r"\.(update|insert|upsert|delete)\s*\(|\b(UPDATE|INSERT|DELETE)\b")


def _check_handler_no_auth(f: SourceFile, ctx) -> List[Match]:
    text = f.text
    if not HANDLER_MARKERS.search(text) or AUTH_MARKERS.search(text):
        return []
    lines = f.lines
    priv = PRIVILEGED_CLIENT.search(text)
    direct = DIRECT_DB.search(text)
    if not priv and not direct:
        return []
    anchor = priv or direct
    ln = line_of_offset(text, anchor.start())
    # point at the client constructor line if the match is an argument
    for back in range(ln, max(0, ln - 4), -1):
        if re.search(r"createClient|postgres\(|Pool\(|Client\(", lines[back - 1]):
            ln = back
            break
    writes = bool(WRITE_OPS.search(text))
    takes_id = bool(re.search(r"(userId|user_id|taskId|id)\b", text)) and has_taint_source(text)
    if priv:
        sev = "Critical" if writes else "High"
        title = ("Privileged database client used without authenticating the caller "
                 f"({'write' if writes else 'read'} path bypasses Row Level Security)")
        note = ("The handler builds a client with a service-role/admin credential, which bypasses database access "
                "policies, and no caller authentication or ownership check was found in the file.")
        if takes_id:
            note += " Record identifiers are taken directly from the request, enabling insecure direct object references (IDOR)."
    else:
        sev = "High" if writes else "Medium"
        title = "Request handler queries the database directly without authenticating the caller"
        note = ("A direct database connection (typically a privileged role that is not subject to RLS) is used in a "
                "public request handler and no authentication check was found.")
    hl = handler_line(f)
    extra = [Location(f.path, hl, hl, lines[hl - 1].strip())] if hl and hl != ln else []
    return [Match(ln, ln, lines[ln - 1].strip(), note, severity=sev, title=title,
                  status="Confirmed" if priv else "Needs validation",
                  confidence="High" if priv else "Medium", extra_locations=extra)]


def handler_line(f: SourceFile) -> int:
    m = HANDLER_MARKERS.search(f.text)
    return line_of_offset(f.text, m.start()) if m else 0


def _check_mass_assignment(f: SourceFile, ctx) -> List[Match]:
    text = f.text
    if not re.search(r"request\.json\(\)|req\.body|await\s+\w+\.json\(\)|request\.get_json", text):
        return []
    body_vars = set(re.findall(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?\w*\.json\(\)", text))
    body_vars |= set(re.findall(r"(?:const|let|var)\s+(\w+)\s*=\s*req\.body\b", text))
    derived = set()
    for grp in re.findall(r"(?:const|let|var)\s*\{([\w\s,:]+)\}\s*=\s*(?:await\s+)?(?:\w*\.json\(\)|req\.body)", text):
        derived |= {v.split(":")[-1].strip() for v in grp.split(",") if v.strip()}
    for bv in body_vars:
        for name, _prop in re.findall(r"(?:const|let|var)\s+(\w+)\s*=\s*" + re.escape(bv) + r"\.(\w+)", text):
            derived.add(name)
        for grp in re.findall(r"(?:const|let|var)\s*\{([\w\s,:]+)\}\s*=\s*" + re.escape(bv) + r"\b", text):
            derived |= {v.split(":")[-1].strip() for v in grp.split(",") if v.strip()}
    candidates = body_vars | derived | {"req.body", "request.body"}
    out = []
    for i, line in enumerate(f.lines, start=1):
        if is_comment(line):
            continue
        m = re.search(r"\.(update|insert|upsert|create|updateOne|findOneAndUpdate|findByIdAndUpdate|assign)\s*\(\s*([\w.]+)\s*[,)]", line)
        if not m:
            m2 = re.search(r"Object\.assign\(\s*\w+\s*,\s*([\w.]+)\s*\)", line)
            if m2 and m2.group(1) in candidates:
                out.append(Match(i, i, line.strip()))
            continue
        arg = m.group(2)
        if arg in candidates or arg.startswith(("req.body", "body.")):
            out.append(Match(i, i, line.strip(),
                             f"`{arg}` comes straight from the request body and is written without an allow-list of fields."))
    return out


def _check_cors(f: SourceFile, ctx) -> List[Match]:
    pat = re.compile(r"[\"']Access-Control-Allow-Origin[\"']\s*[:,]\s*[\"']\*[\"']|"
                     r"Access-Control-Allow-Origin\s*[:=]\s*\"?\*|\bcors\(\s*\)|origin\s*:\s*(\"\*\"|'\*'|true)\b")
    matches = list(regex_lines(f, pat))
    if not matches:
        return []
    creds = re.search(r"Allow-Credentials[\"']?\s*[:,]\s*[\"']?true|credentials\s*:\s*true", f.text, re.I)
    for m in matches:
        if creds:
            m.severity = "High"
            m.note = "Credentials are also allowed, so authenticated cross-origin reads are possible."
        else:
            m.note = ("Any website can call this endpoint from a victim's browser. Impact is limited when authentication "
                      "relies on bearer tokens that other origins cannot read, but it widens the attack surface "
                      "(e.g. combined with missing authentication or token leakage).")
    return matches[:1]


def _check_error_leak(f: SourceFile, ctx) -> List[Match]:
    lines = f.lines
    out = []
    err = re.compile(r"String\(\s*(e|err|error|ex|exception)\s*\)|\b(e|err|error|ex)\.(message|stack)\b|"
                     r"details\s*:\s*(e|err|error)\b|JSON\.stringify\(\s*(e|err|error)\s*\)|\berror\s*:\s*(e|err|error)\s*[,}]")
    resp = re.compile(r"Response\.json|new\s+Response|res\.(json|send|status)|NextResponse|ctx\.body|reply\.send|\breturn\s+\{")
    for i, line in enumerate(lines, start=1):
        if is_comment(line) or re.search(r"console\.|logger\.|log\.(error|warn|info)", line):
            continue
        if err.search(line) and resp.search(window(lines, i, 5, 2)):
            if not re.search(r"(NODE_ENV|DEBUG|isDev|development)", window(lines, i, 4, 1)):
                out.append(Match(i, i, line.strip()))
    return out[:3]


def _check_insecure_random(f: SourceFile, ctx) -> List[Match]:
    pat = re.compile(r"(token|secret|password|passwd|nonce|otp|salt|session|apikey|api_key|reset|verification)\w*\s*[:=][^;\n]*Math\.random\(\)", re.I)
    return list(regex_lines(f, pat))


def _check_weak_hash(f: SourceFile, ctx) -> List[Match]:
    out = []
    for m in regex_lines(f, re.compile(r"createHash\(\s*[\"'](md5|sha1)[\"']|\bmd5\(|\bsha1\(", re.I)):
        if re.search(r"pass(word)?|pwd|secret|token", window(f.lines, m.start_line, 3, 3), re.I):
            out.append(m)
    return out


def _check_tls(f: SourceFile, ctx) -> List[Match]:
    return list(regex_lines(f, re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0")))


def _check_jwt(f: SourceFile, ctx) -> List[Match]:
    out = list(regex_lines(f, re.compile(r"algorithms\s*:\s*\[\s*[\"']none[\"']|ignoreExpiration\s*:\s*true", re.I)))
    if re.search(r"\bjwt\.decode\(", f.text) and not re.search(r"jwt\.verify\(|jwtVerify\(", f.text):
        out += list(regex_lines(f, re.compile(r"\bjwt\.decode\(")))
    return out


def _check_token_storage(f: SourceFile, ctx) -> List[Match]:
    return list(regex_lines(f, re.compile(r"localStorage\.setItem\(\s*[\"'`][^\"'`]*(token|jwt|auth|session|secret)", re.I)))


def _check_postmessage(f: SourceFile, ctx) -> List[Match]:
    return list(regex_lines(f, re.compile(r"postMessage\([^)]*,\s*[\"']\*[\"']\s*\)")))


def _check_debug_config(f: SourceFile, ctx) -> List[Match]:
    out = []
    lines = f.lines
    for i, line in enumerate(lines, start=1):
        if is_comment(line):
            continue
        if re.search(r"\bdebug\w*\s*[:=]\s*\{", line, re.I):
            block = window(lines, i, 0, 4)
            if re.search(r"enabled\s*:\s*true", block):
                end = i + next((k for k, l in enumerate(lines[i - 1:i + 4]) if re.search(r"enabled\s*:\s*true", l)), 0)
                out.append(Match(i, min(len(lines), end + 1), "\n".join(lines[i - 1:end + 2]).strip()))
        elif re.search(r"\b(debug|DEBUG)\s*[:=]\s*(true|True|1)\b", line) and not re.search(r"process\.env|NODE_ENV", line):
            out.append(Match(i, i, line.strip()))
    return out[:2]


RULES = [
    Rule(
        id="CW-JS-XSS-001", title="Cross-site scripting via dangerouslySetInnerHTML",
        category="Cross-Site Scripting (XSS)", cwe="CWE-79", owasp="A03:2021 Injection",
        severity="High", confidence="High", languages=["typescript", "javascript"], status="Confirmed",
        description="React's dangerouslySetInnerHTML renders a string as raw HTML, bypassing React's automatic output "
                    "escaping. When the string contains user-supplied content, attacker-controlled markup and script "
                    "handlers (e.g. <img src=x onerror=...>) execute in other users' browsers.",
        impact="Stored or reflected XSS lets an attacker run JavaScript as the victim: steal session tokens, perform "
               "actions on their behalf, deface the page or pivot to phishing.",
        recommendation="Render user content as text (React escapes it automatically). If limited formatting is truly "
                       "required, sanitise with a vetted library such as DOMPurify using a strict allow-list, and add a "
                       "Content-Security-Policy as defence in depth.",
        secure_code={
            "typescript": "// Preferred: render as plain text - React escapes it\n<p>{userContent}</p>\n\n"
                          "// Only if rich text is a real requirement:\nimport DOMPurify from \"dompurify\";\n\n"
                          "<div\n  dangerouslySetInnerHTML={{\n    __html: DOMPurify.sanitize(userContent, {\n"
                          "      ALLOWED_TAGS: [\"b\", \"i\", \"em\", \"strong\", \"a\"],\n      ALLOWED_ATTR: [\"href\"],\n    }),\n  }}\n/>",
        },
        references=["https://cwe.mitre.org/data/definitions/79.html",
                    "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"],
        check=_check_dangerous_html),
    Rule(
        id="CW-JS-XSS-002", title="Untrusted data written to an HTML sink",
        category="Cross-Site Scripting (XSS)", cwe="CWE-79", owasp="A03:2021 Injection",
        severity="High", confidence="Medium", languages=JS,
        description="A DOM API that parses HTML (innerHTML, outerHTML, document.write, insertAdjacentHTML, v-html, "
                    "jQuery .html(), Angular bypassSecurityTrust*) receives a non-constant value.",
        impact="If the value contains user input, injected markup or script executes in the user's browser.",
        recommendation="Use textContent / innerText or framework data binding for text. Sanitise with DOMPurify when HTML is required.",
        secure_code={"javascript": "element.textContent = userInput; // no HTML parsing\n// or\nelement.innerHTML = DOMPurify.sanitize(userInput);",
                     "typescript": "element.textContent = userInput; // no HTML parsing"},
        references=["https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"],
        check=_check_dom_sinks),
    Rule(
        id="CW-JS-SQLI-001", title="SQL injection via string-built query",
        category="SQL Injection", cwe="CWE-89", owasp="A03:2021 Injection",
        severity="High", confidence="Medium", languages=["typescript", "javascript"],
        description="A SQL statement is assembled with template-literal interpolation or string concatenation and then "
                    "executed. Interpolated values are spliced into the SQL text instead of being sent as bound parameters.",
        impact="An attacker can break out of the string literal and append their own SQL (e.g. `' UNION SELECT ... --`) "
               "to read or modify any data the database role can reach, bypass filters, or cause denial of service.",
        recommendation="Use parameterised queries / the driver's tagged-template API so values are always sent separately "
                       "from SQL. Never pass user-built strings to raw/unsafe execution APIs. Escape LIKE wildcards if "
                       "partial matching is needed, and validate input length/type.",
        secure_code={
            "typescript": "// postgres.js: the sql`` tag sends ${} values as bound parameters\n"
                          "const term = (url.searchParams.get(\"q\") ?? \"\").slice(0, 100);\n"
                          "const pattern = `%${term.replace(/[\\\\%_]/g, \"\\\\$&\")}%`;\n\n"
                          "const rows = await sql`\n  SELECT id, name\n  FROM public.items\n"
                          "  WHERE name ILIKE ${pattern}\n  LIMIT 25\n`;",
            "javascript": "// node-postgres\nconst { rows } = await pool.query(\n  \"SELECT * FROM users WHERE email = $1\",\n  [email]\n);",
        },
        references=["https://cwe.mitre.org/data/definitions/89.html",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
        check=_check_sql_injection),
    Rule(
        id="CW-JS-CMDI-001", title="OS command built from dynamic input",
        category="Command Injection", cwe="CWE-78", owasp="A03:2021 Injection",
        severity="High", confidence="Medium", languages=["typescript", "javascript"],
        description="A shell command is constructed with string concatenation/interpolation or executed with shell: true.",
        impact="Attacker-controlled input can inject shell metacharacters and run arbitrary commands on the server.",
        recommendation="Use execFile/spawn with an argument array and shell disabled; validate inputs against an allow-list.",
        secure_code={"javascript": "import { execFile } from \"node:child_process\";\nexecFile(\"convert\", [inputPath, outputPath], { shell: false }, cb);",
                     "typescript": "import { execFile } from \"node:child_process\";\nexecFile(\"convert\", [inputPath, outputPath], { shell: false }, cb);"},
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        check=_check_cmd_injection),
    Rule(
        id="CW-JS-EVAL-001", title="Dynamic code execution (eval / new Function)",
        category="Code Injection", cwe="CWE-95", owasp="A03:2021 Injection",
        severity="High", confidence="Medium", languages=JS,
        description="eval, new Function or string-based timers compile and run strings as code.",
        impact="If any part of the string is attacker-influenced, arbitrary JavaScript executes.",
        recommendation="Replace with explicit logic, JSON.parse for data, or a lookup table of allowed operations.",
        secure_code={"javascript": "const data = JSON.parse(jsonText); // data only, never code",
                     "typescript": "const data: unknown = JSON.parse(jsonText); // data only, never code"},
        references=["https://cwe.mitre.org/data/definitions/95.html"],
        check=_check_eval),
    Rule(
        id="CW-JS-PATH-001", title="File path built from request input",
        category="Path Traversal", cwe="CWE-22", owasp="A01:2021 Broken Access Control",
        severity="High", confidence="Medium", languages=["typescript", "javascript"],
        description="A file-system call uses a path derived from request data without constraining it to a base directory.",
        impact="`../` sequences can read or overwrite files outside the intended folder (configuration, keys, source).",
        recommendation="Map user choices to an allow-list of files, or resolve the path and verify it stays inside the base directory.",
        secure_code={"typescript": "const base = path.resolve(\"uploads\");\nconst target = path.resolve(base, path.basename(name));\n"
                                   "if (!target.startsWith(base + path.sep)) throw new Error(\"Invalid path\");"},
        references=["https://cwe.mitre.org/data/definitions/22.html"],
        check=_check_path_traversal),
    Rule(
        id="CW-JS-REDIRECT-001", title="Open redirect using request input",
        category="Open Redirect", cwe="CWE-601", owasp="A01:2021 Broken Access Control",
        severity="Medium", confidence="Medium", languages=JS,
        description="The application redirects to a URL taken from the request without validation.",
        impact="Attackers craft trusted-looking links that bounce victims to phishing pages.",
        recommendation="Redirect only to relative paths or an allow-list of hosts.",
        secure_code={"typescript": "const next = req.query.next as string;\nres.redirect(next?.startsWith(\"/\") && !next.startsWith(\"//\") ? next : \"/\");"},
        references=["https://cwe.mitre.org/data/definitions/601.html"],
        check=_check_open_redirect),
    Rule(
        id="CW-JS-AUTHZ-001", title="Privileged data access without authenticating the caller",
        category="Broken Access Control", cwe="CWE-862", owasp="A01:2021 Broken Access Control",
        severity="High", confidence="Medium", languages=["typescript", "javascript"],
        description="A server/edge request handler performs database operations with a privileged credential (service "
                    "role / admin key / direct DB connection) but never verifies who is calling or whether they own the "
                    "records they reference.",
        impact="Any unauthenticated user who can reach the endpoint can read or modify other users' data by supplying "
               "arbitrary identifiers; database Row Level Security is bypassed by the privileged credential.",
        recommendation="Authenticate every request (verify the JWT from the Authorization header), then either query with a "
                       "client scoped to the caller's token so RLS applies, or explicitly enforce ownership in the query. "
                       "Reserve service-role keys for trusted back-office jobs.",
        secure_code={
            "typescript": "import { createClient } from \"npm:@supabase/supabase-js@2\";\n\n"
                          "Deno.serve(async (req: Request) => {\n"
                          "  const authHeader = req.headers.get(\"Authorization\");\n"
                          "  if (!authHeader) return Response.json({ error: \"Unauthorized\" }, { status: 401 });\n\n"
                          "  // Client scoped to the caller's JWT -> Row Level Security is enforced\n"
                          "  const supabase = createClient(\n"
                          "    Deno.env.get(\"SUPABASE_URL\")!,\n"
                          "    Deno.env.get(\"SUPABASE_ANON_KEY\")!,\n"
                          "    { global: { headers: { Authorization: authHeader } } },\n  );\n\n"
                          "  const { data: { user }, error } = await supabase.auth.getUser();\n"
                          "  if (error || !user) return Response.json({ error: \"Unauthorized\" }, { status: 401 });\n\n"
                          "  // ...queries now run as `user` and are filtered by RLS policies\n});",
            "javascript": "app.get(\"/api/profile/:id\", requireAuth, async (req, res) => {\n"
                          "  if (req.params.id !== req.user.id) return res.sendStatus(403);\n  // ...\n});",
        },
        references=["https://cwe.mitre.org/data/definitions/862.html",
                    "https://supabase.com/docs/guides/functions/auth"],
        check=_check_handler_no_auth),
    Rule(
        id="CW-JS-MASS-001", title="Mass assignment: request body written to the database unfiltered",
        category="Mass Assignment", cwe="CWE-915", owasp="A08:2021 Software and Data Integrity Failures",
        severity="High", confidence="Medium", languages=["typescript", "javascript"],
        description="An object taken directly from the request body is passed to an update/insert call, so the client "
                    "decides which columns are written.",
        impact="Attackers can modify fields they should never control (ownership, role, status, foreign keys, "
               "timestamps), e.g. re-assigning a record to themselves or moving it into another tenant.",
        recommendation="Validate the payload with a schema and copy only an explicit allow-list of editable fields; "
                       "derive ownership and identifiers from the authenticated session, never from the body.",
        secure_code={
            "typescript": "// Copy only the fields a client may edit; never ids, owners or roles\n"
                          "const { id, changes } = await req.json();\n"
                          "const update: { name?: string; description?: string } = {};\n"
                          "if (typeof changes?.name === \"string\") update.name = changes.name.slice(0, 200);\n"
                          "if (typeof changes?.description === \"string\") update.description = changes.description.slice(0, 5000);\n"
                          "if (Object.keys(update).length === 0) {\n  return Response.json({ error: \"No valid fields\" }, { status: 400 });\n}\n\n"
                          "await supabase.from(\"items\").update(update).eq(\"id\", id); // user-scoped client so RLS applies",
        },
        references=["https://cwe.mitre.org/data/definitions/915.html",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
        check=_check_mass_assignment),
    Rule(
        id="CW-JS-CORS-001", title="Permissive CORS policy (Access-Control-Allow-Origin: *)",
        category="Security Misconfiguration", cwe="CWE-942", owasp="A05:2021 Security Misconfiguration",
        severity="Low", confidence="Medium", languages=["*"], group_across_files=True,
        description="The API allows requests from any origin.",
        impact="Any website can invoke the API from a visitor's browser and read responses. Severity rises sharply if "
               "credentials are allowed or the endpoint lacks authentication.",
        recommendation="Return an explicit allow-list of trusted origins and only echo the request Origin when it matches.",
        secure_code={"typescript": "const ALLOWED_ORIGINS = new Set([\"https://app.example.com\"]);\n"
                                   "const origin = req.headers.get(\"Origin\") ?? \"\";\n"
                                   "const corsHeaders = {\n  \"Access-Control-Allow-Origin\": ALLOWED_ORIGINS.has(origin) ? origin : \"\",\n"
                                   "  \"Vary\": \"Origin\",\n  \"Access-Control-Allow-Headers\": \"authorization, content-type\",\n"
                                   "  \"Access-Control-Allow-Methods\": \"POST, OPTIONS\",\n};"},
        references=["https://cwe.mitre.org/data/definitions/942.html"],
        check=_check_cors),
    Rule(
        id="CW-JS-ERRLEAK-001", title="Internal error details returned to the client",
        category="Information Disclosure", cwe="CWE-209", owasp="A05:2021 Security Misconfiguration",
        severity="Low", confidence="High", languages=["typescript", "javascript"], group_across_files=True,
        status="Confirmed",
        description="Raw exception text (database/driver messages, stack traces) is serialised into HTTP responses.",
        impact="Error messages reveal table/column names, constraint names, query fragments and infrastructure details "
               "that help attackers refine injection and access-control attacks.",
        recommendation="Log the full error server-side with a correlation ID and return a generic message to the client.",
        secure_code={"typescript": "} catch (error) {\n  const requestId = crypto.randomUUID();\n"
                                   "  console.error(`[${requestId}] request failed`, error);\n"
                                   "  return Response.json({ error: \"Internal error\", requestId }, { status: 500 });\n}"},
        references=["https://cwe.mitre.org/data/definitions/209.html"],
        check=_check_error_leak),
    Rule(
        id="CW-JS-RAND-001", title="Insecure randomness for security-sensitive value",
        category="Cryptographic Failures", cwe="CWE-338", owasp="A02:2021 Cryptographic Failures",
        severity="Medium", confidence="Medium", languages=JS,
        description="Math.random() is predictable and must not generate tokens, passwords, nonces or IDs used for security.",
        impact="Attackers can predict or brute-force generated values.",
        recommendation="Use crypto.randomUUID() or crypto.getRandomValues().",
        secure_code={"typescript": "const token = crypto.randomUUID();"},
        references=["https://cwe.mitre.org/data/definitions/338.html"],
        check=_check_insecure_random),
    Rule(
        id="CW-JS-HASH-001", title="Weak hash used for password or secret",
        category="Cryptographic Failures", cwe="CWE-328", owasp="A02:2021 Cryptographic Failures",
        severity="Medium", confidence="Medium", languages=JS,
        description="MD5/SHA-1 are fast, broken hashes unsuitable for passwords or secrets.",
        impact="Hashes can be cracked quickly offline after a database leak.",
        recommendation="Use bcrypt, scrypt or Argon2 for passwords; SHA-256+ HMAC for integrity.",
        secure_code={"typescript": "import bcrypt from \"bcrypt\";\nconst hash = await bcrypt.hash(password, 12);"},
        references=["https://cwe.mitre.org/data/definitions/328.html"],
        check=_check_weak_hash),
    Rule(
        id="CW-JS-TLS-001", title="TLS certificate validation disabled",
        category="Cryptographic Failures", cwe="CWE-295", owasp="A02:2021 Cryptographic Failures",
        severity="High", confidence="High", languages=["*"], status="Confirmed",
        description="Certificate verification is turned off for outbound TLS connections.",
        impact="Traffic can be intercepted and modified by anyone on the network path (man-in-the-middle).",
        recommendation="Keep verification on; trust a private CA explicitly via the `ca` option if required.",
        secure_code={"typescript": "https.request({ host, ca: fs.readFileSync(\"internal-ca.pem\") });"},
        references=["https://cwe.mitre.org/data/definitions/295.html"],
        check=_check_tls),
    Rule(
        id="CW-JS-JWT-001", title="JWT accepted without proper verification",
        category="Broken Authentication", cwe="CWE-347", owasp="A07:2021 Identification and Authentication Failures",
        severity="High", confidence="Medium", languages=["typescript", "javascript"],
        description="Tokens are decoded without signature verification, accept the `none` algorithm, or ignore expiry.",
        impact="Attackers can forge or replay tokens and impersonate any user.",
        recommendation="Always call jwt.verify with an explicit algorithm allow-list and keep expiry checks enabled.",
        secure_code={"typescript": "const claims = jwt.verify(token, publicKey, { algorithms: [\"RS256\"] });"},
        references=["https://cwe.mitre.org/data/definitions/347.html"],
        check=_check_jwt),
    Rule(
        id="CW-JS-STORAGE-001", title="Authentication token stored in localStorage",
        category="Sensitive Data Exposure", cwe="CWE-922", owasp="A04:2021 Insecure Design",
        severity="Low", confidence="Medium", languages=JS,
        description="Tokens in localStorage are readable by any script running on the origin.",
        impact="Any XSS immediately becomes account takeover by exfiltrating the token.",
        recommendation="Prefer HttpOnly, Secure, SameSite cookies for session tokens.",
        secure_code={"typescript": "// server: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/"},
        references=["https://cwe.mitre.org/data/definitions/922.html"],
        check=_check_token_storage),
    Rule(
        id="CW-JS-MSG-001", title="postMessage sent to any origin",
        category="Sensitive Data Exposure", cwe="CWE-345", owasp="A04:2021 Insecure Design",
        severity="Low", confidence="Medium", languages=JS,
        description="window.postMessage with target origin `*` delivers data to whatever page is loaded in the target window.",
        impact="Sensitive data may leak to a malicious frame/opener.",
        recommendation="Pass the exact expected origin as the second argument.",
        secure_code={"typescript": "target.postMessage(payload, \"https://app.example.com\");"},
        references=["https://cwe.mitre.org/data/definitions/345.html"],
        check=_check_postmessage),
    Rule(
        id="CW-CFG-DEBUG-001", title="Debug / verbose mode enabled in committed configuration",
        category="Security Misconfiguration", cwe="CWE-489", owasp="A05:2021 Security Misconfiguration",
        severity="Low", confidence="Medium", languages=["typescript", "javascript", "json", "yaml", "toml"],
        group_across_files=True,
        description="Debug features and verbose logging are hard-coded on rather than driven by the build environment.",
        impact="If shipped to production, verbose logs and debug paths can expose internal state, tokens or personal data "
               "in the browser console or server logs.",
        recommendation="Derive debug flags from the build mode (e.g. import.meta.env.DEV / NODE_ENV) so production builds "
                       "always disable them.",
        secure_code={"typescript": "export const appConfig = {\n  debug: {\n    enabled: import.meta.env.DEV, // false in production builds\n"
                                   "    logLevel: import.meta.env.DEV ? \"verbose\" : \"warn\",\n  },\n};"},
        references=["https://cwe.mitre.org/data/definitions/489.html"],
        check=_check_debug_config),
]
