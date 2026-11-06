"""Unit tests for the generic rule engine, input collection and local server hardening."""
import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from codewarden.collector import safe_extract_zip
from codewarden.models import SourceFile
from codewarden.rules import ProjectContext, run_rules
from codewarden.rules.secrets import redact


def scan(files):
    sfs = [SourceFile(p, lang, text) for p, lang, text in files]
    return run_rules(sfs, ProjectContext(sfs))


def ids(findings):
    return {f.rule_id for f in findings}


class JavaScriptRules(unittest.TestCase):
    def test_sqli_template_literal_with_request_input(self):
        code = ("const q = url.searchParams.get('q');\n"
                "const query = `SELECT * FROM t WHERE name = '${q}'`;\n"
                "await sql.unsafe(query);\n")
        f = scan([("api/search.ts", "typescript", code)])
        sqli = [x for x in f if x.rule_id == "CW-JS-SQLI-001"]
        self.assertEqual(len(sqli), 1)
        self.assertEqual(sqli[0].severity, "Critical")
        self.assertEqual(sqli[0].primary.start_line, 2)

    def test_tagged_template_is_safe(self):
        code = "const q = req.query.q;\nconst rows = await sql`SELECT * FROM t WHERE name = ${q}`;\n"
        self.assertNotIn("CW-JS-SQLI-001", ids(scan([("api/s.ts", "typescript", code)])))

    def test_dangerous_html(self):
        bad = "<div dangerouslySetInnerHTML={{ __html: comment.text }} />"
        safe = "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.text) }} />"
        self.assertIn("CW-JS-XSS-001", ids(scan([("src/a.tsx", "typescript", bad)])))
        self.assertNotIn("CW-JS-XSS-001", ids(scan([("src/b.tsx", "typescript", safe)])))

    def test_service_role_without_auth(self):
        code = ("Deno.serve(async (req) => {\n  const body = await req.json();\n"
                "  const s = createClient(Deno.env.get('URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n"
                "  await s.from('t').update(body.changes).eq('id', body.id);\n});\n")
        f = scan([("supabase/functions/x/index.ts", "typescript", code)])
        authz = [x for x in f if x.rule_id == "CW-JS-AUTHZ-001"]
        self.assertEqual(authz[0].severity, "Critical")
        self.assertIn("CW-JS-MASS-001", ids(f))

    def test_service_role_with_auth_check_not_flagged(self):
        code = ("Deno.serve(async (req) => {\n  const { data: { user } } = await anon.auth.getUser();\n"
                "  const s = createClient(u, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n});\n")
        self.assertNotIn("CW-JS-AUTHZ-001", ids(scan([("functions/x.ts", "typescript", code)])))

    def test_error_leak_and_cors(self):
        code = ("const h = {'Access-Control-Allow-Origin': '*'};\n"
                "try {} catch (error) {\n  return Response.json({ error: String(error) }, { status: 500 });\n}\n")
        f = ids(scan([("api/x.ts", "typescript", code)]))
        self.assertIn("CW-JS-ERRLEAK-001", f)
        self.assertIn("CW-JS-CORS-001", f)

    def test_console_logging_error_is_fine(self):
        code = "try {} catch (error) {\n  console.error('failed', error.message);\n  return Response.json({ error: 'failed' });\n}\n"
        self.assertNotIn("CW-JS-ERRLEAK-001", ids(scan([("api/x.ts", "typescript", code)])))


class SecretRules(unittest.TestCase):
    def test_placeholder_secret_is_downgraded(self):
        f = scan([("src/config.ts", "typescript", 'export const c = { apiKey: "demo_private_key_NOT_REAL_123" };\n')])
        s = [x for x in f if x.rule_id == "CW-SECRET-001"][0]
        self.assertEqual(s.severity, "Medium")
        self.assertEqual(s.status, "Needs validation")
        self.assertNotIn("NOT_REAL_123", s.primary.snippet)  # masked in evidence

    def test_provider_token_detected_and_redacted(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # built at runtime: no real-looking secret in git
        src = SourceFile("server/gh.py", "python", f'GITHUB = "{token}"\n')
        text, n = redact(src)
        self.assertEqual(n, 1)
        self.assertNotIn(token, text)

    def test_env_lookups_and_public_keys_ignored(self):
        code = ('const key = process.env.API_KEY;\nconst anonKey = "eyJhbGciOiJIUzI1NiJ9";\n'
                '<input type="password" placeholder="Password" />\n')
        self.assertNotIn("CW-SECRET-001", ids(scan([("src/a.tsx", "typescript", code)])))


class SqlRules(unittest.TestCase):
    SCHEMA = """
    CREATE TABLE public.profiles (id UUID PRIMARY KEY REFERENCES auth.users(id), name TEXT, role TEXT);
    CREATE TABLE public.docs (id UUID PRIMARY KEY, team_id UUID REFERENCES public.teams(id), owner_id UUID REFERENCES auth.users(id), body TEXT);
    CREATE TABLE public.teams (id UUID PRIMARY KEY, owner_id UUID REFERENCES auth.users(id));
    CREATE TABLE public.audit (id UUID PRIMARY KEY, msg TEXT);
    ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
    CREATE POLICY "read docs" ON public.docs FOR SELECT TO authenticated USING (true);
    CREATE POLICY "own profile" ON public.profiles FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());
    CREATE POLICY "add docs" ON public.docs FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
    CREATE POLICY "teams" ON public.teams FOR SELECT TO authenticated USING (owner_id = auth.uid());
    """

    def test_policy_rules(self):
        f = scan([("db/schema.sql", "sql", self.SCHEMA)])
        got = ids(f)
        for rid in ("CW-SQL-RLS-001", "CW-SQL-RLS-004", "CW-SQL-RLS-005", "CW-SQL-RLS-006"):
            self.assertIn(rid, got, rid)
        read = next(x for x in f if x.rule_id == "CW-SQL-RLS-001")
        self.assertEqual(read.severity, "High")
        self.assertIn("public.docs", read.secure_code)
        missing = next(x for x in f if x.rule_id == "CW-SQL-RLS-006")
        self.assertIn("audit", missing.title)

    def test_column_protection_suppresses_escalation(self):
        protected = self.SCHEMA + "\nREVOKE UPDATE ON public.profiles FROM authenticated;\n"
        self.assertNotIn("CW-SQL-RLS-004", ids(scan([("db/schema.sql", "sql", protected)])))


class PythonRules(unittest.TestCase):
    def test_python_patterns(self):
        code = ("import subprocess, pickle, yaml\n"
                "cur.execute(f\"SELECT * FROM u WHERE id = {request.args['id']}\")\n"
                "subprocess.run(cmd, shell=True)\n"
                "data = pickle.loads(blob)\n"
                "cfg = yaml.load(stream)\n"
                "app.run(debug=True)\n")
        got = ids(scan([("app.py", "python", code)]))
        for rid in ("CW-PY-SQLI-001", "CW-PY-CMDI-001", "CW-PY-DESER-001", "CW-PY-YAML-001", "CW-PY-DEBUG-001"):
            self.assertIn(rid, got, rid)

    def test_parameterised_query_not_flagged(self):
        code = "cur.execute(\"SELECT * FROM u WHERE id = %s\", (uid,))\ncfg = yaml.safe_load(s)\n"
        got = ids(scan([("app.py", "python", code)]))
        self.assertNotIn("CW-PY-SQLI-001", got)
        self.assertNotIn("CW-PY-YAML-001", got)


class ZipSafety(unittest.TestCase):
    def test_zip_slip_and_absolute_paths_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../evil.txt", "x")
            z.writestr("/abs.txt", "x")
            z.writestr("ok/app.ts", "const a = 1;")
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            dest.mkdir()
            safe_extract_zip(buf.getvalue(), dest)
            self.assertTrue((dest / "ok" / "app.ts").exists())
            self.assertFalse((Path(d) / "evil.txt").exists())
            self.assertEqual(sorted(p.name for p in dest.rglob("*") if p.is_file()), ["app.ts"])


class ServerHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        from codewarden import server
        cls.server_mod = server
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _get(self, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_api_requires_token(self):
        self.assertEqual(self._get("/api/config")[0], 403)
        code, body = self._get("/api/config", {"X-CW-Token": self.server_mod.TOKEN})
        self.assertEqual(code, 200)
        self.assertIn("providers", json.loads(body))

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self._get("/", {"Host": "attacker.example:80"})[0], 403)

    def test_index_served_with_csp(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertIn("frame-ancestors 'none'", r.headers.get("Content-Security-Policy"))


if __name__ == "__main__":
    unittest.main()
