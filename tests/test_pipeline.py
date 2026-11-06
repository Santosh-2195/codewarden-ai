"""End-to-end pipeline tests using a deterministic fake LLM (no network)."""
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from codewarden.ai import providers
from codewarden.pipeline import ScanOptions, ground_line, run_scan
from codewarden.models import SourceFile
from codewarden.report import to_json, to_markdown, to_sarif
from codewarden.report.html import to_html

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "vulnerable-app"


def fake_complete(self, system, user, max_tokens=8000):
    if "executive sections" in system:
        ids = re.findall(r'"id": "(CW-\d{3})"', user)
        return json.dumps({
            "executive_summary": f"Fake summary referencing {ids[0]}.",
            "risk_rating": "Low",  # deliberately inconsistent: pipeline must correct it upward
            "overall_assessment": "Systemic missing authorisation.",
            "attack_chains": [{"title": "Chain", "finding_ids": [ids[0], "CW-999"], "narrative": "Step 1, step 2."}],
            "prioritized_actions": [{"action": "Add auth", "finding_ids": [ids[0]], "effort": "Low"}],
            "positive_observations": ["RLS is enabled on every table."],
        })
    m = re.search(r"<candidates>.*?\n(\[.*?\]|\(none\))\n</candidates>", user, re.S)
    cands = json.loads(m.group(1)) if m and m.group(1).startswith("[") else []
    path = re.search(r'<untrusted_source path="([^"]+)"', user).group(1)
    reviews, findings = [], []
    for c in cands:
        if c["rule"] == "CW-JS-CORS-001":
            reviews.append({"candidate_id": c["candidate_id"], "verdict": "false_positive", "reason": "bearer tokens only"})
            continue
        reviews.append({"candidate_id": c["candidate_id"], "verdict": "confirmed", "severity": c["severity"], "reason": "ok"})
        findings.append({"candidate_id": c["candidate_id"], "title": "AI: " + c["title"], "severity": c["severity"],
                         "status": "Confirmed", "confidence": "High", "description": "AI tailored description of the issue.",
                         "impact": "AI tailored impact statement.", "recommendation": "AI tailored recommendation text.",
                         "secure_code": "// fixed code", "validation_notes": ""})
    if path.endswith("get-profile/index.ts"):
        findings.append({"candidate_id": None, "title": "Profile lookup trusts userId parameter", "cwe": "CWE-639",
                         "category": "Broken Access Control", "severity": "High", "status": "Confirmed",
                         "start_line": 99, "end_line": 99,  # wrong line on purpose -> must be relocated
                         "evidence": 'const userId = url.searchParams.get("userId");',
                         "description": "Any caller can read any profile.", "impact": "IDOR", "recommendation": "Use auth.uid()"})
        findings.append({"candidate_id": None, "title": "Hallucinated eval", "cwe": "CWE-95", "severity": "Critical",
                         "start_line": 5000, "evidence": "eval(userInput)", "description": "does not exist"})
    return json.dumps({"candidate_reviews": reviews, "findings": findings, "file_summary": "fake"})


class PipelineWithFakeAI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.object(providers.LLMClient, "complete", fake_complete):
            cls.result = run_scan(str(APP), ScanOptions(provider="ollama", cache_dir=None, project_name="TaskFlow"))

    def test_ai_enabled(self):
        self.assertTrue(self.result.ai_enabled)
        self.assertEqual(self.result.metrics.ai_errors, 0)

    def test_false_positive_rejected(self):
        self.assertFalse(any(f.rule_id == "CW-JS-CORS-001" for f in self.result.findings))
        self.assertGreaterEqual(self.result.metrics.ai_rejected, 1)

    def test_hallucination_dropped(self):
        self.assertFalse(any("Hallucinated" in f.title for f in self.result.findings))
        self.assertGreaterEqual(self.result.metrics.grounding_dropped, 1)

    def test_new_finding_grounded_or_merged(self):
        # the IDOR finding either merges into the access-control rule finding (same root cause) or is relocated to line 14
        profile = [f for f in self.result.findings if f.primary.file.endswith("get-profile/index.ts")
                   and f.cwe in ("CWE-862", "CWE-639")]
        self.assertEqual(len(profile), 1, "same root cause must not be reported twice")
        lines = {l.start_line for l in profile[0].locations}
        self.assertTrue(14 in lines or 23 in lines)

    def test_ai_text_applied(self):
        sqli = next(f for f in self.result.findings if f.cwe == "CWE-89")
        self.assertEqual(sqli.source, "rule+ai")
        self.assertTrue(sqli.title.startswith("AI: "))

    def test_summary_sanitised(self):
        s = self.result.summary
        self.assertEqual(s["generated_by"], "ai")
        self.assertEqual(s["risk_rating"], "Critical")  # corrected to match evidence
        self.assertNotIn("CW-999", s["attack_chains"][0]["finding_ids"])

    def test_reports_render(self):
        md, html, js, sarif = (to_markdown(self.result), to_html(self.result), to_json(self.result), to_sarif(self.result))
        self.assertIn("## 2. Executive Summary", md)
        self.assertIn("<details", html)
        self.assertEqual(json.loads(sarif)["version"], "2.1.0")
        self.assertEqual(len(json.loads(js)["findings"]), len(self.result.findings))


class Grounding(unittest.TestCase):
    def setUp(self):
        self.f = SourceFile("a.ts", "typescript", "const a = 1;\nconst b = req.query.x;\nrun(b);\n")

    def test_exact_match_relocates(self):
        s, e, verified, relocated = ground_line({"evidence": "const b = req.query.x;", "start_line": 3}, self.f)
        self.assertEqual((s, verified, relocated), (2, True, True))

    def test_unknown_evidence_out_of_range_dropped(self):
        self.assertIsNone(ground_line({"evidence": "nothing like this", "start_line": 40}, self.f))

    def test_prefix_stripped(self):
        s, *_ = ground_line({"evidence": "2 | const b = req.query.x;"}, self.f)
        self.assertEqual(s, 2)


class XssSafeReport(unittest.TestCase):
    def test_html_escapes_repository_content(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "src"
            p.mkdir()
            (p / "x.tsx").write_text('export const X = (c) => <div dangerouslySetInnerHTML={{ __html: c.text }} />;\n'
                                     '// </pre><script>alert(1)</script>\n', encoding="utf-8")
            r = run_scan(d, ScanOptions(provider="none", cache_dir=None))
            html = to_html(r)
            self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()
