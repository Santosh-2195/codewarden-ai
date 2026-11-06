# Submission Checklist

## Required deliverables (docs/SUBMISSION.md)

- [ ] Public GitHub repository URL works when signed out
- [ ] README explains setup, running, dependencies (none), AI integration, features and attribution
- [ ] Working tool: `python -m codewarden serve` and `python -m codewarden scan vulnerable-app` both run
- [ ] Demo video (3-5 min), YouTube Unlisted, opens in a private window
- [ ] Sample report generated **with AI enabled** for CDF TaskFlow: `reports/sample-report.{html,md,json,sarif}`
- [ ] Submission form completed

## Final checks (docs/INSTRUCTIONS.md section 11)

- [ ] Fresh clone + README steps work (test in a new folder: `git clone ... && python -m unittest discover -s tests`)
- [ ] AI functionality is demonstrable (report header shows the model; methodology table shows AI requests)
- [ ] Findings include file paths, line numbers and explanations
- [ ] Secure code recommendations present for each finding
- [ ] Downloadable report (HTML/Markdown) in the repo and on Netlify
- [ ] No real secrets: `git ls-files | findstr /i ".env"` shows only `.env.example`
- [ ] README placeholders replaced (Netlify URL, video URL)
- [ ] GitHub Actions CI is green

## Rubric mapping

| Criterion (weight) | Where the evidence is |
|---|---|
| Detection accuracy (35%) | Sample report findings with code evidence; `eval/RESULTS-*.md` (precision, recall, decoys); grounding and FP-rejection metrics in the report's Methodology section; generic rules in `docs/RULES.md` |
| Fix quality (25%) | "Secure code" for every finding, context-specific (real table/column names, same client library); root-cause recommendations |
| Report quality (20%) | Executive summary, severity grouping, index, locations, evidence, impact, fix, validation notes, attack chains, remediation plan, overall assessment, scope and limitations |
| Ease of use (10%) | Zero dependencies, `.env` auto-loading, `doctor` command, web UI with ZIP/folder/GitHub input, clear README |
| Effective use of AI (10%) | Triage verdicts, severity recalibration, logic-flaw discovery, tailored fixes, uncertainty labels, synthesis; documented in README section 7 and docs/ARCHITECTURE.md |

## Information for the form

- Project name: CodeWarden AI
- Repository: https://github.com/Santosh-2195/codewarden-ai
- Live site / sample report: https://<your-site>.netlify.app/report.html
- Demo video: https://youtu.be/<id>
- AI model used for the sample report: (copy from the report header)
- Setup: Python 3.9+, `copy .env.example .env`, add one API key, `python -m codewarden serve`
