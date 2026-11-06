# Reports

| File | What it is |
|---|---|
| `sample-report.html` / `.md` / `.json` / `.sarif` | **Submission sample report**: CodeWarden AI with the AI layer enabled, run on `vulnerable-app/` (CDF TaskFlow). Regenerate with `python -m codewarden scan vulnerable-app --project "CDF TaskFlow" --out reports --name sample-report`. |
| `baseline-rules-only/` | The same scan with `--provider none` (no AI). Compare the two to see what the AI layer adds: rejected false positives, severity recalibration, logic-flaw findings and tailored explanations and fixes. |
