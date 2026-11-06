# Demo Video Script (target 4:30, maximum 5:00)

Record with OBS Studio at 1920x1080, 30 fps. Scenes: (1) browser, (2) terminal (Windows cmd, font size 18+),
(3) VS Code. Close all other windows and **make sure no API key is visible on screen** (do not open `.env`).

## Before recording

```bat
cd %USERPROFILE%\codewarden-ai
python -m codewarden scan vulnerable-app --project "CDF TaskFlow" --out reports --name sample-report
```

Run it once beforehand so the AI responses are cached; during recording the scan then completes in seconds and
produces identical results. Then start the web UI in a second window: `python -m codewarden serve --no-browser`.

## Shot list

| Time | Scene | Show | Say (suggested) |
|---|---|---|---|
| 0:00-0:25 | Browser: Netlify landing page | Hero, "How a review runs" | "This is CodeWarden AI, an AI-assisted security reviewer built for the CDF CyberSec hackathon. It finds vulnerabilities, proves each one with the exact line of code, and gives a fix you can paste." |
| 0:25-0:55 | Terminal | `python -m codewarden doctor`, then `python -m codewarden rules` scrolling | "No packages to install, just Python. Doctor checks the AI connection. These are the 38 generic rules; none are written for TaskFlow, so the tool works on unseen code." |
| 0:55-1:40 | Browser: http://127.0.0.1:8765 | ZIP upload tab, drop `vulnerable-app.zip`, choose provider, name "CDF TaskFlow", Run. Point at the progress log lines: candidates, secrets masked, AI reviewing files | "I upload the sample app as a ZIP. Rules find candidates, secret values are masked before anything goes to the model, then the model reviews each file with the database schema and policies as context." |
| 1:40-2:40 | Browser: results | Rating box, severity bar, expand the SQL injection finding (evidence, impact, secure code), then the service-role finding, then the `role` privilege escalation finding | "Critical SQL injection: the search term is interpolated and run through sql.unsafe. The fix uses the tagged template so values are bound parameters. This edge function uses the service-role key without checking who is calling, so anyone can update any task. And here the AI and the policy analyser caught that users can update their own profile row including the role column, so anyone can make themselves admin; the fix revokes column updates and adds a trigger." |
| 2:40-3:10 | Browser: results | Expand the hard-coded key finding; point at "Needs validation" and the note | "It doesn't overstate things: the key in demoConfig is clearly fake, so it's reported as an insecure pattern, Medium, not a leaked production credential." |
| 3:10-4:00 | Browser: full HTML report | Executive summary, findings index, attack chains, remediation plan, methodology metrics table (rejected false positives, grounding drops, merged duplicates). Ctrl+P preview to show it prints as PDF | "The report has the executive summary, findings by severity with file and line, attack chains combining issues, a prioritised plan, and metrics showing what the AI contributed: false positives rejected, findings dropped because their evidence didn't exist, duplicates merged." |
| 4:00-4:20 | Terminal | `python eval\run_eval.py` output table | "To check generalisation and false positives I built a separate benchmark app with safe decoys, and the tool reports precision, recall and decoy hits." |
| 4:20-4:35 | VS Code | `reports/sample-report.md` and the SARIF file | "Reports come as HTML, Markdown, JSON and SARIF for GitHub code scanning. Thanks for watching." |

## After recording

1. Upload to YouTube as **Unlisted**, title "CodeWarden AI - CDF CyberSec Hackathon demo".
2. Paste the link into `README.md` (Demo video row) and the submission form.
3. Open the link in a private browser window to confirm it plays without signing in.
