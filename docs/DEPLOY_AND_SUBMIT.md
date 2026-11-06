# Runbook: Generate, Commit, Push, Deploy (Windows cmd)

Every command below is for **Windows cmd**. Run them in order. "You should see" tells you what success looks like.

---

## Step 1 - Unpack the project

```bat
cd %USERPROFILE%
tar -xf %USERPROFILE%\Downloads\codewarden-ai.zip -C %USERPROFILE%
cd %USERPROFILE%\codewarden-ai
dir
```

You should see: `codewarden`, `docs`, `eval`, `reports`, `site`, `tests`, `vulnerable-app`, `README.md`, `netlify.toml`.

## Step 2 - Check Python and run the tests

```bat
python --version
python -m unittest discover -s tests
```

You should see: `Python 3.9` or newer, then `Ran 29 tests ... OK`.

## Step 3 - Add your AI key

```bat
copy .env.example .env
notepad .env
```

Put your key after the matching name, e.g. `GEMINI_API_KEY=AIza...`, save, close Notepad.

```bat
python -m codewarden doctor
```

You should see: `OK: gemini:gemini-flash-latest` (or your provider). If you see "model not found", add
`CODEWARDEN_MODEL=<a model your account lists>` to `.env` and run `doctor` again.

## Step 4 - Generate the AI sample report (the submission report)

```bat
python -m codewarden scan vulnerable-app --project "CDF TaskFlow" --out reports --name sample-report --workers 1
```

You should see: progress lines (`[AI 1/13] ...`), a findings list, and four `Report written: reports\sample-report.*`
lines. Open it:

```bat
start reports\sample-report.html
```

Check: the "AI model" line shows your model (not "rules-only"), and the Methodology table shows AI requests > 0.
If any line says `AI request(s) failed`, just run the same scan command again; successful answers are cached and
only the failed files are retried.

## Step 5 - Run the benchmark with AI

```bat
python eval\run_eval.py --provider gemini
```

(Use your provider name.) You should see a metrics table; it writes `eval\RESULTS-<model>.md`.

## Step 6 - Build the website folder

```bat
python scripts\build_site.py
```

You should see: `Site updated from reports\sample-report.html`.

## Step 7 - Create the GitHub repository

On github.com: **New repository** -> name `codewarden-ai` -> **Public** -> do **not** add README/.gitignore/license
-> Create.

## Step 8 - Commit in logical chunks

```bat
git init
git branch -M main
git config user.name "Santosh Krishnan Venkatachalam"
git config user.email "YOUR_GITHUB_EMAIL"

git add .gitignore .env.example LICENSE requirements.txt
git commit -m "chore: project scaffolding, license and environment template"

git add codewarden/__init__.py codewarden/__main__.py codewarden/models.py codewarden/collector.py
git commit -m "feat: core data models and safe folder/ZIP/GitHub input collector"

git add codewarden/rules/__init__.py codewarden/rules/base.py codewarden/rules/secrets.py codewarden/rules/javascript.py codewarden/rules/python_rules.py
git commit -m "feat: generic rule engine for secrets, JS/TS and Python vulnerabilities"

git add codewarden/rules/sql_model.py codewarden/rules/sql_rules.py
git commit -m "feat: PostgreSQL/Supabase schema model and RLS access-control rules"

git add codewarden/ai
git commit -m "feat: AI layer - stdlib LLM providers, review prompts, triage and synthesis"

git add codewarden/pipeline.py
git commit -m "feat: scan pipeline with evidence grounding, merging and de-duplication"

git add codewarden/report
git commit -m "feat: security reports in Markdown, HTML, JSON and SARIF"

git add codewarden/cli.py codewarden/server.py codewarden/web
git commit -m "feat: command-line interface and hardened local web UI"

git add tests
git commit -m "test: rule, collector, server and end-to-end pipeline tests"

git add eval
git commit -m "test: NoteHub benchmark with ground truth and evaluation script"

git add vulnerable-app
git commit -m "chore: add CDF TaskFlow sample application (provided by organisers)"

git add reports
git commit -m "docs: AI-generated sample security report and rules-only baseline"

git add docs README.md
git commit -m "docs: README, architecture, rule catalog, demo script and runbook"

git add .github
git commit -m "ci: run tests, sample scan and benchmark on every push"

git add site netlify.toml scripts
git commit -m "feat: static showcase site for Netlify"

git status
```

You should see after `git status`: `nothing to commit, working tree clean`.
**Check that `.env` is not listed anywhere** (it is git-ignored). Confirm with:

```bat
git ls-files | findstr /i ".env"
```

You should see only `.env.example`.

## Step 9 - Push

```bat
git remote add origin https://github.com/Santosh-2195/codewarden-ai.git
git push -u origin main
```

You should see: `branch 'main' set up to track 'origin/main'`. Open the repo page; the README renders and the
**Actions** tab shows the CI run turning green within about a minute.

## Step 10 - Deploy the site to Netlify

```bat
npm install -g netlify-cli
netlify --version
netlify login
netlify deploy --prod --dir=site
```

When asked: **Create & configure a new project** -> your team -> project name `codewarden-ai` (pick another if
taken). You should see: `Deployed to production URL: https://codewarden-ai.netlify.app` (or your name). Open
`<url>/report.html` to check the sample report.

## Step 11 - Fill in the placeholders and push again

```bat
notepad README.md
```

Replace `https://REPLACE-WITH-NETLIFY-SITE.netlify.app` with your Netlify URL. Also in `site\index.html` the GitHub
links already point at `https://github.com/Santosh-2195/codewarden-ai`; change them if your repo name differs.

```bat
git add README.md site/index.html
git commit -m "docs: add live site link"
git push
netlify deploy --prod --dir=site
```

## Step 12 - Record the demo, then add the link

Follow `docs\DEMO_SCRIPT.md`. After uploading to YouTube (Unlisted):

```bat
notepad README.md
git add README.md
git commit -m "docs: add demo video link"
git push
```

## Step 13 - Submit

Use `docs\SUBMISSION_CHECKLIST.md`, then fill in the organisers' form with: repository URL, demo video URL, sample
report URL (`https://github.com/Santosh-2195/codewarden-ai/blob/main/reports/sample-report.md` and the Netlify
`report.html`), and setup instructions (README section 1).

---

### Troubleshooting

| Symptom | Fix |
|---|---|
| `python` not found | Install Python 3.12 from python.org and tick "Add python.exe to PATH", or use `py` instead of `python`. |
| `HTTP 429` / rate limit | Add `--workers 1`; re-run (cached answers are reused). |
| `rejected the API key` | Re-copy the key into `.env` with no quotes or spaces. |
| `model not found` | Set `CODEWARDEN_MODEL` in `.env` to a model your account can use. |
| Push rejected (`fetch first`) | The GitHub repo was created with a README. Run `git pull origin main --allow-unrelated-histories`, then push. |
| Port 8765 in use | `python -m codewarden serve --port 8766` |
