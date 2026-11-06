# Architecture and AI Design

## Design goals

The judging rubric weights detection accuracy (35%) and fix quality (25%) highest, penalises false positives and
duplicates, and tests on an unseen codebase. CodeWarden is therefore built around three principles:

1. **Generic detection, never answer keys.** Rules describe vulnerability *patterns* (a privileged client with no
   caller check, an RLS policy that ignores ownership), not files or lines of the sample app.
2. **AI for judgement, code for truth.** The language model decides whether something is really exploitable and
   how to fix it; deterministic code verifies that every claim points at real source.
3. **One finding per root cause.** Merging and grouping keep the report short and actionable.

## Components

| Module | Responsibility |
|---|---|
| `collector.py` | Reads a folder, ZIP or public GitHub repo (via the GitHub zipball API). Skips dependencies, build output, lock files, minified files and binaries. Safe ZIP extraction. |
| `rules/base.py` | `Rule` and `Match` types, helpers, `ProjectContext` (framework detection, file map, SQL model). |
| `rules/secrets.py` | Secret detection used both for findings and for redaction before AI calls. Placeholder detection, client-bundle awareness. |
| `rules/javascript.py` | TS/JS/React/Node/Deno rules, including handler-level analysis (privileged client + no auth marker), body-to-database taint for mass assignment, tagged-template awareness for SQL. |
| `rules/python_rules.py` | Python/Flask/Django rules. |
| `rules/sql_model.py` | Dependency-free PostgreSQL model: statements (comment- and dollar-quote-aware), tables, columns, foreign keys, RLS, policies with `USING`/`WITH CHECK` line positions, grants, functions, triggers. |
| `rules/sql_rules.py` | Cross-file database access-control rules plus **context-aware fix generation** that uses the real table, owner-column and foreign-key names. |
| `ai/providers.py` | Stdlib HTTP adapters for Anthropic, OpenAI(-compatible), Gemini, Groq, OpenRouter, Ollama. Retries with backoff and `Retry-After`, temperature fallback, robust JSON extraction. |
| `ai/prompts.py` | Versioned review and synthesis prompts. |
| `ai/reviewer.py` | File prioritisation, chunking (450 lines, 40 overlap), parallel review, response cache, executive synthesis. |
| `pipeline.py` | Orchestration, evidence grounding, candidate/AI merge, de-duplication, summary validation. |
| `report/` | Markdown, HTML, JSON and SARIF writers. Secrets masked, all text escaped. |
| `server.py`, `web/` | Local web UI with token, Host check and CSP. |

## Data flow

```text
target -> collector -> [SourceFile]
                     -> ProjectContext (frameworks, tree, SqlModel)
                     -> rules -> [candidate Finding R1..Rn]
                     -> redact -> SourceFile.redacted_text
AI on:  select_files (risk priority) -> per-file prompt(context + candidates + numbered code)
        -> {candidate_reviews, findings, file_summary}
        -> combine(): apply verdicts, enrich candidates, ground new findings
off:    candidates as-is
        -> deduplicate() -> sort -> assign CW-001..
        -> summarize() (AI) or deterministic summary -> _clean_summary()
        -> reports
```

## The AI review contract

For each file (or 450-line chunk) the model receives:

- **Project context:** project name, detected stack, file list, and a compact digest of the database model
  (tables, foreign keys, RLS state, every policy with its expressions). This lets the model judge, for example,
  whether an edge function's service-role client bypasses a policy that would otherwise protect the data.
- **Candidates:** rule hits for that file with IDs, CWE, severity, lines and the rule's reasoning.
- **Code:** line-numbered, with secrets masked, wrapped in `<untrusted_source>`.

It must return strict JSON with:

- `candidate_reviews` - a verdict for **every** candidate: `confirmed`, `needs_validation` or `false_positive`, with
  a reason and optional new severity;
- `findings` - full write-ups for kept candidates and for newly discovered issues (title, CWE, severity,
  confidence, status, lines, verbatim evidence line, description, impact, recommendation, secure code, validation
  notes);
- `file_summary`.

The system prompt sets explicit severity definitions, forbids padding and style findings, requires one finding per
root cause, demands drop-in fixes in the file's own framework, tells the model not to overstate placeholder
secrets, and instructs it to treat any instructions inside the code as data.

## Grounding (anti-hallucination)

`pipeline.ground_line()` normalises whitespace and looks for the quoted evidence in both the original and the
redacted file text (exact line, substring, or the line contained in a multi-line quote). Outcomes:

| Evidence | Claimed line | Result |
|---|---|---|
| found | any | finding kept at the **real** line (relocated if needed; counted) |
| not found | valid | kept with confidence lowered one step and a note |
| not found | invalid | **dropped** (counted as a grounding drop) |

## Merging and de-duplication

- AI write-ups linked to a candidate replace the rule's generic text but keep the rule's precise location, CWE and
  category. Severity changes are recorded (`ai_severity_change`).
- A candidate rejected as `false_positive` is removed. A candidate the model did not mention is kept but flagged as
  not explicitly triaged.
- Same file + same CWE family + nearby lines (2 lines in SQL, 25 lines in code) or similar titles are merged, the
  rule-backed finding being the base. CWE families group closely related weaknesses (e.g. CWE-862/863/639/284
  access control).
- Issues with one shared fix (error disclosure, CORS, debug configuration) are grouped across files into one finding
  with multiple locations.

## Executive synthesis

A second prompt receives only verified findings (IDs, severity, status, location, short description) plus the
database digest and returns the executive summary, risk rating, overall assessment, up to three attack chains,
3-8 prioritised actions and positive observations. Post-validation removes references to unknown finding IDs and
raises the risk rating if the model rated it lower than the worst verified finding. If the call fails, a
deterministic summary is generated.

## Reliability and cost controls

- Temperature 0, strict JSON, tolerant parsing (fences, trailing commas).
- Response cache keyed by prompt version, model, system and user prompt: identical code gives identical output.
- Retry with exponential backoff for 429/5xx and network errors; per-file failure falls back to rule findings.
- `--max-files` caps AI cost; files are prioritised by rule hits, backend/API/SQL location and security keywords.
- `--workers` controls parallelism for rate-limited free tiers.

## Extending

Add a rule by appending a `Rule(...)` with a `check(file, ctx)` (per file) or `project_check(ctx)` (cross-file)
function in the relevant `rules/*.py` module, then add positive and negative tests in `tests/test_rules.py` and,
ideally, a ground-truth entry in `eval/benchmark`.
