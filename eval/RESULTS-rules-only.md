# CodeWarden evaluation on NoteHub (rules-only)

Ground truth: 23 vulnerabilities (22 pattern, 1 logic) and 7 safe decoys.

| Metric | Value |
|---|---:|
| Findings reported | 21 |
| True positives (vulnerabilities found) | 22 / 23 |
| Pattern vulnerabilities found | 22 / 22 |
| Logic vulnerabilities found | 0 / 1 |
| Findings not matching ground truth | 0 |
| Decoys wrongly flagged | 0 / 7 |
| Precision | 100% |
| Recall | 96% |
| F1 | 0.98 |

## Missed

- N3 CWE-639 server/routes/notes.js:19 (logic)

## Unmatched findings (review: false positive or valid extra)

- none
