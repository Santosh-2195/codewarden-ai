"""Measure CodeWarden's precision/recall on the NoteHub fixture (an app the rules were not written against).

Usage (from the repository root):
    python eval/run_eval.py                      # rules-only baseline
    python eval/run_eval.py --provider gemini    # full AI pipeline
Writes eval/RESULTS-<mode>.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codewarden.cli import load_dotenv  # noqa: E402
from codewarden.pipeline import ScanOptions, cwe_family, run_scan  # noqa: E402

BENCH = ROOT / "eval" / "benchmark"
TOLERANCE = 3


def locate(app: Path, file: str, contains: str) -> int:
    for i, line in enumerate((app / file).read_text(encoding="utf-8").splitlines(), start=1):
        if contains in line:
            return i
    raise SystemExit(f"ground truth marker not found: {file}: {contains}")


def cwe_match(a: str, b: str) -> bool:
    return a == b or cwe_family(a) == cwe_family(b)


def main() -> int:
    load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="none")
    ap.add_argument("--model")
    args = ap.parse_args()

    gt = json.loads((BENCH / "ground_truth.json").read_text(encoding="utf-8"))
    app = BENCH / gt["app"]
    vulns = [dict(v, line=locate(app, v["file"], v["contains"])) for v in gt["vulnerabilities"]]
    decoys = [dict(d, line=locate(app, d["file"], d["contains"])) for d in gt["decoys"]]

    result = run_scan(str(app), ScanOptions(provider=args.provider, model=args.model, cache_dir=ROOT / ".codewarden" / "cache"))
    matched, fps, decoy_hits = set(), [], []
    for f in result.findings:
        hit = False
        for loc in f.locations:
            for v in vulns:
                if loc.file == v["file"] and abs(loc.start_line - v["line"]) <= TOLERANCE and cwe_match(f.cwe, v["cwe"]):
                    matched.add(v["id"])
                    hit = True
        if not hit:
            fps.append(f)
            for d in decoys:
                if any(l.file == d["file"] and abs(l.start_line - d["line"]) <= 1 for l in f.locations):
                    decoy_hits.append((f, d))

    tp = len(matched)
    total = len(vulns)
    precision = tp / max(1, tp + len(fps))
    recall = tp / total
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    pattern = [v for v in vulns if v["kind"] == "pattern"]
    logic = [v for v in vulns if v["kind"] == "logic"]
    mode = "rules-only" if args.provider == "none" else result.ai_label.replace(":", "_").replace("/", "_")

    lines = [f"# CodeWarden evaluation on NoteHub ({mode})", "",
             f"Ground truth: {total} vulnerabilities ({len(pattern)} pattern, {len(logic)} logic) and {len(decoys)} safe decoys.", "",
             "| Metric | Value |", "|---|---:|",
             f"| Findings reported | {len(result.findings)} |",
             f"| True positives (vulnerabilities found) | {tp} / {total} |",
             f"| Pattern vulnerabilities found | {len([v for v in pattern if v['id'] in matched])} / {len(pattern)} |",
             f"| Logic vulnerabilities found | {len([v for v in logic if v['id'] in matched])} / {len(logic)} |",
             f"| Findings not matching ground truth | {len(fps)} |",
             f"| Decoys wrongly flagged | {len(decoy_hits)} / {len(decoys)} |",
             f"| Precision | {precision:.0%} |", f"| Recall | {recall:.0%} |", f"| F1 | {f1:.2f} |", "",
             "## Missed", ""]
    lines += [f"- {v['id']} {v['cwe']} {v['file']}:{v['line']} ({v['kind']})" for v in vulns if v["id"] not in matched] or ["- none"]
    lines += ["", "## Unmatched findings (review: false positive or valid extra)", ""]
    lines += [f"- {f.id} {f.severity} {f.cwe} {f.primary.label()} - {f.title}" for f in fps] or ["- none"]
    out = ROOT / "eval" / f"RESULTS-{mode}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWritten: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
