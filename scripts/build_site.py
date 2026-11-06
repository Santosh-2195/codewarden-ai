"""Copy the latest sample report into the static Netlify site (site/).

    python scripts/build_site.py

Uses reports/sample-report.* (the AI-generated report) when present, otherwise the
rules-only baseline in reports/baseline-rules-only/.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
CANDIDATES = [
    (ROOT / "reports", "sample-report"),
    (ROOT / "reports" / "baseline-rules-only", "taskflow-rules-only"),
]


def main() -> int:
    for folder, base in CANDIDATES:
        html = folder / f"{base}.html"
        if html.exists():
            break
    else:
        print("No report found. Run a scan first (see README).")
        return 1
    (SITE / "downloads").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(html, SITE / "report.html")
    for ext in ("md", "json", "sarif"):
        src = folder / f"{base}.{ext}"
        if src.exists():
            shutil.copyfile(src, SITE / "downloads" / f"sample-report.{ext}")
    baseline = ROOT / "reports" / "baseline-rules-only" / "taskflow-rules-only.html"
    if baseline.exists():
        shutil.copyfile(baseline, SITE / "baseline-report.html")
    print(f"Site updated from {html.relative_to(ROOT)}")
    print("  site/report.html, site/baseline-report.html, site/downloads/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
