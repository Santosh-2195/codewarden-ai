"""Command-line interface.

    python -m codewarden scan <folder|zip|github-url> [--provider gemini] [--out reports]
    python -m codewarden serve            # local web UI on http://127.0.0.1:8765
    python -m codewarden rules [--markdown]
    python -m codewarden doctor
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __tool_name__, __version__
from .ai.providers import DEFAULT_MODELS, KEY_ENV, PROVIDERS, LLMClient, ProviderError, check_provider, detect_provider, env_key
from .collector import InputError
from .models import SEVERITIES, SEV_RANK

COLORS = {"Critical": "\033[1;31m", "High": "\033[31m", "Medium": "\033[33m", "Low": "\033[36m", "Info": "\033[37m"}
RESET = "\033[0m"


def _enable_ansi() -> bool:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        os.system("")  # enables VT100 escape processing on Windows 10+ consoles
    return True


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env loader (no dependency). Existing environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        v = v.strip().strip('"').strip("'")
        if k and v and k not in os.environ:
            os.environ[k] = v


def _safe_print(msg: str) -> None:
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"), flush=True)


def cmd_scan(args) -> int:
    from .pipeline import ScanOptions, run_scan
    from .report import write_reports

    color = _enable_ansi()
    provider = args.provider
    if provider == "auto":
        provider = detect_provider()
        if not provider:
            _safe_print("No AI provider configured (no API key found). Running in rules-only mode.\n"
                        "  For the full AI review set e.g. GEMINI_API_KEY in a .env file, or use --provider ollama.")
            provider = "none"
    opts = ScanOptions(provider=provider, model=args.model, max_files=args.max_files, workers=args.workers,
                       cache_dir=None if args.no_cache else Path(".codewarden/cache"), min_severity=args.min_severity,
                       project_name=args.project)
    _safe_print(f"{__tool_name__} v{__version__}")
    try:
        result = run_scan(args.target, opts, progress=lambda m: _safe_print("  " + m))
    except (InputError, ProviderError, ValueError) as exc:
        _safe_print(f"ERROR: {exc}")
        return 2
    import re as _re
    name = args.name or _re.sub(r"[^A-Za-z0-9_.-]+", "-", result.project).strip("-").lower() + "-security-report"
    paths = write_reports(result, Path(args.out), name, args.format.split(","))
    c = result.counts()
    _safe_print("")
    _safe_print(f"Risk rating: {result.summary.get('risk_rating')}   Findings: {len(result.findings)}   "
                + "  ".join(f"{s}: {c[s]}" for s in SEVERITIES if c[s]))
    _safe_print("-" * 78)
    for f in result.findings:
        sev = f"{COLORS[f.severity]}{f.severity:<8}{RESET}" if color else f"{f.severity:<8}"
        _safe_print(f"{f.id}  {sev}  {f.title[:60]}")
        _safe_print(f"         {f.primary.label()}  [{f.status}]")
    _safe_print("-" * 78)
    for p in paths:
        _safe_print(f"Report written: {p}")
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] <= threshold for f in result.findings):
            return 1
    return 0


def cmd_serve(args) -> int:
    from .server import serve
    return serve(args.host, args.port, open_browser=not args.no_browser)


def cmd_rules(args) -> int:
    from .rules import ALL_RULES
    if args.markdown:
        print("| Rule ID | Title | CWE | Default severity | Languages |\n|---|---|---|---|---|")
        for r in ALL_RULES:
            print(f"| `{r.id}` | {r.title} | {r.cwe} | {r.severity} | {', '.join(r.languages)} |")
    else:
        for r in ALL_RULES:
            print(f"{r.id:<20} {r.cwe:<9} {r.severity:<8} {r.title}")
        print(f"\n{len(ALL_RULES)} rules.")
    return 0


def cmd_doctor(args) -> int:
    print(f"{__tool_name__} v{__version__}  (Python {sys.version.split()[0]})")
    print("\nConfigured providers:")
    for p in PROVIDERS:
        names = KEY_ENV.get(p) or []
        has = bool(env_key(p)) or p in ("ollama",)
        mark = "yes" if env_key(p) else ("local" if p == "ollama" else "no")
        print(f"  {p:<18} key: {mark:<5} default model: {DEFAULT_MODELS[p]:<26} env: {', '.join(names) or '-'}")
    chosen = args.provider if args.provider != "auto" else detect_provider()
    if not chosen:
        print("\nNo API key found. Add one to .env (see .env.example) or run with --provider none / ollama.")
        return 1
    print(f"\nTesting {chosen} ...")
    try:
        client = LLMClient.create(chosen, args.model)
    except ProviderError as exc:
        print(f"  FAIL: {exc}")
        return 1
    ok, msg = check_provider(client)
    print(f"  {'OK' if ok else 'FAIL'}: {client.label} {'' if ok else msg}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="codewarden", description=f"{__tool_name__}: find, fix and fortify source code.")
    p.add_argument("--version", action="version", version=f"{__tool_name__} {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="analyse a folder, ZIP file or public GitHub URL")
    s.add_argument("target", help="path to a folder or .zip, or https://github.com/<owner>/<repo>")
    s.add_argument("--provider", default="auto", choices=["auto", "none"] + PROVIDERS,
                   help="AI provider (default: auto-detect from API keys; 'none' = rules only)")
    s.add_argument("--model", help="model name (default per provider, or CODEWARDEN_MODEL)")
    s.add_argument("--out", default="reports", help="output directory (default: reports)")
    s.add_argument("--name", help="report base file name (default: <project>-security-report)")
    s.add_argument("--project", help="display name of the application in the report (default: folder/repo name)")
    s.add_argument("--format", default="md,html,json,sarif", help="comma list of md,html,json,sarif")
    s.add_argument("--max-files", type=int, default=60, help="max files sent to the AI (highest risk first)")
    s.add_argument("--workers", type=int, default=3, help="parallel AI requests (lower for free tiers)")
    s.add_argument("--min-severity", default="Low", choices=SEVERITIES, help="hide findings below this severity")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit code 1 if a finding at/above this severity exists (CI)")
    s.add_argument("--no-cache", action="store_true", help="do not reuse cached AI responses")
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("serve", help="start the local web interface")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.add_argument("--no-browser", action="store_true")
    v.set_defaults(func=cmd_serve)

    r = sub.add_parser("rules", help="list detection rules")
    r.add_argument("--markdown", action="store_true")
    r.set_defaults(func=cmd_rules)

    d = sub.add_parser("doctor", help="check configuration and AI connectivity")
    d.add_argument("--provider", default="auto", choices=["auto"] + PROVIDERS)
    d.add_argument("--model")
    d.set_defaults(func=cmd_doctor)
    return p


def main(argv=None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
