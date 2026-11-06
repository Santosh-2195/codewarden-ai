"""Collect source files from a local folder, a ZIP archive or a public GitHub URL.

Repository contents are treated strictly as untrusted *data*: nothing is executed,
archives are extracted with path-traversal and size guards, and symlinks are ignored.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import List, Optional, Tuple

from .models import SourceFile

LANG_BY_EXT = {
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".vue": "javascript", ".svelte": "javascript",
    ".py": "python",
    ".sql": "sql",
    ".java": "java", ".kt": "kotlin", ".go": "go", ".php": "php", ".rb": "ruby", ".cs": "csharp",
    ".html": "html", ".htm": "html",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".sh": "shell",
}
SPECIAL_NAMES = {
    "dockerfile": "docker",
    ".env": "env",
}
CONFIG_JSON_NAMES = {"firebase.json", "vercel.json", "netlify.json", "config.json", "appsettings.json"}

SKIP_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "dist", "build", "out", ".next", ".nuxt", "coverage",
    "__pycache__", ".venv", "venv", "env", "vendor", "target", ".cache", ".idea", ".vscode",
    ".turbo", ".parcel-cache", ".codewarden", "site-packages", "bower_components",
}
SKIP_FILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".d.ts", ".snap")

MAX_FILE_BYTES = 400_000
MAX_FILES = 3000
MAX_ZIP_TOTAL_BYTES = 200 * 1024 * 1024
MAX_ZIP_MEMBERS = 20000
MAX_DOWNLOAD_BYTES = 80 * 1024 * 1024

GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[^\s?#]+))?/?(?:[?#].*)?$"
)


class InputError(Exception):
    """Raised when the supplied target cannot be read."""


def detect_language(path: Path) -> Optional[str]:
    name = path.name.lower()
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    if name.startswith(".env"):
        # .env.local, .env.production ... but not .env.example templates
        if name.endswith((".example", ".sample", ".template")):
            return None
        return "env"
    if name in CONFIG_JSON_NAMES:
        return "json"
    if name in SKIP_FILE_NAMES or name.endswith(SKIP_SUFFIXES):
        return None
    return LANG_BY_EXT.get(path.suffix.lower())


def _read_text(path: Path) -> Optional[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None  # binary
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def collect_directory(root: Path, skipped: Optional[List[str]] = None) -> List[SourceFile]:
    files: List[SourceFile] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d in (".github",))
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            try:
                if fpath.is_symlink():
                    continue
                if fpath.stat().st_size > MAX_FILE_BYTES:
                    if skipped is not None:
                        skipped.append(f"{fpath.relative_to(root).as_posix()} (too large)")
                    continue
            except OSError:
                continue
            lang = detect_language(fpath)
            if not lang:
                continue
            text = _read_text(fpath)
            if text is None:
                continue
            rel = fpath.relative_to(root).as_posix()
            files.append(SourceFile(path=rel, language=lang, text=text))
            if len(files) >= MAX_FILES:
                if skipped is not None:
                    skipped.append(f"file limit of {MAX_FILES} reached; remaining files skipped")
                return files
    return files


def safe_extract_zip(data: bytes, dest: Path) -> None:
    """Extract a ZIP archive defensively (zip-slip, zip-bomb and symlink protection)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise InputError("The uploaded file is not a valid ZIP archive.") from exc
    members = zf.infolist()
    if len(members) > MAX_ZIP_MEMBERS:
        raise InputError(f"ZIP has too many entries ({len(members)} > {MAX_ZIP_MEMBERS}).")
    total = sum(m.file_size for m in members)
    if total > MAX_ZIP_TOTAL_BYTES:
        raise InputError("ZIP expands beyond the 200 MB safety limit.")
    dest = dest.resolve()
    for m in members:
        name = m.filename.replace("\\", "/")
        if not name or name.endswith("/"):
            continue
        mode = (m.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            continue  # never materialise symlinks from untrusted archives
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or re.match(r"^[A-Za-z]:", name):
            continue  # zip-slip attempt
        target = (dest / Path(*pure.parts)).resolve()
        if dest not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(m) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out, length=1024 * 1024)


def _single_top_dir(root: Path) -> Path:
    entries = [p for p in root.iterdir() if not p.name.startswith("__MACOSX")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def download_github(url: str) -> Tuple[str, bytes]:
    m = GITHUB_RE.match(url.strip())
    if not m:
        raise InputError("Only public https://github.com/<owner>/<repo> URLs are supported.")
    owner, repo, ref = m.group("owner"), m.group("repo"), m.group("ref")
    api = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    headers = {"User-Agent": "codewarden-ai", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(api, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            chunks, size = [], 0
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise InputError("Repository archive exceeds the 80 MB download limit.")
                chunks.append(chunk)
    except urllib.error.HTTPError as exc:
        raise InputError(f"GitHub download failed (HTTP {exc.code}). Is the repository public?") from exc
    except urllib.error.URLError as exc:
        raise InputError(f"GitHub download failed: {exc.reason}") from exc
    return repo, b"".join(chunks)


def load_target(target: str, skipped: Optional[List[str]] = None) -> Tuple[str, List[SourceFile], Optional[Path]]:
    """Return (project_name, files, temp_dir_to_cleanup)."""
    target = target.strip().strip('"')
    if target.lower().startswith(("http://", "https://")):
        name, data = download_github(target)
        tmp = Path(tempfile.mkdtemp(prefix="codewarden_"))
        safe_extract_zip(data, tmp)
        root = _single_top_dir(tmp)
        return name, collect_directory(root, skipped), tmp
    path = Path(target).expanduser()
    if not path.exists():
        raise InputError(f"Target not found: {target}")
    if path.is_file() and path.suffix.lower() == ".zip":
        tmp = Path(tempfile.mkdtemp(prefix="codewarden_"))
        safe_extract_zip(path.read_bytes(), tmp)
        root = _single_top_dir(tmp)
        name = path.stem
        return name, collect_directory(root, skipped), tmp
    if path.is_dir():
        return path.resolve().name, collect_directory(path, skipped), None
    raise InputError("Target must be a folder, a .zip file or a GitHub URL.")


def load_zip_bytes(data: bytes, name: str, skipped: Optional[List[str]] = None) -> Tuple[str, List[SourceFile], Path]:
    tmp = Path(tempfile.mkdtemp(prefix="codewarden_"))
    safe_extract_zip(data, tmp)
    root = _single_top_dir(tmp)
    return name, collect_directory(root, skipped), tmp
