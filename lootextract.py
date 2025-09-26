#!/usr/bin/env python3
"""
find_secrets_endpoints.py

Recursively search a codebase using grep for:
  - `-m/--mode secrets`   : likely hardcoded secrets/credentials/tokens
  - `-m/--mode endpoints` : URLs/domains/DB URIs/JDBCs and similar endpoints

Writes grep results to raw_output.txt, then (unless --raw) parses and cleans
into clean_output.json. You can also parse an existing raw file with --clean.

Examples
--------
# 1) Full run (grep -> raw_output.txt -> clean_output.json)
python find_secrets_endpoints.py -m secrets --dir .

# 2) Raw-only (just write raw_output.txt and stop)
python find_secrets_endpoints.py -m endpoints --dir ./src --raw

# 3) Parse/clean a previously produced raw file
python find_secrets_endpoints.py -m secrets --clean -i raw_output.txt

# 4) Limit scanned file types and customize outputs
python find_secrets_endpoints.py -m secrets --include-ext .py .env .yml -o secrets.json -r raw_secrets.txt
"""

from __future__ import annotations
import argparse
import datetime as _dt
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# =========================
# SETTINGS (mostly up top)
# =========================

# Where to search by default
DEFAULT_SEARCH_DIR = "."

# Default file names
DEFAULT_RAW_PATH = "raw_output.txt"
DEFAULT_CLEAN_PATH = "clean_output.json"

# Directories/files to exclude from grep recursion (feel free to extend)
EXCLUDE_DIRS = [
    ".git", ".hg", ".svn", ".idea", ".vscode", ".tox", ".mypy_cache", ".pytest_cache",
    "__pycache__", "node_modules", "dist", "build", "target", "vendor", ".venv", "venv",
    ".DS_Store", "coverage", "out", "bin", "obj", ".github", ".next", ".nuxt"
]

EXCLUDE_FILES = [
    "*.min.js", "*.map", "*.lock", "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
    "*.pdf", "*.psd", "*.zip", "*.tar", "*.gz", "*.7z", "*.tgz", "*.rar", "*.exe", "*.dll",
    "*.so", "*.dylib", "*.class", "*.jar", "*.war", "*.ear", "*.ttf", "*.woff", "*.woff2",
    "*.eot", "*.otf", "*.bin", "*.obj", "*.o", "*.a",".ser"
]

# Optional: limit grep to certain extensions (e.g., --include-ext .py .js .env)
# If empty, grep scans all text files (binary ignored via -I).
DEFAULT_INCLUDE_EXTS: List[str] = []

# Grep knobs
GREP_CASE_INSENSITIVE = True  # -i
GREP_USE_EXTENDED = True      # -E
GREP_IGNORE_BINARY = True     # -I
GREP_WITH_FILENAME = True     # -H
GREP_WITH_LINE_NUMBER = True  # -n
GREP_RECURSIVE = True         # -R
GREP_NO_COLOR = False          # --no-color

# Max context length stored in clean JSON (avoid monster lines)
MAX_CONTEXT_CHARS = 3000

# Heuristics: values to ignore as "not secrets"
NON_SECRET_SENTINELS = {
    "", "none", "null", "nil", "undefined", "notset", "n/a", "na",
    "true", "false", "yes", "no", "changeme", "change_me", "placeholder",
    "example", "sample", "test", "testing", "foobar", "password", "pass",
    "xxxxx", "******", "********", "redacted", "<redacted>", "todo"
}

# ---------------------------------------------
# Modes => (grep patterns, python extractors)
# ---------------------------------------------
# Grep patterns are intentionally broad to ensure recall; Python regex extractors
# then narrow down to the exact values and deduplicate.

# Broad grep patterns for "secrets" (case-insensitive with -i)
SECRETS_GREP_TERMS: List[str] = [
    r"password[[:space:]]*[:=]",
    r"passwd[[:space:]]*[:=]",
    r"pwd[[:space:]]*[:=]",
    r"passphrase[[:space:]]*[:=]",
    r"secret[[:space:]]*[:=]",
    r"api[ _-]?key[[:space:]]*[:=]",
    r"access[ _-]?key[[:space:]]*[:=]",
    r"client[ _-]?secret[[:space:]]*[:=]",
    r"auth[ _-]?token[[:space:]]*[:=]",
    r"token[[:space:]]*[:=]",
    r"authorization[[:space:]]*[:=]|authorization:[[:space:]]*bearer",
    # .env style variables
    r"[A-Z0-9_]*(PASSWORD|PASS|TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)[[:space:]]*=",
    # Specific secrets/markers
    r"(AKIA|ASIA)[0-9A-Z]{16}",
    r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID",
    r"gh[pousr]_[A-Za-z0-9]{36}",
    r"github_pat_[A-Za-z0-9_]{60,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",     # Slack tokens
    r"sk_(live|test)_[0-9A-Za-z]{24,}",  # Stripe
    r"AIza[0-9A-Za-z_\-]{35}",           # Google API key
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"ssh-(rsa|ed25519)[[:space:]]+[A-Za-z0-9+/=]+",
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",  # JWT-like
]

# Broad grep patterns for "endpoints"
ENDPOINTS_GREP_TERMS: List[str] = [
    r"http://", r"https://",
    r"jdbc:", r"r2dbc:", r"odbc:",
    r"s3://", r"gs://",
    r"redis://", r"amqp://", r"kafka://",
    r"mongodb://", r"mssql://", r"mysql://",
    r"postgres://", r"postgresql://", r"oracle://", r"redshift://", r"clickhouse://",
    r"blob\.core\.windows\.net", r"vault\.azure\.net", r"amazonaws\.com", r"snowflakecomputing\.com",
    r"va\.gov",
    # Domain-like endings to catch hostnames without schemes (keep list moderate to reduce noise)
    r"[A-Za-z0-9._-]+\.(com|net|org|io|gov|mil|edu|co|ai|dev|app|cloud|me|us|uk|de|fr|jp|in|br|ru|ch|nl|se|no|au|ca|es|it|pl)\b",
    # IPv4 hints
    r"([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{2,5})?",
]

# Python extractors: compile with named group (?P<val>...)
SECRETS_EXTRACTORS: List[re.Pattern] = [
    # Generic assignments: password/secret/token/etc.  x = "value"
    re.compile(r'(?i)\b(?:password|passwd|pwd|passphrase)\b\s*[:=]\s*["\']?(?P<val>[^"\',#\s]+[^"\',#\s])["\']?'),
    re.compile(r'(?i)\b(?:api[-_ ]?key|access[-_ ]?key|secret(?:[-_ ]?key)?|client[-_ ]?secret|private[-_ ]?key)\b\s*[:=]\s*["\']?(?P<val>[^\s,"\';#]+)["\']?'),
    # .env style
    re.compile(r'(?i)^\s*[A-Z0-9_]*(?:PASSWORD|PASS|TOKEN|SECRET|API(?:[_-]?KEY)?|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)\s*=\s*["\']?(?P<val>[^"\',#\r\n]+)'),
    # JSON style
    re.compile(r'(?i)"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"\s*:\s*"(?P<val>[^"]+)"'),
    # Authorization header (Bearer token)
    re.compile(r'(?i)\bauthorization\b\s*[:=]\s*(?:bearer\s+)?(?P<val>[A-Za-z0-9_\-\.=]+)'),
    # AWS Access Key ID / Secret Access Key
    re.compile(r'\b(?P<val>(?:AKIA|ASIA)[0-9A-Z]{16})\b'),
    re.compile(r'(?i)\baws_secret_access_key\b\s*[:=]\s*["\']?(?P<val>[A-Za-z0-9/+=]{40})["\']?'),
    re.compile(r'(?i)\baws_access_key_id\b\s*[:=]\s*["\']?(?P<val>(?:AKIA|ASIA)[0-9A-Z]{16})["\']?'),
    # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_) + PATs
    re.compile(r'\b(?P<val>gh[pousr]_[A-Za-z0-9]{36})\b'),
    re.compile(r'\b(?P<val>github_pat_[A-Za-z0-9_]{60,})\b'),
    # Slack
    re.compile(r'\b(?P<val>xox[baprs]-[A-Za-z0-9-]{10,})\b'),
    # Stripe
    re.compile(r'\b(?P<val>sk_(?:live|test)_[0-9A-Za-z]{24,})\b'),
    # Google API key
    re.compile(r'\b(?P<val>AIza[0-9A-Za-z_\-]{35})\b'),
    # JWT
    re.compile(r'\b(?P<val>eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b'),
    # PEM/SSH markers (we store the marker line as value)
    re.compile(r'(?P<val>-----BEGIN [A-Z ]*PRIVATE KEY-----)'),
    re.compile(r'(?P<val>ssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+(?:\s+\S+)?)'),
]

ENDPOINTS_EXTRACTORS: List[re.Pattern] = [
    re.compile(r'\b(?P<val>https?://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>jdbc:[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>r2dbc:[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>s3://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>gs://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>redis://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>amqp://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>kafka://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>mongodb://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>mssql://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>mysql://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>postgres(?:ql)?://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>oracle://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>redshift://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>clickhouse://[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>[A-Za-z0-9._-]+\.(?:com|net|org|io|gov|mil|edu|co|ai|dev|app|cloud|me|us|uk|de|fr|jp|in|br|ru|ch|nl|se|no|au|ca|es|it|pl)\b)'),
    re.compile(r'\b(?P<val>(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?)\b'),
    re.compile(r'\b(?P<val>[A-Za-z0-9-]+\.blob\.core\.windows\.net/[^\s"\'<>\)\]]+)'),
    re.compile(r'\b(?P<val>[A-Za-z0-9-]+\.vault\.azure\.net[^\s"\'<>\)\]]*)'),
    re.compile(r'\b(?P<val>[A-Za-z0-9.-]+\.amazonaws\.com[^\s"\'<>\)\]]*)'),
    re.compile(r'\b(?P<val>[A-Za-z0-9.-]*va\.gov[^\s"\'<>\)\]]*)'),
    re.compile(r'\b(?P<val>[A-Za-z0-9.-]+\.snowflakecomputing\.com[^\s"\'<>\)\]]*)'),
]

# Map modes to grep terms + extractors
MODES = {
    "secrets": {
        "grep_terms": SECRETS_GREP_TERMS,
        "extractors": SECRETS_EXTRACTORS,
    },
    "endpoints": {
        "grep_terms": ENDPOINTS_GREP_TERMS,
        "extractors": ENDPOINTS_EXTRACTORS,
    },
}


# =========================
# Utilities
# =========================

def _normalize_quotes_and_tail(s: str) -> str:
    """Trim whitespace, quotes, trailing commas/semicolons, and closing punctuation."""
    s = s.strip().strip("'").strip('"')
    s = re.sub(r'[;,]+$', '', s).strip()
    # Strip trailing ).]} if looks like it was part of inline syntax
    s = re.sub(r'[\)\]\}]+$', '', s).strip()
    return s


def _is_likely_secret_value(val: str) -> bool:
    v = val.strip().lower()
    if len(v) < 4:
        return False
    if v in NON_SECRET_SENTINELS:
        return False
    # Avoid obvious non-secret noise
    if v.startswith("http://") or v.startswith("https://"):
        return False
    return True


def _split_grep_line(line: str) -> Optional[Tuple[str, int, str]]:
    """
    Parse a grep -Hn output line: "file:line:content".
    We locate the first pattern ':<digits>:' to be robust even if file path contains ':'.
    """
    s = line.rstrip("\n")
    m = re.search(r':(\d+):', s)
    if not m:
        return None
    i1, i2 = m.span()
    file_path = s[:i1]
    try:
        line_no = int(m.group(1))
    except ValueError:
        return None
    content = s[i2:]
    return file_path, line_no, content


def _build_grep_command(
    mode: str,
    search_dir: str,
    include_exts: Sequence[str],
    exclude_dirs: Sequence[str],
    exclude_files: Sequence[str],
    raw_out: str,
) -> List[str]:
    """Construct the grep command arguments list."""
    terms = MODES[mode]["grep_terms"]
    args: List[str] = ["grep"]

    if GREP_RECURSIVE: args.append("-R")
    if GREP_IGNORE_BINARY: args.append("-I")
    if GREP_WITH_FILENAME: args.append("-H")
    if GREP_WITH_LINE_NUMBER: args.append("-n")
    if GREP_CASE_INSENSITIVE: args.append("-i")
    if GREP_USE_EXTENDED: args.append("-E")
    if GREP_NO_COLOR: args.append("--no-color")

    for d in exclude_dirs:
        args.extend(["--exclude-dir", d])
    for f in exclude_files:
        args.extend(["--exclude", f])

    # Include extension globs like --include=*.py
    for ext in include_exts:
        ext = ext.strip()
        if not ext:
            continue
        if not ext.startswith("*.") and not ext.startswith("."):
            # Allow bare "py" -> "*.py"
            ext = "*." + ext
        if ext.startswith("."):
            ext = "*" + ext
        args.append(f"--include={ext}")

    # Add all patterns with -e (safer than one mega-pattern)
    for pat in terms:
        args.extend(["-e", pat])

    args.append("--")  # end of options
    args.append(str(search_dir))
    return args


def run_grep_to_file(cmd: List[str], raw_path: Path) -> int:
    """
    Run grep and stream stdout to raw_path (text). Returns exit code.
    Note: grep exits with code 0 on matches, 1 on no matches, >1 on error.
    """
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # Locale C can speed grep a bit and avoid Unicode surprises
    env.setdefault("LC_ALL", "C")
    env.setdefault("LANG", "C")
    with raw_path.open("w", encoding="utf-8", errors="ignore") as out:
        proc = subprocess.run(
            cmd,
            stdout=out,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=env,
        )
    if proc.returncode > 1:
        sys.stderr.write(f"[!] grep error (code {proc.returncode}): {proc.stderr}\n")
    return proc.returncode


def parse_and_clean(
    raw_file: Path,
    mode: str,
) -> List[Dict[str, object]]:
    """Parse grep raw output and extract clean entries."""
    extractors: List[re.Pattern] = MODES[mode]["extractors"]
    results: List[Dict[str, object]] = []
    seen: set = set()

    with raw_file.open("r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            parsed = _split_grep_line(raw_line)
            if not parsed:
                continue
            file_path, line_no, context = parsed
            cleaned_context = context.strip()
            if len(cleaned_context) > MAX_CONTEXT_CHARS:
                cleaned_context = cleaned_context[:MAX_CONTEXT_CHARS] + " …"

            # Try each extractor; a single line can yield multiple values
            for rx in extractors:
                for m in rx.finditer(context):
                    val = m.groupdict().get("val") or m.group(0)
                    val = _normalize_quotes_and_tail(val)
                    if mode == "secrets" and not _is_likely_secret_value(val):
                        continue
                    key = (val, file_path, line_no)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "secret": val,                # requested field name
                        "context": cleaned_context,   # the line
                        "file": file_path,
                        "line": line_no,
                    })
    return results


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# =========================
# CLI
# =========================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="find_secrets_endpoints.py",
        description="Use grep to recursively find secrets or endpoints, then clean to JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-m", "--mode", choices=("secrets", "endpoints"), default="secrets",
                   help="Search mode (patterns & parsing differ per mode).")
    p.add_argument("--dir", dest="search_dir", default=DEFAULT_SEARCH_DIR,
                   help="Root directory to scan (only used when not --clean).")
    p.add_argument("--raw", action="store_true",
                   help="Only write raw_output.txt and stop (skip clean).")
    p.add_argument("--clean", action="store_true",
                   help="Skip grep and just parse/clean an input raw file.")
    p.add_argument("-i", "--input", dest="input_raw_file", default=None,
                   help="Raw grep output to clean (required with --clean).")
    p.add_argument("-r", "--raw-out", dest="raw_out", default=DEFAULT_RAW_PATH,
                   help="Path for raw grep output.")
    p.add_argument("-o", "--output", dest="clean_out", default=DEFAULT_CLEAN_PATH,
                   help="Path for clean JSON output.")
    p.add_argument("--include-ext", nargs="*", default=DEFAULT_INCLUDE_EXTS,
                   help="Optional file extensions to include (e.g., .py .env .yml).")
    p.add_argument("--exclude-dir", nargs="*", default=EXCLUDE_DIRS,
                   help="Directories to exclude from grep recursion.")
    p.add_argument("--exclude-file", nargs="*", default=EXCLUDE_FILES,
                   help="File globs to exclude from grep.")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    mode = args.mode

    # Sanity: --clean vs --raw
    if args.clean and args.raw:
        sys.stderr.write("[!] --clean and --raw are mutually exclusive.\n")
        return 2

    raw_path = Path(args.raw_out)
    clean_path = Path(args.clean_out)

    if args.clean:
        if not args.input_raw_file:
            sys.stderr.write("[!] --clean requires -i/--input RAW_FILE\n")
            return 2
        raw_in = Path(args.input_raw_file)
        if not raw_in.exists():
            sys.stderr.write(f"[!] Input raw file not found: {raw_in}\n")
            return 2
        cleaned = parse_and_clean(raw_in, mode)
        write_json(clean_path, cleaned)
        print(f"[✓] Cleaned {len(cleaned)} entries -> {clean_path}")
        return 0

    # Otherwise run grep first
    grep_cmd = _build_grep_command(
        mode=mode,
        search_dir=args.search_dir,
        include_exts=args.include_ext,
        exclude_dirs=args.exclude_dir,
        exclude_files=args.exclude_file,
        raw_out=args.raw_out,
    )

    # Display the grep command for transparency
    printable = " ".join(shlex.quote(x) for x in grep_cmd)
    print(f"[i] Running:\n{printable}")
    rc = run_grep_to_file(grep_cmd, raw_path)
    if rc > 1:
        return rc  # grep error already reported
    matches_note = "matches" if rc == 0 else "no matches"
    print(f"[i] Grep finished ({matches_note}); raw -> {raw_path}")

    if args.raw:
        return 0  # stop after raw output

    # Parse/clean the fresh raw output
    cleaned = parse_and_clean(raw_path, mode)
    write_json(clean_path, cleaned)
    print(f"[✓] Cleaned {len(cleaned)} entries -> {clean_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
