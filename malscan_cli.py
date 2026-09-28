"""Command-line scanner.

    python malscan_cli.py suspicious.exe
    python malscan_cli.py C:\\some\\folder --recursive
    python malscan_cli.py file.exe --json

Useful for batch work and for checking the pipeline without the web interface.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malscan.scanner import ScanError, scan_path  # noqa: E402

COLORS = {
    "Malicious": "\033[91m", "Suspicious": "\033[93m", "Benign": "\033[92m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


# The default Windows console encoding is cp1252, which cannot represent the
# arrows and dashes used below -- printing them raised UnicodeEncodeError and
# killed the scan part-way through its own report. Ask for UTF-8, and if the
# stream refuses, fall back to ASCII rather than dying on a cosmetic detail.
_UNICODE_OK = True
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    _UNICODE_OK = False

UP, DOWN, DASH = (
    (chr(0x2191), chr(0x2193), chr(0x2014)) if _UNICODE_OK else ("+", "-", "-")
)


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _supports_color() else text


def scan_one(path: Path, args) -> dict | None:
    try:
        result = scan_path(path, save_history=not args.no_history)
    except ScanError as exc:
        print(f"  skipped {path.name}: {exc}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"  failed  {path.name}: {exc}", file=sys.stderr)
        return None

    if args.json:
        return {
            "file": str(path),
            "sha256": result.sha256,
            "size": result.size,
            "type": result.features_result.file_type.label,
            "verdict": result.verdict,
            "probability": round(result.probability, 6),
            "confidence": round(result.confidence, 6),
            "engine": result.prediction.engine,
            "rules": [m["name"] for m in result.rule_matches],
            "scan_ms": result.duration_ms,
            "top_factors": [
                {"feature": c.feature, "value": c.display_value,
                 "effect_points": round(c.contribution * 100, 2)}
                for c in result.contributions[:6]
            ],
        }

    color = COLORS.get(result.verdict, "")
    print(f"\n{BOLD if _supports_color() else ''}{path.name}{RESET if _supports_color() else ''}")
    print(f"  Verdict     : {_c(result.verdict, color)} "
          f"({result.probability * 100:.1f}% malicious, "
          f"{result.confidence * 100:.0f}% confidence)")
    print(f"  Type        : {result.features_result.file_type.label}")
    print(f"  Size        : {result.size:,} bytes")
    print(f"  SHA-256     : {result.sha256}")
    print(f"  Engine      : {result.prediction.engine} ({result.prediction.model_name})")
    print(f"  Scan time   : {result.duration_ms} ms")

    if result.rule_matches:
        print(f"  Rules       : {len(result.rule_matches)} matched")
        for m in result.rule_matches[:6]:
            print(f"      [sev {m['severity']}] {m['name']} {DASH} {m['description']}")

    if result.contributions and not args.quiet:
        print("  Top factors :")
        for c in result.contributions[:6]:
            arrow = UP if c.direction == "malicious" else DOWN
            print(f"      {arrow} {c.contribution * 100:+6.2f} pts  "
                  f"{c.description} = {c.display_value}")

    for w in result.warnings:
        print(f"  ! {w}")
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="MalScan AI command-line scanner")
    ap.add_argument("target", help="file or directory to scan")
    ap.add_argument("-r", "--recursive", action="store_true",
                    help="recurse into subdirectories")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="omit the per-feature breakdown")
    ap.add_argument("--no-history", action="store_true",
                    help="do not record results in the database")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        sys.exit(1)

    if target.is_file():
        targets = [target]
    else:
        pattern = "**/*" if args.recursive else "*"
        targets = sorted(p for p in target.glob(pattern) if p.is_file())
        if not targets:
            print(f"No files found in {target}", file=sys.stderr)
            sys.exit(1)
        if not args.json:
            print(f"Scanning {len(targets)} file(s) in {target}")

    results = []
    for path in targets:
        out = scan_one(path, args)
        if out:
            results.append(out)

    if args.json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2))
    elif len(targets) > 1:
        print(f"\nScanned {len(targets)} file(s).")


if __name__ == "__main__":
    main()
