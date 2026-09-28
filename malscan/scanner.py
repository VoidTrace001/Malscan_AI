"""The scan pipeline. This is the one function the UI actually calls.

Safety model
------------
The file stays in memory as a plain byte buffer and is parsed as data. It is
never written somewhere executable, never handed to a shell, never imported as
a library, never run. Everything is static analysis, so holding a real sample
here is about as risky as holding a photograph of one. The buffer goes away
when the scan returns.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from malscan.config import CONFIG
from malscan.features import FeatureResult, extract_features
from malscan.model.explain import Contribution, explain, narrative
from malscan.model.predict import Prediction, classify, get_classifier
from malscan.storage.history import get_history


class ScanError(Exception):
    """Raised when a file cannot be accepted for scanning."""


@dataclass
class ScanResult:
    filename: str
    features_result: FeatureResult
    prediction: Prediction
    contributions: list[Contribution]
    explanation: list[str]
    duration_ms: int
    scan_id: int | None = None
    warnings: list[str] = field(default_factory=list)

    # Convenience accessors so the UI does not reach through three layers.
    @property
    def verdict(self) -> str:
        return self.prediction.verdict

    @property
    def probability(self) -> float:
        return self.prediction.probability

    @property
    def confidence(self) -> float:
        return self.prediction.confidence

    @property
    def sha256(self) -> str:
        return self.features_result.hashes.get("sha256", "")

    @property
    def size(self) -> int:
        return self.features_result.size

    @property
    def rule_matches(self) -> list[dict]:
        return self.features_result.rule_matches

    @property
    def pe(self):
        return self.features_result.pe


def scan_bytes(
    data: bytes,
    filename: str = "uploaded_file",
    save_history: bool = True,
    threshold_malicious: float | None = None,
    threshold_suspicious: float | None = None,
) -> ScanResult:
    """Run the full static analysis pipeline over a byte buffer."""
    started = time.perf_counter()
    warnings: list[str] = []

    if not data:
        raise ScanError("The file is empty -- there is nothing to analyse.")

    max_bytes = CONFIG.max_upload_mb * 1024 * 1024
    if len(data) > max_bytes:
        raise ScanError(
            f"File is {len(data) / 1024 / 1024:.1f} MB, over the "
            f"{CONFIG.max_upload_mb} MB limit."
        )

    # 1. Static feature extraction (+ rule matching).
    result = extract_features(
        data,
        filename,
        run_rules=True,
        string_limit=CONFIG.string_scan_limit,
        min_string_len=CONFIG.min_string_len,
    )
    if len(data) > CONFIG.string_scan_limit:
        warnings.append(
            f"Only the first {CONFIG.string_scan_limit // (1024 * 1024)} MB were "
            "string-mined; structural analysis covered the whole file."
        )
    if result.file_type.is_pe and not result.pe.parsed:
        warnings.append(
            f"This file starts with a PE header but could not be fully parsed "
            f"({result.pe.error}). Structural features are unavailable, so the "
            "verdict leans on content signals alone."
        )
    elif not result.file_type.is_pe:
        warnings.append(
            f"This is not a Windows executable ({result.file_type.label}). "
            "The model was trained on PE structure, so PE-specific features are "
            "absent and the verdict rests on content and rule signals only -- "
            "treat it as weaker evidence."
        )

    # 2. Classify.
    classifier = get_classifier()
    prediction = classifier.predict(result.features)
    if threshold_malicious is not None or threshold_suspicious is not None:
        prediction.verdict = classify(
            prediction.probability, threshold_malicious, threshold_suspicious
        )
        if threshold_malicious is not None:
            prediction.threshold_malicious = threshold_malicious
        if threshold_suspicious is not None:
            prediction.threshold_suspicious = threshold_suspicious

    # 3. Explain.
    contributions = explain(classifier, result.features, engine=prediction.engine)
    explanation = narrative(contributions, prediction, result)

    duration_ms = int((time.perf_counter() - started) * 1000)

    scan = ScanResult(
        filename=filename,
        features_result=result,
        prediction=prediction,
        contributions=contributions,
        explanation=explanation,
        duration_ms=duration_ms,
        warnings=warnings,
    )

    # 4. Record.
    if save_history:
        try:
            scan.scan_id = get_history().add(scan)
        except Exception as exc:
            scan.warnings.append(f"Scan completed but could not be saved: {exc}")

    return scan


def scan_path(path, save_history: bool = True) -> ScanResult:
    """Scan a file from disk -- used by the CLI and by batch testing."""
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        raise ScanError(f"No such file: {p}")
    if p.is_dir():
        raise ScanError(f"{p} is a directory, not a file.")
    return scan_bytes(p.read_bytes(), p.name, save_history=save_history)
