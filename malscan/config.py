"""Paths, limits and thresholds.

All in one place so nothing else in the codebase has to hardcode a location or
invent a magic number.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Config:
    # --- paths -----------------------------------------------------------
    root: Path = ROOT
    model_dir: Path = ROOT / "models"
    data_dir: Path = ROOT / "data"
    sample_dir: Path = ROOT / "samples"
    rules_file: Path = ROOT / "malscan" / "rules" / "malscan_rules.yar"
    db_path: Path = ROOT / "data" / "malscan.db"
    dataset_path: Path = ROOT / "data" / "dataset.parquet"
    dataset_csv: Path = ROOT / "data" / "dataset.csv"
    model_path: Path = ROOT / "models" / "malscan_model.joblib"
    metrics_path: Path = ROOT / "models" / "metrics.json"

    # --- scanning limits -------------------------------------------------
    # Files are never executed. They are read into a temp buffer, analysed,
    # then deleted. This cap stops a huge upload from exhausting memory.
    max_upload_mb: int = 64
    # Only this many bytes are string-mined; enough for signal, bounded cost.
    string_scan_limit: int = 8 * 1024 * 1024
    min_string_len: int = 5

    # --- verdict thresholds ----------------------------------------------
    # Probability of the "malicious" class.
    threshold_malicious: float = 0.65
    threshold_suspicious: float = 0.40

    # --- entropy heuristics ----------------------------------------------
    high_entropy_cutoff: float = 7.0
    packed_entropy_cutoff: float = 7.4

    # --- training --------------------------------------------------------
    random_state: int = 42
    test_size: float = 0.2
    n_synthetic_per_class: int = 6000

    # Directories mined for *real* benign PE files to calibrate the benign
    # feature distribution. Missing directories are skipped silently.
    benign_source_dirs: tuple = field(
        default_factory=lambda: (
            Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32",
            Path(os.environ.get("SystemRoot", "C:/Windows")) / "SysWOW64",
            ROOT / ".venv",
        )
    )

    def ensure_dirs(self) -> None:
        for p in (self.model_dir, self.data_dir, self.sample_dir):
            p.mkdir(parents=True, exist_ok=True)


CONFIG = Config()
CONFIG.ensure_dirs()
