"""Inference: feature vector in, verdict out.

The model is loaded once and cached. With no trained model on disk we fall
back to the heuristic scorer at the bottom of this file, so the app still
runs; it just says so on every verdict instead of pretending otherwise.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from malscan.config import CONFIG
from malscan.features.schema import FEATURE_NAMES, to_vector

VERDICT_MALICIOUS = "Malicious"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_BENIGN = "Benign"


@dataclass
class Prediction:
    probability: float             # P(malicious), 0..1
    verdict: str
    confidence: float              # how far from the undecided middle, 0..1
    model_name: str
    calibrated: bool = False
    engine: str = "model"          # "model" or "heuristic"
    threshold_malicious: float = CONFIG.threshold_malicious
    threshold_suspicious: float = CONFIG.threshold_suspicious
    notes: list[str] = field(default_factory=list)


def _score_single_threaded(model) -> None:
    """Pin a loaded estimator to single-threaded scoring.

    The forests are fitted with ``n_jobs=-1``, which is the right call for
    training. It is the wrong one for scoring: a scan classifies a single row,
    and the explainer at most 74, so joblib spends far longer standing up a
    worker pool than the trees take to traverse. Pinning it to one thread cuts
    a PE scan roughly in half.

    Purely an execution setting -- the predictions are identical either way.
    Anything whose shape we do not recognise is left untouched.
    """
    if model is None:
        return
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1
    # CalibratedClassifierCV keeps the real forest one level down, per fold.
    for fold in getattr(model, "calibrated_classifiers_", []):
        inner = getattr(fold, "estimator", None)
        if inner is not None and hasattr(inner, "n_jobs"):
            inner.n_jobs = 1


class Classifier:
    """Wraps the persisted model bundle."""

    def __init__(self, model_path: Path | None = None):
        self.model_path = Path(model_path or CONFIG.model_path)
        self.model = None
        self.raw_model = None
        self.model_name = "heuristic"
        self.calibrated = False
        self.trained_at = ""
        self.feature_names = FEATURE_NAMES
        self.baseline: dict = {}
        self.feature_importance: list[dict] = []
        self.load_error = ""
        self._load()

    # ------------------------------------------------------------------
    @property
    def is_trained(self) -> bool:
        return self.model is not None

    def _load(self) -> None:
        if not self.model_path.exists():
            self.load_error = "No trained model found -- using heuristic fallback"
            return
        try:
            import joblib

            bundle = joblib.load(self.model_path)
            self.model = bundle["model"]
            self.raw_model = bundle.get("raw_model", bundle["model"])
            self.model_name = bundle.get("model_name", "unknown")
            self.calibrated = bool(bundle.get("calibrated", False))
            self.trained_at = bundle.get("trained_at", "")
            self.feature_names = bundle.get("feature_names", FEATURE_NAMES)
            self.baseline = bundle.get("baseline", {}) or {}
            self.feature_importance = bundle.get("feature_importance", []) or []

            if self.feature_names != FEATURE_NAMES:
                self.model = None
                self.load_error = (
                    "Saved model was trained on a different feature schema "
                    f"({len(self.feature_names)} features vs {len(FEATURE_NAMES)} "
                    "now). Retrain from the Model page."
                )
                return

            _score_single_threaded(self.model)
            _score_single_threaded(self.raw_model)
        except Exception as exc:
            self.model = None
            self.load_error = f"Could not load model: {exc}"

        if not self.baseline:
            self._baseline_from_dataset()

    def _baseline_from_dataset(self) -> None:
        """Older bundles predate the stored baseline; recover it from the CSV."""
        if not CONFIG.dataset_csv.exists():
            return
        try:
            import pandas as pd

            df = pd.read_csv(CONFIG.dataset_csv, usecols=FEATURE_NAMES + ["label"])
            benign = df[df.label == 0][FEATURE_NAMES].to_numpy(dtype=float)
            malicious = df[df.label == 1][FEATURE_NAMES].to_numpy(dtype=float)
            if len(benign) and len(malicious):
                self.baseline = {
                    "benign_median": np.median(benign, axis=0).tolist(),
                    "benign_p10": np.percentile(benign, 10, axis=0).tolist(),
                    "benign_p90": np.percentile(benign, 90, axis=0).tolist(),
                    "malicious_median": np.median(malicious, axis=0).tolist(),
                }
        except Exception:
            pass

    # ------------------------------------------------------------------
    def predict_proba(self, features: dict[str, float]) -> float:
        vector = np.array([to_vector(features)], dtype=np.float32)
        if self.model is None:
            return _heuristic_score(features)
        return float(self.model.predict_proba(vector)[0, 1])

    def predict_batch(self, matrix: np.ndarray) -> np.ndarray:
        if self.model is None:
            return np.array([0.5] * len(matrix))
        return self.model.predict_proba(matrix)[:, 1]

    def predict(self, features: dict[str, float]) -> Prediction:
        notes: list[str] = []
        in_domain = pe_features_usable(features)

        if self.model is None:
            proba = _heuristic_score(features)
            engine, model_name, calibrated = "heuristic", "heuristic", False
            notes.append(
                "No trained model is loaded -- this score comes from a "
                "transparent heuristic, not machine learning."
            )
            if self.load_error:
                notes.append(self.load_error)
        elif in_domain:
            proba = self.predict_proba(features)
            engine, model_name, calibrated = "model", self.model_name, self.calibrated
        else:
            # Outside what the model was trained on, see _content_score.
            proba = _content_score(features)
            engine, model_name, calibrated = "content", "content heuristic", False
            notes.append(
                "There is no parsable PE structure here, and PE structure is "
                f"what the {self.model_name} model was trained on. Running it "
                "anyway would mean extrapolating well outside its training "
                "data, so this verdict comes from content signals instead: "
                "rule matches, string indicators and entropy."
            )

        verdict = classify(proba)

        # Distance from the undecided midpoint, rescaled so 0.5 -> 0% and
        # 0.0/1.0 -> 100%. Do not be tempted to show the raw probability as
        # confidence; a 50% score means we have no idea, not 50% sure.
        confidence = abs(proba - 0.5) * 2.0
        if engine != "model":
            # Fewer signals went into this, so the same distance from the
            # midpoint should not buy the same certainty.
            confidence *= 0.6

        return Prediction(
            probability=proba,
            verdict=verdict,
            confidence=confidence,
            model_name=model_name,
            calibrated=calibrated,
            engine=engine,
            notes=notes,
        )


def classify(
    proba: float,
    threshold_malicious: float | None = None,
    threshold_suspicious: float | None = None,
) -> str:
    """Three-way verdict.

    The middle band earns its keep. Forced into yes/no the model has to commit
    on files it cannot actually separate, and "someone should look at this" is
    a more useful answer than a confident coin flip.
    """
    tm = CONFIG.threshold_malicious if threshold_malicious is None else threshold_malicious
    ts = CONFIG.threshold_suspicious if threshold_suspicious is None else threshold_suspicious
    if proba >= tm:
        return VERDICT_MALICIOUS
    if proba >= ts:
        return VERDICT_SUSPICIOUS
    return VERDICT_BENIGN


# ----------------------------------------------------------------------
# Heuristic fallback
# ----------------------------------------------------------------------
# (feature, weight, value at which the signal counts as fully on). Kept
# simple on purpose. This is a stopgap for when no model is loaded, not an
# attempt to compete with one.
_HEURISTIC_RULES = [
    ("rule_max_severity", 0.28, 5.0),
    # Severity on its own under-reads a file that trips several rules:
    # four independent detections is a stronger signal than one, even when
    # the worst of the four is no worse.
    ("rule_hits", 0.16, 5.0),
    ("imp_suspicious_ratio", 0.14, 0.35),
    ("sec_entropy_max", 0.10, 7.9),
    ("str_suspicious_kw", 0.10, 15.0),
    ("packer_hit", 0.08, 1.0),
    ("sec_wx_count", 0.07, 2.0),
    ("imp_dynamic_resolution", 0.06, 1.0),
    ("imp_table_sparse", 0.06, 1.0),
    ("str_embedded_mz", 0.05, 2.0),
    ("overlay_ratio", 0.04, 0.6),
    ("sec_zero_raw_count", 0.04, 2.0),
]


def _heuristic_score(features: dict[str, float]) -> float:
    score = 0.0
    for name, weight, full_scale in _HEURISTIC_RULES:
        value = float(features.get(name, 0.0))
        score += weight * min(1.0, value / full_scale) if full_scale else 0.0
    # Signed metadata and a valid checksum are mild exculpatory evidence.
    if features.get("pe_has_signature"):
        score -= 0.10
    if features.get("pe_has_version_info"):
        score -= 0.04
    return float(min(1.0, max(0.0, score)))


# ----------------------------------------------------------------------
# Scoring files the model was never trained on
# ----------------------------------------------------------------------
# Every training row came from a PE that parsed. A .txt or a .doc leaves all
# 40-odd structural features at zero, and the model has never seen that, so
# what comes back is not a careful answer, just an unpredictable one. I hit
# this with a 166-byte README that scored 59% malicious: "no imports, no
# sections" apparently reads like a stripped binary.
#
# So don't ask it. Score those files on what they do have (rules, strings,
# entropy) and label which engine produced the number.
_CONTENT_RULES = [
    # Rule hits carry the most weight here. They match on content, so unlike
    # everything PE-shaped they still work on a document or a script.
    ("rule_max_severity", 0.50, 5.0),
    ("rule_hits", 0.14, 4.0),
    ("str_suspicious_kw", 0.14, 12.0),
    # An MZ buried inside a non-executable: dropper docs and SFX lures.
    ("str_embedded_mz", 0.12, 1.0),
    ("str_base64_blobs", 0.08, 6.0),
    ("packer_hit", 0.06, 1.0),
    ("str_urls", 0.03, 8.0),
    ("str_ips", 0.03, 4.0),
]

# Under 6.5 entropy tells you nothing. Over it the file is compressed,
# encrypted or packed -- but so is every zip and jpeg, hence the low weight.
_ENTROPY_FLOOR = 6.5
_ENTROPY_CEIL = 7.9
_ENTROPY_WEIGHT = 0.10

# Claims to be a PE, won't parse. Malformed headers break naive parsers while
# the real loader still runs the image. Plain truncation looks identical
# though, so this is a nudge and not a verdict.
_MALFORMED_PE_WEIGHT = 0.30
_MALFORMED_PE_DESC = "Declares a PE header that could not be parsed"


def pe_features_usable(features: dict[str, float]) -> bool:
    """Did we actually get the PE structure the model expects?

    Checking ``is_pe`` on its own is not enough. Plenty of files carry an
    MZ/PE header and still fail to parse, which leaves the structural
    features at zero.
    """
    return (
        float(features.get("is_pe", 0.0)) >= 0.5
        and float(features.get("pe_num_sections", 0.0)) >= 1.0
    )


def _content_score(features: dict[str, float]) -> float:
    """Score from content signals only, for files with no usable PE."""
    score = 0.0
    for name, weight, full_scale in _CONTENT_RULES:
        value = float(features.get(name, 0.0))
        score += weight * min(1.0, value / full_scale) if full_scale else 0.0

    entropy = float(features.get("entropy_overall", 0.0))
    if entropy > _ENTROPY_FLOOR:
        ramp = (entropy - _ENTROPY_FLOOR) / (_ENTROPY_CEIL - _ENTROPY_FLOOR)
        score += _ENTROPY_WEIGHT * min(1.0, ramp)

    if float(features.get("is_pe", 0.0)) >= 0.5:
        # Only reachable when the PE failed to parse; if it had parsed we
        # would be in the model branch, not here.
        score += _MALFORMED_PE_WEIGHT

    # All readable text, no rule hits, no API names: that is just a text
    # file. Push it properly benign instead of leaving it at "unproven".
    if (
        float(features.get("printable_ratio", 0.0)) > 0.90
        and float(features.get("rule_hits", 0.0)) == 0
        and float(features.get("str_suspicious_kw", 0.0)) == 0
    ):
        score -= 0.10

    return float(min(1.0, max(0.0, score)))


# ----------------------------------------------------------------------
_classifier: Classifier | None = None
_lock = threading.Lock()


def get_classifier() -> Classifier:
    global _classifier
    if _classifier is None:
        with _lock:
            if _classifier is None:
                _classifier = Classifier()
    return _classifier


def reload_classifier() -> Classifier:
    """Called after retraining so the running app picks up the new model."""
    global _classifier
    with _lock:
        _classifier = Classifier()
    return _classifier
