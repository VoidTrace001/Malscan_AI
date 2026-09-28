"""Why a given file got the score it did.

A bare number is not much use to anyone, so every scan comes with an
attribution. The method is ablation: take one feature, reset it to the median
of the benign training data, leave the other 72 alone, and see how far the
malicious probability moves. That delta is the feature's contribution.

Same idea as SHAP, roughly, but it costs one batched forward pass and no extra
dependency, which keeps scans inside the few-seconds budget.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from malscan.features.schema import (
    FEATURE_DOCS, FEATURE_NAMES, FEATURE_TO_GROUP, to_vector,
)
from malscan.model.predict import Classifier
from malscan.util import human_bytes

# Features whose raw numbers need rephrasing before a human reads them.
_PERCENT_FEATURES = {
    "printable_ratio", "null_ratio", "overlay_ratio", "imp_suspicious_ratio",
}
_LOG_FEATURES = {
    "file_size_log", "str_count_log", "pe_size_of_code_log", "pe_size_of_image_log",
}
_BOOLEAN_FEATURES = {
    name for name in FEATURE_NAMES
    if name.startswith(("is_", "pe_has_", "pe_is_", "imp_has_", "str_has_"))
    or name in {
        "pe_timestamp_plausible", "pe_checksum_valid", "pe_aslr", "pe_dep",
        "pe_seh", "pe_ep_in_code_section", "imp_dynamic_resolution",
        "imp_table_sparse", "packer_hit", "pe_subsystem_gui",
        "pe_subsystem_console",
    }
}


@dataclass
class Contribution:
    feature: str
    description: str
    group: str
    value: float
    display_value: str
    benign_typical: str
    contribution: float      # signed: + pushes malicious, - pushes benign
    direction: str           # "malicious" | "benign"

    @property
    def abs_contribution(self) -> float:
        return abs(self.contribution)


def _format_value(name: str, value: float) -> str:
    if name in _BOOLEAN_FEATURES:
        return "yes" if value >= 0.5 else "no"
    if name in _PERCENT_FEATURES:
        return f"{value * 100:.1f}%"
    if name in _LOG_FEATURES:
        actual = (10.0 ** value) - 1.0
        if name == "file_size_log":
            return human_bytes(actual)
        return f"{actual:,.0f}"
    if abs(value - round(value)) < 1e-6 and abs(value) < 1e6:
        return f"{int(round(value))}"
    return f"{value:.2f}"


def explain(
    classifier: Classifier,
    features: dict[str, float],
    top_k: int = 12,
    engine: str = "model",
) -> list[Contribution]:
    """Rank the features by how much each moved this file's score.

    ``engine`` is whichever scorer actually produced the verdict. Explaining a
    content-scored file by ablating the model would describe a decision that
    was never made, so the explanation always follows the engine.
    """
    if engine == "content":
        return _rule_explain(features, top_k, _CONTENT_MODE)
    if classifier.model is None or engine == "heuristic":
        return _heuristic_explain(features, top_k)

    baseline = classifier.baseline.get("benign_median")
    if not baseline or len(baseline) != len(FEATURE_NAMES):
        return _heuristic_explain(features, top_k)

    original = np.array(to_vector(features), dtype=np.float32)
    benign_median = np.array(baseline, dtype=np.float32)

    # Row 0 is the file as it is; row i+1 is the file with feature i normalised.
    variants = np.tile(original, (len(FEATURE_NAMES) + 1, 1))
    for i in range(len(FEATURE_NAMES)):
        variants[i + 1, i] = benign_median[i]

    probs = classifier.model.predict_proba(variants)[:, 1]
    actual_prob = float(probs[0])

    p10 = classifier.baseline.get("benign_p10") or [0.0] * len(FEATURE_NAMES)
    p90 = classifier.baseline.get("benign_p90") or [0.0] * len(FEATURE_NAMES)

    contributions: list[Contribution] = []
    for i, name in enumerate(FEATURE_NAMES):
        delta = actual_prob - float(probs[i + 1])
        if abs(delta) < 1e-4:
            continue  # this feature made no difference to this file
        value = float(original[i])
        if name in _BOOLEAN_FEATURES:
            typical = f"usually {'yes' if benign_median[i] >= 0.5 else 'no'}"
        else:
            typical = (
                f"typically {_format_value(name, float(p10[i]))}"
                f"-{_format_value(name, float(p90[i]))}"
            )
        contributions.append(
            Contribution(
                feature=name,
                description=FEATURE_DOCS.get(name, name),
                group=FEATURE_TO_GROUP.get(name, "Other"),
                value=value,
                display_value=_format_value(name, value),
                benign_typical=typical,
                contribution=delta,
                direction="malicious" if delta > 0 else "benign",
            )
        )

    contributions.sort(key=lambda c: -c.abs_contribution)
    return contributions[:top_k]


_HEURISTIC_MODE = "heuristic"
_CONTENT_MODE = "content"


def _rule_explain(features: dict[str, float], top_k: int, mode: str) -> list[Contribution]:
    """Same shape of output when a weighted rule table is in charge.

    Each weight is a fixed contribution rather than an ablation, so what the
    reader sees is exactly the arithmetic that produced the score.
    """
    from malscan.model.predict import _CONTENT_RULES, _HEURISTIC_RULES

    table = _CONTENT_RULES if mode == _CONTENT_MODE else _HEURISTIC_RULES
    label = (
        "n/a (content signals only)" if mode == _CONTENT_MODE
        else "n/a (heuristic mode)"
    )

    out = []
    for name, weight, full_scale in table:
        value = float(features.get(name, 0.0))
        if value <= 0:
            continue
        out.append(
            Contribution(
                feature=name,
                description=FEATURE_DOCS.get(name, name),
                group=FEATURE_TO_GROUP.get(name, "Other"),
                value=value,
                display_value=_format_value(name, value),
                benign_typical=label,
                contribution=weight * min(1.0, value / full_scale),
                direction="malicious",
            )
        )

    if mode == _CONTENT_MODE:
        from malscan.model.predict import (
            _ENTROPY_CEIL, _ENTROPY_FLOOR, _ENTROPY_WEIGHT,
        )

        if float(features.get("is_pe", 0.0)) >= 0.5:
            from malscan.model.predict import (
                _MALFORMED_PE_DESC, _MALFORMED_PE_WEIGHT,
            )

            out.append(
                Contribution(
                    feature="pe_unparsable",
                    description=_MALFORMED_PE_DESC,
                    group="PE header",
                    value=1.0,
                    display_value="yes",
                    benign_typical=label,
                    contribution=_MALFORMED_PE_WEIGHT,
                    direction="malicious",
                )
            )

        entropy = float(features.get("entropy_overall", 0.0))
        if entropy > _ENTROPY_FLOOR:
            ramp = min(1.0, (entropy - _ENTROPY_FLOOR) / (_ENTROPY_CEIL - _ENTROPY_FLOOR))
            out.append(
                Contribution(
                    feature="entropy_overall",
                    description=FEATURE_DOCS.get("entropy_overall", "entropy_overall"),
                    group=FEATURE_TO_GROUP.get("entropy_overall", "Other"),
                    value=entropy,
                    display_value=_format_value("entropy_overall", entropy),
                    benign_typical=label,
                    contribution=_ENTROPY_WEIGHT * ramp,
                    direction="malicious",
                )
            )

    out.sort(key=lambda c: -c.abs_contribution)
    return out[:top_k]


def _heuristic_explain(features: dict[str, float], top_k: int) -> list[Contribution]:
    """Same shape of output when the heuristic scorer is in charge."""
    return _rule_explain(features, top_k, _HEURISTIC_MODE)


def narrative(
    contributions: list[Contribution],
    prediction,
    result,
) -> list[str]:
    """Plain-English bullet points describing why the verdict came out this way.

    ``result`` is the FeatureResult, which carries the concrete evidence (rule
    names, section names, URLs) that turns a feature name into a real finding.
    """
    lines: list[str] = []
    pushing_bad = [c for c in contributions if c.direction == "malicious"][:5]
    pushing_good = [c for c in contributions if c.direction == "benign"][:3]

    if prediction.engine == "heuristic":
        lines.append(
            "No trained model is loaded, so the reasoning below comes from "
            "fixed heuristics rather than a learned decision."
        )
    elif prediction.engine == "content":
        lines.append(
            "This file has no parsable PE structure, so the trained model was "
            "not consulted -- it would have been guessing outside its training "
            "data. The reasoning below is drawn from content signals only, and "
            "is weaker evidence than a verdict on a Windows executable."
        )

    if pushing_bad:
        lines.append("**What raised the score:**")
        for c in pushing_bad:
            lines.append(
                f"- {c.description} — this file: **{c.display_value}** "
                f"({c.benign_typical}); "
                f"contributed +{c.contribution * 100:.1f} points"
            )
    else:
        lines.append(
            "**No individual feature pushed this file towards malicious.**"
        )

    if pushing_good:
        lines.append("**What lowered the score:**")
        for c in pushing_good:
            lines.append(
                f"- {c.description} — this file: **{c.display_value}** "
                f"({c.benign_typical}); "
                f"contributed {c.contribution * 100:.1f} points"
            )

    # Concrete corroborating evidence, independent of the model.
    if result.rule_matches:
        top = result.rule_matches[:4]
        lines.append("**Detection rules that matched:**")
        for m in top:
            lines.append(
                f"- `{m['name']}` (severity {m['severity']}/5, {m['category']}): "
                f"{m['description']}"
            )

    if result.pe.parsed and result.pe.anomalies:
        lines.append("**What stands out in the structure:**")
        for a in result.pe.anomalies[:6]:
            lines.append(f"- {a}")

    return lines
