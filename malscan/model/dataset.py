"""Building the training set.

HOW THIS DATASET IS BUILT, AND WHAT IT IS WORTH
===============================================
The constraint I am working under: no live malware corpus for a student
project, and EMBER (the usual public benchmark) is a ~10 GB download that in
any case ships pre-computed features rather than files this extractor could
parse.

So the training set gets built in two halves.

1. BENIGN, measured rather than invented.
   Real PE files off the host machine (System32, SysWOW64, the project's own
   virtualenv) go through the same extractor used at scan time. So this half
   is genuine observed data, quirks included: reproducible-build timestamps,
   hotpatch sections, catalog signing instead of embedded. None of that gets
   tidied away.

2. MALICIOUS, synthesised from documented behaviour profiles.
   Each sample starts life as a real benign backbone (a bootstrap-resampled
   measured row) and then gets a family profile applied. Only the features
   that malware research keeps reporting as discriminative are shifted; the
   rest stay at their realistic benign values.

The backbone is the important bit. Generate malicious rows from scratch and
the model can pull the classes apart on generation artefacts instead of
anything security-relevant, which makes the accuracy figure worthless. Sharing
a backbone forces the boundary onto the shifted features and nothing else.

The generator also emits deliberate hard cases, so the problem is not
trivially separable:
  * packed-but-benign installers (high entropy, packer hit, sparse imports)
  * stealthy malware carrying only a weak subset of its family profile
Both land inside the other class's region, which makes ~100% accuracy
impossible by construction. That is the intent.

WHAT THIS MEANS FOR THE RESULTS
-------------------------------
These metrics say whether the model learned the relationship *encoded in this
data* between structure and maliciousness. They are not a claim about
real-world detection rates; that needs a labelled corpus of real samples.
:func:`load_external_dataset` is the drop-in path for one, and the README
covers the swap.
"""
from __future__ import annotations

import concurrent.futures as futures
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from malscan.config import CONFIG
from malscan.features import extract_features
from malscan.features.schema import FEATURE_NAMES

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi", ".pyd"}

# Features that are *ratios or flags* and must stay inside a fixed range after
# noise is applied. Anything not listed is clipped to >= 0 only.
BOUNDED_01 = {
    "printable_ratio", "null_ratio", "overlay_ratio", "imp_suspicious_ratio",
}
BINARY_FEATURES = {
    name for name in FEATURE_NAMES
    if name.startswith(("is_", "pe_has_", "pe_is_", "imp_has_", "str_has_"))
    or name in {
        "pe_timestamp_plausible", "pe_checksum_valid", "pe_subsystem_gui",
        "pe_subsystem_console", "pe_aslr", "pe_dep", "pe_seh",
        "pe_ep_in_code_section", "imp_dynamic_resolution", "imp_table_sparse",
        "packer_hit",
    }
}
ENTROPY_FEATURES = {
    "entropy_overall", "entropy_first_block", "entropy_last_block",
    "sec_entropy_mean", "sec_entropy_max", "sec_entropy_min",
    "pe_ep_section_entropy", "str_max_entropy", "res_entropy_max",
}


# ----------------------------------------------------------------------
# Malicious family profiles
# ----------------------------------------------------------------------
# Each entry maps a feature to how it is transformed relative to the benign
# backbone value:
#   ("set",   value)        -> assign a fixed value (flags)
#   ("add",   lo, hi)       -> add a uniform random amount
#   ("scale", lo, hi)       -> multiply by a uniform random factor
#   ("floor", lo, hi)       -> raise to at least a uniform random value
#   ("prob",  p)            -> set the flag to 1 with probability p
#
# The choices below follow behaviour repeatedly documented in malware analysis
# literature and in the EMBER/PE-feature line of work: packing raises entropy
# and empties the import table, injection and persistence pull in specific API
# clusters, and evasive samples strip the metadata that normal builds carry.
@dataclass
class Family:
    name: str
    weight: float               # relative prevalence in the generated set
    profile: dict               # feature -> transform tuple


FAMILIES: list[Family] = [
    Family(
        name="packed_dropper",
        weight=0.26,
        profile={
            "entropy_overall": ("floor", 7.2, 7.95),
            "sec_entropy_max": ("floor", 7.4, 7.99),
            "sec_entropy_mean": ("floor", 6.6, 7.6),
            "pe_ep_section_entropy": ("floor", 7.0, 7.9),
            "sec_high_entropy_count": ("floor", 1, 3),
            "packer_hit": ("prob", 0.65),
            "imp_func_count": ("scale", 0.02, 0.15),
            "imp_dll_count": ("scale", 0.1, 0.4),
            "imp_table_sparse": ("prob", 0.9),
            "imp_dynamic_resolution": ("prob", 0.85),
            "sec_nonstandard_names": ("floor", 1, 4),
            "pe_has_version_info": ("prob", 0.15),
            "pe_has_debug": ("prob", 0.05),
            "str_count_log": ("scale", 0.3, 0.6),
            "sec_zero_raw_count": ("floor", 0, 2),
            "sec_vsize_ratio_max": ("floor", 3, 20),
            "rule_hits": ("floor", 1, 4),
            "rule_max_severity": ("floor", 2, 4),
            "pe_has_signature": ("set", 0),
            "str_base64_blobs": ("floor", 0, 3),
        },
    ),
    Family(
        name="ransomware",
        weight=0.16,
        profile={
            "imp_has_crypt": ("set", 1),
            "imp_suspicious_count": ("floor", 12, 40),
            "imp_suspicious_ratio": ("floor", 0.12, 0.4),
            "str_suspicious_kw": ("floor", 8, 25),
            "entropy_overall": ("floor", 6.5, 7.6),
            "sec_entropy_max": ("floor", 7.0, 7.9),
            "str_urls": ("floor", 1, 6),
            "rule_hits": ("floor", 2, 6),
            "rule_max_severity": ("floor", 4, 5),
            "pe_has_signature": ("set", 0),
            "pe_has_version_info": ("prob", 0.25),
            "str_registry": ("floor", 2, 12),
            "imp_has_advapi32": ("set", 1),
            "str_max_entropy": ("floor", 4.6, 5.6),
        },
    ),
    Family(
        name="rat_backdoor",
        weight=0.20,
        profile={
            "imp_has_network": ("set", 1),
            "imp_suspicious_count": ("floor", 10, 35),
            "imp_suspicious_ratio": ("floor", 0.10, 0.35),
            "str_ips": ("floor", 1, 8),
            "str_urls": ("floor", 1, 10),
            "str_suspicious_kw": ("floor", 6, 20),
            "imp_dynamic_resolution": ("prob", 0.7),
            "rule_hits": ("floor", 2, 5),
            "rule_max_severity": ("floor", 3, 5),
            "pe_has_signature": ("set", 0),
            "pe_has_version_info": ("prob", 0.3),
            "pe_subsystem_console": ("prob", 0.2),
            "pe_subsystem_gui": ("prob", 0.6),
            "str_registry": ("floor", 1, 8),
            "sec_wx_count": ("floor", 0, 2),
        },
    ),
    Family(
        name="spyware_keylogger",
        weight=0.14,
        profile={
            "imp_has_user32": ("set", 1),
            "imp_suspicious_count": ("floor", 8, 25),
            "imp_suspicious_ratio": ("floor", 0.08, 0.3),
            "str_suspicious_kw": ("floor", 5, 18),
            "imp_has_network": ("prob", 0.7),
            "str_paths": ("floor", 3, 15),
            "rule_hits": ("floor", 1, 4),
            "rule_max_severity": ("floor", 3, 4),
            "pe_has_signature": ("set", 0),
            "pe_has_version_info": ("prob", 0.35),
            "str_urls": ("floor", 0, 5),
        },
    ),
    Family(
        name="injector_loader",
        weight=0.14,
        profile={
            "imp_suspicious_count": ("floor", 6, 20),
            "imp_suspicious_ratio": ("floor", 0.15, 0.5),
            "imp_func_count": ("scale", 0.05, 0.3),
            "imp_dynamic_resolution": ("set", 1),
            "sec_wx_count": ("floor", 1, 3),
            "pe_has_tls": ("prob", 0.35),
            "entropy_overall": ("floor", 6.8, 7.8),
            "sec_entropy_max": ("floor", 7.2, 7.95),
            "str_embedded_mz": ("floor", 0, 2),
            "rule_hits": ("floor", 2, 5),
            "rule_max_severity": ("floor", 4, 5),
            "pe_has_signature": ("set", 0),
            "pe_has_version_info": ("prob", 0.12),
            "pe_aslr": ("prob", 0.3),
            "pe_dep": ("prob", 0.35),
            "file_size_log": ("add", -0.9, -0.2),
        },
    ),
    Family(
        name="trojanized_installer",
        weight=0.10,
        profile={
            # Looks legitimate on the surface -- this is the hard family.
            "overlay_ratio": ("floor", 0.3, 0.85),
            "str_embedded_mz": ("floor", 1, 3),
            "entropy_last_block": ("floor", 7.0, 7.95),
            "imp_suspicious_count": ("floor", 3, 12),
            "str_urls": ("floor", 1, 5),
            "rule_hits": ("floor", 1, 3),
            "rule_max_severity": ("floor", 2, 4),
            "file_size_log": ("add", 0.2, 0.8),
            "str_suspicious_kw": ("floor", 2, 10),
        },
    ),
]

# Benign files that *look* alarming: legitimate packed/obfuscated software.
# Without these the model would simply learn "high entropy == malicious".
BENIGN_HARD_PROFILE = {
    "entropy_overall": ("floor", 7.0, 7.9),
    "sec_entropy_max": ("floor", 7.3, 7.95),
    "packer_hit": ("prob", 0.5),
    "imp_func_count": ("scale", 0.05, 0.3),
    "imp_table_sparse": ("prob", 0.7),
    "imp_dynamic_resolution": ("prob", 0.6),
    "sec_nonstandard_names": ("floor", 1, 3),
    "overlay_ratio": ("floor", 0.2, 0.7),
    "rule_hits": ("floor", 1, 2),
    "rule_max_severity": ("floor", 2, 3),
}


# ----------------------------------------------------------------------
# 1. Measure real benign files
# ----------------------------------------------------------------------
def find_pe_files(dirs=None, limit: int = 1500, max_bytes: int = 12 * 1024 * 1024) -> list[Path]:
    """Locate candidate benign PE files on the host machine."""
    dirs = dirs or CONFIG.benign_source_dirs
    found: list[Path] = []
    for root in dirs:
        root = Path(root)
        if not root.exists():
            continue
        try:
            for dirpath, _dirnames, filenames in os.walk(root):
                for fn in filenames:
                    if Path(fn).suffix.lower() not in PE_EXTENSIONS:
                        continue
                    p = Path(dirpath) / fn
                    try:
                        if 1024 < p.stat().st_size <= max_bytes:
                            found.append(p)
                    except OSError:
                        continue
                    if len(found) >= limit:
                        return found
                # System32 subdirectories are mostly locale resources; one
                # level is plenty and keeps the walk fast.
                if root.name.lower() in {"system32", "syswow64"}:
                    break
        except (PermissionError, OSError):
            continue
    return found


def _extract_one(path: Path) -> dict | None:
    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return None
    try:
        # A smaller string budget keeps dataset building to a few minutes;
        # scan-time extraction uses the full budget. The first megabyte
        # covers the code and rdata of virtually every system binary.
        result = extract_features(
            data, path.name, run_rules=True, string_limit=1024 * 1024
        )
    except Exception:
        return None
    if not result.pe.parsed:
        return None
    row = dict(result.features)
    row["_source"] = path.name
    return row


def collect_real_benign(limit: int = 1500, workers: int = 8, progress=None) -> pd.DataFrame:
    """Extract features from real PE files on this machine."""
    paths = find_pe_files(limit=limit)
    rows: list[dict] = []
    if not paths:
        return pd.DataFrame(columns=FEATURE_NAMES + ["_source"])

    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for i, row in enumerate(pool.map(_extract_one, paths)):
            if row:
                rows.append(row)
            if progress and i % 25 == 0:
                progress(i / len(paths), f"Analysed {i}/{len(paths)} system binaries")

    return pd.DataFrame(rows)


# ----------------------------------------------------------------------
# 2. Apply profiles
# ----------------------------------------------------------------------
def _apply_profile(row: np.ndarray, index: dict[str, int], profile: dict,
                   rng: np.random.Generator, strength: float = 1.0) -> None:
    """Mutate a feature row in place according to a family profile.

    ``strength`` in [0, 1] controls how much of the profile is applied -- a
    stealthy sample only partially expresses its family's traits.
    """
    for feature, transform in profile.items():
        i = index.get(feature)
        if i is None:
            continue
        if strength < 1.0 and rng.random() > strength:
            continue  # this trait simply is not expressed in this sample

        kind = transform[0]
        current = row[i]

        if kind == "set":
            row[i] = float(transform[1])
        elif kind == "prob":
            row[i] = float(rng.random() < transform[1])
        elif kind == "add":
            row[i] = current + rng.uniform(transform[1], transform[2])
        elif kind == "scale":
            row[i] = current * rng.uniform(transform[1], transform[2])
        elif kind == "floor":
            target = rng.uniform(transform[1], transform[2])
            row[i] = max(current, target)


def _add_noise(matrix: np.ndarray, index: dict[str, int], rng: np.random.Generator,
               scale: float = 0.06) -> None:
    """Per-sample multiplicative jitter on continuous features only."""
    for name, i in index.items():
        if name in BINARY_FEATURES:
            continue
        col = matrix[:, i]
        if name in ENTROPY_FEATURES:
            col += rng.normal(0, 0.10, size=col.shape)
        else:
            col *= 1.0 + rng.normal(0, scale, size=col.shape)


def _clip(matrix: np.ndarray, index: dict[str, int]) -> None:
    for name, i in index.items():
        if name in BINARY_FEATURES:
            matrix[:, i] = np.clip(np.round(matrix[:, i]), 0, 1)
        elif name in BOUNDED_01:
            matrix[:, i] = np.clip(matrix[:, i], 0.0, 1.0)
        elif name in ENTROPY_FEATURES:
            matrix[:, i] = np.clip(matrix[:, i], 0.0, 8.0)
        else:
            matrix[:, i] = np.maximum(matrix[:, i], 0.0)


def _bootstrap(
    backbone: np.ndarray, n: int, rng: np.random.Generator
) -> tuple[np.ndarray, np.ndarray]:
    """Resample rows, returning both the samples and their source row indices.

    The source index is carried all the way into the dataframe so that the
    train/test split can be *grouped* by originating file. Without that, the
    same real binary would seed rows on both sides of the split and the
    reported accuracy would be inflated by leakage.
    """
    idx = rng.integers(0, backbone.shape[0], size=n)
    return backbone[idx].astype(float).copy(), idx


# ----------------------------------------------------------------------
# 3. Build the full dataset
# ----------------------------------------------------------------------
def build_dataset(
    n_per_class: int | None = None,
    benign_limit: int = 1500,
    seed: int | None = None,
    progress=None,
) -> tuple[pd.DataFrame, dict]:
    """Return (dataframe, metadata). The dataframe has FEATURE_NAMES + label."""
    n_per_class = n_per_class or CONFIG.n_synthetic_per_class
    rng = np.random.default_rng(seed if seed is not None else CONFIG.random_state)
    index = {name: i for i, name in enumerate(FEATURE_NAMES)}

    if progress:
        progress(0.0, "Locating real benign binaries on this machine...")
    real = collect_real_benign(limit=benign_limit, progress=progress)

    meta: dict = {
        "real_benign_files": int(len(real)),
        "families": [f.name for f in FAMILIES],
        "n_per_class": n_per_class,
    }

    if len(real) < 50:
        raise RuntimeError(
            f"Only {len(real)} real benign PE files could be analysed. "
            "MalScan needs at least 50 to calibrate the benign distribution. "
            "Check that C:/Windows/System32 is readable, or supply an external "
            "dataset via load_external_dataset()."
        )

    backbone = real[FEATURE_NAMES].to_numpy(dtype=float)

    # ---- benign class ---------------------------------------------------
    if progress:
        progress(0.75, "Generating benign class...")
    n_hard_benign = int(n_per_class * 0.12)
    benign, benign_src = _bootstrap(backbone, n_per_class, rng)
    for r in range(n_per_class - n_hard_benign, n_per_class):
        _apply_profile(benign[r], index, BENIGN_HARD_PROFILE, rng, strength=0.8)
    _add_noise(benign, index, rng)
    _clip(benign, index)

    # ---- malicious class ------------------------------------------------
    if progress:
        progress(0.85, "Generating malicious class from behaviour profiles...")
    malicious, malicious_src = _bootstrap(backbone, n_per_class, rng)

    weights = np.array([f.weight for f in FAMILIES], dtype=float)
    weights /= weights.sum()
    assignments = rng.choice(len(FAMILIES), size=n_per_class, p=weights)

    # 15% of malicious samples are "stealthy": only a partial profile.
    stealth_mask = rng.random(n_per_class) < 0.15
    family_labels = []
    for r in range(n_per_class):
        fam = FAMILIES[assignments[r]]
        strength = float(rng.uniform(0.3, 0.55)) if stealth_mask[r] else 1.0
        _apply_profile(malicious[r], index, fam.profile, rng, strength=strength)
        family_labels.append(fam.name + ("_stealth" if stealth_mask[r] else ""))
    _add_noise(malicious, index, rng)
    _clip(malicious, index)

    # ---- assemble -------------------------------------------------------
    X = np.vstack([benign, malicious])
    y = np.concatenate([np.zeros(n_per_class, int), np.ones(n_per_class, int)])
    groups = ["benign"] * (n_per_class - n_hard_benign) + ["benign_packed"] * n_hard_benign
    groups += family_labels

    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y
    df["group"] = groups
    # Which real binary each synthetic row was derived from -- the split key.
    df["source_id"] = np.concatenate([benign_src, malicious_src])

    df = df.sample(frac=1.0, random_state=CONFIG.random_state).reset_index(drop=True)

    meta.update(
        {
            "total_rows": int(len(df)),
            "benign_rows": int((df.label == 0).sum()),
            "malicious_rows": int((df.label == 1).sum()),
            "hard_benign_rows": n_hard_benign,
            "stealth_malicious_rows": int(stealth_mask.sum()),
            "n_features": len(FEATURE_NAMES),
            "unique_source_files": int(df["source_id"].nunique()),
            "split_strategy": "grouped by source_id (no source file spans the split)",
        }
    )
    if progress:
        progress(1.0, "Dataset ready")
    return df, meta


def load_external_dataset(path: str | Path) -> pd.DataFrame:
    """Drop-in path for a real labelled corpus.

    Accepts a CSV/Parquet file containing the columns in ``FEATURE_NAMES``
    plus a ``label`` column (0 = benign, 1 = malicious). Any missing feature
    column is filled with 0 so that partially-overlapping schemas still load.
    Point ``train.py --dataset`` at the result to retrain on real data.
    """
    path = Path(path)
    df = pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_csv(path)

    if "label" not in df.columns:
        raise ValueError("External dataset must contain a 'label' column (0/1)")

    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    for c in missing:
        df[c] = 0.0
    if missing:
        print(f"[warn] {len(missing)} feature column(s) missing, filled with 0: "
              f"{', '.join(missing[:8])}{'...' if len(missing) > 8 else ''}")

    if "group" not in df.columns:
        df["group"] = df["label"].map({0: "benign", 1: "malicious"})
    if "source_id" not in df.columns:
        # Real corpora have one row per real file, so each row is its own group.
        df["source_id"] = np.arange(len(df))
    return df[FEATURE_NAMES + ["label", "group", "source_id"]]
