"""Entropy and byte-histogram maths.

Cheapest useful signal in static analysis. Compressed, encrypted or packed
regions push towards 8.0 bits/byte; ordinary code and text sit well below.

All vectorised with numpy, which is worth the import here: these run over
every byte of every scanned file, and a plain ``for b in data`` loop over a
4 MB buffer takes seconds on its own. That alone would blow the scan budget.
"""
from __future__ import annotations

import math

import numpy as np


def _counts(data: bytes) -> np.ndarray:
    """Frequency of each of the 256 byte values."""
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 for empty input."""
    if not data:
        return 0.0
    counts = _counts(data)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def byte_histogram(data: bytes) -> list[float]:
    """Normalised 256-bin byte frequency histogram."""
    if not data:
        return [0.0] * 256
    return (_counts(data) / len(data)).tolist()


def chi_square_uniform(data: bytes) -> float:
    """Chi-square distance between the byte histogram and a uniform one.

    Encrypted/compressed data approaches uniform (low score); text and code are
    heavily skewed (high score). Normalised by length so it is size-independent.
    """
    if not data:
        return 0.0
    counts = _counts(data).astype(np.float64)
    expected = len(data) / 256.0
    chi2 = float(np.sum((counts - expected) ** 2) / expected)
    return chi2 / len(data)


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes in the printable ASCII range (plus tab/CR/LF)."""
    if not data:
        return 0.0
    counts = _counts(data)
    printable = int(counts[32:127].sum() + counts[9] + counts[10] + counts[13])
    return printable / len(data)


def null_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return float(_counts(data)[0]) / len(data)


def block_entropies(data: bytes, block_size: int = 4096) -> list[float]:
    """Entropy per fixed-size block -- used to spot packed regions."""
    if not data:
        return []

    arr = np.frombuffer(data, dtype=np.uint8)
    n_full = len(arr) // block_size
    out: list[float] = []

    if n_full:
        # Offset each block's byte values into its own 256-wide slot so a
        # single bincount produces every block's histogram at once. This beats
        # np.add.at by an order of magnitude, and np.add.at in turn beats a
        # per-block Python loop.
        blocks = arr[: n_full * block_size].reshape(n_full, block_size)
        offsets = (np.arange(n_full, dtype=np.int64) * 256)[:, None]
        counts = np.bincount(
            (blocks.astype(np.int64) + offsets).ravel(), minlength=n_full * 256
        ).reshape(n_full, 256)

        probs = counts / block_size
        with np.errstate(divide="ignore", invalid="ignore"):
            terms = np.where(probs > 0, probs * np.log2(probs), 0.0)
        out = (-terms.sum(axis=1)).tolist()

    tail = arr[n_full * block_size :]
    if tail.size:
        out.append(shannon_entropy(tail.tobytes()))
    return out


def sliding_entropy(data: bytes, window: int = 4096, step: int = 2048) -> list[float]:
    """Overlapping-window entropy, for a smoother profile than fixed blocks."""
    if not data:
        return []
    return [
        shannon_entropy(data[i : i + window])
        for i in range(0, max(1, len(data) - window + 1), step)
    ]


def max_run_length(data: bytes, value: int = 0) -> int:
    """Longest run of a repeated byte -- large zero runs suggest padding."""
    if not data:
        return 0
    arr = np.frombuffer(data, dtype=np.uint8) == value
    if not arr.any():
        return 0
    # Count consecutive True values by resetting a cumulative sum at each False.
    idx = np.flatnonzero(~arr)
    if idx.size == 0:
        return int(arr.size)
    padded = np.concatenate(([-1], idx, [arr.size]))
    return int(np.max(np.diff(padded) - 1))


# Kept so the maths stays readable next to the vectorised version above.
def _shannon_entropy_reference(data: bytes) -> float:  # pragma: no cover
    if not data:
        return 0.0
    from collections import Counter

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
