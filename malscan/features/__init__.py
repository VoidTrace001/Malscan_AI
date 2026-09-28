"""Static feature extraction for MalScan AI."""

from malscan.features.schema import FEATURE_NAMES, FEATURE_GROUPS, FEATURE_DOCS, blank_features
from malscan.features.extractor import extract_features, FeatureResult

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_GROUPS",
    "FEATURE_DOCS",
    "blank_features",
    "extract_features",
    "FeatureResult",
]
