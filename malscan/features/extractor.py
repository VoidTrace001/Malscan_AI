"""Pulls the whole feature extraction together.

:func:`extract_features` is the only entry point. Bytes in; out comes both the
numeric vector for the model and the fuller report the UI renders. Read-only
throughout, nothing is executed.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from malscan.features import entropy as ent
from malscan.features import filetype, hashes
from malscan.features.pe_features import PEReport, parse_pe
from malscan.features.schema import blank_features
from malscan.features.strings_features import StringStats, analyse_strings


@dataclass
class FeatureResult:
    """Everything learned about a file in one pass."""
    features: dict[str, float]
    file_type: filetype.FileType
    pe: PEReport
    strings: StringStats
    hashes: dict[str, str]
    fuzzy_hash: str
    size: int
    rule_matches: list[dict] = field(default_factory=list)
    block_entropy: list[float] = field(default_factory=list)
    byte_histogram: list[float] = field(default_factory=list)

    @property
    def is_pe(self) -> bool:
        return self.file_type.is_pe


def _log10(x: float) -> float:
    """Log that tolerates zero -- sizes and counts span many magnitudes."""
    return math.log10(x + 1.0)


def extract_features(
    data: bytes,
    filename: str = "",
    run_rules: bool = True,
    string_limit: int = 8 * 1024 * 1024,
    min_string_len: int = 5,
) -> FeatureResult:
    """Extract the full static feature set from a file buffer."""
    feats = blank_features()
    size = len(data)

    # ---- file-level ------------------------------------------------------
    ft = filetype.detect(data, filename)
    feats["file_size_log"] = _log10(size)
    feats["entropy_overall"] = ent.shannon_entropy(data)
    feats["entropy_first_block"] = ent.shannon_entropy(data[:4096])
    feats["entropy_last_block"] = ent.shannon_entropy(data[-4096:])
    feats["printable_ratio"] = ent.printable_ratio(data)
    feats["null_ratio"] = ent.null_ratio(data)
    feats["byte_chi2"] = ent.chi_square_uniform(data)
    feats["is_pe"] = float(ft.is_pe)
    feats["is_script"] = float(ft.is_script)
    feats["is_document"] = float(ft.is_document)
    feats["is_archive"] = float(ft.is_archive)

    # ---- rules -----------------------------------------------------------
    rule_matches: list[dict] = []
    if run_rules:
        # Imported lazily: the rules engine imports the feature package.
        from malscan.rules.engine import get_engine

        rule_matches = get_engine().scan(data)
    feats["rule_hits"] = float(len(rule_matches))
    feats["rule_max_severity"] = float(
        max((m.get("severity", 0) for m in rule_matches), default=0)
    )

    # ---- strings ---------------------------------------------------------
    s = analyse_strings(data, min_len=min_string_len, limit=string_limit)
    feats["str_count_log"] = _log10(s.count)
    feats["str_avg_len"] = s.avg_len
    feats["str_max_len"] = float(min(s.max_len, 4096))  # clip pathological runs
    feats["str_max_entropy"] = s.max_entropy
    feats["str_urls"] = float(s.urls)
    feats["str_ips"] = float(s.ips)
    feats["str_registry"] = float(s.registry)
    feats["str_paths"] = float(s.paths)
    feats["str_suspicious_kw"] = float(s.suspicious)
    feats["str_base64_blobs"] = float(s.base64_blobs)
    feats["str_has_pdb"] = float(s.has_pdb)
    feats["str_embedded_mz"] = float(s.embedded_mz)

    # ---- PE --------------------------------------------------------------
    pe = parse_pe(data) if ft.is_pe else PEReport()
    if pe.parsed:
        _fill_pe_features(feats, pe, size)

    return FeatureResult(
        features=feats,
        file_type=ft,
        pe=pe,
        strings=s,
        hashes=hashes.file_hashes(data),
        fuzzy_hash=hashes.ssdeep_like(data),
        size=size,
        rule_matches=rule_matches,
        block_entropy=ent.block_entropies(data[: 2 * 1024 * 1024]),
        byte_histogram=ent.byte_histogram(data[: 4 * 1024 * 1024]),
    )


def _fill_pe_features(feats: dict[str, float], pe: PEReport, size: int) -> None:
    from malscan.features.pe_features import (
        CRYPTO_DLLS, NETWORK_DLLS, SHELL_DLLS, STANDARD_SECTIONS,
    )

    feats["pe_is_64bit"] = float(pe.is_64bit)
    feats["pe_is_dll"] = float(pe.is_dll)
    feats["pe_num_sections"] = float(len(pe.sections))
    feats["pe_timestamp_plausible"] = float(pe.timestamp_plausible)
    feats["pe_timestamp_age_years"] = min(pe.timestamp_age_years, 40.0)
    feats["pe_size_of_code_log"] = _log10(pe.size_of_code)
    feats["pe_size_of_image_log"] = _log10(pe.size_of_image)
    feats["pe_size_of_headers"] = float(pe.size_of_headers)
    feats["pe_checksum_valid"] = float(pe.checksum_valid)
    feats["pe_subsystem_gui"] = float("GUI" in pe.subsystem)
    feats["pe_subsystem_console"] = float("CUI" in pe.subsystem or "CONSOLE" in pe.subsystem)
    feats["pe_aslr"] = float(pe.aslr)
    feats["pe_dep"] = float(pe.dep)
    feats["pe_seh"] = float(pe.seh)
    feats["pe_has_debug"] = float(pe.has_debug)
    feats["pe_has_relocs"] = float(pe.has_relocs)
    feats["pe_has_tls"] = float(pe.has_tls)
    feats["pe_has_resources"] = float(pe.has_resources)
    feats["pe_has_signature"] = float(pe.has_signature)
    feats["pe_has_version_info"] = float(pe.has_version_info)
    feats["pe_ep_in_code_section"] = float(pe.entry_point_in_code)
    feats["pe_ep_section_entropy"] = pe.entry_point_entropy

    # ---- sections --------------------------------------------------------
    entropies = [s.entropy for s in pe.sections]
    if entropies:
        mean = sum(entropies) / len(entropies)
        feats["sec_entropy_mean"] = mean
        feats["sec_entropy_max"] = max(entropies)
        feats["sec_entropy_min"] = min(entropies)
        feats["sec_entropy_std"] = (
            sum((e - mean) ** 2 for e in entropies) / len(entropies)
        ) ** 0.5
    feats["sec_high_entropy_count"] = float(sum(1 for e in entropies if e >= 7.4))
    feats["sec_wx_count"] = float(sum(1 for s in pe.sections if s.is_wx))
    feats["sec_zero_raw_count"] = float(
        sum(1 for s in pe.sections if s.raw_size == 0 and s.virtual_size > 0)
    )
    feats["sec_nonstandard_names"] = float(
        sum(1 for s in pe.sections if s.name.lower() not in STANDARD_SECTIONS)
    )
    ratios = [min(s.vsize_ratio, 50.0) for s in pe.sections]
    if ratios:
        feats["sec_vsize_ratio_mean"] = sum(ratios) / len(ratios)
        feats["sec_vsize_ratio_max"] = max(ratios)

    # ---- imports ---------------------------------------------------------
    dlls = set(pe.imports.keys())
    feats["imp_dll_count"] = float(len(dlls))
    feats["imp_func_count"] = float(pe.import_count)
    feats["imp_has_kernel32"] = float("kernel32.dll" in dlls)
    feats["imp_has_advapi32"] = float("advapi32.dll" in dlls)
    feats["imp_has_network"] = float(bool(dlls & NETWORK_DLLS))
    feats["imp_has_user32"] = float("user32.dll" in dlls)
    feats["imp_has_crypt"] = float(bool(dlls & CRYPTO_DLLS))
    feats["imp_has_shell"] = float(bool(dlls & SHELL_DLLS))
    feats["imp_suspicious_count"] = float(len(pe.suspicious_apis))
    feats["imp_suspicious_ratio"] = (
        len(pe.suspicious_apis) / pe.import_count if pe.import_count else 0.0
    )

    api_names = {f.split("!", 1)[-1].lower() for f in pe.suspicious_apis}
    feats["imp_dynamic_resolution"] = float(
        bool({"loadlibrarya", "loadlibraryw"} & api_names) and "getprocaddress" in api_names
    )
    # A 5 MB binary importing 3 functions is not a normal compiler output.
    expected = max(8.0, 12.0 * math.log10(size + 1))
    feats["imp_table_sparse"] = float(pe.import_count < expected * 0.35)
    feats["exp_count"] = float(len(pe.exports))

    # ---- packing ---------------------------------------------------------
    feats["overlay_ratio"] = pe.overlay_ratio
    feats["packer_hit"] = float(bool(pe.packer))
    feats["res_entropy_max"] = pe.resource_max_entropy
