"""The canonical feature schema.

One ordered list that the model, the extractor and the explainer all agree on.
New features go here first: ``FEATURE_NAMES`` fixes the column order of the
training matrix and the input order at inference, so the two cannot drift.

The descriptions are not internal notes. They are printed verbatim to whoever
is reading a verdict, so they are written for someone who does not know what a
section table or an import thunk is. Keep them that way: say what the signal
means about the file, not what the field is called in the spec.
"""
from __future__ import annotations

from collections import OrderedDict

# group -> {feature name: plain-language description shown to the reader}
FEATURE_GROUPS: "OrderedDict[str, OrderedDict[str, str]]" = OrderedDict()

FEATURE_GROUPS["File"] = OrderedDict([
    ("file_size_log", "How big the file is"),
    ("entropy_overall",
     "How random the whole file looks, from 0 to 8 - high means packed or encrypted"),
    ("entropy_first_block",
     "How random the opening 4 KB looks, where the file's header sits"),
    ("entropy_last_block",
     "How random the final 4 KB looks, where extra data tends to get tacked on"),
    ("printable_ratio", "How much of the file is readable text"),
    ("null_ratio", "How much of the file is empty padding"),
    ("byte_chi2",
     "How evenly the byte values are spread - a very even spread suggests encryption"),
    ("is_pe", "The file is a Windows program"),
    ("is_script", "The file is a script or plain text"),
    ("is_document", "The file is a document, such as Office or PDF"),
    ("is_archive", "The file is a compressed archive, such as a ZIP"),
])

FEATURE_GROUPS["PE Header"] = OrderedDict([
    ("pe_is_64bit", "Built for 64-bit Windows"),
    ("pe_is_dll", "It is a shared library rather than a program you run directly"),
    ("pe_num_sections", "How many parts the program is divided into"),
    ("pe_timestamp_plausible", "The build date on the file looks believable"),
    ("pe_timestamp_age_years", "How many years ago the file claims it was built"),
    ("pe_size_of_code_log", "How much of the file is actual program code"),
    ("pe_size_of_image_log", "How much memory the program asks for when it loads"),
    ("pe_size_of_headers", "How much room the file's own headers take up"),
    ("pe_checksum_valid",
     "The file's built-in integrity check still matches, so it has not been "
     "edited since it was built"),
    ("pe_subsystem_gui", "Runs as a windowed application"),
    ("pe_subsystem_console", "Runs in a console window"),
    ("pe_aslr",
     "Keeps the standard defence that loads the program at a random address"),
    ("pe_dep",
     "Keeps the standard defence that stops data being run as code"),
    ("pe_seh", "Leaves Windows' normal error handling switched on"),
    ("pe_has_debug", "Still carries leftover debugging information"),
    ("pe_has_relocs", "Can be loaded at a different address than it prefers"),
    ("pe_has_tls",
     "Runs hidden setup code before the program's real starting point, which is "
     "sometimes used to dodge analysis"),
    ("pe_has_resources", "Bundles resources such as icons or images"),
    ("pe_has_signature", "Carries a digital signature from whoever published it"),
    ("pe_has_version_info", "States a publisher, product name and version"),
    ("pe_ep_in_code_section",
     "Starts running inside the normal code area, as a legitimate program does"),
    ("pe_ep_section_entropy",
     "How random the code looks at the exact point the program starts"),
])

FEATURE_GROUPS["Sections"] = OrderedDict([
    ("sec_entropy_mean", "Average randomness across every part of the program"),
    ("sec_entropy_max", "Randomness of the most scrambled-looking part"),
    ("sec_entropy_min", "Randomness of the least scrambled-looking part"),
    ("sec_entropy_std", "How much the randomness varies from part to part"),
    ("sec_high_entropy_count", "How many parts look packed or encrypted"),
    ("sec_wx_count",
     "Parts the program can both rewrite and run, which is how self-modifying "
     "code behaves"),
    ("sec_zero_raw_count",
     "Parts that reserve memory but hold nothing on disk, so they get filled in "
     "while running"),
    ("sec_nonstandard_names",
     "Parts with unusual names that normal build tools do not produce"),
    ("sec_vsize_ratio_mean",
     "Average gap between the memory a part claims and what it actually holds"),
    ("sec_vsize_ratio_max",
     "The largest such gap - a wide one suggests the file unpacks itself"),
])

FEATURE_GROUPS["Imports"] = OrderedDict([
    ("imp_dll_count", "How many Windows libraries the program borrows from"),
    ("imp_func_count", "How many Windows functions the program borrows"),
    ("imp_has_kernel32", "Uses core Windows functions for files, memory and processes"),
    ("imp_has_advapi32", "Uses the Windows registry or system services"),
    ("imp_has_network", "Is able to communicate over the network"),
    ("imp_has_user32", "Can create windows, or watch keyboard and mouse input"),
    ("imp_has_crypt", "Uses Windows encryption functions"),
    ("imp_has_shell", "Can launch other programs or open files"),
    ("imp_suspicious_count", "How many of the functions it borrows are on our watchlist"),
    ("imp_suspicious_ratio", "What share of the functions it borrows are on our watchlist"),
    ("imp_dynamic_resolution",
     "Looks its functions up while running instead of declaring them upfront, "
     "which is a common way to hide what a program intends to do"),
    ("imp_table_sparse",
     "Declares far fewer functions than a file this size normally would, which "
     "is typical of packed files"),
    ("exp_count", "How many functions this file offers to other programs"),
])

FEATURE_GROUPS["Content"] = OrderedDict([
    ("str_count_log", "How many readable pieces of text the file contains"),
    ("str_avg_len", "Average length of those pieces of text"),
    ("str_max_len", "Length of the longest piece of text"),
    ("str_max_entropy", "How scrambled the most random piece of text looks"),
    ("str_urls", "How many web addresses are buried in the file"),
    ("str_ips", "How many IP addresses are buried in the file"),
    ("str_registry", "How many Windows registry locations are named"),
    ("str_paths", "How many file or folder locations are named"),
    ("str_suspicious_kw", "How many words from our watchlist turn up"),
    ("str_base64_blobs", "Long encoded blocks that may be a hidden payload"),
    ("str_has_pdb", "Still carries the build path from the original developer's machine"),
    ("str_embedded_mz", "Whole other programs hidden inside this one"),
])

FEATURE_GROUPS["Packing & Rules"] = OrderedDict([
    ("overlay_ratio", "How much data is tacked on past the program's proper end"),
    ("packer_hit",
     "Matches a known packer such as UPX, meaning the real contents have been "
     "compressed out of sight"),
    ("rule_hits", "How many detection rules this file set off"),
    ("rule_max_severity", "How serious the worst rule it set off was, from 0 to 5"),
    ("res_entropy_max", "How scrambled the most random bundled resource looks"),
])

FEATURE_DOCS: "OrderedDict[str, str]" = OrderedDict()
for _group, _items in FEATURE_GROUPS.items():
    FEATURE_DOCS.update(_items)

FEATURE_NAMES: list[str] = list(FEATURE_DOCS.keys())
N_FEATURES = len(FEATURE_NAMES)

# Reverse index: feature -> group, used by the UI to colour explanations.
FEATURE_TO_GROUP = {
    name: group for group, items in FEATURE_GROUPS.items() for name in items
}


def blank_features() -> dict[str, float]:
    """A zero-filled feature dict in canonical order."""
    return {name: 0.0 for name in FEATURE_NAMES}


def to_vector(features: dict[str, float]) -> list[float]:
    """Order a feature dict into the model's expected input vector."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
