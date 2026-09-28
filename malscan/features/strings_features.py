"""Embedded string mining.

Strings survive compilation, which makes them leaky: the URL a dropper calls
home to, the registry key it writes for persistence, the API name a packer
resolves at runtime. This pulls out the printable ones and scores them.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

# --- regexes over the extracted strings -----------------------------------
RE_URL = re.compile(r"https?://[^\s\"'<>\\]{4,}", re.IGNORECASE)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_REGISTRY = re.compile(
    r"(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\[A-Za-z])[\\\w .-]*", re.IGNORECASE
)
RE_PATH = re.compile(r"[A-Za-z]:\\[\w .\\-]{3,}|/(?:usr|etc|tmp|var|home)/[\w./-]{3,}")
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
RE_PDB = re.compile(r"[A-Za-z]:\\[^\s]*\.pdb", re.IGNORECASE)

# API / behaviour keywords that repeatedly show up in offensive tooling.
SUSPICIOUS_KEYWORDS = {
    # process injection / memory
    "virtualalloc", "virtualprotect", "writeprocessmemory", "readprocessmemory",
    "createremotethread", "ntunmapviewofsection", "queueuserapc",
    "setwindowshookex", "openprocess", "resumethread", "suspendthread",
    # dynamic API resolution
    "loadlibrarya", "loadlibraryw", "getprocaddress", "ldrloaddll",
    # persistence
    "currentversion\\run", "schtasks", "createservice",
    "regsetvalue", "regcreatekey", "userinit", "winlogon",
    # anti-analysis
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "outputdebugstring", "vmware", "virtualbox",
    "sandboxie", "wireshark", "ollydbg", "x64dbg", "procmon",
    # credential / data theft
    "cryptunprotectdata", "lsass", "keylog", "getasynckeystate",
    "clipboard", "screenshot", "password", "credential",
    # network / c2
    "internetopena", "internetconnect", "httpsendrequest", "winhttpopen",
    "urldownloadtofile", "wsastartup",
    # destructive / ransom
    "vssadmin", "delete shadows", "bcdedit", "cipher /w",
    "cryptencrypt", "cryptgenkey", "bitcoin", "ransom", "decrypt your files",
    # living-off-the-land
    "powershell -enc", "-encodedcommand", "invoke-expression", "iex(",
    "downloadstring", "frombase64string", "rundll32", "regsvr32", "mshta",
    "wscript.shell", "cmd.exe /c", "certutil -decode",
}

_CRYPTO_CONSTANTS = (
    b"\x67\x45\x23\x01",              # MD5 / SHA state init
    b"\xd7\x6a\xa4\x78",              # MD5 sine table
    b"\x63\x7c\x77\x7b\xf2\x6b\x6f",  # AES S-box head
    b"\x2b\x7e\x15\x16",              # AES FIPS-197 test key
)


@dataclass
class StringStats:
    count: int = 0
    avg_len: float = 0.0
    max_len: int = 0
    max_entropy: float = 0.0
    urls: int = 0
    ips: int = 0
    registry: int = 0
    paths: int = 0
    suspicious: int = 0
    base64_blobs: int = 0
    has_pdb: int = 0
    embedded_mz: int = 0
    crypto_constants: int = 0
    # kept for the UI, not fed to the model
    top_urls: list[str] = field(default_factory=list)
    top_ips: list[str] = field(default_factory=list)
    matched_keywords: list[str] = field(default_factory=list)
    sample_strings: list[str] = field(default_factory=list)


def extract_strings(data: bytes, min_len: int = 5, limit: int = 8 * 1024 * 1024) -> list[str]:
    """Pull ASCII and UTF-16LE printable runs out of a buffer."""
    buf = data[:limit]
    ascii_strings = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, buf)
    # UTF-16LE shows up constantly in Windows binaries (wide-char literals).
    wide_strings = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, buf)

    out = [s.decode("ascii", "ignore") for s in ascii_strings]
    out += [s.decode("utf-16-le", "ignore") for s in wide_strings]
    return out


def _string_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _plausible_ip(ip: str) -> bool:
    """Filter version strings like 1.2.3.4 that are not really addresses."""
    parts = ip.split(".")
    try:
        if any(int(p) > 255 for p in parts):
            return False
    except ValueError:
        return False
    # 0.x and 1.0.0.x are almost always version numbers, not C2 addresses.
    if parts[0] == "0" or ip.startswith("1.0.0"):
        return False
    return True


def analyse_strings(
    data: bytes, min_len: int = 5, limit: int = 8 * 1024 * 1024
) -> StringStats:
    strings = extract_strings(data, min_len=min_len, limit=limit)
    stats = StringStats(count=len(strings))
    if not strings:
        return stats

    lengths = [len(s) for s in strings]
    stats.avg_len = sum(lengths) / len(lengths)
    stats.max_len = max(lengths)

    # Entropy is only meaningful on longer strings; short ones are noisy.
    long_strings = [s for s in strings if len(s) >= 16]
    if long_strings:
        stats.max_entropy = max(_string_entropy(s) for s in long_strings)

    joined = "\n".join(strings)
    lowered = joined.lower()

    urls = RE_URL.findall(joined)
    ips = [ip for ip in RE_IP.findall(joined) if _plausible_ip(ip)]
    stats.urls = len(urls)
    stats.ips = len(ips)
    stats.registry = len(RE_REGISTRY.findall(joined))
    stats.paths = len(RE_PATH.findall(joined))
    stats.base64_blobs = len(RE_BASE64.findall(joined))
    stats.has_pdb = 1 if RE_PDB.search(joined) else 0

    matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    stats.suspicious = len(matched)
    stats.matched_keywords = sorted(matched)[:40]

    stats.top_urls = list(dict.fromkeys(urls))[:15]
    stats.top_ips = list(dict.fromkeys(ips))[:15]
    # A readable cross-section for the UI: the longest strings tend to be the
    # interesting ones (paths, commands, ransom notes).
    stats.sample_strings = sorted(set(strings), key=len, reverse=True)[:40]

    # An extra "MZ" beyond offset 0 often means a dropped/embedded payload.
    stats.embedded_mz = max(0, data.count(b"MZ\x90\x00") - 1)
    stats.crypto_constants = sum(1 for c in _CRYPTO_CONSTANTS if c in data)

    return stats
