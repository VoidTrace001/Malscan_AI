"""File identity hashes.

These never go to the model; there is no pattern in a hash to generalise from.
They are here to identify a sample in the scan history and to give the user
something to paste into VirusTotal.
"""
from __future__ import annotations

import hashlib


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def ssdeep_like(data: bytes, block: int = 4096) -> str:
    """A small rolling block digest used as a cheap similarity fingerprint.

    This is a stand-in for ssdeep/TLSH: each 4 KB block is reduced to one
    base32 character derived from its md5, so two near-identical files produce
    near-identical strings. Good enough to spot repeat uploads and variants.
    """
    if not data:
        return ""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    out = []
    for i in range(0, len(data), block):
        h = hashlib.md5(data[i : i + block]).digest()[0]
        out.append(alphabet[h % 32])
    return "".join(out[:64])
