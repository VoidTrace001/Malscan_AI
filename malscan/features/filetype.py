"""File type detection from magic bytes.

Uses ``python-magic`` when it is installed and its libmagic backend actually
loads. That is a fussy dependency on Windows, so there is a built-in magic-byte
table to fall back on.

Note that nothing here looks at the file extension. Anyone can rename a file.
"""
from __future__ import annotations

from dataclasses import dataclass

try:  # pragma: no cover - environment dependent
    import magic as _magic  # type: ignore

    _magic.from_buffer(b"test")  # libmagic DLL is only touched on first call
    HAVE_MAGIC = True
except Exception:  # pragma: no cover
    _magic = None
    HAVE_MAGIC = False


# (offset, signature, category, label)
_SIGNATURES: list[tuple[int, bytes, str, str]] = [
    (0, b"MZ", "pe", "Windows executable (PE/MZ)"),
    (0, b"\x7fELF", "elf", "Linux executable (ELF)"),
    # 0xCAFEBABE is shared by Java class files and Mach-O fat binaries. The
    # two are separated below by the bytes that follow, not by this table.
    (0, b"\xca\xfe\xba\xbe", "java_or_macho", "Java class or Mach-O fat binary"),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O 64-bit binary"),
    (0, b"%PDF", "document", "PDF document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "document", "Legacy Office document (OLE2)"),
    (0, b"PK\x03\x04", "archive", "ZIP container (may be a modern Office file)"),
    (0, b"Rar!\x1a\x07", "archive", "RAR archive"),
    (0, b"\x1f\x8b", "archive", "GZIP archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip archive"),
    (0, b"\xfd7zXZ", "archive", "XZ archive"),
    (0, b"\x89PNG", "image", "PNG image"),
    (0, b"\xff\xd8\xff", "image", "JPEG image"),
    (0, b"GIF8", "image", "GIF image"),
    (0, b"dex\n", "android", "Android DEX bytecode"),
]

_SCRIPT_HINTS = (
    b"#!/", b"<?php", b"<script", b"import ", b"function ", b"#include",
    b"powershell", b"Set-", b"$(", b"@echo", b"using System",
)

_OFFICE_XML_MARKERS = (b"word/", b"xl/", b"ppt/", b"[Content_Types].xml")


@dataclass
class FileType:
    category: str        # pe | script | document | archive | image | other ...
    label: str           # human readable
    detail: str = ""     # extra info (libmagic string, or refinement)

    @property
    def is_pe(self) -> bool:
        return self.category == "pe"

    @property
    def is_script(self) -> bool:
        return self.category == "script"

    @property
    def is_document(self) -> bool:
        return self.category == "document"

    @property
    def is_archive(self) -> bool:
        return self.category == "archive"


def detect(data: bytes, filename: str = "") -> FileType:
    """Identify a buffer by content, refining a few ambiguous containers."""
    head = data[:4096]

    for offset, sig, category, label in _SIGNATURES:
        if head[offset : offset + len(sig)] == sig:
            ft = FileType(category=category, label=label)
            if category == "java_or_macho":
                # A Java class file stores minor/major version right after the
                # magic; a Mach-O fat header stores an architecture count,
                # which is always small. Java major versions start at 45.
                major = int.from_bytes(head[6:8], "big")
                ft = (
                    FileType("java", f"Java class file (major version {major})")
                    if major >= 45
                    else FileType("macho", "Mach-O fat binary")
                )
            if category == "archive" and sig == b"PK\x03\x04":
                probe = data[:65536]
                if any(m in probe for m in _OFFICE_XML_MARKERS):
                    ft = FileType("document", "Modern Office document (OOXML)")
            if HAVE_MAGIC:
                try:
                    ft.detail = _magic.from_buffer(data[:8192])
                except Exception:
                    pass
            return ft

    # No binary signature: decide between script/text and unknown binary.
    sample = head[:2048]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    if sample and printable / len(sample) > 0.90:
        lowered = sample.lower()
        if any(h.lower() in lowered for h in _SCRIPT_HINTS):
            return FileType("script", "Script / source file")
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in {"ps1", "bat", "cmd", "sh", "js", "vbs", "py", "pl", "rb", "php"}:
            return FileType("script", f"Script file (.{ext})")
        return FileType("text", "Plain text")

    return FileType("other", "Unrecognised binary")
