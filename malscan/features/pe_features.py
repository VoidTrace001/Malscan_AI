"""PE (Portable Executable) structural analysis.

Everything here is *static*: the file is parsed as a data structure, never
loaded or executed. ``pefile`` does the parsing; this module turns the parse
tree into the numeric features the model was trained on, plus a human-readable
report for the UI.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:  # pragma: no cover
    pefile = None
    HAVE_PEFILE = False

from malscan.features.entropy import shannon_entropy

# The only data directories anything below actually walks. The presence flags
# (debug, relocs, TLS, resources, signature) are read straight off the optional
# header's directory table, which needs no directory parsing at all -- so
# parsing the full set just to reach imports, exports and resources drags in
# the exception directory, which on a sizeable binary costs more than the whole
# rest of the scan and is never once looked at.
_PARSED_DIRECTORIES = [
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
]

# Section names the mainstream toolchains emit. Anything outside this list is
# worth a note; packers tend to write UPX0/UPX1, .aspack, .themida and so on.
STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".xdata",
    ".rsrc", ".reloc", ".bss", ".tls", ".debug", ".didat", ".sdata",
    "code", "data", ".00cfg", ".gfids", ".textbss", ".crt", ".init",
    ".fini", ".rodata", ".comment", ".note", ".eh_fram", ".gcc_exc",
}

PACKER_SECTION_HINTS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    "pec1": "PECompact", "pec2": "PECompact",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".mew": "MEW", ".fsg": "FSG", ".packed": "Generic packer",
    ".yp": "Y0da", ".boom": "Generic packer", "kkrunchy": "kkrunchy",
}

PACKER_BYTE_HINTS = {
    b"UPX!": "UPX",
    b"UPX0": "UPX",
    b"ASPack": "ASPack",
    b"PECompact2": "PECompact",
    b"MPRESS1": "MPRESS",
    b".vmp0": "VMProtect",
    b"Themida": "Themida",
    b"FSG!": "FSG",
    b"PEtite": "Petite",
}

# APIs that are legitimate on their own but form well-known offensive
# building blocks (injection, hollowing, persistence, anti-analysis).
SUSPICIOUS_APIS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "readprocessmemory", "createremotethread",
    "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread",
    "queueuserapc", "ntunmapviewofsection", "ntmapviewofsection",
    "setthreadcontext", "getthreadcontext", "openprocess", "openthread",
    "suspendthread", "resumethread", "createprocessinternalw",
    "setwindowshookexa", "setwindowshookexw", "getasynckeystate",
    "getkeyboardstate", "attachthreadinput", "blockinput",
    "isdebuggerpresent", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "ntsetinformationthread", "outputdebugstringa",
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
    "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress",
    "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
    "createservicea", "createservicew", "openscmanagera", "startservicea",
    "adjusttokenprivileges", "lookupprivilegevaluea", "openprocesstoken",
    "createtoolhelp32snapshot", "process32first", "process32next",
    "module32first", "shellexecutea", "shellexecutew", "winexec",
    "urldownloadtofilea", "urldownloadtofilew", "internetopena",
    "internetopenurla", "internetreadfile", "httpsendrequesta",
    "winhttpsendrequest", "wsastartup", "wsasocketa", "inet_addr",
    "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptacquirecontexta",
    "cryptunprotectdata", "cryptstringtobinarya",
    "findfirstfilea", "findnextfilea", "deletefilea", "movefileexa",
    "setfileattributesa", "createfilemappinga", "mapviewoffile",
    "getmodulefilenamea", "gettickcount", "queryperformancecounter",
    "sleep", "sleepex", "terminateprocess", "exitwindowsex",
}

NETWORK_DLLS = {"ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll",
                "urlmon.dll", "netapi32.dll", "dnsapi.dll", "iphlpapi.dll"}
CRYPTO_DLLS = {"crypt32.dll", "advapi32.dll", "bcrypt.dll", "ncrypt.dll",
               "cryptsp.dll", "cryptbase.dll"}
SHELL_DLLS = {"shell32.dll", "shlwapi.dll"}


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    is_executable: bool
    is_writable: bool
    is_readable: bool

    @property
    def is_wx(self) -> bool:
        return self.is_executable and self.is_writable

    @property
    def vsize_ratio(self) -> float:
        if self.raw_size == 0:
            return 10.0 if self.virtual_size > 0 else 0.0
        return self.virtual_size / self.raw_size


@dataclass
class PEReport:
    parsed: bool = False
    error: str = ""
    is_64bit: bool = False
    is_dll: bool = False
    machine: str = ""
    subsystem: str = ""
    timestamp: int = 0
    timestamp_str: str = ""
    timestamp_plausible: bool = False
    timestamp_age_years: float = 0.0
    size_of_code: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum_stored: int = 0
    checksum_actual: int = 0
    checksum_valid: bool = False
    entry_point: int = 0
    entry_point_section: str = ""
    entry_point_in_code: bool = False
    entry_point_entropy: float = 0.0
    aslr: bool = False
    dep: bool = False
    seh: bool = True
    has_debug: bool = False
    has_relocs: bool = False
    has_tls: bool = False
    has_resources: bool = False
    has_signature: bool = False
    has_version_info: bool = False
    version_info: dict = field(default_factory=dict)
    sections: list[SectionInfo] = field(default_factory=list)
    imports: dict = field(default_factory=dict)      # dll -> [functions]
    import_count: int = 0
    suspicious_apis: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    imphash: str = ""
    overlay_size: int = 0
    overlay_ratio: float = 0.0
    resource_max_entropy: float = 0.0
    resource_count: int = 0
    packer: str = ""
    anomalies: list[str] = field(default_factory=list)


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def parse_pe(data: bytes) -> PEReport:
    """Parse a PE buffer into a structured report. Never raises."""
    report = PEReport()
    if not HAVE_PEFILE:
        report.error = "pefile is not installed"
        return report
    if len(data) < 64 or data[:2] != b"MZ":
        report.error = "Not a PE file (missing MZ header)"
        return report

    try:
        pe = pefile.PE(data=data, fast_load=True)
        # Load only what we read. A directory that will not parse is a quirk of
        # this one file, not grounds for calling the whole header malformed, so
        # a failure here leaves that directory empty and the parse stands.
        _safe(lambda: pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY[d] for d in _PARSED_DIRECTORIES]
        ))
    except Exception as exc:
        report.error = f"PE parse failed: {exc}"
        # A malformed header is itself a signal, so record it rather than
        # discarding the file.
        report.anomalies.append("PE header is malformed or truncated")
        return report

    try:
        report.parsed = True
        _fill_header(report, pe, data)
        _fill_sections(report, pe)
        _fill_imports(report, pe)
        _fill_exports(report, pe)
        _fill_resources(report, pe)
        _fill_overlay(report, pe, data)
        _detect_packer(report, data)
        _collect_anomalies(report)
    except Exception as exc:  # defensive: a partial report beats no report
        report.error = f"Partial analysis: {exc}"
    finally:
        _safe(pe.close)

    return report


def _fill_header(report: PEReport, pe, data: bytes) -> None:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER

    report.is_64bit = oh.Magic == 0x20B
    report.is_dll = bool(fh.Characteristics & 0x2000)
    report.machine = _safe(lambda: pefile.MACHINE_TYPE[fh.Machine], "") or hex(fh.Machine)
    report.machine = report.machine.replace("IMAGE_FILE_MACHINE_", "")
    report.subsystem = (
        _safe(lambda: pefile.SUBSYSTEM_TYPE[oh.Subsystem], "") or str(oh.Subsystem)
    ).replace("IMAGE_SUBSYSTEM_", "")

    report.timestamp = fh.TimeDateStamp
    now = time.time()
    # 1995-01-01 .. now + 1 day. Zeroed, future or absurdly old timestamps are
    # a classic sign of a tampered or reproducible-build-faked header.
    report.timestamp_plausible = 788918400 < fh.TimeDateStamp < now + 86400
    if report.timestamp:
        report.timestamp_str = _safe(
            lambda: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(fh.TimeDateStamp)),
            "invalid",
        )
        report.timestamp_age_years = max(0.0, (now - fh.TimeDateStamp) / 31_557_600)
    else:
        report.timestamp_str = "0 (not set)"

    report.size_of_code = oh.SizeOfCode
    report.size_of_image = oh.SizeOfImage
    report.size_of_headers = oh.SizeOfHeaders
    report.checksum_stored = oh.CheckSum
    # Recomputing means pefile serialising the whole image back out, which is
    # the single most expensive thing in a scan. With no checksum stored there
    # is nothing to compare against and the verdict is "not set" either way, so
    # only pay for it when the answer can actually differ.
    if report.checksum_stored:
        report.checksum_actual = _safe(pe.generate_checksum, 0) or 0
    report.checksum_valid = (
        report.checksum_stored != 0
        and report.checksum_stored == report.checksum_actual
    )

    dc = oh.DllCharacteristics
    report.aslr = bool(dc & 0x0040)   # DYNAMIC_BASE
    report.dep = bool(dc & 0x0100)    # NX_COMPAT
    report.seh = not bool(dc & 0x0400)  # NO_SEH

    report.entry_point = oh.AddressOfEntryPoint

    def _dir(name: str) -> bool:
        d = _safe(lambda: oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[name]])
        return bool(d and d.VirtualAddress and d.Size)

    report.has_debug = _dir("IMAGE_DIRECTORY_ENTRY_DEBUG")
    report.has_relocs = _dir("IMAGE_DIRECTORY_ENTRY_BASERELOC")
    report.has_tls = _dir("IMAGE_DIRECTORY_ENTRY_TLS")
    report.has_resources = _dir("IMAGE_DIRECTORY_ENTRY_RESOURCE")
    report.has_signature = _dir("IMAGE_DIRECTORY_ENTRY_SECURITY")

    report.imphash = _safe(pe.get_imphash, "") or ""


def _fill_sections(report: PEReport, pe) -> None:
    for section in pe.sections:
        raw = _safe(section.get_data, b"") or b""
        name = section.Name.rstrip(b"\x00").decode("utf-8", "ignore").strip()
        ch = section.Characteristics
        report.sections.append(
            SectionInfo(
                name=name or "(unnamed)",
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=shannon_entropy(raw),
                characteristics=ch,
                is_executable=bool(ch & 0x20000000),
                is_writable=bool(ch & 0x80000000),
                is_readable=bool(ch & 0x40000000),
            )
        )

    # Locate the section holding the entry point.
    ep = report.entry_point
    for sec in report.sections:
        if sec.virtual_address <= ep < sec.virtual_address + max(
            sec.virtual_size, sec.raw_size
        ):
            report.entry_point_section = sec.name
            report.entry_point_in_code = sec.is_executable
            report.entry_point_entropy = sec.entropy
            break


def _fill_imports(report: PEReport, pe) -> None:
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []
    for entry in entries:
        dll = (entry.dll or b"").decode("utf-8", "ignore").lower()
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("utf-8", "ignore"))
            elif imp.ordinal is not None:
                funcs.append(f"ordinal_{imp.ordinal}")
        report.imports[dll] = funcs
        report.import_count += len(funcs)

    for dll, funcs in report.imports.items():
        for fn in funcs:
            if fn.lower() in SUSPICIOUS_APIS:
                report.suspicious_apis.append(f"{dll}!{fn}")
    report.suspicious_apis.sort()


def _fill_exports(report: PEReport, pe) -> None:
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not exp:
        return
    for sym in exp.symbols:
        if sym.name:
            report.exports.append(sym.name.decode("utf-8", "ignore"))
        else:
            report.exports.append(f"ordinal_{sym.ordinal}")


def _fill_resources(report: PEReport, pe) -> None:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return
    max_entropy, count = 0.0, 0
    for res_type in root.entries:
        for res_id in getattr(res_type, "directory", type("x", (), {"entries": []})).entries:
            for res_lang in getattr(res_id, "directory", type("x", (), {"entries": []})).entries:
                data_rva = _safe(lambda: res_lang.data.struct.OffsetToData)
                size = _safe(lambda: res_lang.data.struct.Size, 0) or 0
                if not data_rva or not size or size > 16 * 1024 * 1024:
                    continue
                blob = _safe(lambda: pe.get_data(data_rva, size), b"") or b""
                if blob:
                    count += 1
                    max_entropy = max(max_entropy, shannon_entropy(blob))
    report.resource_count = count
    report.resource_max_entropy = max_entropy

    vs = getattr(pe, "VS_FIXEDFILEINFO", None)
    fi = getattr(pe, "FileInfo", None)
    report.has_version_info = bool(vs or fi)
    if fi:
        for file_info in fi:
            for entry in file_info:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        report.version_info[k.decode("utf-8", "ignore")] = v.decode(
                            "utf-8", "ignore"
                        )


def _fill_overlay(report: PEReport, pe, data: bytes) -> None:
    """Overlay = bytes appended past the last section.

    Installers legitimately use it, but so do droppers hiding a payload.
    """
    offset = _safe(pe.get_overlay_data_start_offset)
    if offset is None or offset >= len(data):
        return
    report.overlay_size = len(data) - offset
    report.overlay_ratio = report.overlay_size / max(1, len(data))


def _detect_packer(report: PEReport, data: bytes) -> None:
    for sec in report.sections:
        hit = PACKER_SECTION_HINTS.get(sec.name.lower())
        if hit:
            report.packer = hit
            return
    head = data[:4096] + data[-4096:]
    for sig, name in PACKER_BYTE_HINTS.items():
        if sig in head:
            report.packer = name
            return


def _collect_anomalies(report: PEReport) -> None:
    """Plain-language notes shown alongside the verdict."""
    a = report.anomalies

    if report.packer:
        a.append(f"Packed or protected with {report.packer}")
    if not report.timestamp_plausible:
        a.append(f"Compile timestamp is implausible ({report.timestamp_str})")
    if report.checksum_stored and not report.checksum_valid:
        a.append("Stored PE checksum does not match the file contents")
    if not report.aslr:
        a.append("ASLR is disabled")
    if not report.dep:
        a.append("DEP / NX is disabled")

    high = [s for s in report.sections if s.entropy >= 7.4]
    if high:
        names = ", ".join(s.name for s in high[:4])
        a.append(f"High-entropy section(s) suggest compression or encryption: {names}")

    wx = [s for s in report.sections if s.is_wx]
    if wx:
        a.append(
            "Writable + executable section(s): "
            + ", ".join(s.name for s in wx[:4])
            + " (self-modifying or unpacking code)"
        )

    odd = [
        s for s in report.sections
        if s.name.lower() not in STANDARD_SECTIONS and s.name != "(unnamed)"
    ]
    if odd:
        a.append("Non-standard section name(s): " + ", ".join(s.name for s in odd[:4]))

    stuffed = [s for s in report.sections if s.raw_size == 0 and s.virtual_size > 0]
    if stuffed:
        a.append(
            "Section(s) with zero raw size but non-zero virtual size: "
            + ", ".join(s.name for s in stuffed[:4])
            + " (space reserved for an unpacked payload)"
        )

    if report.entry_point_section and not report.entry_point_in_code:
        a.append(
            f"Entry point sits in non-executable section '{report.entry_point_section}'"
        )

    if 0 < report.import_count <= 8:
        a.append(
            f"Only {report.import_count} imported function(s) -- the real import "
            "table is likely resolved at runtime"
        )
    if report.import_count == 0 and report.parsed:
        a.append("No import table at all (strong packing indicator)")

    names = {f.split("!", 1)[-1].lower() for f in report.suspicious_apis}
    if "loadlibrarya" in names or "loadlibraryw" in names:
        if "getprocaddress" in names:
            a.append("Imports LoadLibrary + GetProcAddress (dynamic API resolution)")

    if report.overlay_ratio > 0.25:
        a.append(
            f"Overlay data is {report.overlay_ratio:.0%} of the file "
            "(possible embedded payload)"
        )
    # Compressed media (PNG icons, JPEGs) legitimately sit near 7.9, so only
    # flag a resource that is denser than ordinary compression explains.
    if report.resource_max_entropy >= 7.95:
        a.append(
            "A resource is denser than normal compression explains "
            "(possible encrypted payload)"
        )
    if not report.has_signature:
        a.append(
            "No embedded Authenticode signature (note: Microsoft system files "
            "are usually catalog-signed instead, which static parsing cannot see)"
        )
    if not report.has_version_info:
        a.append("No version information resource")
