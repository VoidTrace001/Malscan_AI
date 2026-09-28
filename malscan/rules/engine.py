"""Rule matching.

``yara-python`` is the preferred backend, but it is a native extension and does
not always install cleanly (older Pythons, locked-down machines). So there is
also a pure-Python matcher that handles a useful subset of the same rule file:
plain text strings, plus ``N of them`` and ``any of them`` conditions.

Callers get the same result shape either way and never have to care which one
answered.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from malscan.config import CONFIG

try:
    import yara  # type: ignore
    HAVE_YARA = True
except Exception:  # pragma: no cover
    yara = None
    HAVE_YARA = False


@dataclass
class _FallbackRule:
    name: str
    description: str
    severity: int
    category: str
    strings: list[bytes]
    threshold: int
    requires_mz: bool


class RuleEngine:
    """Compiles the rule file once and scans buffers against it."""

    def __init__(self, rules_path=None):
        self.rules_path = rules_path or CONFIG.rules_file
        self.backend = "none"
        self.error = ""
        self._yara_rules = None
        self._fallback: list[_FallbackRule] = []
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.rules_path.exists():
            self.error = f"Rule file not found: {self.rules_path}"
            return

        source = self.rules_path.read_text(encoding="utf-8", errors="ignore")

        if HAVE_YARA:
            try:
                self._yara_rules = yara.compile(source=source)
                self.backend = "yara-python"
                return
            except Exception as exc:  # fall through to the Python matcher
                self.error = f"YARA compile failed, using fallback: {exc}"

        self._fallback = _parse_fallback_rules(source)
        self.backend = "builtin" if self._fallback else "none"

    # ------------------------------------------------------------------
    @property
    def rule_count(self) -> int:
        if self._yara_rules is not None:
            return sum(1 for _ in self._yara_rules)
        return len(self._fallback)

    def scan(self, data: bytes) -> list[dict]:
        """Return a list of matches: name, description, severity, category."""
        if self._yara_rules is not None:
            return self._scan_yara(data)
        return self._scan_fallback(data)

    # ------------------------------------------------------------------
    def _scan_yara(self, data: bytes) -> list[dict]:
        try:
            matches = self._yara_rules.match(data=data, timeout=30)
        except Exception as exc:
            self.error = f"YARA scan error: {exc}"
            return []

        out = []
        for m in matches:
            meta = m.meta or {}
            out.append(
                {
                    "name": m.rule,
                    "description": meta.get("description", m.rule),
                    "severity": int(meta.get("severity", 2)),
                    "category": meta.get("category", "general"),
                    "matched_strings": _yara_match_preview(m),
                }
            )
        return sorted(out, key=lambda r: -r["severity"])

    def _scan_fallback(self, data: bytes) -> list[dict]:
        lowered = data.lower()
        is_mz = data[:2] == b"MZ"
        out = []
        for rule in self._fallback:
            if rule.requires_mz and not is_mz:
                continue
            hits = [s for s in rule.strings if s.lower() in lowered]
            if len(hits) >= rule.threshold:
                out.append(
                    {
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "category": rule.category,
                        "matched_strings": [
                            h.decode("utf-8", "ignore") for h in hits[:6]
                        ],
                    }
                )
        return sorted(out, key=lambda r: -r["severity"])


def _yara_match_preview(match) -> list[str]:
    """Readable list of which strings actually fired, across yara versions."""
    previews: list[str] = []
    for s in getattr(match, "strings", []) or []:
        # yara-python >= 4.3 yields StringMatch objects; older yields tuples.
        identifier = getattr(s, "identifier", None)
        if identifier is None and isinstance(s, tuple) and len(s) >= 3:
            identifier = s[1]
            value = s[2]
            previews.append(f"{identifier}: {_safe_text(value)}")
            continue
        instances = getattr(s, "instances", []) or []
        if instances:
            value = getattr(instances[0], "matched_data", b"")
            previews.append(f"{identifier}: {_safe_text(value)}")
        elif identifier:
            previews.append(str(identifier))
    return previews[:8]


def _safe_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "ignore")
    else:
        text = str(value)
    text = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return text[:80]


# ----------------------------------------------------------------------
# Fallback parser: enough YARA to keep the rule file as the single source
# of truth even when the native module is unavailable.
# ----------------------------------------------------------------------
_RULE_BLOCK = re.compile(r"rule\s+(\w+)\s*\{(.*?)\n\}", re.DOTALL)
_META_ITEM = re.compile(r'(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*(\d+)')
_TEXT_STRING = re.compile(r'\$\w*\s*=\s*"((?:[^"\\]|\\.)*)"')
_COUNT_COND = re.compile(r"(\d+|any|all)\s+of\s+them", re.IGNORECASE)


def _parse_fallback_rules(source: str) -> list[_FallbackRule]:
    rules: list[_FallbackRule] = []
    for name, body in _RULE_BLOCK.findall(source):
        meta_section = _section(body, "meta:")
        strings_section = _section(body, "strings:")
        cond_section = _section(body, "condition:")

        meta: dict[str, str] = {}
        for m in _META_ITEM.finditer(meta_section):
            key = m.group(1) or m.group(3)
            val = m.group(2) if m.group(2) is not None else m.group(4)
            meta[key] = val

        literals = []
        for raw in _TEXT_STRING.findall(strings_section):
            try:
                literal = raw.encode().decode("unicode_escape").encode("latin-1")
            except Exception:
                literal = raw.encode("utf-8", "ignore")
            if len(literal) >= 3:
                literals.append(literal)
        if not literals:
            continue  # hex/regex-only rules are skipped by the fallback

        threshold = len(literals)
        cm = _COUNT_COND.search(cond_section)
        if cm:
            token = cm.group(1).lower()
            threshold = 1 if token == "any" else len(literals) if token == "all" else int(token)
        elif " and " in cond_section:
            threshold = max(2, len(literals) // 2)
        else:
            threshold = 1

        rules.append(
            _FallbackRule(
                name=name,
                description=meta.get("description", name),
                severity=int(meta.get("severity", 2)),
                category=meta.get("category", "general"),
                strings=literals,
                threshold=min(threshold, len(literals)),
                requires_mz="uint16(0) == 0x5A4D" in cond_section,
            )
        )
    return rules


def _section(body: str, header: str) -> str:
    """Slice one `meta:` / `strings:` / `condition:` block out of a rule body."""
    start = body.find(header)
    if start == -1:
        return ""
    start += len(header)
    ends = [
        body.find(h, start)
        for h in ("meta:", "strings:", "condition:")
        if body.find(h, start) != -1
    ]
    return body[start : min(ends)] if ends else body[start:]


# ----------------------------------------------------------------------
_engine: RuleEngine | None = None
_lock = threading.Lock()


def get_engine() -> RuleEngine:
    """Process-wide singleton -- compiling rules on every scan would be waste."""
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = RuleEngine()
    return _engine


def reload_engine() -> RuleEngine:
    global _engine
    with _lock:
        _engine = RuleEngine()
    return _engine
