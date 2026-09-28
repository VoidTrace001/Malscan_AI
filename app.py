"""MalScan AI — Streamlit entry point.

Run with:
    streamlit run app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow 'streamlit run app.py' from any working directory.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

st.set_page_config(
    page_title="MalScan AI — Malware Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from malscan import __version__  # noqa: E402
from malscan.config import CONFIG  # noqa: E402
from malscan.ui import (  # noqa: E402
    page_dashboard, page_history, page_model, page_rules, page_scan,
)
from malscan.ui.theme import brand_header, inject_css  # noqa: E402

PAGES = {
    "Scan": page_scan.render,
    "Dashboard": page_dashboard.render,
    "History": page_history.render,
    "Model": page_model.render,
    "Detection rules": page_rules.render,
    "About": None,
}


def main() -> None:
    inject_css()

    with st.sidebar:
        st.markdown("### MalScan AI")
        st.caption(f"v{__version__} · static analysis only")

        choice = st.radio(
            "Navigation",
            list(PAGES.keys()),
            label_visibility="collapsed",
        )

        st.divider()
        _sidebar_status()

    brand_header()

    if choice == "About":
        _about()
    else:
        PAGES[choice]()


def _sidebar_status() -> None:
    """A compact, honest read-out of what is actually loaded."""
    from malscan.model.predict import get_classifier
    from malscan.rules.engine import get_engine
    from malscan.storage.history import get_history

    classifier = get_classifier()
    engine = get_engine()

    st.markdown("**System status**")
    if classifier.is_trained:
        st.markdown(f"Model: `{classifier.model_name}`")
    else:
        st.markdown("⚠️ Model: **heuristic fallback**")
        st.caption("Train a model on the Model page.")

    st.markdown(f"Rules: `{engine.rule_count}` via `{engine.backend}`")

    try:
        total = get_history().stats()["total"]
        st.markdown(f"Scans recorded: `{total:,}`")
    except Exception:
        pass

    st.divider()
    st.caption(
        "Uploaded files are parsed as data and never executed. "
        f"Limit {CONFIG.max_upload_mb} MB."
    )


def _about() -> None:
    st.subheader("About MalScan AI")

    st.markdown(
        """
**MalScan AI** classifies files as malicious or benign from their *static*
structure alone — the file is parsed as data and never run.

Built by **Tamal Mishra** (BCA, Cybersecurity — EThames Business School,
Hyderabad) as an academic project exploring machine learning as an alternative
to signature-only malware detection.

##### Why not just use signatures?

A signature only matches what someone has already catalogued. It cannot
generalise, which leaves it weak against:

- **Zero-day malware** that has never been seen before
- **Polymorphic and metamorphic malware** that rewrites itself between infections
- **Packed or obfuscated payloads** whose bytes differ every build

A model working on *structural* features does not need to have seen the
specific sample. It picks up what malicious files tend to have in common:
entropy that suggests packing, import tables that have obviously been
stripped, sections that are writable and executable at the same time, API
combinations that only make sense if you are injecting into another process.

##### How a scan works

1. **File type detection** from magic bytes, never the extension
2. **Static feature extraction** — 73 features covering PE headers, sections,
   imports, entropy, embedded strings and packing indicators
3. **Rule matching** against the bundled signature set
4. **Classification** by the trained ensemble, producing a calibrated probability
5. **Explanation** by ablation — each feature is reset to its typical benign
   value to measure how much it moved *this file's* score
6. **Logging** to SQLite so results can be revisited

##### Being clear about the limits

This is a working prototype. The caveats below matter more than the accuracy
number does:

- **Static analysis cannot see runtime behaviour.** A file that only decrypts
  its payload once it is running leaves very little on disk to catch.
- **The malicious training class is synthesised** from documented behaviour
  profiles rather than taken from live samples. The Model page goes into this
  properly. The accuracy figure reflects the relationship encoded in that data,
  not a detection rate measured in the field.
- **A verdict is evidence, not proof.** Plenty of legitimate packed software
  trips the same indicators. That is what the middle "Suspicious" band is for,
  instead of forcing a binary call.

##### Technology

| Component | Choice |
|---|---|
| Language | Python 3.9+ |
| Interface | Streamlit |
| Models | scikit-learn (Random Forest), XGBoost |
| PE parsing | pefile |
| Rule matching | yara-python, with a pure-Python fallback |
| File typing | magic bytes, optionally python-magic |
| Visualisation | Plotly |
| Storage | SQLite |

##### Where this could go next

- Cross-referencing verdicts against the VirusTotal API
- Dynamic analysis in an isolated sandbox to observe real behaviour
- Wider format coverage — APKs, Office macros, scripts
- Retraining on a real labelled corpus (the training script already accepts one)
        """
    )

    st.divider()
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Features extracted", "73")
    with c2:
        from malscan.rules.engine import get_engine
        st.metric("Detection rules", get_engine().rule_count)
    with c3:
        st.metric("Version", __version__)


if __name__ == "__main__":
    main()
