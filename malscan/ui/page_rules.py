"""The Detection rules page: what the rule engine is looking for."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from malscan.config import CONFIG
from malscan.rules.engine import get_engine, reload_engine
from malscan.ui.theme import card


def render() -> None:
    st.subheader("Detection rules")

    engine = get_engine()

    c1, c2, c3 = st.columns(3)
    with c1:
        card("Backend", engine.backend)
    with c2:
        card("Rules loaded", str(engine.rule_count))
    with c3:
        card("Rule file", CONFIG.rules_file.name)

    if engine.error:
        st.warning(engine.error)

    if engine.backend == "builtin":
        st.info(
            "Running the built-in fallback matcher because `yara-python` is not "
            "available. It evaluates plain-text patterns from the same rule "
            "file, but skips hex and regex rules — install `yara-python` for "
            "full coverage."
        )

    st.caption(
        "Pattern signatures, evaluated alongside the model. Do not read a "
        "single match as a verdict; plenty of legitimate software calls the "
        "same APIs. What makes them useful is that rule hits and severity go "
        "back into the model as two of its 73 features."
    )

    parsed = _parse_rule_metadata()
    if parsed:
        df = pd.DataFrame(parsed)
        c1, c2 = st.columns([1, 1])
        categories = sorted(df["Category"].unique())
        chosen = c1.multiselect("Category", categories, default=categories)
        min_sev = c2.slider("Minimum severity", 1, 5, 1)

        view = df[df.Category.isin(chosen) & (df.Severity >= min_sev)]
        st.dataframe(
            view.sort_values(["Severity", "Rule"], ascending=[False, True]),
            width="stretch", hide_index=True, height=520,
            column_config={
                "Severity": st.column_config.NumberColumn(
                    "Severity", format="%d ⭐", width="small"
                ),
            },
        )

        st.markdown("##### Rules by category")
        counts = df.groupby("Category").size().sort_values(ascending=False)
        st.bar_chart(counts)

    with st.expander("View the raw rule file"):
        try:
            st.code(CONFIG.rules_file.read_text(encoding="utf-8"), language="c")
        except OSError as exc:
            st.error(f"Could not read the rule file: {exc}")

    if st.button("Reload rules from disk"):
        engine = reload_engine()
        st.success(f"Reloaded — {engine.rule_count} rules via {engine.backend}.")
        st.rerun()

    st.caption(
        f"Edit `{CONFIG.rules_file}` to add your own rules, then press reload. "
        "Give each rule a `severity` (1-5) and a `category` in its meta block so "
        "it shows up correctly here and in scan reports."
    )


def _parse_rule_metadata() -> list[dict]:
    """Pull name/description/severity/category out of the rule file for display."""
    from malscan.rules.engine import _META_ITEM, _RULE_BLOCK, _section

    try:
        source = CONFIG.rules_file.read_text(encoding="utf-8")
    except OSError:
        return []

    rows = []
    for name, body in _RULE_BLOCK.findall(source):
        meta_section = _section(body, "meta:")
        meta = {}
        for m in _META_ITEM.finditer(meta_section):
            key = m.group(1) or m.group(3)
            val = m.group(2) if m.group(2) is not None else m.group(4)
            meta[key] = val
        rows.append({
            "Rule": name,
            "Severity": int(meta.get("severity", 2)),
            "Category": meta.get("category", "general"),
            "Description": meta.get("description", ""),
        })
    return rows
