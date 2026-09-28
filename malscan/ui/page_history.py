"""The History page: browse, filter and re-open past scans."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from malscan.storage.history import get_history
from malscan.ui.theme import VERDICT_STYLE, card, human_bytes, rule_chip


def render() -> None:
    st.subheader("Scan history")
    st.caption(
        "Every scan is recorded here. Only the analysis output and the file's "
        "hashes are stored — never the file itself."
    )

    history = get_history()

    c1, c2, c3 = st.columns([2, 1, 1])
    search = c1.text_input("Search", placeholder="File name, SHA-256 or MD5")
    verdict = c2.selectbox("Verdict", ["All", "Malicious", "Suspicious", "Benign"])
    limit = c3.selectbox("Show", [25, 50, 100, 250, 1000], index=2)

    rows = history.recent(limit=limit, verdict=verdict, search=search or None)

    if not rows:
        st.info(
            "No scans recorded yet."
            if not (search or verdict != "All")
            else "No scans match those filters."
        )
        return

    st.caption(f"{len(rows)} scan(s)")

    table = pd.DataFrame([
        {
            "ID": r["id"],
            "Scanned (UTC)": r["scanned_at"].replace("T", " ").replace("+00:00", ""),
            "File": r["filename"],
            "Type": r["file_type"],
            "Size": human_bytes(r["file_size"]),
            "Verdict": r["verdict"],
            "Probability": f"{r['probability'] * 100:.1f}%",
            "Rules": r["rule_hits"],
            "Time": f"{r['scan_ms']} ms",
            "SHA-256": (r["sha256"] or "")[:16] + "...",
        }
        for r in rows
    ])

    st.dataframe(
        table,
        width="stretch",
        hide_index=True,
        height=min(560, 60 + 35 * len(table)),
        column_config={
            "Probability": st.column_config.TextColumn(width="small"),
        },
    )

    st.divider()
    c1, c2 = st.columns([1, 3])
    chosen = c1.selectbox(
        "Open a scan",
        [r["id"] for r in rows],
        format_func=lambda i: f"#{i} — {next(r['filename'] for r in rows if r['id'] == i)}",
    )
    if chosen:
        _render_detail(history.get(chosen), history)

    st.divider()
    c1, c2 = st.columns(2)
    c1.download_button(
        "Export all history as CSV",
        pd.DataFrame(history.export_rows()).to_csv(index=False),
        file_name="malscan_history.csv",
        mime="text/csv",
        width="stretch",
    )
    with c2:
        if st.button("Clear all history", width="stretch"):
            st.session_state["confirm_clear"] = True
        if st.session_state.get("confirm_clear"):
            st.warning("This permanently deletes every recorded scan.")
            cc1, cc2 = st.columns(2)
            if cc1.button("Yes, delete everything", type="primary",
                          width="stretch"):
                history.clear()
                st.session_state["confirm_clear"] = False
                st.success("History cleared.")
                st.rerun()
            if cc2.button("Cancel", width="stretch"):
                st.session_state["confirm_clear"] = False
                st.rerun()


def _render_detail(row: dict | None, history) -> None:
    if not row:
        st.warning("That scan could not be loaded.")
        return

    color, bg, icon = VERDICT_STYLE.get(row["verdict"], VERDICT_STYLE["Benign"])
    st.markdown(
        f"### {icon} Scan #{row['id']} — "
        f"<span style='color:{color}'>{row['verdict']}</span> "
        f"({row['probability'] * 100:.1f}%)",
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        card("File", row["filename"])
        card("Type", row["file_label"] or row["file_type"] or "unknown")
        card("Size", human_bytes(row["file_size"]))
    with c2:
        card("Scanned at (UTC)", row["scanned_at"].replace("T", " "))
        card("Classifier", f"{row['model_name']} ({row['engine']})")
        card("Duration", f"{row['scan_ms']} ms")
    with c3:
        card("Entropy", f"{(row['entropy'] or 0):.2f} / 8.00")
        card("Packer", row["packer"] or "none detected")
        card("Rules matched", str(row["rule_hits"]))

    card("SHA-256", row["sha256"], mono=True)
    card("MD5", row["md5"] or "", mono=True)

    factors = _load_json(row["factors"])
    if factors:
        st.markdown("##### Why this verdict")
        st.dataframe(
            pd.DataFrame([
                {
                    "Feature": f["description"],
                    "Value": f["value"],
                    "Effect (pts)": round(f["contribution"] * 100, 2),
                    "Pushes toward": f["direction"],
                }
                for f in factors
            ]),
            width="stretch", hide_index=True,
        )

    rules = _load_json(row["rules"])
    if rules:
        st.markdown("##### Rules matched")
        for m in rules:
            rule_chip(m)

    anomalies = _load_json(row["anomalies"])
    if anomalies:
        st.markdown("##### Structural observations")
        for a in anomalies:
            st.markdown(f"- {a}")

    duplicates = history.by_hash(row["sha256"])
    if len(duplicates) > 1:
        st.info(
            f"This exact file has been scanned {len(duplicates)} times "
            f"(scan IDs: {', '.join(str(d['id']) for d in duplicates[:10])})."
        )

    c1, c2 = st.columns(2)
    c1.download_button(
        "Download this scan as JSON",
        json.dumps({**row, "features": _load_json(row["features"]),
                    "factors": factors, "rules": rules, "anomalies": anomalies},
                   indent=2, default=str),
        file_name=f"malscan_scan_{row['id']}.json",
        mime="application/json",
        width="stretch",
    )
    if c2.button("Delete this scan", width="stretch"):
        history.delete(row["id"])
        st.success(f"Scan #{row['id']} deleted.")
        st.rerun()


def _load_json(blob):
    try:
        return json.loads(blob or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
