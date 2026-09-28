"""The Dashboard page: aggregate view over everything scanned so far."""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from malscan.storage.history import get_history
from malscan.ui.theme import VERDICT_STYLE, plotly_layout


def render() -> None:
    st.subheader("Dashboard")
    stats = get_history().stats()

    if not stats["total"]:
        st.info(
            "Nothing to summarise yet — scan a few files and this page will "
            "fill in with verdict breakdowns, file-type mix and rule trends."
        )
        return

    by_verdict = stats["by_verdict"]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total scans", f"{stats['total']:,}")
    c2.metric("Unique files", f"{stats['unique_files']:,}")
    c3.metric("Malicious", by_verdict.get("Malicious", 0))
    c4.metric("Suspicious", by_verdict.get("Suspicious", 0))
    c5.metric("Median scan time", f"{stats['avg_scan_ms']} ms")

    st.divider()

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("##### Verdict breakdown")
        labels = list(by_verdict.keys())
        fig = go.Figure(go.Pie(
            labels=labels,
            values=list(by_verdict.values()),
            hole=0.55,
            marker=dict(colors=[VERDICT_STYLE.get(v, ("#8c8c8c",))[0] for v in labels]),
            textinfo="label+percent",
        ))
        st.plotly_chart(plotly_layout(fig, 320), width="stretch")

    with c2:
        st.markdown("##### File types scanned")
        types = stats["by_type"]
        fig = go.Figure(go.Bar(
            x=list(types.values()), y=list(types.keys()),
            orientation="h", marker=dict(color="#4dabf7"),
        ))
        fig.update_layout(xaxis_title="Scans")
        st.plotly_chart(plotly_layout(fig, 320), width="stretch")

    if stats["daily"] and len(stats["daily"]) > 1:
        st.markdown("##### Scans over time")
        daily = pd.DataFrame(stats["daily"])
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=daily["date"], y=daily["count"], name="All scans",
            mode="lines+markers", line=dict(color="#4dabf7", width=2),
        ))
        fig.add_trace(go.Scatter(
            x=daily["date"], y=daily["malicious"], name="Malicious",
            mode="lines+markers", line=dict(color="#ff4d4f", width=2),
        ))
        fig.update_layout(xaxis_title="Date", yaxis_title="Scans")
        st.plotly_chart(plotly_layout(fig, 300), width="stretch")

    if stats["top_rules"]:
        st.markdown("##### Most frequently matched detection rules")
        rules = pd.DataFrame(stats["top_rules"])
        fig = go.Figure(go.Bar(
            x=rules["count"], y=rules["rule"], orientation="h",
            marker=dict(color="#ffa94d"),
        ))
        fig.update_layout(xaxis_title="Times matched")
        st.plotly_chart(
            plotly_layout(fig, max(280, 32 * len(rules))), width="stretch"
        )

    st.divider()
    st.markdown("##### Score distribution")
    rows = get_history().recent(limit=1000)
    if rows:
        df = pd.DataFrame(rows)
        fig = px.histogram(
            df, x="probability", color="verdict", nbins=40,
            color_discrete_map={k: v[0] for k, v in VERDICT_STYLE.items()},
        )
        fig.update_layout(xaxis_title="Malicious probability",
                          yaxis_title="Number of scans", bargap=0.05)
        st.plotly_chart(plotly_layout(fig, 320), width="stretch")
        st.caption(
            "A detector in good shape piles up near 0 and near 1 with not "
            "much stranded in the middle. A fat middle band means a lot of "
            "files it cannot separate, and those are the ones somebody should "
            "look at."
        )
