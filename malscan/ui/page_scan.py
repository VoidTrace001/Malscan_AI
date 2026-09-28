"""The Scan page: upload a file, get an explained verdict."""
from __future__ import annotations

import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from malscan.config import CONFIG
from malscan.scanner import ScanError, scan_bytes
from malscan.ui.theme import (
    VERDICT_STYLE, card, human_bytes, note, plotly_layout, rule_chip,
    verdict_banner,
)


def render() -> None:
    st.subheader("Scan a file")
    st.caption(
        "Upload any file. MalScan parses it as data, extracts static features "
        "and classifies it. Nothing is executed and the file is not stored."
    )

    with st.expander("Detection thresholds", expanded=False):
        c1, c2 = st.columns(2)
        t_mal = c1.slider(
            "Malicious at or above", 0.50, 0.95, CONFIG.threshold_malicious, 0.01,
            help="Raise this to cut false alarms; lower it to catch more malware.",
        )
        t_sus = c2.slider(
            "Suspicious at or above", 0.10, 0.60, CONFIG.threshold_suspicious, 0.01,
            help="Scores between the two thresholds are flagged for human review.",
        )
        if t_sus >= t_mal:
            st.warning("The suspicious threshold should sit below the malicious one.")

    uploaded = st.file_uploader(
        f"Choose a file (max {CONFIG.max_upload_mb} MB)",
        type=None,
        help="Executables, DLLs, documents, scripts and archives are all accepted.",
    )

    col_a, col_b = st.columns([1, 3])
    scan_clicked = col_a.button("Scan file", type="primary", disabled=uploaded is None,
                                width="stretch")
    if uploaded is not None:
        col_b.caption(f"Ready: **{uploaded.name}** ({human_bytes(uploaded.size)})")

    if scan_clicked and uploaded is not None:
        data = uploaded.getvalue()
        with st.spinner("Extracting static features and classifying..."):
            try:
                result = scan_bytes(
                    data, uploaded.name,
                    threshold_malicious=t_mal, threshold_suspicious=t_sus,
                )
            except ScanError as exc:
                st.error(str(exc))
                return
            except Exception as exc:
                st.error(f"The scan failed unexpectedly: {exc}")
                return
        st.session_state["last_scan"] = result

    result = st.session_state.get("last_scan")
    if result is not None:
        st.divider()
        _render_result(result)


# ----------------------------------------------------------------------
def _render_result(r) -> None:
    subtitle = (
        f"{r.filename} &nbsp;·&nbsp; {human_bytes(r.size)} &nbsp;·&nbsp; "
        f"{r.features_result.file_type.label} &nbsp;·&nbsp; "
        f"analysed in {r.duration_ms} ms"
    )
    verdict_banner(r.verdict, r.probability, r.confidence, subtitle)

    for w in r.warnings:
        note(w)
    for n in r.prediction.notes:
        note(n)

    by_model = r.prediction.engine == "model"

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        card("Model confidence" if by_model else "Confidence",
             f"{r.confidence * 100:.0f}%")
    with c2:
        card("Rules matched", str(len(r.rule_matches)))
    with c3:
        card("Randomness",
             f"{r.features_result.features['entropy_overall']:.2f} / 8.00")
    with c4:
        card("Classifier",
             f"{r.prediction.model_name}"
             + (" (calibrated)" if r.prediction.calibrated else ""))

    tabs = st.tabs([
        "Why this verdict", "File identity", "Program structure",
        "Text & clues", "Detection rules", "Randomness map", "All features",
    ])

    with tabs[0]:
        _tab_explanation(r)
    with tabs[1]:
        _tab_identity(r)
    with tabs[2]:
        _tab_pe(r)
    with tabs[3]:
        _tab_strings(r)
    with tabs[4]:
        _tab_rules(r)
    with tabs[5]:
        _tab_entropy(r)
    with tabs[6]:
        _tab_features(r)

    st.divider()
    _download_report(r)


def _tab_explanation(r) -> None:
    if not r.contributions:
        st.info("No feature moved the score measurably for this file.")
        return

    st.markdown("##### How each feature moved the score")
    if r.prediction.engine == "model":
        st.caption(
            "Each bar shows how much the malicious probability would drop (or "
            "rise) if that single feature looked typical for a benign file, "
            "with everything else unchanged."
        )
    else:
        st.caption(
            "Each bar is the weight this signal carried. These weights are "
            "fixed rather than learned, so what you see here is the entire "
            "calculation and not a summary of one."
        )

    items = list(reversed(r.contributions))
    labels = [c.description for c in items]
    values = [c.contribution * 100 for c in items]
    colors = [
        VERDICT_STYLE["Malicious"][0] if c.direction == "malicious"
        else VERDICT_STYLE["Benign"][0]
        for c in items
    ]
    hover = [
        f"<b>{c.description}</b><br>this file: {c.display_value}<br>"
        + (f"benign {c.benign_typical}<br>" if r.prediction.engine == "model" else "")
        + f"effect: {c.contribution * 100:+.2f} points"
        for c in items
    ]

    fig = go.Figure(
        go.Bar(
            x=values, y=labels, orientation="h",
            marker=dict(color=colors),
            hovertext=hover, hoverinfo="text",
        )
    )
    fig.update_layout(xaxis_title="Effect on malicious probability (percentage points)")
    st.plotly_chart(
        plotly_layout(fig, height=max(300, 34 * len(items))),
        width="stretch",
    )

    st.markdown("##### In plain language")
    for line in r.explanation:
        st.markdown(line)

    with st.expander("Contribution detail"):
        st.dataframe(
            pd.DataFrame([
                {
                    "Feature": c.feature,
                    "Group": c.group,
                    "This file": c.display_value,
                    "Benign range": c.benign_typical,
                    "Effect (pts)": round(c.contribution * 100, 2),
                    "Pushes toward": c.direction,
                }
                for c in r.contributions
            ]),
            width="stretch", hide_index=True,
        )


def _tab_identity(r) -> None:
    h = r.features_result.hashes
    c1, c2 = st.columns(2)
    with c1:
        card("File name", r.filename)
        card("Size", f"{human_bytes(r.size)} ({r.size:,} bytes)")
        card("Detected type", r.features_result.file_type.label)
        if r.features_result.file_type.detail:
            card("Type detail", r.features_result.file_type.detail)
    with c2:
        card("SHA-256", h.get("sha256", ""), mono=True)
        card("SHA-1", h.get("sha1", ""), mono=True)
        card("MD5", h.get("md5", ""), mono=True)
        if r.pe.imphash:
            card("Import fingerprint", r.pe.imphash, mono=True)

    card("Similarity fingerprint", r.features_result.fuzzy_hash or "n/a", mono=True)
    st.caption(
        "The similarity fingerprint is a rolling block digest: near-identical "
        "files produce near-identical strings, which helps spot repackaged "
        "variants of the same sample."
    )

    sha = h.get("sha256", "")
    if sha:
        st.markdown(
            f"Cross-reference on VirusTotal: "
            f"[`{sha[:24]}...`](https://www.virustotal.com/gui/file/{sha})"
        )
        st.caption(
            "MalScan does not send anything anywhere — this is just a link "
            "built from the hash, for you to open if you choose."
        )


def _tab_pe(r) -> None:
    pe = r.pe
    if not r.features_result.file_type.is_pe:
        st.info(
            f"This file is {r.features_result.file_type.label}, not a Windows "
            "executable, so there is no PE structure to show."
        )
        return
    if not pe.parsed:
        st.error(f"The PE header could not be parsed: {pe.error}")
        return

    c1, c2, c3 = st.columns(3)
    with c1:
        card("Architecture", f"{pe.machine} ({'64-bit' if pe.is_64bit else '32-bit'})")
        card("Type", "Shared library (DLL)" if pe.is_dll else "Program (EXE)")
        card("Runs as", pe.subsystem or "unknown")
    with c2:
        card("Compiled", pe.timestamp_str
             + ("" if pe.timestamp_plausible else "  ⚠️ implausible"))
        card("Entry point", f"0x{pe.entry_point:08X} in {pe.entry_point_section or '?'}")
        card("Checksum", "valid" if pe.checksum_valid
             else ("mismatch" if pe.checksum_stored else "not set"))
    with c3:
        card("Imported functions", f"{pe.import_count} from {len(pe.imports)} DLL(s)")
        card("Exports", str(len(pe.exports)))
        card("Packer", pe.packer or "none detected")

    st.markdown("##### Safety features and markings")
    flags = {
        "ASLR": pe.aslr, "DEP / NX": pe.dep, "SEH": pe.seh,
        "Signed": pe.has_signature, "Version info": pe.has_version_info,
        "Relocations": pe.has_relocs, "Debug info": pe.has_debug, "TLS": pe.has_tls,
    }
    cols = st.columns(len(flags))
    for col, (name, on) in zip(cols, flags.items()):
        col.markdown(
            f"<div style='text-align:center'><div style='font-size:1.4rem'>"
            f"{'✅' if on else '❌'}</div><div style='font-size:0.75rem;opacity:0.75'>"
            f"{name}</div></div>",
            unsafe_allow_html=True,
        )
    st.caption(
        "**ASLR**, **DEP/NX** and **SEH** are standard protections any normal "
        "compiler switches on, so their absence is worth a second look without "
        "proving anything on its own. **Signed** means a named publisher "
        "vouched for the file. **TLS** lets code run before the program's "
        "official starting point, which is occasionally used to slip past "
        "analysis tools."
    )

    if pe.anomalies:
        st.markdown("##### What stands out in the structure")
        for a in pe.anomalies:
            st.markdown(f"- {a}")

    st.markdown("##### Sections — the separate parts of the program")
    if pe.sections:
        sec_df = pd.DataFrame([
            {
                "Name": s.name,
                "Address": f"0x{s.virtual_address:08X}",
                "Size in memory": s.virtual_size,
                "Size on disk": s.raw_size,
                "Randomness": round(s.entropy, 3),
                "R": "✓" if s.is_readable else "",
                "W": "✓" if s.is_writable else "",
                "X": "✓" if s.is_executable else "",
            }
            for s in pe.sections
        ])
        st.dataframe(sec_df, width="stretch", hide_index=True)
        st.caption(
            "**R**, **W** and **X** are what the program may do with each part: "
            "read it, write to it, or run it as code. A part marked both W and "
            "X can rewrite its own instructions while running, which ordinary "
            "software rarely needs and unpackers rely on. A part claiming far "
            "more memory than it occupies on disk is the other classic sign of "
            "something that unpacks itself."
        )

        fig = go.Figure(go.Bar(
            x=[s.name for s in pe.sections],
            y=[s.entropy for s in pe.sections],
            marker=dict(
                color=[s.entropy for s in pe.sections],
                colorscale=[[0, "#52c41a"], [0.85, "#faad14"], [1, "#ff4d4f"]],
                cmin=0, cmax=8,
            ),
        ))
        fig.add_hline(
            y=CONFIG.packed_entropy_cutoff, line_dash="dash", line_color="#ff4d4f",
            annotation_text="packing threshold (7.4)", annotation_position="top left",
        )
        fig.update_layout(yaxis_title="Entropy (bits/byte)", yaxis_range=[0, 8.2])
        st.plotly_chart(plotly_layout(fig, 300, "Entropy per section"),
                        width="stretch")

    if pe.imports:
        st.markdown("##### Imports")
        suspicious = {s.lower() for s in pe.suspicious_apis}
        for dll, funcs in sorted(pe.imports.items()):
            flagged = [f for f in funcs if f"{dll}!{f}".lower() in suspicious]
            label = f"{dll} — {len(funcs)} function(s)"
            if flagged:
                label += f"  ⚠️ {len(flagged)} on the watchlist"
            with st.expander(label):
                if flagged:
                    st.markdown("**On the suspicious-API watchlist:** "
                                + ", ".join(f"`{f}`" for f in flagged))
                st.caption(", ".join(funcs[:400]))

    if pe.version_info:
        st.markdown("##### Version information")
        st.dataframe(
            pd.DataFrame(list(pe.version_info.items()), columns=["Field", "Value"]),
            width="stretch", hide_index=True,
        )


def _tab_strings(r) -> None:
    s = r.features_result.strings
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Strings extracted", f"{s.count:,}")
    c2.metric("URLs", s.urls)
    c3.metric("IP addresses", s.ips)
    c4.metric("Suspicious keywords", s.suspicious)

    if s.top_urls:
        st.markdown("##### Embedded URLs")
        st.code("\n".join(s.top_urls), language=None)
    if s.top_ips:
        st.markdown("##### Embedded IP addresses")
        st.code("\n".join(s.top_ips), language=None)
    if s.matched_keywords:
        st.markdown("##### Suspicious keywords found")
        st.markdown(" ".join(f"`{k}`" for k in s.matched_keywords))

    extra = []
    if s.base64_blobs:
        extra.append(f"{s.base64_blobs} long base64-looking blob(s)")
    if s.embedded_mz:
        extra.append(f"{s.embedded_mz} embedded PE header(s)")
    if s.crypto_constants:
        extra.append(f"{s.crypto_constants} known cryptographic constant(s)")
    if s.has_pdb:
        extra.append("a compiler PDB debug path")
    if extra:
        st.markdown("##### Also present")
        for e in extra:
            st.markdown(f"- {e}")

    if s.sample_strings:
        with st.expander("Longest extracted strings"):
            st.code("\n".join(s.sample_strings), language=None)


def _tab_rules(r) -> None:
    from malscan.rules.engine import get_engine

    engine = get_engine()
    st.caption(
        f"Backend: **{engine.backend}** · {engine.rule_count} rules loaded"
        + (f" · {engine.error}" if engine.error else "")
    )
    if not r.rule_matches:
        st.success("No detection rules matched this file.")
        return

    st.markdown(f"##### {len(r.rule_matches)} rule(s) matched")
    for m in r.rule_matches:
        rule_chip(m)
        if m.get("matched_strings"):
            with st.expander(f"What matched in {m['name']}"):
                st.code("\n".join(m["matched_strings"]), language=None)

    st.caption(
        "One rule match is not a verdict. Ordinary software uses plenty of "
        "these APIs quite legitimately. The model weighs rule hits alongside "
        "everything else it looks at."
    )


def _tab_entropy(r) -> None:
    blocks = r.features_result.block_entropy
    if not blocks:
        st.info("No data to plot.")
        return

    st.markdown("##### Entropy across the file")
    st.caption(
        "Each point is one 4 KB block. Sustained values above ~7.4 indicate "
        "compressed, encrypted or packed content."
    )
    fig = go.Figure(go.Scatter(
        x=[i * 4096 for i in range(len(blocks))], y=blocks,
        mode="lines", line=dict(width=1.4, color="#4dabf7"),
        fill="tozeroy", fillcolor="rgba(77,171,247,0.14)",
    ))
    fig.add_hline(y=CONFIG.packed_entropy_cutoff, line_dash="dash",
                  line_color="#ff4d4f", annotation_text="7.4")
    fig.update_layout(xaxis_title="File offset (bytes)",
                      yaxis_title="Entropy (bits/byte)", yaxis_range=[0, 8.2])
    st.plotly_chart(plotly_layout(fig, 320), width="stretch")

    hist = r.features_result.byte_histogram
    if hist:
        st.markdown("##### Byte value distribution")
        st.caption(
            "Plain code and text are heavily skewed toward a few byte values. "
            "A flat distribution across all 256 values means the content is "
            "compressed or encrypted."
        )
        fig2 = go.Figure(go.Bar(x=list(range(256)), y=hist,
                                marker=dict(color="#9775fa")))
        fig2.update_layout(xaxis_title="Byte value (0-255)", yaxis_title="Frequency")
        st.plotly_chart(plotly_layout(fig2, 260), width="stretch")


def _tab_features(r) -> None:
    from malscan.features.schema import FEATURE_DOCS, FEATURE_GROUPS

    st.caption(
        f"All {len(r.features_result.features)} features extracted from this "
        "file, in the exact order the model consumes them."
    )
    rows = []
    for group, items in FEATURE_GROUPS.items():
        for name in items:
            rows.append({
                "Group": group,
                "Feature": name,
                "Value": round(float(r.features_result.features.get(name, 0.0)), 4),
                "Meaning": FEATURE_DOCS[name],
            })
    df = pd.DataFrame(rows)

    chosen = st.multiselect("Filter by group", list(FEATURE_GROUPS.keys()),
                            default=list(FEATURE_GROUPS.keys()))
    st.dataframe(df[df.Group.isin(chosen)], width="stretch",
                 hide_index=True, height=520)


def _download_report(r) -> None:
    report = {
        "malscan_version": "1.0.0",
        "file": {
            "name": r.filename,
            "size_bytes": r.size,
            "type": r.features_result.file_type.label,
            "hashes": r.features_result.hashes,
            "fuzzy_hash": r.features_result.fuzzy_hash,
            "imphash": r.pe.imphash,
        },
        "verdict": {
            "label": r.verdict,
            "malicious_probability": round(r.probability, 6),
            "confidence": round(r.confidence, 6),
            "engine": r.prediction.engine,
            "model": r.prediction.model_name,
            "calibrated": r.prediction.calibrated,
            "threshold_malicious": r.prediction.threshold_malicious,
            "threshold_suspicious": r.prediction.threshold_suspicious,
        },
        "top_factors": [
            {
                "feature": c.feature,
                "description": c.description,
                "value": c.display_value,
                "benign_typical": c.benign_typical,
                "effect_points": round(c.contribution * 100, 3),
                "pushes_toward": c.direction,
            }
            for c in r.contributions
        ],
        "rule_matches": r.rule_matches,
        "pe_anomalies": r.pe.anomalies,
        "features": r.features_result.features,
        "scan_ms": r.duration_ms,
        "warnings": r.warnings,
    }
    c1, c2 = st.columns(2)
    c1.download_button(
        "Download JSON report",
        json.dumps(report, indent=2),
        file_name=f"malscan_{r.sha256[:16]}.json",
        mime="application/json",
        width="stretch",
    )
    c2.download_button(
        "Download feature CSV",
        pd.DataFrame([r.features_result.features]).to_csv(index=False),
        file_name=f"malscan_features_{r.sha256[:16]}.csv",
        mime="text/csv",
        width="stretch",
    )
