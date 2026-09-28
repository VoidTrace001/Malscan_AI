"""Shared styling and small presentation helpers for the Streamlit UI."""
from __future__ import annotations

import streamlit as st

# Re-exported so the UI can keep importing every presentation helper from one
# place, even though this one has to live outside the Streamlit-bound module.
from malscan.util import human_bytes

__all__ = [
    "VERDICT_STYLE", "SEVERITY_COLOR", "GROUP_COLOR",
    "inject_css", "brand_header", "verdict_banner", "card", "rule_chip",
    "note", "human_bytes", "plotly_layout",
]

# Verdict -> (accent colour, soft background, icon)
VERDICT_STYLE = {
    "Malicious":  ("#ff4d4f", "rgba(255, 77, 79, 0.12)",  "⛔"),
    "Suspicious": ("#faad14", "rgba(250, 173, 20, 0.12)", "⚠️"),
    "Benign":     ("#52c41a", "rgba(82, 196, 26, 0.12)",  "✅"),
}

SEVERITY_COLOR = {
    5: "#ff4d4f", 4: "#ff7a45", 3: "#faad14", 2: "#fadb14", 1: "#8c8c8c", 0: "#8c8c8c",
}

GROUP_COLOR = {
    "File": "#4dabf7",
    "PE Header": "#9775fa",
    "Sections": "#f783ac",
    "Imports": "#ffa94d",
    "Content": "#38d9a9",
    "Packing & Rules": "#ff8787",
}

CSS = """
<style>
  /* --- layout ------------------------------------------------------- */
  .block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1280px; }
  #MainMenu, footer { visibility: hidden; }

  /* --- brand -------------------------------------------------------- */
  .ms-brand {
      display: flex; align-items: center; gap: 0.7rem; margin-bottom: 0.2rem;
  }
  .ms-brand-title {
      font-size: 1.55rem; font-weight: 700; letter-spacing: -0.5px; margin: 0;
      background: linear-gradient(90deg, #4dabf7, #9775fa);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  .ms-brand-sub { font-size: 0.82rem; opacity: 0.65; margin: 0 0 1.2rem 0; }

  /* --- verdict banner ----------------------------------------------- */
  .ms-verdict {
      border-radius: 14px; padding: 1.3rem 1.6rem; margin: 0.5rem 0 1.2rem 0;
      border: 1px solid var(--vc); background: var(--vbg);
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 1rem;
  }
  .ms-verdict-label { font-size: 1.9rem; font-weight: 700; color: var(--vc); line-height: 1.1; }
  .ms-verdict-sub   { font-size: 0.85rem; opacity: 0.75; margin-top: 0.25rem; }
  .ms-verdict-score { font-size: 2.5rem; font-weight: 700; color: var(--vc); line-height: 1; }
  .ms-verdict-score-label { font-size: 0.72rem; opacity: 0.7; text-align: right;
      text-transform: uppercase; letter-spacing: 0.08em; }

  /* --- cards -------------------------------------------------------- */
  .ms-card {
      border: 1px solid rgba(128,128,128,0.22); border-radius: 12px;
      padding: 0.95rem 1.15rem; margin-bottom: 0.75rem;
      background: rgba(128,128,128,0.045);
  }
  .ms-card-title {
      font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.09em;
      opacity: 0.6; margin-bottom: 0.35rem;
  }
  .ms-card-value { font-size: 1.15rem; font-weight: 600; word-break: break-all; }

  /* --- rule chips --------------------------------------------------- */
  .ms-rule {
      border-left: 3px solid var(--sc); border-radius: 6px;
      padding: 0.55rem 0.8rem; margin-bottom: 0.45rem;
      background: rgba(128,128,128,0.07);
  }
  .ms-rule-name { font-weight: 600; font-family: ui-monospace, monospace; font-size: 0.9rem; }
  .ms-rule-sev {
      font-size: 0.68rem; padding: 0.1rem 0.45rem; border-radius: 20px;
      background: var(--sc); color: #11151c; font-weight: 700; margin-left: 0.4rem;
  }
  .ms-rule-desc { font-size: 0.83rem; opacity: 0.8; margin-top: 0.2rem; }

  /* --- misc --------------------------------------------------------- */
  .ms-hash {
      font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.78rem;
      word-break: break-all; opacity: 0.9;
  }
  .ms-note {
      border-left: 3px solid #4dabf7; background: rgba(77,171,247,0.08);
      padding: 0.6rem 0.9rem; border-radius: 6px; font-size: 0.85rem;
      margin-bottom: 0.6rem;
  }
  .ms-tag {
      display: inline-block; padding: 0.15rem 0.55rem; border-radius: 20px;
      font-size: 0.72rem; margin: 0.12rem 0.2rem 0.12rem 0;
      background: rgba(128,128,128,0.16);
  }
  div[data-testid="stMetricValue"] { font-size: 1.5rem; }
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def brand_header() -> None:
    st.markdown(
        """
        <div class="ms-brand">
          <span style="font-size:1.7rem">\U0001f6e1️</span>
          <span class="ms-brand-title">MalScan AI</span>
        </div>
        <p class="ms-brand-sub">
          Static malware detection with machine learning &mdash; files are analysed, never executed.
        </p>
        """,
        unsafe_allow_html=True,
    )


def verdict_banner(verdict: str, probability: float, confidence: float,
                   subtitle: str = "") -> None:
    color, bg, icon = VERDICT_STYLE.get(verdict, VERDICT_STYLE["Benign"])
    st.markdown(
        f"""
        <div class="ms-verdict" style="--vc:{color}; --vbg:{bg}">
          <div>
            <div class="ms-verdict-label">{icon} {verdict}</div>
            <div class="ms-verdict-sub">{subtitle}</div>
          </div>
          <div>
            <div class="ms-verdict-score">{probability * 100:.1f}%</div>
            <div class="ms-verdict-score-label">malicious probability</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def card(title: str, value: str, mono: bool = False) -> None:
    cls = "ms-card-value ms-hash" if mono else "ms-card-value"
    st.markdown(
        f'<div class="ms-card"><div class="ms-card-title">{title}</div>'
        f'<div class="{cls}">{value}</div></div>',
        unsafe_allow_html=True,
    )


def rule_chip(match: dict) -> None:
    color = SEVERITY_COLOR.get(int(match.get("severity", 0)), "#8c8c8c")
    st.markdown(
        f"""
        <div class="ms-rule" style="--sc:{color}">
          <span class="ms-rule-name">{match['name']}</span>
          <span class="ms-rule-sev">SEV {match['severity']}</span>
          <span class="ms-tag">{match.get('category', 'general')}</span>
          <div class="ms-rule-desc">{match['description']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def note(text: str) -> None:
    st.markdown(f'<div class="ms-note">{text}</div>', unsafe_allow_html=True)


def plotly_layout(fig, height: int = 320, title: str = ""):
    """Consistent, theme-neutral chart chrome."""
    fig.update_layout(
        height=height,
        title=title or None,
        margin=dict(l=10, r=10, t=40 if title else 16, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
        hoverlabel=dict(font_size=12),
    )
    fig.update_xaxes(gridcolor="rgba(128,128,128,0.18)", zerolinecolor="rgba(128,128,128,0.3)")
    fig.update_yaxes(gridcolor="rgba(128,128,128,0.18)", zerolinecolor="rgba(128,128,128,0.3)")
    return fig
