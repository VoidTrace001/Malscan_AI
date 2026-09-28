"""The Model page: how the classifier performs, and how to retrain it."""
from __future__ import annotations

import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from malscan.config import CONFIG
from malscan.model.predict import get_classifier, reload_classifier
from malscan.ui.theme import card, note, plotly_layout


def render() -> None:
    st.subheader("Model")

    classifier = get_classifier()
    metrics = _load_metrics()

    if not classifier.is_trained:
        st.error(
            "**No trained model is loaded.** MalScan is falling back to a "
            "transparent heuristic scorer, so verdicts are rule-of-thumb rather "
            "than learned. Train a model below to enable the classifier."
        )
        if classifier.load_error:
            st.caption(classifier.load_error)
    else:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            card("Active model", classifier.model_name)
        with c2:
            card("Probability calibration",
                 "isotonic" if classifier.calibrated else "none")
        with c3:
            card("Feature count", str(len(classifier.feature_names)))
        with c4:
            card("Trained at (UTC)",
                 (classifier.trained_at or "unknown").replace("T", " "))

        st.caption(
            "Everything on this page is measured on Windows executables whose "
            "PE structure parsed, since that is all the model was trained on "
            "and all it gets asked about. Files without that structure go to "
            "the content scorer instead; each verdict says which engine "
            "produced it."
        )

    st.divider()
    tabs = st.tabs([
        "Performance", "Feature importance", "Threshold trade-off",
        "Training data", "Retrain",
    ])

    with tabs[0]:
        _tab_performance(metrics)
    with tabs[1]:
        _tab_importance(metrics, classifier)
    with tabs[2]:
        _tab_threshold(metrics)
    with tabs[3]:
        _tab_data(metrics)
    with tabs[4]:
        _tab_retrain()


# ----------------------------------------------------------------------
def _load_metrics() -> dict:
    if not CONFIG.metrics_path.exists():
        return {}
    try:
        return json.loads(CONFIG.metrics_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _tab_performance(metrics: dict) -> None:
    if not metrics:
        st.info("No metrics file yet. Train a model to populate this page.")
        return

    best = metrics["models"][0]
    cv = metrics.get("cross_validation", {})

    st.markdown(
        f"##### {best['name']} — held-out test set "
        f"({metrics.get('test_rows', '?'):,} rows)"
    )
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Accuracy", f"{best['accuracy'] * 100:.2f}%")
    c2.metric("Precision", f"{best['precision'] * 100:.2f}%")
    c3.metric("Recall", f"{best['recall'] * 100:.2f}%")
    c4.metric("F1", f"{best['f1']:.4f}")
    c5.metric("ROC-AUC", f"{best['roc_auc']:.4f}")

    st.caption(
        f"5-fold cross-validated ROC-AUC: **{cv.get('mean', 0):.4f} ± "
        f"{cv.get('std', 0):.4f}** "
        f"({cv.get('grouped_by', 'standard folds')})."
    )

    note(
        "**Precision and recall trade against each other here.** "
        f"Recall {best['recall'] * 100:.1f}% means "
        f"{best['confusion_matrix']['false_negative']} malicious files in the "
        f"test set were missed; precision {best['precision'] * 100:.1f}% means "
        f"{best['confusion_matrix']['false_positive']} benign files were wrongly "
        "flagged. Which error matters more depends on where the scanner sits — "
        "the Threshold trade-off tab lets you move that line."
    )

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("##### Confusion matrix")
        cm = best["confusion_matrix"]
        z = [[cm["true_negative"], cm["false_positive"]],
             [cm["false_negative"], cm["true_positive"]]]
        fig = go.Figure(go.Heatmap(
            z=z,
            x=["Predicted benign", "Predicted malicious"],
            y=["Actually benign", "Actually malicious"],
            text=[[f"{v:,}" for v in row] for row in z],
            texttemplate="%{text}", textfont=dict(size=17),
            colorscale=[[0, "#1a2332"], [1, "#4dabf7"]], showscale=False,
        ))
        st.plotly_chart(plotly_layout(fig, 300), width="stretch")
        st.caption(
            f"False positive rate {best['false_positive_rate'] * 100:.2f}% · "
            f"False negative rate {best['false_negative_rate'] * 100:.2f}%"
        )

    with c2:
        st.markdown("##### ROC curve")
        roc = best.get("roc_curve", {})
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=roc.get("fpr", []), y=roc.get("tpr", []),
            mode="lines", name=f"{best['name']} (AUC {best['roc_auc']:.4f})",
            line=dict(color="#4dabf7", width=2.5), fill="tozeroy",
            fillcolor="rgba(77,171,247,0.12)",
        ))
        fig.add_trace(go.Scatter(
            x=[0, 1], y=[0, 1], mode="lines", name="Random",
            line=dict(color="#8c8c8c", width=1, dash="dash"),
        ))
        fig.update_layout(xaxis_title="False positive rate",
                          yaxis_title="True positive rate")
        st.plotly_chart(plotly_layout(fig, 300), width="stretch")

    st.markdown("##### Model comparison")
    st.dataframe(
        pd.DataFrame([
            {
                "Model": m["name"],
                "Accuracy": f"{m['accuracy'] * 100:.2f}%",
                "Precision": f"{m['precision'] * 100:.2f}%",
                "Recall": f"{m['recall'] * 100:.2f}%",
                "F1": f"{m['f1']:.4f}",
                "ROC-AUC": f"{m['roc_auc']:.4f}",
                "PR-AUC": f"{m['pr_auc']:.4f}",
                "Brier": f"{m['brier']:.4f}",
                "Selected": "✓" if m["name"] == metrics["best_model"] else "",
            }
            for m in metrics["models"]
        ]),
        width="stretch", hide_index=True,
    )
    st.caption(
        "Selection is on ROC-AUC because it does not depend on where the "
        "decision threshold sits, and the threshold is adjustable at scan time."
    )

    groups = best.get("per_group_accuracy", {})
    if groups:
        st.markdown("##### Accuracy by sample group")
        st.caption(
            "The synthetic malicious families and the deliberately hard "
            "benign cases, scored separately. Pay attention to the low numbers "
            "here; they are where the model still struggles."
        )
        gdf = pd.DataFrame([
            {"Group": g, "Samples": s["n"], "Accuracy": s["accuracy"]}
            for g, s in groups.items()
        ]).sort_values("Accuracy")
        fig = go.Figure(go.Bar(
            x=gdf["Accuracy"], y=gdf["Group"], orientation="h",
            marker=dict(
                color=gdf["Accuracy"],
                colorscale=[[0, "#ff4d4f"], [0.8, "#faad14"], [1, "#52c41a"]],
                cmin=0, cmax=1,
            ),
            text=[f"{a:.1%} (n={n})" for a, n in zip(gdf["Accuracy"], gdf["Samples"])],
            textposition="auto",
        ))
        fig.update_layout(xaxis_title="Accuracy", xaxis_range=[0, 1.05])
        st.plotly_chart(plotly_layout(fig, max(300, 30 * len(gdf))),
                        width="stretch")


def _tab_importance(metrics: dict, classifier) -> None:
    importances = metrics.get("feature_importance") or classifier.feature_importance
    if not importances:
        st.info("No feature importances available. Train a model first.")
        return

    st.markdown("##### What the model relies on overall")
    st.caption(
        "Global importance across the whole training set. This is different "
        "from the per-file explanation on a scan result: this says what usually "
        "matters, that says what mattered for one specific file."
    )

    from malscan.features.schema import FEATURE_DOCS, FEATURE_TO_GROUP
    from malscan.ui.theme import GROUP_COLOR

    top = importances[:25][::-1]
    fig = go.Figure(go.Bar(
        x=[f["importance"] for f in top],
        y=[FEATURE_DOCS.get(f["feature"], f["feature"]) for f in top],
        orientation="h",
        marker=dict(color=[
            GROUP_COLOR.get(FEATURE_TO_GROUP.get(f["feature"], ""), "#4dabf7")
            for f in top
        ]),
        hovertext=[
            f"{f['feature']}<br>group: {FEATURE_TO_GROUP.get(f['feature'], '?')}"
            f"<br>importance: {f['importance']:.5f}"
            for f in top
        ],
        hoverinfo="text",
    ))
    fig.update_layout(xaxis_title="Relative importance")
    st.plotly_chart(plotly_layout(fig, max(400, 26 * len(top))),
                    width="stretch")

    st.dataframe(
        pd.DataFrame([
            {
                "Feature": f["feature"],
                "Group": FEATURE_TO_GROUP.get(f["feature"], ""),
                "Meaning": FEATURE_DOCS.get(f["feature"], ""),
                "Importance": f["importance"],
            }
            for f in importances
        ]),
        width="stretch", hide_index=True, height=400,
    )


def _tab_threshold(metrics: dict) -> None:
    sweep = metrics.get("threshold_sweep")
    if not sweep:
        st.info(
            "No threshold sweep recorded. Retrain to generate one "
            "(this data is produced from version 2 of the training script)."
        )
        return

    st.markdown("##### Where to draw the line")
    st.caption(
        "Moving the threshold trades missed malware against false alarms. "
        "There is no single right answer. It depends on what each kind of "
        "mistake costs wherever the scanner is actually running."
    )

    df = pd.DataFrame(sweep)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df.threshold, y=df.precision, name="Precision",
                             line=dict(color="#4dabf7", width=2.5)))
    fig.add_trace(go.Scatter(x=df.threshold, y=df.recall, name="Recall",
                             line=dict(color="#ff4d4f", width=2.5)))
    fig.add_trace(go.Scatter(x=df.threshold, y=df.f1, name="F1",
                             line=dict(color="#52c41a", width=2, dash="dot")))
    fig.add_vline(x=CONFIG.threshold_malicious, line_dash="dash",
                  line_color="#faad14",
                  annotation_text=f"default ({CONFIG.threshold_malicious})")
    fig.update_layout(xaxis_title="Decision threshold", yaxis_title="Score",
                      yaxis_range=[0, 1.05])
    st.plotly_chart(plotly_layout(fig, 340), width="stretch")

    st.dataframe(
        df.rename(columns={
            "threshold": "Threshold", "precision": "Precision", "recall": "Recall",
            "f1": "F1", "false_positive_rate": "FP rate",
            "missed_malware": "Missed malware", "false_alarms": "False alarms",
        }),
        width="stretch", hide_index=True, height=380,
    )


def _tab_data(metrics: dict) -> None:
    data = metrics.get("dataset", {})

    st.markdown("##### How the training data was built")
    st.warning(
        "**Read this before quoting the accuracy figures.**\n\n"
        "The benign class is *measured*: real PE files from this machine's "
        "system directories, put through the exact same extractor the scanner "
        "uses. The malicious class is *synthesised*: each sample starts as a "
        "real benign file's feature vector and then has a documented malware "
        "behaviour profile applied to the features that research consistently "
        "finds discriminative.\n\n"
        "That design means the metrics measure whether the model learned the "
        "encoded relationship between file structure and maliciousness. They "
        "are **not** a measured real-world detection rate against live malware "
        "— that would require a labelled corpus of real samples. The Retrain "
        "tab accepts exactly such a corpus when one is available."
    )

    if data:
        c1, c2, c3 = st.columns(3)
        with c1:
            card("Total rows", f"{data.get('total_rows', 0):,}")
            card("Real binaries measured", f"{data.get('real_benign_files', '?')}")
        with c2:
            card("Benign rows", f"{data.get('benign_rows', 0):,}")
            card("Malicious rows", f"{data.get('malicious_rows', 0):,}")
        with c3:
            card("Deliberately hard benign", f"{data.get('hard_benign_rows', 0):,}")
            card("Stealth malicious", f"{data.get('stealth_malicious_rows', 0):,}")

        st.markdown(f"**Data source:** {data.get('source', 'unknown')}")
        if data.get("split_strategy"):
            st.markdown(f"**Split strategy:** {data['split_strategy']}")
        split = metrics.get("split", {})
        if split:
            st.caption(
                f"{split.get('train_source_files', '?')} source binaries seeded the "
                f"training rows and {split.get('test_source_files', '?')} seeded the "
                "test rows, with none shared. Without that grouping, rows derived "
                "from the same binary would appear on both sides and every score "
                "here would be inflated."
            )
        if data.get("families"):
            st.markdown("**Malware families modelled:** "
                        + ", ".join(f"`{f}`" for f in data["families"]))

    st.markdown("##### Using a real labelled corpus instead")
    st.code(
        "# Any CSV/Parquet with the 73 feature columns plus a 'label' column\n"
        "python -m malscan.model.train --dataset path/to/real_corpus.csv",
        language="bash",
    )


def _tab_retrain() -> None:
    st.markdown("##### Retrain the classifier")
    st.caption(
        "Rebuilds the dataset from this machine's binaries and retrains both "
        "candidate models. Existing scan history is untouched."
    )

    c1, c2 = st.columns(2)
    benign_limit = c1.slider(
        "Real binaries to measure", 200, 3000, 1200, 100,
        help="More files means a better benign distribution but a longer build.",
    )
    n_per_class = c2.slider(
        "Rows generated per class", 1000, 15000, CONFIG.n_synthetic_per_class, 500
    )

    # Measured at roughly 0.25-0.8 s per binary of wall-clock, depending
    # heavily on file sizes in System32 and on how busy the machine is.
    # Feature extraction dominates; model fitting itself takes under a minute.
    lo, hi = benign_limit * 0.25 / 60, benign_limit * 0.8 / 60
    st.caption(
        f"Rough estimate: **{lo:.0f}-{hi:.0f} minutes**, almost all of it "
        "feature extraction. The page stays busy until it finishes."
    )

    if st.button("Start retraining", type="primary"):
        from malscan.model.train import train

        bar = st.progress(0.0, text="Starting...")

        def on_progress(pct, msg):
            bar.progress(min(1.0, float(pct)), text=msg)

        try:
            metrics = train(
                n_per_class=n_per_class,
                benign_limit=benign_limit,
                progress=on_progress,
            )
        except Exception as exc:
            bar.empty()
            st.error(f"Training failed: {exc}")
            return

        bar.progress(1.0, text="Done")
        reload_classifier()
        best = metrics["models"][0]
        st.success(
            f"Trained **{metrics['best_model']}** — accuracy "
            f"{best['accuracy'] * 100:.2f}%, ROC-AUC {best['roc_auc']:.4f}, "
            f"in {metrics['training_seconds']:.0f}s. The new model is now live."
        )
        st.rerun()
