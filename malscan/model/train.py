"""Training and evaluation.

Fits a Random Forest and an XGBoost on the same split, compares them on
held-out data and saves whichever wins, along with the metrics report the
Model page renders.

Run it directly:
    python -m malscan.model.train                 # build data + train
    python -m malscan.model.train --dataset x.csv # train on a real corpus
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, average_precision_score, brier_score_loss,
    confusion_matrix, f1_score, precision_recall_curve, precision_score,
    recall_score, roc_auc_score, roc_curve,
)
from sklearn.model_selection import (
    GroupShuffleSplit, StratifiedGroupKFold, cross_val_score,
)

from malscan.config import CONFIG
from malscan.features.schema import FEATURE_NAMES
from malscan.model.dataset import build_dataset, load_external_dataset

try:
    from xgboost import XGBClassifier
    HAVE_XGB = True
except ImportError:  # pragma: no cover
    HAVE_XGB = False


def build_models(random_state: int = 42) -> dict:
    """The two candidate classifiers.

    Both are tree ensembles because the feature set is tabular, mixed-scale and
    full of non-linear thresholds ("entropy above 7.4", "fewer than 8 imports")
    -- exactly what trees split on natively, with no feature scaling required.
    """
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=400,
            max_depth=18,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=random_state,
        )
    }
    if HAVE_XGB:
        models["XGBoost"] = XGBClassifier(
            n_estimators=500,
            max_depth=7,
            learning_rate=0.06,
            subsample=0.85,
            colsample_bytree=0.85,
            reg_lambda=1.5,
            min_child_weight=2,
            eval_metric="logloss",
            tree_method="hist",
            n_jobs=-1,
            random_state=random_state,
        )
    return models


def _evaluate(name, model, X_test, y_test, groups_test) -> dict:
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    fpr, tpr, _ = roc_curve(y_test, proba)
    prec_curve, rec_curve, _ = precision_recall_curve(y_test, proba)

    # Per-group recall shows whether the hard cases actually got caught.
    per_group = {}
    if groups_test is not None:
        gdf = pd.DataFrame({"group": groups_test, "y": y_test, "pred": pred})
        for group, sub in gdf.groupby("group"):
            correct = int((sub.y == sub.pred).sum())
            per_group[str(group)] = {
                "n": int(len(sub)),
                "accuracy": round(correct / len(sub), 4),
            }

    return {
        "name": name,
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "pr_auc": round(float(average_precision_score(y_test, proba)), 4),
        "brier": round(float(brier_score_loss(y_test, proba)), 4),
        "confusion_matrix": {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        },
        "false_positive_rate": round(float(fp / max(1, fp + tn)), 4),
        "false_negative_rate": round(float(fn / max(1, fn + tp)), 4),
        "roc_curve": {
            "fpr": [round(float(v), 4) for v in fpr[:: max(1, len(fpr) // 200)]],
            "tpr": [round(float(v), 4) for v in tpr[:: max(1, len(tpr) // 200)]],
        },
        "pr_curve": {
            "precision": [round(float(v), 4) for v in prec_curve[:: max(1, len(prec_curve) // 200)]],
            "recall": [round(float(v), 4) for v in rec_curve[:: max(1, len(rec_curve) // 200)]],
        },
        "per_group_accuracy": per_group,
    }


def train(
    dataset_path: str | None = None,
    n_per_class: int | None = None,
    benign_limit: int = 1500,
    save: bool = True,
    progress=None,
) -> dict:
    """Build (or load) a dataset, train both models, keep the better one."""
    started = time.time()

    if dataset_path:
        if progress:
            progress(0.05, f"Loading external dataset: {dataset_path}")
        df = load_external_dataset(dataset_path)
        data_meta = {
            "source": "external",
            "path": str(dataset_path),
            "total_rows": int(len(df)),
            "benign_rows": int((df.label == 0).sum()),
            "malicious_rows": int((df.label == 1).sum()),
        }
    else:
        df, data_meta = build_dataset(
            n_per_class=n_per_class, benign_limit=benign_limit, progress=progress
        )
        data_meta["source"] = "measured-benign + profile-synthesised-malicious"
        # Keep the exact training data alongside the model for reproducibility.
        try:
            df.to_csv(CONFIG.dataset_csv, index=False)
            data_meta["saved_to"] = str(CONFIG.dataset_csv)
        except Exception as exc:
            data_meta["save_error"] = str(exc)

    X = df[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy(dtype=int)
    groups = df["group"].to_numpy() if "group" in df.columns else np.zeros(len(y))
    # Synthetic rows are bootstrapped from a pool of real binaries, so several
    # rows can descend from the same file. Splitting at random would put
    # near-duplicates on both sides and inflate every score. Splitting by
    # source file instead means the test set contains only binaries the model
    # has never seen in any form.
    source_id = (
        df["source_id"].to_numpy()
        if "source_id" in df.columns
        else np.arange(len(df))
    )

    splitter = GroupShuffleSplit(
        n_splits=1, test_size=CONFIG.test_size, random_state=CONFIG.random_state
    )
    train_idx, test_idx = next(splitter.split(X, y, groups=source_id))
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    g_test = groups[test_idx]
    source_train = source_id[train_idx]

    leaked = set(source_id[train_idx]) & set(source_id[test_idx])
    assert not leaked, f"grouped split leaked {len(leaked)} source files"

    results, fitted = [], {}
    candidates = build_models(CONFIG.random_state)
    for i, (name, model) in enumerate(candidates.items()):
        if progress:
            progress(0.90 + 0.03 * i, f"Training {name}...")
        model.fit(X_train, y_train)
        fitted[name] = model
        results.append(_evaluate(name, model, X_test, y_test, g_test))

    # Pick on ROC-AUC: it is threshold-independent, which matters because the
    # UI exposes an adjustable decision threshold.
    results.sort(key=lambda r: (-r["roc_auc"], -r["f1"]))
    best_name = results[0]["name"]
    best_model = fitted[best_name]

    if progress:
        progress(0.96, f"Cross-validating {best_name}...")
    # Grouped CV for the same reason as the grouped holdout above.
    cv = StratifiedGroupKFold(
        n_splits=5, shuffle=True, random_state=CONFIG.random_state
    )
    # n_jobs=1 here on purpose: the estimator already parallelises across all
    # cores, so parallelising the folds too would oversubscribe them and run
    # slower than serial, badly so on a 4-core machine.
    cv_scores = cross_val_score(
        best_model, X, y, groups=source_id, cv=cv, scoring="roc_auc", n_jobs=1
    )

    # Probabilities drive the confidence number shown to the user, so calibrate
    # them rather than trusting raw ensemble votes.
    if progress:
        progress(0.98, "Calibrating probabilities...")
    inner_cv = StratifiedGroupKFold(
        n_splits=5, shuffle=True, random_state=CONFIG.random_state
    )
    calibrated = CalibratedClassifierCV(
        best_model, method="isotonic",
        cv=list(inner_cv.split(X_train, y_train, groups=source_train)),
    )
    calibrated.fit(X_train, y_train)
    cal_proba = calibrated.predict_proba(X_test)[:, 1]
    calibrated_brier = float(brier_score_loss(y_test, cal_proba))

    uncalibrated_brier = results[0]["brier"]
    use_calibrated = calibrated_brier <= uncalibrated_brier
    final_model = calibrated if use_calibrated else best_model

    importances = _feature_importance(best_model)

    # Reference profile of the benign training rows. The explainer needs it to
    # answer "what would this file's score be if this one feature looked
    # normal?", which is how each scan gets a per-feature contribution.
    benign_rows = X_train[y_train == 0]
    malicious_rows = X_train[y_train == 1]
    baseline = {
        "benign_median": np.median(benign_rows, axis=0).astype(float).tolist(),
        "benign_p10": np.percentile(benign_rows, 10, axis=0).astype(float).tolist(),
        "benign_p90": np.percentile(benign_rows, 90, axis=0).astype(float).tolist(),
        "malicious_median": np.median(malicious_rows, axis=0).astype(float).tolist(),
    }

    # How the decision threshold trades false alarms against misses. The UI
    # plots this so the operating point is a visible choice, not a hidden one.
    # cal_proba was already computed above; reuse it rather than predicting twice.
    final_proba = cal_proba if use_calibrated else best_model.predict_proba(X_test)[:, 1]
    threshold_sweep = []
    for t in np.arange(0.05, 1.0, 0.05):
        pred_t = (final_proba >= t).astype(int)
        tn_t, fp_t, fn_t, tp_t = confusion_matrix(
            y_test, pred_t, labels=[0, 1]
        ).ravel()
        threshold_sweep.append({
            "threshold": round(float(t), 2),
            "precision": round(float(precision_score(y_test, pred_t, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, pred_t, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, pred_t, zero_division=0)), 4),
            "false_positive_rate": round(float(fp_t / max(1, fp_t + tn_t)), 4),
            "missed_malware": int(fn_t),
            "false_alarms": int(fp_t),
        })

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "training_seconds": round(time.time() - started, 1),
        "best_model": best_name,
        "calibrated": bool(use_calibrated),
        "calibration": {
            "brier_uncalibrated": uncalibrated_brier,
            "brier_calibrated": round(calibrated_brier, 4),
            "method": "isotonic (5-fold)",
        },
        "cross_validation": {
            "metric": "roc_auc",
            "folds": 5,
            "grouped_by": "source binary (StratifiedGroupKFold)",
            "scores": [round(float(s), 4) for s in cv_scores],
            "mean": round(float(cv_scores.mean()), 4),
            "std": round(float(cv_scores.std()), 4),
        },
        "models": results,
        "dataset": data_meta,
        "feature_importance": importances,
        "threshold_sweep": threshold_sweep,
        "n_features": len(FEATURE_NAMES),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "environment": {
            "python": platform.python_version(),
            "xgboost_available": HAVE_XGB,
        },
    }

    metrics["split"] = {
        "strategy": "GroupShuffleSplit by source binary",
        "train_source_files": int(len(set(source_id[train_idx]))),
        "test_source_files": int(len(set(source_id[test_idx]))),
        "leaked_source_files": 0,
    }

    if save:
        CONFIG.ensure_dirs()
        joblib.dump(
            {
                "model": final_model,
                "raw_model": best_model,
                "feature_names": FEATURE_NAMES,
                "model_name": best_name,
                "calibrated": use_calibrated,
                "baseline": baseline,
                "feature_importance": importances,
                "trained_at": metrics["trained_at"],
                "version": 2,
            },
            CONFIG.model_path,
            compress=3,
        )
        CONFIG.metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    if progress:
        progress(1.0, f"Done -- {best_name}, ROC-AUC {results[0]['roc_auc']}")
    return metrics


def _feature_importance(model, top: int = 30) -> list[dict]:
    values = getattr(model, "feature_importances_", None)
    if values is None:
        return []
    pairs = sorted(
        ({"feature": n, "importance": round(float(v), 5)}
         for n, v in zip(FEATURE_NAMES, values)),
        key=lambda d: -d["importance"],
    )
    return pairs[:top]


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the MalScan AI classifier")
    ap.add_argument("--dataset", help="CSV/Parquet with FEATURE_NAMES + label")
    ap.add_argument("--n-per-class", type=int, default=None)
    ap.add_argument("--benign-limit", type=int, default=1500,
                    help="How many real system binaries to measure")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    def cli_progress(pct, msg):
        print(f"[{pct * 100:5.1f}%] {msg}", flush=True)

    metrics = train(
        dataset_path=args.dataset,
        n_per_class=args.n_per_class,
        benign_limit=args.benign_limit,
        save=not args.no_save,
        progress=cli_progress,
    )

    print("\n" + "=" * 62)
    print(f"  Best model : {metrics['best_model']}")
    print(f"  Dataset    : {metrics['dataset']['total_rows']} rows "
          f"({metrics['dataset'].get('real_benign_files', '?')} real benign files measured)")
    print(f"  CV ROC-AUC : {metrics['cross_validation']['mean']:.4f} "
          f"+/- {metrics['cross_validation']['std']:.4f}")
    print("=" * 62)
    for r in metrics["models"]:
        print(f"  {r['name']:<14} acc={r['accuracy']:.4f}  prec={r['precision']:.4f}  "
              f"rec={r['recall']:.4f}  f1={r['f1']:.4f}  auc={r['roc_auc']:.4f}")
    cm = metrics["models"][0]["confusion_matrix"]
    print(f"\n  Confusion (best): TN={cm['true_negative']} FP={cm['false_positive']} "
          f"FN={cm['false_negative']} TP={cm['true_positive']}")
    print(f"  False positive rate: {metrics['models'][0]['false_positive_rate']:.4f}")
    print("\n  Hardest groups:")
    groups = metrics["models"][0]["per_group_accuracy"]
    for g, s in sorted(groups.items(), key=lambda kv: kv[1]["accuracy"])[:5]:
        print(f"    {g:<28} acc={s['accuracy']:.3f}  (n={s['n']})")
    print(f"\n  Saved model   -> {CONFIG.model_path}")
    print(f"  Saved metrics -> {CONFIG.metrics_path}")


if __name__ == "__main__":
    main()
