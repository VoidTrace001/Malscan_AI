# MalScan AI — Architecture

## System overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Streamlit interface (app.py)                  │
│   Scan  ·  Dashboard  ·  History  ·  Model  ·  Rules  ·  About       │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ bytes + filename
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      scanner.scan_bytes()                            │
│   size validation → extraction → classification → explanation → log  │
└────────┬───────────────────────────────────────────────┬─────────────┘
         │                                               │
         ▼                                               ▼
┌────────────────────────────┐              ┌──────────────────────────┐
│  Feature extraction        │              │  Rule engine             │
│  features/extractor.py     │◄─────────────┤  rules/engine.py         │
│                            │  hits +      │  yara-python  ─or─       │
│  ├ filetype.py  magic bytes│  severity    │  built-in matcher        │
│  ├ pe_features.py  headers │              │  malscan_rules.yar (27)  │
│  ├ entropy.py   Shannon    │              └──────────────────────────┘
│  ├ strings_features.py     │
│  └ hashes.py    identity   │
│                            │
│      → 73 ordered features │
│        (features/schema.py)│
└─────────────┬──────────────┘
              │ feature vector
              ▼
┌────────────────────────────┐              ┌──────────────────────────┐
│  Inference                 │              │  Explanation             │
│  model/predict.py          ├─────────────►│  model/explain.py        │
│                            │  model +     │                          │
│  PE parsed → RandomForest  │  baseline    │  ablation attribution:   │
│  / XGBoost + isotonic      │              │  reset one feature to    │
│  otherwise → content score │              │  the benign median, see  │
│  no model → heuristic      │              │  how far the score moves │
└─────────────┬──────────────┘              └────────────┬─────────────┘
              │ probability + verdict                     │ contributions
              └──────────────────┬────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   storage/history.py  →  SQLite                      │
│      analysis output + hashes only — the file itself is never kept   │
└──────────────────────────────────────────────────────────────────────┘
```

## Training pipeline

```
 C:\Windows\System32, SysWOW64, .venv
              │
              │  same extractor used at scan time
              ▼
 ┌────────────────────────────┐
 │  Real benign feature rows  │  ← measured, not invented
 └──────────────┬─────────────┘
                │ bootstrap resample (source_id recorded)
        ┌───────┴────────┐
        ▼                ▼
 ┌────────────┐   ┌──────────────────────────────┐
 │  Benign    │   │  Malicious                   │
 │  + 12%     │   │  6 family profiles applied   │
 │  packed-   │   │  + 15% stealth (partial      │
 │  but-legit │   │    profile only)             │
 └──────┬─────┘   └───────────┬──────────────────┘
        └────────┬────────────┘
                 ▼
     GroupShuffleSplit by source_id
     (no source binary spans the split)
                 ▼
     RandomForest  vs  XGBoost
                 ▼
     select on ROC-AUC → isotonic calibration
                 ▼
     models/malscan_model.joblib  +  models/metrics.json
```

## Feature groups

| Group | Count | Examples |
|---|---:|---|
| File | 11 | size, overall entropy, printable ratio, byte chi-square, type flags |
| PE Header | 22 | architecture, timestamp plausibility, checksum validity, ASLR/DEP/SEH, directory presence, entry-point entropy |
| Sections | 10 | mean/max/min/std entropy, high-entropy count, writable+executable count, non-standard names, virtual-size ratios |
| Imports | 13 | DLL and function counts, DLL-family flags, suspicious-API count and ratio, dynamic resolution, sparse import table, export count |
| Content | 12 | string count and lengths, URLs, IPs, registry keys, paths, suspicious keywords, base64 blobs, embedded MZ headers |
| Packing & Rules | 5 | overlay ratio, packer signature, rule hit count, max rule severity, max resource entropy |
| **Total** | **73** | |

The ordered list lives in `malscan/features/schema.py`, and the extractor,
the model and the explainer all work from it. Load a model trained against a
different schema and it is rejected outright, rather than quietly producing
nonsense.

## Key design decisions

**Static only.** The file is parsed as a data structure. Nothing is written to
an executable path, passed to a shell, loaded as a library, or run.

**Three-way verdict.** Benign / Suspicious / Malicious instead of a binary
call. Force a decision on a genuinely ambiguous file and what you get back is
confident nonsense.

**Tree ensembles.** The features are tabular and full of non-linear cutoffs
("entropy above 7.4", "fewer than 8 imports"). Trees split on that sort of
thing natively and need no scaling.

**Selection on ROC-AUC.** It does not depend on a threshold, and the
threshold here is adjustable at scan time anyway.

**Isotonic calibration.** If a number is going to be labelled "confidence"
in the UI it should mean something. A raw ensemble vote fraction does not.

**Grouped splitting.** Synthetic rows descend from real binaries, so the
split is by source binary. Split at random and near-duplicates end up on both
sides, which inflates every score you report.

**Domain routing.** The classifier only gets asked when the PE structure it
was trained on is really there: `is_pe` *and* a section table that parsed. An
MZ header on its own does not count. Anything else is scored from content
signals, because a model asked about a point it has never seen does not answer
carefully, it just answers. `pe_features_usable()` in `model/predict.py` is
the one place that decision gets made. `model/explain.py` keys off the same
engine, so the explanation always describes the calculation that actually
ran.

**Graceful degradation.** No `yara-python` → built-in pattern matcher. No
`python-magic` → built-in magic-byte table. No trained model → heuristic
scorer that says so on every verdict. The sidebar reports which backend is
live so none of this is guesswork.
