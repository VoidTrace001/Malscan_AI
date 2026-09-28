# MalScan AI

**An AI-powered static malware detection and analysis system.**

Tamal Mishra · BCA (Cybersecurity) · EThames Business School, Hyderabad

---

MalScan AI decides whether a file is malicious from its **static structure
alone**. The file is parsed as data and never executed. It pulls 73 features
out of the PE headers, sections, imports, entropy and embedded strings, runs
them through a trained tree ensemble, and returns a calibrated probability
along with a per-feature breakdown of *why* it landed there.

## Why not just use signatures?

A signature only matches what someone has already catalogued. That leaves it
weak in three predictable places: zero-day malware, polymorphic and metamorphic
code that rewrites itself between infections, and packed payloads whose bytes
come out different every build.

A model working on structural features does not need to have seen the specific
sample. It picks up on what malicious files tend to have in common: entropy
that suggests packing, an import table that has obviously been stripped,
sections that are writable and executable at once, API combinations that only
really make sense if you are injecting into another process.

---

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model (measures real binaries on this machine; see note below)
python -m malscan.model.train

# 3. Launch the web interface
streamlit run app.py
```

Training measures around 1000 real binaries from this machine's system
directories and takes about **5-15 minutes**. Almost all of that is feature
extraction, not the actual model fitting. Use `--benign-limit` to trade time
for dataset size.

Then open http://localhost:8501.

You can run the app before training as well. It drops back to a plain
heuristic scorer and says so on every verdict rather than quietly pretending
there is a model behind it.

### Try it out

```bash
python scripts/make_samples.py      # writes harmless test files to samples/
```

These push different paths through the pipeline: clean text, a script that
only *mentions* suspicious API names, a high-entropy blob, a broken PE header,
and a copy of a real system binary. None of it is malware. Add `--eicar` and
it will also write the standard EICAR test string, at which point your
antivirus should quarantine it. That reaction is the point.

### Command line

```bash
python malscan_cli.py suspicious.exe          # scan one file
python malscan_cli.py C:\folder --recursive   # scan a tree
python malscan_cli.py file.exe --json         # machine-readable output
```

### Tests

```bash
python tests/test_malscan.py                  # 31 tests, no pytest needed
```

---

## How a scan works

```
Upload (Streamlit)
    ↓
File type detection          magic bytes, never the extension
    ↓
Static feature extraction    73 features: PE headers · sections · imports
                             entropy · strings · packing indicators
    ↓
Rule matching                27 YARA rules, severity 1-5
    ↓
ML classification            Random Forest / XGBoost → calibrated probability
    ↓
Explanation                  per-feature ablation attribution
    ↓
SQLite scan history
```

### The three-way verdict

| Verdict | Probability | Meaning |
|---|---|---|
| **Benign** | < 0.40 | Nothing structurally concerning |
| **Suspicious** | 0.40 – 0.65 | Genuinely ambiguous; worth a human look |
| **Malicious** | ≥ 0.65 | Multiple structural indicators agree |

The middle band is there on purpose. Forced into a yes/no the model has to
commit on files it genuinely cannot separate, and "someone should review this"
is a more useful answer than a confident coin flip. Both thresholds can be
moved per-scan in the UI, and the Model page plots what each setting costs you
in missed malware against false alarms.

### Explanations

Every verdict comes with an **ablation** breakdown. For each feature in turn,
MalScan resets it to the median of the benign training data, leaves the other
72 alone, and asks the model again. However far the malicious probability
moves is that feature's contribution to *this* verdict. Roughly the same idea
as SHAP, but it needs no extra dependency and one batched forward pass.

Worth not confusing with the global feature importances on the Model page.
Those tell you what usually matters. The ablation tells you what mattered
here.

Each bar is labelled from the description in `features/schema.py`, and those
are written for someone who does not already know what an import thunk is —
"looks its functions up while running instead of declaring them upfront, which
is a common way to hide what a program intends to do" rather than "imports
LoadLibrary + GetProcAddress together". They are printed verbatim to the
reader, in the UI and in the CLI, so they are part of the interface rather than
internal notes. Anything added there should stay in that register.

### Performance

Only files with a parsable PE structure reach the trained model, so that is
what scan cost tracks:

| File | Size | Scan |
|---|---|---|
| Text, script or document | < 2 KB | 1–2 ms |
| High-entropy blob | 256 KB | ~52 ms |
| Malformed PE | 2 KB | ~61 ms |
| Real system binary, full model path | 352 KB | ~890 ms |

Three things keep the full path under a second:

- **Inference is pinned to one thread.** The forests are fitted with
  `n_jobs=-1`, which is right for training and wrong for scoring: a scan
  classifies a single row and the explainer at most 74, so joblib spent longer
  standing up a worker pool than the trees took to traverse. The tell was that
  one row cost 620 ms and seventy-four cost 650 ms — the cost was per call, not
  per row. Pinning it cut prediction to 245 ms and explanation to 265 ms.
- **Only the data directories that get read are parsed.** Loading the full set
  dragged in the exception directory, which on a sizeable binary costs more
  than the rest of the scan and is never once looked at. The presence flags
  (debug, TLS, relocations, resources, signature) come straight off the
  optional header and need no directory parsing at all.
- **The PE checksum is recomputed only when one is stored.** Recomputing means
  `pefile` serialising the whole image back out, and with no stored checksum
  the verdict is "not set" either way.

Together those took a real-binary scan from 1883 ms to 889 ms. None of it
changes what comes out: predictions are bitwise identical, and the parsed PE
report was diffed field by field across 15 real binaries with no differences.

Loading the model is a separate cost — **2–5 seconds, once per process**. The
web app pays it once per session; the CLI pays it on every invocation, which is
why a one-file CLI run reports several seconds while the scan inside it takes
under one. That time is spent unpickling 2000 trees rather than decompressing,
so compression settings barely move it and the only real lever is a smaller
forest.

---

## Project layout

```
malscan/
├── config.py               paths, thresholds, limits — no magic numbers elsewhere
├── util.py                 shared helpers, deliberately free of any framework
├── scanner.py              the scan pipeline; the one function the UI calls
├── features/
│   ├── schema.py           the 73-feature contract + reader-facing descriptions
│   ├── extractor.py        orchestrator: bytes → feature vector + rich report
│   ├── pe_features.py      PE headers, sections, imports, packer detection
│   ├── strings_features.py embedded strings, URLs, IPs, suspicious keywords
│   ├── entropy.py          Shannon entropy, byte histograms, chi-square
│   ├── filetype.py         magic-byte typing with a python-magic fast path
│   └── hashes.py           MD5/SHA-1/SHA-256 + a rolling similarity digest
├── rules/
│   ├── malscan_rules.yar   27 detection rules with severity and category
│   └── engine.py           yara-python, with a pure-Python fallback matcher
├── model/
│   ├── dataset.py          training set construction (read this one carefully)
│   ├── train.py            trains RF + XGBoost, compares, calibrates, saves
│   ├── predict.py          inference, domain routing, heuristic fallback
│   └── explain.py          ablation-based per-scan attribution
├── storage/history.py      SQLite scan history
└── ui/                     Streamlit pages
app.py                      web entry point
malscan_cli.py              command-line scanner
tests/test_malscan.py       test suite
```

---

## Being clear about the training data

**Read this before you read the accuracy number.** The caveats here matter
more than the figure does.

I cannot host a live malware corpus for a student project, and EMBER, the
standard public benchmark, is a ~10 GB download that ships pre-computed
features rather than files this extractor could actually parse. So the dataset
gets built in two halves:

**1. The benign class is measured, not invented.** Real PE files from this
machine's system directories go through the *same* extractor the scanner uses
at runtime. So the quirks of real software survive into the data instead of
being idealised away: reproducible-build timestamps that look implausible,
hotpatch sections with odd names, catalog signing that static parsing cannot
see.

**2. The malicious class is synthesised from documented behaviour profiles.**
Each synthetic sample starts as a *real benign feature vector* and then has a
family profile applied — six families covering packed droppers, ransomware,
RATs, spyware, injectors and trojanised installers. Only the features that
malware research consistently finds discriminative are shifted; everything else
keeps its realistic benign value.

The shared real backbone is the part that makes this worth anything. Generate
malicious rows from scratch and the model can separate the classes on
generation artefacts instead of on security-relevant structure, and then the
accuracy figure tells you nothing.

Two more guards on top of that:

- **Deliberate hard cases.** 12% of the benign rows are packed-but-legitimate
  installers (high entropy, packer hit, sparse imports), and 15% of malicious
  rows are "stealthy", carrying only part of their family profile. Both land
  inside the other class's territory, so clean separation is impossible by
  construction. That is intentional.
- **Grouped train/test splitting.** Several rows descend from the same real
  binary. Splitting at random would put near-duplicates on both sides and
  inflate every score. MalScan splits by *source binary* (`GroupShuffleSplit`,
  and `StratifiedGroupKFold` for cross-validation), so the test set contains
  only binaries the model has never seen in any form. The trainer asserts that
  zero source files span the split.

### Staying inside the model's domain

Every training row came from a real Windows binary whose headers, sections and
import table parsed. A text file, a Word document, or a PE too corrupt to read
has none of that, so those forty-odd structural features sit at zero. The
model has never seen that region of the feature space.

Ask it anyway and you do not get a cautious answer, you get an unpredictable
one. A 166-byte plain-text README came back at **59% malicious**. Nothing about
it was suspicious; "no imports, no sections" just happens to look more like a
stripped binary than like a normal one.

So MalScan stopped asking. With no usable PE structure the file is scored on
what it does have (rule matches, string indicators, whole-file entropy, and
whether it claimed a PE header it could not honour) and every verdict says
which engine produced it:

| File | Engine | Before | After |
|------|--------|--------|-------|
| Plain-text README | content | Suspicious 59.0% | Benign 0.0% |
| Shadow-copy-deleting script | content | Malicious 100.0% | Malicious 78.0% |
| Deliberately malformed PE | content | Suspicious 59.4% | Suspicious 40.0% |
| Real system binary | model | Benign 2.4% | Benign 2.4% |

The content engine's weights are fixed and written down rather than learned,
so the bars on the *Why this verdict* tab are the whole calculation, not a
summary of it. Confidence gets scaled down on these too, since fewer signals
went into them.

### What the metrics do and do not mean

What the figures measure is whether the model **learned the relationship
encoded in the data** between file structure and maliciousness. They are
**not** a detection rate measured against live malware in the field. Quoting
them as "MalScan detects N% of real malware" would be wrong.

### Training on a real corpus

The path is already there. Any CSV or Parquet with the 73 feature columns plus
a `label` column (0 = benign, 1 = malicious) drops straight in:

```bash
python -m malscan.model.train --dataset path/to/real_corpus.csv
```

Missing feature columns are filled with zero and reported, so a
partially-overlapping schema still loads. With one row per real file, each row
becomes its own split group automatically.

---

## Other limitations worth stating

- **Static analysis cannot see runtime behaviour.** A sample that only
  decrypts its payload once it is running leaves very little on disk for a
  static scanner to find. Sandbox analysis is the obvious complement, which is
  why it sits under future scope.
- **A verdict is evidence, not proof.** Legitimate packed software trips a lot
  of the same indicators. Hence the Suspicious band.
- **Non-PE files get weaker analysis, and a different engine.** The structural
  features are PE-specific, so the model is not asked about files that have
  none of them (see *Staying inside the model's domain* above). Documents and
  scripts are still typed, string-mined and rule-matched, and the scanner says
  outright when a verdict rests only on those.
- **Rule matches are inputs, not conclusions.** Ordinary Windows DLLs match
  several of the bundled rules. That is expected, and it is why rule hits are
  two features among 73 rather than a verdict in their own right.

---

## Safety model

Uploaded files sit in memory as a plain byte buffer and get parsed as data.
Nothing is written somewhere executable, handed to a shell, imported as a
library, or run. The buffer is dropped when the scan returns.

The scan history keeps the analysis output and the hashes. **Not the file.**
That is what makes the database safe to leave lying around.

The SHA-256 on a result links out to VirusTotal if you want to cross-reference
it. The link is built locally from the hash; nothing is transmitted.

---

## Technology

| Component | Choice | Why |
|---|---|---|
| Language | Python 3.9+ | Ecosystem for both ML and binary parsing |
| Interface | Streamlit | Usable UI without a separate frontend build |
| Models | scikit-learn RF, XGBoost | Tabular features full of non-linear thresholds — what trees split on natively, no scaling needed |
| PE parsing | pefile | Mature, pure-Python, no execution required |
| Rules | yara-python (+ fallback) | Industry standard, with a pure-Python matcher when unavailable |
| File typing | magic bytes (+ python-magic) | Extensions are trivially forged; headers are not |
| Visualisation | Plotly | Interactive charts inside Streamlit |
| Storage | SQLite | Zero-configuration, single file, ships with Python |

Neither optional native dependency is required. Without `yara-python` the
built-in matcher handles the plain-text patterns from the same rule file;
without `python-magic` the bundled magic-byte table does the typing. The
sidebar always says which backend is actually live.

Models are selected on **ROC-AUC**, since it does not depend on a threshold
and the threshold here is adjustable at scan time anyway. Probabilities are
**isotonically calibrated**, because the confidence figure shown to a user
ought to mean something and a raw ensemble vote fraction does not.

---

## Future scope

- Cross-referencing verdicts against the VirusTotal API
- Dynamic analysis in an isolated sandbox, to see actual behaviour
- Wider format coverage: APKs, Office macros, scripts
- Retraining on a real labelled corpus (the training script already takes one)
- Deploying as a hosted service instead of a local app
