"""Generate the MalScan AI system guide as print-ready HTML.

Every table of data (features, rules, metrics) is pulled live from the project
so the document cannot drift out of step with the code.
"""
import collections
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from malscan.config import CONFIG
from malscan.features.schema import FEATURE_GROUPS, N_FEATURES
from malscan.rules.engine import get_engine
from malscan.ui.page_rules import _parse_rule_metadata

OUT = ROOT / "docs" / "MalScan_AI_System_Guide.html"
E = html.escape

metrics = json.loads((ROOT / "models" / "metrics.json").read_text(encoding="utf-8"))
rules = _parse_rule_metadata()
engine = get_engine()
models = {m["name"]: m for m in metrics["models"]}
ds = metrics["dataset"]

# ---------------------------------------------------------------- helpers
def table(headers, rows, cls=""):
    h = "".join(f"<th>{c}</th>" for c in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows
    )
    return (f'<table class="{cls}"><thead><tr>{h}</tr></thead>'
            f"<tbody>{body}</tbody></table>")


# ---------------------------------------------------------------- content
TECH = [
    ("Python 3.9+<br><span class='sub'>running 3.13.15</span>",
     "The language the whole system is written in.",
     "It is the only ecosystem with both mature binary-parsing libraries and "
     "mature machine-learning libraries. Using one language for the parser, "
     "the model and the interface removes every translation layer between "
     "them."),
    ("Streamlit",
     "Turns the Python code into a web interface: upload box, tabs, charts, "
     "tables.",
     "It renders a browser UI directly from Python, so there is no separate "
     "front-end project, no JavaScript build step and no API layer to keep in "
     "sync. For a single developer that removes an entire tier of work."),
    ("pefile",
     "Reads the internal structure of a Windows program: headers, sections, "
     "imports, exports, resources.",
     "It is pure Python and treats the file strictly as a data structure. It "
     "never asks Windows to load the program, which is exactly the property a "
     "malware scanner needs."),
    ("YARA<br><span class='sub'>yara-python</span>",
     "Matches the file against 27 written rules describing known malicious "
     "patterns.",
     "YARA is the industry standard for malware pattern rules and is used by "
     "VirusTotal and most commercial vendors. Its rule syntax is readable, so "
     "the detection logic can be inspected and extended by hand."),
    ("scikit-learn",
     "Provides the Random Forest classifier, the probability calibration and "
     "every evaluation metric.",
     "It is the reference toolkit for classical machine learning, with the "
     "grouped splitting and calibration methods this project depends on built "
     "in and well tested."),
    ("XGBoost",
     "A second, competing classifier (gradient boosting).",
     "Training two different algorithms and selecting between them on measured "
     "performance is more defensible than asserting one is better. Both are "
     "trained every run and the comparison is recorded."),
    ("NumPy",
     "Holds the feature vectors as numeric arrays and powers the explanation "
     "step.",
     "The explainer builds 74 variants of the file's feature vector and scores "
     "them in one batch. NumPy makes that a single fast operation instead of a "
     "loop."),
    ("pandas",
     "Organises the training set and every table shown in the interface.",
     "It is the standard way to handle labelled tabular data in Python and "
     "reads and writes the CSV/Parquet training files directly."),
    ("Plotly",
     "Draws the charts: contribution bars, entropy graphs, ROC curves, "
     "dashboards.",
     "Its charts are interactive inside Streamlit, so values can be hovered "
     "and inspected rather than just looked at."),
    ("SQLite",
     "Stores the history of every scan.",
     "It ships inside Python, needs no server, no installation and no "
     "configuration, and keeps the whole database in one file that can be "
     "copied or deleted."),
    ("joblib",
     "Saves the trained model to disk and loads it back.",
     "It is the format scikit-learn itself recommends, and it handles the "
     "large numeric arrays inside a trained forest efficiently."),
    ("python-magic<br><span class='sub'>optional</span>",
     "Identifies file types from their content.",
     "Optional by design. If it is missing, MalScan falls back to its own "
     "magic-byte table, so a missing system library degrades the result "
     "instead of stopping the program."),
]

PIPELINE = [
    ("1", "File type detection",
     "Reads the first few bytes of the file and matches them against known "
     "signatures. The extension is deliberately ignored, because anyone can "
     "rename <code>virus.exe</code> to <code>holiday.jpg</code>; the bytes at "
     "the start of a file are far harder to fake.",
     "features/filetype.py"),
    ("2", "Hashing",
     "Computes MD5, SHA-1 and SHA-256 fingerprints, plus a similarity digest "
     "that stays close for near-identical files, so repackaged variants of the "
     "same sample can be spotted.",
     "features/hashes.py"),
    ("3", "Structural analysis",
     "If the file is a Windows program, its headers, section table, imports, "
     "exports and resources are parsed out and examined for anomalies.",
     "features/pe_features.py"),
    ("4", "Randomness measurement",
     "Measures entropy for the whole file, for each section and for every 4 KB "
     "block. Ordinary code and text are predictable; compressed or encrypted "
     "content is not, so a high reading suggests something is hidden.",
     "features/entropy.py"),
    ("5", "Text mining",
     "Pulls readable text out of the binary and counts web addresses, IP "
     "addresses, registry paths, file paths, suspicious keywords, encoded "
     "blocks and any executables hidden inside.",
     "features/strings_features.py"),
    ("6", "Rule matching",
     f"Runs {engine.rule_count} YARA rules over the file. Each carries a "
     "category and a severity from 1 to 5. The number of hits and the worst "
     "severity become two of the 73 features.",
     "rules/engine.py"),
    ("7", "Classification",
     "The 73 numbers are handed to the trained model, which returns a "
     "probability that the file is malicious. Files without a usable Windows "
     "structure are routed to a content scorer instead.",
     "model/predict.py"),
    ("8", "Explanation",
     "Each feature in turn is reset to its typical benign value and the model "
     "is asked again. How far the score moves is that feature's contribution "
     "to this particular verdict.",
     "model/explain.py"),
    ("9", "Recording",
     "The verdict, the evidence and the hashes are written to SQLite. The file "
     "itself is never stored.",
     "storage/history.py"),
]

USES = [
    ("Triaging an unknown file",
     "Someone receives an attachment or downloads an installer and wants a "
     "reasoned opinion before opening it. MalScan gives a verdict plus the "
     "evidence behind it in about a second."),
    ("Catching what signatures miss",
     "Signature scanners only recognise malware someone has already catalogued. "
     "Because MalScan judges structure rather than exact bytes, it can flag a "
     "sample it has never seen, which is the entire argument for the approach."),
    ("Bulk checking a folder",
     "The command-line scanner walks a directory tree and emits JSON, so it can "
     "be scripted into a larger workflow or scheduled."),
    ("Teaching and learning static analysis",
     "Every stage is visible: the headers, the section permissions, the entropy "
     "graph, the matched rules, the per-feature contributions. It shows how the "
     "conclusion was reached rather than only stating it."),
    ("Demonstrating explainable AI",
     "Security tools are often criticised for being unaccountable. Every verdict "
     "here can be traced to specific measurable properties of the file."),
    ("Keeping an audit trail",
     "The scan history records what was examined and what was concluded, "
     "without ever retaining the files themselves."),
]

EXTENSIONS = [
    ("Cross-reference with VirusTotal", "Small",
     "The SHA-256 is already computed and linked. Calling the VirusTotal API "
     "would add 70+ other engines' opinions beside MalScan's own."),
    ("Train on a real malware corpus", "Medium",
     "The training script already accepts a CSV or Parquet file with the 73 "
     "feature columns and a label. Supplying real samples would replace the "
     "synthesised malicious class and turn the accuracy figure into a genuine "
     "detection rate."),
    ("Support more file formats", "Medium",
     "The structural features are specific to Windows programs. Equivalent "
     "extractors for Android APKs, Linux ELF binaries and Office macros would "
     "extend real coverage beyond PE files."),
    ("Dynamic analysis in a sandbox", "Large",
     "Running the file in an isolated virtual machine and watching its actual "
     "behaviour would catch the one thing static analysis fundamentally cannot: "
     "a payload that only decrypts itself once running."),
    ("Deploy as a hosted service", "Medium",
     "Moving from a local app to a shared web service with accounts, quotas and "
     "an upload queue would let a whole team use one instance."),
    ("Continuous retraining", "Medium",
     "New malware appears constantly. A scheduled retraining pipeline that "
     "ingests newly labelled samples would stop the model ageing."),
]

QA = [
    ("Why machine learning instead of a signature scanner?",
     "A signature only matches malware someone has already seen and catalogued. "
     "It cannot recognise a new variant. A model trained on structural "
     "properties does not need the specific sample, only the shape of it, so it "
     "can flag something genuinely new."),
    ("Is it safe to scan real malware with this?",
     "Yes. The file is read into memory as plain data and parsed. It is never "
     "written to an executable location, never passed to a shell, never loaded "
     "as a library and never run. Analysing a sample is about as risky as "
     "looking at a photograph of one."),
    ("What is entropy, in one sentence?",
     "A measure of how unpredictable the bytes are, from 0 to 8. Normal code "
     "and text score low because they repeat; compressed or encrypted data "
     "scores near 8 because it looks random, which is why a high value suggests "
     "something is being hidden."),
    ("Why three verdicts instead of malicious or clean?",
     "Some files genuinely sit on the boundary, and legitimate packed software "
     "trips many of the same indicators as malware. Forcing a binary answer on "
     "those produces a confident guess. Saying 'a person should look at this' "
     "is more honest and more useful."),
    ("Why was Random Forest chosen over XGBoost?",
     f"Models are selected on ROC-AUC, which does not depend on a threshold. "
     f"Random Forest scored {models['RandomForest']['roc_auc']} against "
     f"XGBoost's {models['XGBoost']['roc_auc']} — very close, and the selection "
     f"rule picked the higher one. XGBoost was actually better on raw accuracy, "
     f"and the comparison is recorded rather than hidden."),
    ("What does calibration mean here?",
     "A raw forest vote of 0.8 does not reliably mean an 80% chance of being "
     "malicious. Isotonic calibration corrects those scores against held-out "
     "data so the number shown to a user carries its plain meaning. It improved "
     f"the Brier score from {metrics['calibration']['brier_uncalibrated']} to "
     f"{metrics['calibration']['brier_calibrated']}, where lower is better."),
    ("Why is the accuracy figure not a detection rate?",
     "The malicious half of the training data is synthesised from documented "
     "behaviour profiles, not collected from live samples. The figure shows the "
     "model learned the relationship present in that data. It is not a measured "
     "detection rate against real malware in the wild, and should never be "
     "quoted as one."),
    ("What stops the model being tested on files it trained on?",
     "Several rows descend from the same source binary. The split is done by "
     "source binary rather than by row, so no binary appears on both sides. The "
     "trainer asserts this and records "
     f"{metrics['split']['leaked_source_files']} leaked files."),
    ("What happens to a file that is not a Windows program?",
     "The model is not asked, because it was trained only on parsable Windows "
     "executables and would be guessing outside its experience. Such files are "
     "scored from content signals instead — rules, strings, entropy — and the "
     "verdict states which engine produced it and that the evidence is weaker."),
    ("What is the single biggest limitation?",
     "Static analysis cannot observe behaviour. A file that only decrypts its "
     "payload once running leaves very little on disk to detect. That is why "
     "sandbox analysis is the most valuable future addition."),
]

# ---------------------------------------------------------------- build
parts = []
A = parts.append

A("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>MalScan AI — System Guide</title><style>
@page { size: A4; margin: 17mm 15mm 16mm 15mm; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", -apple-system, system-ui, sans-serif;
  font-size: 10.2pt; line-height: 1.55; color: #1a1d21; margin: 0; }
h1,h2,h3 { line-height: 1.25; }
h1 { font-size: 25pt; margin: 0 0 4pt; letter-spacing: -0.4pt; }
h2 { font-size: 15pt; margin: 0 0 10pt; padding-bottom: 5pt;
  border-bottom: 2.5pt solid #1f6feb; color: #0b3a82;
  break-after: avoid; page-break-after: avoid; }
h3 { font-size: 11.5pt; margin: 15pt 0 5pt; color: #0b3a82;
  break-after: avoid; page-break-after: avoid; }
p { margin: 0 0 8pt; }
code { font-family: Consolas, ui-monospace, monospace; font-size: 9pt;
  background: #eef1f5; padding: 1pt 3.5pt; border-radius: 3px; }
.sub { font-size: 8.4pt; color: #5c6570; font-weight: 400; }
table { width: 100%; border-collapse: collapse; margin: 8pt 0 12pt;
  font-size: 9.2pt; }
th { background: #0b3a82; color: #fff; text-align: left; padding: 5pt 7pt;
  font-weight: 600; font-size: 9pt; }
td { padding: 5pt 7pt; border-bottom: 0.5pt solid #d8dde4;
  vertical-align: top; }
tbody tr:nth-child(even) { background: #f6f8fa; }
tr { break-inside: avoid; page-break-inside: avoid; }
section { break-before: page; page-break-before: page; }
section.first { break-before: auto; page-break-before: auto; }
.cover { text-align: center; padding-top: 58mm; }
.cover .rule { width: 70pt; height: 3.5pt; background: #1f6feb;
  margin: 13pt auto; }
.cover .by { margin-top: 26pt; font-size: 11pt; }
.cover .meta { color: #5c6570; font-size: 9.4pt; margin-top: 3pt; }
.tag { display: inline-block; background: #e7effb; color: #0b3a82;
  border-radius: 10px; padding: 1.5pt 8pt; font-size: 8.6pt;
  font-weight: 600; }
.lead { font-size: 11pt; color: #3d444d; }
.box { background: #f6f8fa; border-left: 3pt solid #1f6feb;
  padding: 8pt 11pt; margin: 10pt 0; break-inside: avoid; }
.warn { background: #fff8e6; border-left-color: #d98f00; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 9pt;
  margin: 9pt 0; }
.stat { background: #f6f8fa; border: 0.5pt solid #d8dde4; border-radius: 5px;
  padding: 8pt 10pt; }
.stat b { display: block; font-size: 17pt; color: #0b3a82;
  line-height: 1.15; }
.stat span { font-size: 8.6pt; color: #5c6570; }
.toc li { margin-bottom: 3.5pt; }
ol, ul { margin: 0 0 9pt; padding-left: 17pt; }
li { margin-bottom: 3pt; }
.q { font-weight: 600; color: #0b3a82; margin-bottom: 2pt; }
.qa { margin-bottom: 11pt; break-inside: avoid; page-break-inside: avoid; }
.flow td:first-child { font-weight: 700; color: #1f6feb; width: 20pt;
  font-size: 11pt; }
.nowrap { white-space: nowrap; }
</style></head><body>""")

# ---- cover
A(f"""<div class="cover">
<div class="tag">System Reference Guide</div>
<h1>MalScan AI</h1>
<div class="rule"></div>
<p class="lead">Detecting malicious software by examining a file's<br>
structure, without ever running it</p>
<div class="by"><b>Tamal Mishra</b></div>
<div class="meta">BCA (Cybersecurity) &middot; EThames Business School, Hyderabad<br>
EDC ID EDC-2024-189 &middot; OU ID 1289-24-861-024</div>
<div class="meta" style="margin-top:20pt">
{N_FEATURES} features &middot; {engine.rule_count} detection rules &middot;
{ds['total_rows']:,} training rows</div>
</div>""")

# ---- 1 what it is
A(f"""<section><h2>1 &nbsp; What MalScan AI is</h2>
<p class="lead">MalScan AI looks at a file and decides whether it is malicious
— without ever opening or running it.</p>
<p>It works the way a forensic examiner would: by studying the structure of the
thing rather than its behaviour. It measures {N_FEATURES} separate properties
of a file — how its internal sections are arranged, which Windows functions it
borrows, how random its contents look, what text is buried inside it — and
feeds those measurements to a model trained to recognise the patterns malicious
files tend to share.</p>
<p>The result is a probability, a verdict of <b>Benign</b>, <b>Suspicious</b>
or <b>Malicious</b>, and — importantly — a breakdown of exactly which
properties pushed the score in which direction.</p>

<div class="grid">
<div class="stat"><b>{N_FEATURES}</b><span>properties measured per file</span></div>
<div class="stat"><b>{engine.rule_count}</b><span>pattern rules applied</span></div>
<div class="stat"><b>{models[metrics['best_model']]['roc_auc']}</b>
<span>ROC-AUC on held-out test data</span></div>
<div class="stat"><b>&lt; 1 s</b><span>typical scan of a Windows program</span></div>
</div>

<h3>The problem it addresses</h3>
<p>Traditional antivirus works by signature: a catalogue of fingerprints of
known malware. It is fast and precise, but it can only recognise what someone
has already found and added to the list. That leaves three predictable gaps:</p>
<ul>
<li><b>Zero-day malware</b> — brand new, so nobody has catalogued it yet.</li>
<li><b>Polymorphic malware</b> — rewrites itself between infections, so its
fingerprint changes every time.</li>
<li><b>Packed malware</b> — compressed or encrypted so its bytes look different
in every build.</li>
</ul>
<p>A model that judges <i>structure</i> does not need to have seen the specific
file. It recognises the traits malicious programs tend to share: randomness
suggesting hidden content, an import table that has obviously been stripped,
memory regions that are writable and executable at the same time, function
combinations that only make sense if you intend to inject code into another
process.</p>

<div class="box warn"><b>An honest boundary.</b> This complements signature
scanning; it does not replace it. A signature scanner is near-perfect on
malware it already knows. MalScan is designed for the cases it does not.</div>
</section>""")

# ---- 2 how a scan works
A(f"""<section><h2>2 &nbsp; How a scan works, step by step</h2>
<p>Every scan runs the same nine stages. The whole sequence takes under a
second for a typical Windows program.</p>
{table(["#", "Stage", "What happens", "Code"],
       [(n, f"<b>{t}</b>", d, f"<code>{f}</code>") for n, t, d, f in PIPELINE],
       "flow")}
<div class="box"><b>Nothing is ever executed.</b> At no point is the file
written somewhere it could run, handed to a command shell, loaded as a library
or launched. It is read into memory as a plain block of bytes and taken apart
as data. That is what makes it safe to examine a genuine malware sample.</div>
</section>""")

# ---- 3 technology
A(f"""<section><h2>3 &nbsp; What each technology does and why it was chosen</h2>
<p>Every component was chosen for a specific reason. This table is the direct
answer to "what did you use, and why that?"</p>
{table(["Technology", "What it does", "Why this one"],
       [(f"<b>{n}</b>", w, y) for n, w, y in TECH])}
<h3>Designed to degrade, not to fail</h3>
<p>Two of these are optional on purpose. Without <code>yara-python</code> a
built-in pure-Python matcher handles the plain-text patterns from the same rule
file. Without <code>python-magic</code> the bundled magic-byte table identifies
file types. In both cases the program keeps working with reduced capability
instead of refusing to start, and the sidebar always states which backend is
actually live — so the user is never misled about what is running.</p>
</section>""")

# ---- 4 features
A(f"""<section><h2>4 &nbsp; The {N_FEATURES} properties measured</h2>
<p>These are the "extracts" — every measurement taken from a file, in the exact
order the model receives them. They are grouped into six families. The
descriptions below are the same words shown to the user in the interface.</p>""")

for group, items in FEATURE_GROUPS.items():
    A(f"<h3>{E(group)} &nbsp;<span class='sub'>{len(items)} features</span></h3>")
    A(table(["#", "Internal name", "What it measures"],
            [(i, f"<code>{E(n)}</code>", E(d))
             for i, (n, d) in enumerate(items.items(), 1)]))

A("""<div class="box"><b>Why a fixed order matters.</b> The list lives in one
file, <code>features/schema.py</code>, and the extractor, the model and the
explainer all read it from there. A model trained against a different list is
rejected on load rather than being allowed to produce nonsense from
mismatched columns.</div>
</section>""")

# ---- 5 rules
by_cat = collections.defaultdict(list)
for r in rules:
    by_cat[r["Category"]].append(r)

A(f"""<section><h2>5 &nbsp; The {len(rules)} detection rules</h2>
<p>Alongside the model, the file is matched against {len(rules)} hand-written
YARA rules describing known malicious techniques. Each has a category and a
severity from 1 to 5.</p>
<div class="box"><b>A rule hit is evidence, not a verdict.</b> Ordinary Windows
software legitimately uses many of these same functions. That is exactly why
rule hits enter the model as two features among {N_FEATURES} rather than
deciding the answer by themselves.</div>""")

for cat in sorted(by_cat):
    items = sorted(by_cat[cat], key=lambda x: -x["Severity"])
    A(f"<h3>{E(cat)} &nbsp;<span class='sub'>{len(items)} "
      f"rule{'s' if len(items) != 1 else ''}</span></h3>")
    A(table(["Sev", "Rule", "What it looks for"],
            [(f"<b>{r['Severity']}</b>", f"<code>{E(r['Rule'])}</code>",
              E(r["Description"])) for r in items]))
A("</section>")

# ---- 6 the model
rf, xgb = models["RandomForest"], models["XGBoost"]
best = models[metrics["best_model"]]
A(f"""<section><h2>6 &nbsp; The machine learning, explained plainly</h2>

<h3>What the model actually is</h3>
<p>A <b>Random Forest</b> is a large collection of decision trees. Each tree
asks a sequence of yes/no questions about the numbers it is given — "is the
entropy above 7.4?", "are there fewer than eight imports?" — and arrives at a
guess. This model contains 400 such trees, and the forest's answer is the vote
across all of them. Tree-based models were chosen because the features are full
of exactly those natural cut-off points, which trees handle directly and
without any rescaling of the data.</p>

<h3>Where the training data came from</h3>
<p>This is the part that most deserves scrutiny, and it is stated openly rather
than buried.</p>
<p><b>The benign half is measured, not invented.</b>
{ds['real_benign_files']:,} real Windows programs from this machine's system
folders were passed through the <i>same</i> extractor the scanner uses live. So
the awkward realities of genuine software survive into the data instead of
being idealised away.</p>
<p><b>The malicious half is synthesised from documented behaviour profiles.</b>
A live malware corpus cannot be hosted for a student project. Instead each
synthetic sample <i>starts as a real benign file's measurements</i> and then has
a family profile applied, shifting only those properties that malware research
consistently finds meaningful. Six families are modelled:
{", ".join("<code>" + E(f) + "</code>" for f in ds["families"])}.</p>
<p>That shared real backbone is what makes the exercise meaningful. Generating
malicious rows from nothing would let the model separate the classes on
artefacts of the generator rather than on anything security-relevant.</p>

{table(["Dataset property", "Value"], [
  ("Total rows", f"{ds['total_rows']:,}"),
  ("Benign / malicious", f"{ds['benign_rows']:,} / {ds['malicious_rows']:,}"),
  ("Real source binaries", f"{ds['unique_source_files']:,}"),
  ("Deliberately hard benign rows",
   f"{ds['hard_benign_rows']:,} <span class='sub'>(packed but legitimate)</span>"),
  ("Deliberately subtle malicious rows",
   f"{ds['stealth_malicious_rows']:,} <span class='sub'>(partial profile only)</span>"),
  ("Train / test rows",
   f"{metrics['train_rows']:,} / {metrics['test_rows']:,}"),
  ("Split method", E(metrics["split"]["strategy"])),
  ("Source files spanning the split",
   f"<b>{metrics['split']['leaked_source_files']}</b> "
   "<span class='sub'>(asserted by the trainer)</span>"),
])}

<div class="box"><b>Why the split is grouped.</b> Several rows descend from the
same original binary. Splitting at random would scatter near-duplicates across
both sides, so the model would be tested on files it had effectively already
seen and every score would be inflated. Splitting by source binary prevents
that, and the trainer refuses to proceed if any file appears on both sides.</div>

<h3>Choosing between the two models</h3>
<p>Both algorithms are trained every run and compared on held-out data.</p>
{table(["Measure", "Random Forest", "XGBoost", "What it means"], [
  ("Accuracy", rf["accuracy"], xgb["accuracy"],
   "Share of test files judged correctly"),
  ("Precision", rf["precision"], xgb["precision"],
   "When it says malicious, how often it is right"),
  ("Recall", rf["recall"], xgb["recall"],
   "Share of malicious files it actually caught"),
  ("F1", rf["f1"], xgb["f1"], "Balance of precision and recall"),
  ("<b>ROC-AUC</b>", f"<b>{rf['roc_auc']}</b>", f"<b>{xgb['roc_auc']}</b>",
   "<b>Ranking quality at any threshold &mdash; the selection criterion</b>"),
  ("False alarm rate", rf["false_positive_rate"], xgb["false_positive_rate"],
   "Clean files wrongly flagged"),
  ("Miss rate", rf["false_negative_rate"], xgb["false_negative_rate"],
   "Malicious files wrongly cleared"),
])}
<p><b>{metrics['best_model']} was selected</b> on ROC-AUC, which measures how
well the model ranks files regardless of where the cut-off is placed — the
right criterion here, because the threshold is adjustable at scan time. Note
that XGBoost was actually better on raw accuracy; the comparison is recorded
rather than quietly dropped.</p>
<p>Cross-validation over {metrics['cross_validation']['folds']} grouped folds
gave a mean ROC-AUC of <b>{metrics['cross_validation']['mean']}</b>
(standard deviation {metrics['cross_validation']['std']}), so the result is
stable rather than a lucky split.</p>

<h3>Calibration: making the percentage mean something</h3>
<p>If 70% of the trees vote "malicious", that is <i>not</i> the same as a 70%
chance the file is malicious. Isotonic calibration corrects the raw scores
against held-out data so the number shown to a user carries its ordinary
meaning. Measured by Brier score, where lower is better, this improved the
figure from <b>{metrics['calibration']['brier_uncalibrated']}</b> to
<b>{metrics['calibration']['brier_calibrated']}</b>.</p>

<div class="box warn"><b>What the accuracy figure does and does not mean.</b>
It shows the model learned the relationship <i>present in this dataset</i>
between file structure and maliciousness. It is <b>not</b> a detection rate
measured against live malware. Saying "MalScan detects
{best['accuracy'] * 100:.1f}% of real malware" would be wrong, and the project
states so in its own interface.</div>
</section>""")

# ---- 7 verdict + explanation
sweep = metrics["threshold_sweep"]
A(f"""<section><h2>7 &nbsp; The verdict, and how it is justified</h2>

<h3>Three outcomes, not two</h3>
{table(["Verdict", "Probability", "Meaning"], [
  ("<b>Benign</b>", f"below {CONFIG.threshold_suspicious}",
   "Nothing structurally concerning"),
  ("<b>Suspicious</b>",
   f"{CONFIG.threshold_suspicious} &ndash; {CONFIG.threshold_malicious}",
   "Genuinely ambiguous &mdash; a person should look"),
  ("<b>Malicious</b>", f"{CONFIG.threshold_malicious} and above",
   "Multiple structural indicators agree"),
])}
<p>The middle band exists deliberately. Forced into a yes/no answer, the model
must commit on files it genuinely cannot separate — and legitimate packed
software trips many of the same indicators as malware. "Someone should review
this" is a more honest answer than a confident coin flip. Both thresholds can
be moved during a scan, and the Model page shows what each setting costs in
missed malware against false alarms:</p>
{table(["Threshold", "Missed malware", "False alarms", "Precision", "Recall"],
       [(s["threshold"], s["missed_malware"], s["false_alarms"],
         s["precision"], s["recall"]) for s in sweep[:9]])}

<h3>Why this verdict: the explanation method</h3>
<p>A bare percentage is not much use on its own, so every scan comes with an
attribution built by <b>ablation</b>:</p>
<ol>
<li>The file is scored normally.</li>
<li>One feature is reset to the typical value for a harmless file, with the
other {N_FEATURES - 1} left exactly as they are.</li>
<li>The model is asked again. However far the score moves is that feature's
contribution.</li>
<li>This repeats for every feature, and the largest movers are shown as a bar
chart with a plain-language summary beneath.</li>
</ol>
<p>It is the same idea as SHAP, a standard explainability technique, but it
needs no extra library and costs a single batched pass, which keeps a scan
inside its one-second budget.</p>
<div class="box"><b>Two different questions.</b> The feature importances on the
Model page say what matters <i>generally</i>, across all files. The ablation
says what mattered <i>for this one file</i>. They frequently disagree, and that
is expected.</div>

<h3>Which properties matter most overall</h3>
{table(["Rank", "Feature", "Importance"],
       [(i, f"<code>{E(f['feature'])}</code>", f["importance"])
        for i, f in enumerate(metrics["feature_importance"][:10], 1)])}

<h3>Knowing when not to answer</h3>
<p>Every training row came from a real Windows binary whose structure parsed.
A text file or a Word document has none of that, so forty-odd structural
features sit at zero — a region of the problem the model has never seen. Asked
anyway, it does not answer cautiously; it answers unpredictably. A harmless
166-byte text file once came back at <b>59% malicious</b>, simply because "no
imports, no sections" resembles a stripped binary more than a normal one.</p>
<p>So MalScan stops asking. Without usable structure the file is scored on what
it does have — rule matches, text indicators, overall randomness — and the
verdict states which engine produced it and that the evidence is weaker.</p>
</section>""")

# ---- 8 safety, performance
A(f"""<section><h2>8 &nbsp; Safety, privacy and speed</h2>

<h3>The safety model</h3>
<ul>
<li>Uploaded files stay in memory as a plain byte buffer and are parsed as
data. Nothing is written to an executable location, passed to a shell, imported
as a library or run.</li>
<li>The buffer is discarded as soon as the scan returns.</li>
<li>The history database stores the analysis and the hashes — <b>never the
file</b>. That is what makes it safe to keep.</li>
<li>Nothing is transmitted anywhere. The VirusTotal link on a result is
constructed locally from the hash; opening it is the user's choice.</li>
<li>Uploads are capped at {CONFIG.max_upload_mb} MB so a single large file
cannot exhaust memory.</li>
</ul>

<h3>How fast it is</h3>
{table(["File", "Size", "Scan time"], [
  ("Text, script or document", "under 2 KB", "1&ndash;2 ms"),
  ("High-randomness blob", "256 KB", "~52 ms"),
  ("Malformed Windows program", "2 KB", "~61 ms"),
  ("Real system binary <span class='sub'>(full model path)</span>",
   "352 KB", "~890 ms"),
])}
<p>Only files with a parsable Windows structure reach the trained model, which
is why they cost the most. Three optimisations keep that path under a second:
inference is pinned to a single thread — the forest is built for parallel
training, but for a single file the coordination cost exceeded the work itself;
only the parts of the file structure actually read are parsed; and the internal
checksum is recomputed only when the file carries one to compare against.
Together these took a real-binary scan from 1883 ms to 889 ms with
byte-identical results.</p>
<p>Loading the model costs a further 2&ndash;5 seconds, once when the program
starts. The web app pays that once per session.</p>
</section>""")

# ---- 9 uses
A(f"""<section><h2>9 &nbsp; What it is useful for</h2>
{table(["Use", "How it helps"], [(f"<b>{t}</b>", d) for t, d in USES])}

<h3>Being straight about the limits</h3>
<ul>
<li><b>Static analysis cannot observe behaviour.</b> A file that only decrypts
its payload once running leaves very little on disk to find. This is the
fundamental ceiling of the approach, and the reason sandbox analysis is the
most valuable thing that could be added.</li>
<li><b>A verdict is evidence, not proof.</b> Legitimate packed software trips
many of the same indicators. Hence the Suspicious band.</li>
<li><b>Non-Windows files get weaker analysis.</b> The structural features are
specific to Windows programs. Documents and scripts are still typed, mined and
rule-matched, and the scanner says outright when a verdict rests only on
those.</li>
<li><b>The malicious training class is synthesised.</b> The accuracy figure
reflects a relationship learned from that data, not a field detection rate.</li>
<li><b>Rule matches are inputs, not conclusions.</b> Ordinary Windows libraries
match several bundled rules, which is expected.</li>
</ul>
</section>""")

# ---- 10 future
A(f"""<section><h2>10 &nbsp; How far it could be taken</h2>
<p>The current system is a working prototype with clear, honest boundaries.
Each of the following is a genuine next step rather than a wish.</p>
{table(["Extension", "Effort", "What it would add"],
       [(f"<b>{t}</b>", f"<span class='nowrap'>{e}</span>", d)
        for t, e, d in EXTENSIONS])}
<h3>The single most valuable addition</h3>
<p>Training on a real labelled malware corpus. The path is already built — the
training script accepts any CSV or Parquet file carrying the {N_FEATURES}
feature columns plus a label:</p>
<p><code>python -m malscan.model.train --dataset real_corpus.csv</code></p>
<p>Missing columns are filled with zero and reported, so a partially
overlapping schema still loads. That one change would convert the accuracy
figure from "the model learned this dataset" into a genuine measured detection
rate — which is the main thing presently standing between this prototype and a
deployable tool.</p>
</section>""")

# ---- 11 Q&A
A("""<section><h2>11 &nbsp; Questions you should expect</h2>
<p>Short, direct answers to the questions most likely to be asked about this
project.</p>""")
for q, a in QA:
    A(f'<div class="qa"><div class="q">{q}</div><div>{a}</div></div>')
A("</section>")

# ---- 12 glossary / layout
A(f"""<section><h2>12 &nbsp; Quick reference</h2>

<h3>Terms in one line each</h3>
{table(["Term", "Meaning"], [
  ("<b>PE</b> (Portable Executable)",
   "The file format of every Windows <code>.exe</code> and <code>.dll</code>."),
  ("<b>Entropy</b>",
   "How unpredictable the bytes are, 0&ndash;8. High suggests compression or "
   "encryption &mdash; something hidden."),
  ("<b>Packing</b>",
   "Compressing or encrypting a program so its real contents are not visible "
   "until it runs. Used legitimately too, which is why it is a hint, not "
   "proof."),
  ("<b>Imports</b>",
   "The Windows functions a program borrows. Which ones it asks for says a lot "
   "about what it intends to do."),
  ("<b>Section</b>",
   "A named region of a program &mdash; code, data, resources &mdash; each "
   "with permissions to read, write or execute."),
  ("<b>Overlay</b>",
   "Data appended past the program's proper end. A common hiding place."),
  ("<b>YARA</b>",
   "The industry-standard language for writing malware pattern rules."),
  ("<b>ROC-AUC</b>",
   "How well a model ranks malicious above benign, independent of any "
   "threshold. 1.0 is perfect, 0.5 is guessing."),
  ("<b>Calibration</b>",
   "Adjusting raw scores so a stated probability means what it says."),
  ("<b>Ablation</b>",
   "Changing one input and re-measuring, to find out how much that input "
   "mattered."),
  ("<b>False positive</b>", "A harmless file wrongly flagged as malicious."),
  ("<b>False negative</b>", "A malicious file wrongly cleared."),
])}

<h3>Where everything lives</h3>
{table(["Path", "Responsibility"], [
  ("<code>app.py</code>", "Web interface entry point"),
  ("<code>malscan_cli.py</code>", "Command-line scanner"),
  ("<code>malscan/config.py</code>",
   "Every path, limit and threshold &mdash; no magic numbers elsewhere"),
  ("<code>malscan/scanner.py</code>",
   "The scan pipeline; the single function the interface calls"),
  ("<code>malscan/features/</code>",
   f"The {N_FEATURES}-feature contract and all the extractors"),
  ("<code>malscan/rules/</code>",
   f"The {engine.rule_count} YARA rules and the matching engine"),
  ("<code>malscan/model/</code>",
   "Dataset building, training, inference, explanation"),
  ("<code>malscan/storage/</code>", "SQLite scan history"),
  ("<code>malscan/ui/</code>", "The six interface pages"),
  ("<code>tests/test_malscan.py</code>",
   "31 tests, runnable without pytest"),
])}

<h3>Running it</h3>
<p><code>pip install -r requirements.txt</code> &mdash; install dependencies<br>
<code>python -m malscan.model.train</code> &mdash; build the model<br>
<code>streamlit run app.py</code> &mdash; launch the web interface<br>
<code>python malscan_cli.py file.exe</code> &mdash; scan from the command line<br>
<code>python tests/test_malscan.py</code> &mdash; run the test suite</p>
<p class="sub">The app runs before training too; it falls back to a transparent
heuristic scorer and says so on every verdict rather than pretending there is a
model behind it.</p>
</section>""")

A("</body></html>")

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text("".join(parts), encoding="utf-8")
print(f"wrote {OUT}  ({OUT.stat().st_size:,} bytes)")


# ------------------------------------------------------------ PDF
def to_pdf(src: Path) -> None:
    """Print the HTML to PDF using whichever Chromium browser is installed.

    Chrome and Edge both ship a headless PDF printer, so the document needs no
    Python PDF library and nothing extra in the virtual environment.
    """
    import subprocess
    import tempfile

    candidates = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    ]
    browser = next((c for c in candidates if c.exists()), None)
    if browser is None:
        print("no Chrome or Edge found -- open the HTML and print to PDF by hand")
        return

    pdf = src.with_suffix(".pdf")
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run(
            [str(browser), "--headless", "--disable-gpu", "--no-sandbox",
             "--no-pdf-header-footer", f"--user-data-dir={profile}",
             f"--print-to-pdf={pdf}", src.as_uri()],
            check=False, capture_output=True, timeout=180,
        )
    if pdf.exists():
        print(f"wrote {pdf}  ({pdf.stat().st_size:,} bytes)")
    else:
        print("PDF step failed -- open the HTML and print to PDF by hand")


to_pdf(OUT)
