# Nmap_AI — Network Host Risk Classifier

A command-line tool that combines **Nmap network scanning** with **machine learning** to automatically detect suspicious hosts on a local network. The pipeline runs end-to-end: scan → feature engineering → model training → risk prediction → alert generation → detailed report.

---

## Tech Stack

- **Python 3.11+**
- **scikit-learn** — Logistic Regression, Decision Tree, F1-based model selection
- **pandas / numpy** — feature engineering (~60 numeric features per host)
- **Nmap** — network discovery and service detection (`-sV`, NSE scripts)
- **joblib** — model serialization

---

## Features

- Scans local network with Nmap and parses XML output into structured host records
- Extracts ~60 numeric features per host (open port counts, risk-tier flags, protocol categories)
- Assigns heuristic training labels (`normal` / `suspicious`) using a rule-based scoring system
- Trains Logistic Regression and Decision Tree classifiers; selects the best by F1 score on the suspicious class
- Predicts risk level for each host with probability scores and severity tiers (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`)
- Generates structured security alerts per host (e.g. `[CRITICAL] High Risk Port Detected: RDP`, `[HIGH] Cleartext Protocol in Use: FTP`)
- Produces a detailed explanation for each flagged host including detected services, dangerous service combinations, exposure patterns, and real-world attack technique mapping (Brute Force, Lateral Movement, Reconnaissance)
- Generates per-host security recommendations based on exposed services
- Assigns a 0–100 risk score derived from model confidence
- Exports a full text report with per-host analysis, alert list, and remediation steps
- Caches scan results (SHA-256 keyed) to avoid redundant network scans
- Falls back to built-in synthetic data when Nmap is unavailable — pipeline always runs end-to-end
- Includes a testcase mode with a simulated 52-host internet café network (no real scan needed)

---

## Project Structure

```
Nmap_AI/
├── src/
│   ├── main.py                # CLI entry point — dispatches all commands
│   ├── scanner.py             # Nmap subprocess wrapper
│   ├── parser_nmap.py         # Nmap XML → host records
│   ├── features.py            # Feature engineering → DataFrame (~60 columns)
│   ├── labeling.py            # Heuristic scoring and label assignment
│   ├── trainer.py             # Model training and selection
│   ├── predictor.py           # Inference, severity scoring, risk score (0–100)
│   ├── alerts.py              # Structured alert generation (CRITICAL/HIGH/MEDIUM/LOW)
│   ├── explainer.py           # Per-host explanation with attack technique mapping
│   ├── recommender.py         # Per-host security recommendations
│   ├── port_intel.py          # Port profile database and enrichment
│   ├── scan_cache.py          # Scan result caching and history snapshots
│   ├── unknown_enrichment.py  # Second-pass Nmap scan for unknown ports
│   ├── synthetic_data.py      # 20 synthetic hosts for demo/fallback
│   ├── test_case_records.py   # 52-host simulated internet café testcase
│   ├── sample_data.py         # Minimal fallback sample records
│   ├── local_target.py        # Detects local machine IP via UDP socket
│   ├── constants.py           # Port group definitions and threshold constants
│   └── utils.py               # Shared utilities and report formatters
├── requirements.txt
└── .gitignore
```

---

## Setup

```bash
python3 -m venv MyEnv
source MyEnv/bin/activate
pip install -r requirements.txt
```

Install [Nmap](https://nmap.org/download.html) if you want live network scanning.

---

## Usage

All commands run from the project root:

```bash
# Full pipeline — scan the current network, train, and predict
python3 src/main.py full

# Full pipeline using testcase XML (no real scan, no Nmap needed)
python3 src/test_case_records.py
python3 src/main.py full testcase

# Full pipeline with a forced fresh Nmap scan (ignores cache)
python3 src/main.py full --rescan

# Generate safe synthetic data, train, and predict without scanning
python3 src/main.py generate-dataset

# Run individual stages
python3 src/main.py scan
python3 src/main.py build-training
python3 src/main.py train
python3 src/main.py predict

# Analyze an existing Nmap XML file offline
python3 src/main.py analyze <path/to/scan.xml>
```

### Command / Nmap dependency matrix

| Command | Needs Nmap? |
|---|---|
| `full` | Yes (falls back to sample data if unavailable) |
| `full testcase` | No |
| `full --rescan` | Yes |
| `generate-dataset` | No |
| `scan` | Yes (falls back to sample data) |
| `build-training` | No (uses cached scan data) |
| `train` | No |
| `predict` | No (uses cached scan data) |
| `analyze <xml>` | No |

---

## Pipeline Overview

```
Network / XML / Synthetic data
        │
        ▼
   Nmap scan  ──►  XML parse  ──►  Host records
        │
        ▼
   Feature engineering  (~60 columns per host)
        │
        ▼
   Heuristic labeling  (rule-based score → normal / suspicious)
        │
        ▼
   Model training  (Logistic Regression + Decision Tree → best F1)
        │
        ▼
   Risk prediction  (probability + severity tier + risk score 0–100)
        │
        ▼
   Alert generation  (CRITICAL / HIGH / MEDIUM / LOW per triggered rule)
        │
        ▼
   Explanation + attack mapping  (why flagged, service combos, ATT&CK techniques)
        │
        ▼
   Reports  (prediction_result.txt, predictions.csv, port_details, history snapshots)
```

---

## Terminal Output

The terminal shows a concise per-host summary for each suspicious host:

```
[1] 10.10.0.203 (client-pc-43-pivot)
    Severity : CRITICAL | Risk Score : 99.8/100 | Confidence : 0.998
    Ports    : 21;23;445;3389
    Alerts   : 5 triggered (top 3 shown)
      [CRITICAL] High Risk Port Detected: SMB
      [CRITICAL] High Risk Port Detected: RDP
      [HIGH] Cleartext Protocol in Use: FTP
    → Full explanation: result/prediction_result.txt
```

Full analysis — detected services, dangerous combinations, exposure patterns, and real-world attack mapping — is written to `result/prediction_result.txt`.

---

## Output

After running, check the `result/` folder:

| File | Description |
|---|---|
| `prediction_result.txt` | Main report — suspicious hosts with risk scores, security alerts, why-flagged explanations, attack technique mapping, and recommendations |
| `predictions.csv` | Full prediction table with probability scores, severity, risk score, alert summary, and feature counts |
| `port_details.txt` | Detailed per-port report with risk levels, enrichment data, and remediation actions |
| `port_details.csv` | Machine-readable version of the port detail report |
| `scan_result.txt` | Human-readable scan summary with open ports and enriched service info |
| `best_model.joblib` | Serialized trained model bundle |
| `metrics.txt` | F1, precision, recall for the selected model |
| `feature_importance.txt` | Which features the model weighted most heavily |
| `training_data_full.csv` | Complete feature dataset used for training |
| `training_data.csv` | Readable training table with risk summaries |
| `history/` | Timestamped JSON snapshots of each run |
