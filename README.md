# Nmap_AI — Network Host Risk Classifier

A command-line tool that combines **Nmap network scanning** with **machine learning** to automatically detect suspicious hosts on a local network. The pipeline runs end-to-end: scan → feature engineering → model training → risk prediction → report generation.

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
- Generates security recommendations per host based on exposed services
- Caches scan results (SHA-256 keyed) to avoid redundant network scans
- Falls back to built-in synthetic data when Nmap is unavailable — pipeline always runs end-to-end
- Includes a testcase mode with a simulated 50-host internet café network (no real scan needed)

---

## Project Structure

```
Nmap_AI/
├── src/
│   ├── main.py                # CLI entry point — dispatches all commands
│   ├── scanner.py             # Nmap subprocess wrapper
│   ├── parser_nmap.py         # Nmap XML → host records
│   ├── features.py            # Feature engineering → DataFrame
│   ├── labeling.py            # Heuristic scoring and label assignment
│   ├── trainer.py             # Model training and selection
│   ├── predictor.py           # Inference and severity scoring
│   ├── recommender.py         # Per-host security recommendations
│   ├── port_intel.py          # Port profile database and enrichment
│   ├── scan_cache.py          # Scan result caching and history snapshots
│   ├── unknown_enrichment.py  # Second-pass Nmap scan for unknown ports
│   ├── synthetic_data.py      # 20 synthetic hosts for demo/fallback
│   ├── test_case_records.py   # 52-host simulated internet café testcase
│   ├── sample_data.py         # Minimal fallback sample records
│   ├── local_target.py        # Detects local machine IP via UDP socket
│   ├── constants.py           # Port group definitions (risk tiers, categories)
│   └── utils.py               # Shared utilities
├── requirements.txt
└── .gitignore
```

---

## Setup

```bash
# Create and activate a virtual environment
python3 -m venv MyEnv
source MyEnv/bin/activate       # macOS / Linux
# MyEnv\Scripts\activate        # Windows

pip install -r requirements.txt
```

Install Nmap if you want live network scanning:

```bash
brew install nmap       # macOS
# https://nmap.org/download.html  — Windows installer
```

---

## Usage

All commands run from the project root:

```bash
# Full pipeline — scan the current network, train, and predict
python3 src/main.py full

# Full pipeline using testcase XML (no real scan, no Nmap needed)
python3 src/test_case_records.py
python3 src/main.py full testcase

# Run individual stages
python3 src/main.py scan              # Scan only
python3 src/main.py build-training    # Build training CSV from scan results
python3 src/main.py train             # Train model from CSV
python3 src/main.py predict           # Predict from saved model

# Analyze an existing Nmap XML file offline
python3 src/main.py analyze <path/to/scan.xml>
```

### Command / Nmap dependency matrix

| Command | Needs Nmap? |
|---|---|
| `full` | Yes (falls back to sample data if unavailable) |
| `full testcase` | No |
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
   Risk prediction  (probability + severity tier)
        │
        ▼
   Reports  (prediction_result.txt, predictions.csv, history snapshots)
```

---

## Output

After running, check the `result/` folder:

| File | Description |
|---|---|
| `prediction_result.txt` | Main report — suspicious hosts, risk scores, recommendations |
| `predictions.csv` | Full prediction table with features and probability scores |
| `best_model.joblib` | Serialized trained model bundle |
| `metrics.txt` | F1, precision, recall for the selected model |
| `training_data_full.csv` | Complete feature dataset used for training |
| `scan_result.txt` | Human-readable scan summary |
| `history/` | Timestamped JSON snapshots of each run |
