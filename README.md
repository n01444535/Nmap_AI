## CAP4630 Project 4 Submission

This project uses Nmap scan data plus machine learning to classify hosts as `normal` or `suspicious`.

The workflow can:

- scan the current network target with Nmap
- fall back to built-in sample data if Nmap is missing or fails
- generate training data from scan results
- train a machine learning model
- predict suspicious hosts
- run on testcase XML files instead of a real scan

## Requirements

- Python 3.11+
- Nmap installed if you want real scanning

## Setup

Run commands from the `Submission` folder.

Create and activate a virtual environment:

```bash
python3 -m venv MyEnv
source MyEnv/bin/activate
pip3 install -r requirements.txt
```

Deactivate when finished:

```bash
deactivate
```

## Quick Start

Show command help:

```bash
python3 main.py -h
```

Run the full real workflow:

```bash
python3 main.py full
```

Generate testcase XML first, then run testcase mode:

```bash
python3 test_case_records.py
python3 main.py full testcase
```

## Commands

### `scan`

Collect records and write scan output.

```bash
python3 main.py scan
```

### `build-training`

Build training CSV files from current records.

```bash
python3 main.py build-training
```

### `train`

Train the model from `result/training_data_full.csv`.

```bash
python3 main.py train
```

### `predict`

Collect current records, load the trained model, and predict host risk.

```bash
python3 main.py predict
```

### `full`

Run the complete pipeline:

1. collect records
2. build training data
3. train the model
4. predict suspicious hosts
5. write reports

```bash
python3 main.py full
```

### `full testcase`

Use testcase XML files instead of scanning the current network.

```bash
python3 test_case_records.py
python3 main.py full testcase
```

## Which Commands Need Nmap?

| Command | Needs Nmap? | Notes |
|---|---|---|
| `scan` | Usually yes | Falls back to sample data if Nmap is missing or fails |
| `build-training` | Usually yes | Uses current scan data or sample fallback |
| `train` | No | Trains from saved CSV |
| `predict` | Usually yes | Collects records first, then predicts |
| `full` | Usually yes | Full real workflow |
| `full testcase` | No | Uses local testcase XML |

## Data Sources

This submission can run in three ways:

### 1. Real scan mode

- Used by `python3 main.py full`
- Uses Nmap if available
- Scans the current local target

### 2. Testcase mode

- Used by `python3 main.py full testcase`
- Uses XML files created by `python3 test_case_records.py`
- Does not scan the real network

### 3. Sample fallback mode

- Used automatically if Nmap is not installed or a real scan fails
- Lets the project still run end-to-end for demonstration

## Notes About Training

- Training labels are heuristic: the code assigns `normal` or `suspicious` from extracted features.
- If real scan data is too small or contains only one class, built-in sample records are added for training only.
- This keeps the ML pipeline usable even on simple home networks with very low risk.

## Result Files

After running commands, check the `result` folder.

### Core output

- `scan_result.txt`
  - Readable scan summary

- `scan_mode.txt`
  - Tells whether the run used real scan, testcase mode, or sample fallback

- `connected_devices.json`
  - Raw structured scan data

### Training output

- `training_data.csv`
  - Smaller human-readable training dataset

- `training_data_full.csv`
  - Full feature dataset used for ML training

- `training_note.txt`
  - Explains whether sample data was added during training preparation

- `best_model.joblib`
  - Saved trained model

- `metrics.txt`
  - Evaluation results for the trained model

### Prediction output

- `predictions.csv`
  - Detailed prediction table

- `prediction_result.txt`
  - Main readable final report with suspicious-host analysis and recommendations

## Nmap Installation

Install Nmap only if you want real scan mode.

### macOS

```bash
brew install nmap
```

### Windows

Download from:

https://nmap.org/download.html

During installation, make sure `Add to PATH` is enabled.

## Example Usage

### Real run

```bash
python3 main.py full
```

### Testcase run

```bash
python3 test_case_records.py
python3 main.py full testcase
```

### Training only

```bash
python3 main.py build-training
python3 main.py train
```

### Prediction only

```bash
python3 main.py predict
```
