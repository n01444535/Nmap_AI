# Nmap_AI — SOC-Grade Network Host Risk Classifier

> Automated network scanning → feature engineering → ML classification → structured triage → MITRE ATT&CK-mapped explanations → full security report.

A personal research project built from self-study in network security and machine learning. The pipeline runs end-to-end with no manual steps: scan a network, train a model on the results, and receive prioritized, explainable threat reports.

---

## Why This Matters for SOC Analysts

Traditional port scanners return raw data. This tool turns that data into **analyst-ready triage**:

- Instead of "port 445 is open" → `[CRITICAL] High Risk Port Detected: SMB — primary vector for ransomware and lateral movement`
- Instead of "host is suspicious" → `Triage: Immediate Action ↳ Isolate or block the host and begin incident response now`
- Instead of a list of flags → a MITRE ATT&CK-mapped explanation of which techniques the host enables

The goal is to close the gap between raw scan data and actionable SOC workflow.

---

## Tech Stack

| Layer | Tools |
|---|---|
| Network scanning | Nmap — two-phase: fast port discovery (`-T4 --min-rate 2000`) then targeted service scan (`-sV`, NSE: `default`, `safe`, `banner`, `smb-os-discovery`, `ssl-cert`) |
| Feature engineering | pandas / numpy — ~60 numeric features per host |
| ML classification | scikit-learn — Logistic Regression + Decision Tree, best F1 wins |
| Anomaly detection | scikit-learn — Isolation Forest trained unsupervised alongside the classifier |
| Model persistence | joblib |
| Dashboard | Streamlit + Plotly — visual SOC triage UI |
| Reporting | Plain text + CSV — readable without any external tool |

---

## Features

### Core Pipeline
- Scans local network with Nmap and parses XML output into structured host records
- Extracts ~60 numeric features per host: open port counts, risk-tier flags, cleartext count, DB count, admin port count, fileshare count, remote access count, uncommon port count
- Assigns heuristic training labels (`normal` / `suspicious`) via rule-based scoring
- Trains Logistic Regression and Decision Tree; selects the best by F1 on the suspicious class
- Predicts with probability score (0.0–1.0) and severity tier: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`

### SOC Analyst Layer
- **Risk Score (0–100)** derived from model confidence
- **Structured Alerts** — 25+ named rules fire per host (e.g. `[CRITICAL] Unauthenticated Service Exposed: Redis`, `[HIGH] Multiple Remote Access Vectors Exposed`)
- **SOC Triage Status** — three action levels based on alert severity and probability:
  - `Immediate Action` — isolate and begin incident response now
  - `Investigate` — review service versions and authentication logs
  - `Monitor` — capture traffic and watch for anomalies
- **Asset Fingerprinting** — classifies each host as: `server`, `workstation`, `database_server`, `file_server`, `container_host`, `printer`, `iot_camera`, `iot_device`, `mail_server`, `network_device`, or `unknown`
- **Baseline Comparison** — saves a port baseline after each run; subsequent runs detect new hosts, newly opened ports, closed ports, and **service version changes** (e.g. `nginx 1.18` → `nginx 1.24` on port 80)
- **Isolation Forest Anomaly Detection** — unsupervised second opinion trained on all host feature vectors; produces a 0–1 `anomaly_score` per host to catch unusual profiles the classifier may not flag
- **Continuous Monitor Mode** — `monitor` command runs full scan → predict → baseline diff on a configurable interval; press Ctrl+C to stop
- **Streamlit SOC Dashboard** — visual triage UI: risk score bars, severity/triage distribution charts, color-coded host table, anomaly scores, baseline state, and feature importance — launch with `streamlit run src/dashboard.py`
- **MITRE ATT&CK Mapping** — flags enabled techniques with IDs:
  - T1110 Brute Force (SSH, RDP, SMB, WinRM, database ports…)
  - TA0008 Lateral Movement (SMB, RDP, WinRM, Docker API, K8s API…)
  - T1046 Reconnaissance (SNMP, NetBIOS, LDAP, DNS, Elasticsearch…)
  - TA0010 Data Exfiltration (FTP, DNS, SMTP, NFS)
- **Dangerous Combination Detection** — flags high-risk port pairs (e.g. SMB + RDP = classic ransomware path, Redis + Docker API = cache-to-container pivot)
- **Per-Host Recommendations** — actionable remediation steps for every exposed service
- **Feature Importance Report** — which features drove the model's decisions
- **config.yaml Overrides** — user-defined `trusted_hosts` (never flagged) and `ignore_ports` (excluded from risk scoring) to eliminate false positives on known-good infrastructure

### Infrastructure
- SHA-256 keyed scan cache — avoids redundant Nmap scans
- Scan history snapshots — timestamped JSON per run
- Cumulative history dataset — CSV that grows across runs for future ML retraining
- Unknown port enrichment — second-pass targeted Nmap scan on unidentified ports
- Fallback to synthetic data when Nmap is unavailable — pipeline always completes

---

## Project Structure

```
Nmap_AI/
├── src/
│   ├── main.py                # CLI entry point — all commands dispatched here
│   ├── scanner.py             # Nmap subprocess wrapper (two-phase: fast port + targeted service)
│   ├── parser_nmap.py         # Nmap XML → structured host records
│   ├── features.py            # Feature engineering → DataFrame (~60 columns per host)
│   ├── labeling.py            # Heuristic rule-based label assignment (normal/suspicious)
│   ├── trainer.py             # Model training, F1 selection, feature importance
│   ├── predictor.py           # Inference: probability, severity, risk score, triage, asset type
│   ├── triage.py              # SOC triage engine: Immediate Action / Investigate / Monitor
│   ├── asset_profiler.py      # Device fingerprinting: server, workstation, container_host…
│   ├── baseline.py            # Baseline save/load/compare for change detection
│   ├── config_loader.py       # Loads config.yaml — trusted hosts, ignored ports overrides
│   ├── alerts.py              # 25+ named alert rules (CRITICAL/HIGH/MEDIUM/LOW)
│   ├── explainer.py           # Explanation: services, combos, exposure patterns, MITRE ATT&CK
│   ├── recommender.py         # Per-host security recommendations
│   ├── port_intel.py          # Port profile database — risk tier, category, description
│   ├── scan_cache.py          # Scan caching, history snapshots, learned record memory
│   ├── unknown_enrichment.py  # Second-pass scan for unknown/unidentified ports
│   ├── synthetic_data.py      # 20 synthetic hosts for demo/fallback (no Nmap needed)
│   ├── test_case_records.py   # 52-host simulated internet café for testcase mode
│   ├── sample_data.py         # Minimal fallback records when Nmap scan yields nothing
│   ├── local_target.py        # Detects local machine IP via UDP socket
│   ├── constants.py           # All numeric constants: port sets, thresholds, model params
│   ├── utils.py               # Shared utilities, report formatters, baseline diff display
│   └── dashboard.py           # Streamlit SOC dashboard — visual triage UI
├── config.yaml                # User overrides: trusted_hosts, ignore_ports
├── requirements.txt
└── .gitignore
```

---

## Setup

```bash
python3 -m venv MyEnv
MyEnv/bin/pip3 install -r requirements.txt   # macOS/Linux
# Windows: MyEnv\Scripts\pip3 install -r requirements.txt
```

> **Note:** All `python3` commands below should also use `MyEnv/bin/python3` (macOS/Linux) or `MyEnv\Scripts\python3` (Windows) if your shell doesn't pick up the venv after `source MyEnv/bin/activate`.

Install [Nmap](https://nmap.org/download.html) for live network scanning. All other commands work without it.

---

## Usage

All commands run from the project root:

```bash
# Recommended: full pipeline (scan → train → predict → report)
python3 src/main.py full

# Testcase mode — 52-host internet café simulation, no Nmap needed
python3 src/test_case_records.py
python3 src/main.py full testcase

# Force a fresh Nmap scan (ignore cache)
python3 src/main.py full --rescan

# Continuous monitoring — scan every 5 minutes (Ctrl+C to stop)
python3 src/main.py monitor
python3 src/main.py monitor --interval 10  # custom interval in minutes

# Launch the Streamlit SOC dashboard
streamlit run src/dashboard.py

# Generate synthetic training data, train, and predict (offline demo)
python3 src/main.py generate-dataset

# Analyze an existing Nmap XML file (no scanning)
python3 src/main.py analyze path/to/scan.xml

# Individual stages
python3 src/main.py scan
python3 src/main.py build-training
python3 src/main.py train
python3 src/main.py predict
```

### Nmap Dependency Matrix

| Command | Needs Nmap? |
|---|---|
| `full` | Yes — falls back to sample data if unavailable |
| `full testcase` | No |
| `full --rescan` | Yes |
| `generate-dataset` | No |
| `analyze <xml>` | No |
| `scan` | Yes — falls back to sample data |
| `build-training`, `train`, `predict` | No |

---

## Pipeline

```
Network / Testcase XML / Synthetic data
         │
         ▼
    Nmap scan (two-phase)
      Phase 1: fast port discovery  (-T4, --min-rate 2000, -p-, no service detect)
      Phase 2: targeted service scan (-sV, NSE scripts, only on open ports found above)
         ──►  XML parse  ──►  Host records
         │
         ▼
    Feature engineering  (~60 columns: risk flags, port counts, categories)
         │
         ▼
    Heuristic labeling  (rule-based score → normal / suspicious)
         │
         ▼
    Model training  (Logistic Regression + Decision Tree → best F1)
         │
         ▼
    Baseline comparison  (new hosts? new ports? changes since last scan?)
         │
         ▼
    Risk prediction  (probability + severity + risk score 0–100)
         │
         ▼
    Asset fingerprinting  (server / workstation / container_host / …)
         │
         ▼
    Triage assignment  (Immediate Action / Investigate / Monitor)
         │
         ▼
    Alert generation  (25+ named rules, CRITICAL → LOW)
         │
         ▼
    Explanation + MITRE ATT&CK mapping
         │
         ▼
    Reports  (prediction_result.txt, predictions.csv, port_details, history snapshots)
```

---

## Terminal Output (Sample)

```
================ AI SECURITY ALERT SUMMARY ================

[1] 10.10.0.203 (client-pc-43-pivot)  [workstation]
    Severity : CRITICAL | Risk Score : 99.8/100 | Confidence : 0.998
    Triage   : Immediate Action
               ↳ Isolate or block the host and begin incident response now
    Ports    : 21;23;445;3389
    Alerts   : 5 triggered (top 3 shown)
      [CRITICAL] High Risk Port Detected: SMB
      [CRITICAL] High Risk Port Detected: RDP
      [HIGH] Cleartext Protocol in Use: FTP
    → Full report: result/prediction_result.txt
----------------------------------------------------------

==========================================================
```

---

## Report Output (prediction_result.txt — Sample)

```
[1] IP: 10.10.0.203
Hostname  : client-pc-43-pivot
Asset Type: workstation
Severity  : CRITICAL
Triage    : Immediate Action
Risk Score: 99.8/100
Confidence: 0.998

Top Risk Ports: 21;23;445;3389

Why flagged:
  Flagged because: 4 known high-risk port(s) detected (4 critical/very-high): 21, 23, 445, 3389

  Detected high-risk services:
    • FTP                port 21          cleartext file transfer — credentials visible on the wire
    • Telnet             port 23          cleartext remote shell — passwords sent in plaintext
    • SMB                port 445         Windows file sharing — primary ransomware and lateral movement vector
    • RDP                port 3389        Windows remote desktop — common brute-force and ransomware entry

  Dangerous service combinations:
    • SMB (445) + RDP (3389) both open — classic ransomware lateral movement path
    • Telnet (23) + FTP (21) — two cleartext credential channels active simultaneously

  MITRE ATT&CK mapping:
    • [T1110] Brute Force            FTP (21), Telnet (23), RDP (3389), SMB (445)
                                       ↳ attacker repeatedly tries credentials to gain unauthorized access
    • [TA0008] Lateral Movement      SMB (445), RDP (3389)
                                       ↳ attacker moves through the network after initial compromise

Security Alerts:
  [CRITICAL] High Risk Port Detected: SMB
    SMB (port 445) is exposed — primary vector for ransomware and lateral movement
  [CRITICAL] High Risk Port Detected: RDP
    RDP (port 3389) is exposed — common brute-force and ransomware entry point
  [HIGH] Cleartext Protocol in Use: FTP
    FTP (port 21) is open — file contents and credentials transmitted without encryption

Recommendations:
- Review SMB or file-sharing exposure and restrict it to trusted subnets
- Restrict remote desktop services with firewall rules and MFA
- Disable plain FTP or restrict it behind VPN and strong authentication
```

---

## Output Files

| File | Description |
|---|---|
| `result/prediction_result.txt` | Full triage report — alerts, MITRE mapping, explanations, recommendations, baseline diff |
| `result/predictions.csv` | Prediction table with probability, risk score, severity, triage status, asset type, anomaly score, alert summary |
| `result/baseline.json` | Saved port baseline — compared on the next run to detect changes |
| `result/port_details.txt` | Per-port detail report with risk level, enrichment data, and remediation |
| `result/port_details.csv` | Machine-readable port detail table |
| `result/scan_result.txt` | Human-readable scan summary |
| `result/best_model.joblib` | Serialized trained model bundle |
| `result/metrics.txt` | F1, precision, recall for the selected model |
| `result/feature_importance.txt` | Top features driving model decisions |
| `result/training_data_full.csv` | Full feature dataset used for training |
| `result/training_data.csv` | Readable training table with risk summaries |
| `result/history_dataset.csv` | Cumulative history across all runs |
| `result/history/` | Timestamped JSON snapshots of each full run |

---

## Triage Levels

| Level | Trigger Condition | Recommended Action |
|---|---|---|
| `Immediate Action` | CRITICAL alert OR probability > 0.98 | Isolate host, begin incident response |
| `Investigate` | HIGH alert OR probability > 0.95 | Review logs, verify service versions |
| `Monitor` | Suspicious with MEDIUM/LOW alerts | Capture traffic, watch outbound connections |

---

## Alert Severity Levels

| Severity | Example Triggers |
|---|---|
| CRITICAL | Telnet (23), SMB (445), RDP (3389), VNC (5900), Docker API, Redis, Elasticsearch, database ports |
| HIGH | FTP (21), TFTP, SNMP, WinRM, Memcached, MQTT, multiple cleartext/admin/remote-access services |
| MEDIUM | Excessive open ports (≥8), uncommon port cluster (≥3 non-standard ports) |
| LOW | SSH (22), HTTP (80), SMTP (25), DNS (53), IoT/printer devices |

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Triggered By |
|---|---|---|
| T1110 | Brute Force | SSH, Telnet, FTP, RDP, VNC, SMB, WinRM, MSSQL, MySQL, PostgreSQL, MongoDB, Redis |
| TA0008 | Lateral Movement | SMB, RDP, WinRM, RPC Bind, NetBIOS, SSH, VNC, Docker API, Kubernetes API |
| T1046 | Network Service Discovery (Recon) | SNMP, RPC Bind, NetBIOS, LDAP, DNS, NFS, FTP, Telnet, Elasticsearch, Redis, MongoDB |
| TA0010 | Data Exfiltration | FTP, DNS, SMTP, NFS |

---

## Limitations

- The ML model trains on heuristic labels derived from the same scan — it learns the rule-based scoring, not real ground truth. This is intentional for a supervised demo with no labeled dataset.
- Feature extraction is port-based; the model cannot analyze packet payloads or timing behavior.
- Nmap scan depth depends on network conditions and requires elevated privileges for some scan types.
- Baseline comparison tracks open ports only — service version changes within the same port are not detected.
- No real-time monitoring — this is a point-in-time snapshot tool, not a continuous IDS.

---

## Future Roadmap

| Phase | Upgrade | Status |
|---|---|---|
| Near-term | Config file (YAML) for risk thresholds, ignored ports, trusted hosts | ✅ Done |
| Near-term | Service version change detection in baseline comparison | ✅ Done |
| Near-term | Continuous monitor mode with configurable scan interval | ✅ Done |
| Mid-term | Isolation Forest / anomaly detection for unlabeled environments | ✅ Done |
| Mid-term | Streamlit dashboard for visual triage | ✅ Done |
| Long-term | Zeek / Suricata log ingestion | Planned |
| Long-term | LLM-based analyst assistant for natural language queries | Planned |
