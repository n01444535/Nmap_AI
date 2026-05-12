# EN: Load the trained model and predict host risk.
# VI: Mở mô hình đã học rồi đoán máy có nguy hiểm không.

import joblib
import pandas as pd
from constants import (
    SEVERITY_CRITICAL_MIN_PROB, SEVERITY_HIGH_MIN_PROB, SEVERITY_MEDIUM_MIN_PROB,
    ANOMALY_HIGH_THRESHOLD,
    RISK_WEIGHT_ML_PROB, RISK_WEIGHT_ALERT_SEVERITY, RISK_WEIGHT_ANOMALY,
    RISK_WEIGHT_BASELINE, RISK_WEIGHT_ASSET,
)
from alerts import generate_alerts_for_row, alerts_to_summary_string
from asset_profiler import classify_asset
from features import records_to_dataframe
from port_intel import risky_ports_from_record
from recommender import recommend_for_row
from triage import compute_triage_status, TRIAGE_NONE

_ASSET_CRITICALITY_SCORES = {
    "database_server": 1.0,
    "container_host":  0.9,
    "server":          0.8,
    "mail_server":     0.8,
    "file_server":     0.8,
    "network_device":  0.6,
    "workstation":     0.5,
    "iot_device":      0.4,
    "iot_camera":      0.4,
    "printer":         0.2,
    "unknown":         0.5,
}

_ALERT_SEVERITY_SCORES = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}


def _max_alert_severity_score(alert_list):
    if not alert_list:
        return 0.0
    return max(_ALERT_SEVERITY_SCORES.get(alert.get("severity", ""), 0.0) for alert in alert_list)


def _baseline_change_score(ip, baseline_diff):
    if baseline_diff is None:
        return 0.0
    if ip in baseline_diff.get("new_hosts", []):
        return 0.5
    if ip in baseline_diff.get("new_ports", {}):
        return 1.0
    if ip in baseline_diff.get("version_changes", {}):
        return 0.5
    return 0.0


def _compute_composite_risk_score(row, baseline_diff):
    ml_prob = float(row.get("predicted_probability_suspicious", 0.0))
    anomaly = float(row.get("anomaly_score", 0.0))
    alert_score = _max_alert_severity_score(row.get("_alert_list", []))
    asset_score = _ASSET_CRITICALITY_SCORES.get(row.get("asset_type", "unknown"), 0.5)
    baseline_score = _baseline_change_score(str(row.get("ip", "")), baseline_diff)
    composite = (
        ml_prob * RISK_WEIGHT_ML_PROB
        + alert_score * RISK_WEIGHT_ALERT_SEVERITY
        + anomaly * RISK_WEIGHT_ANOMALY
        + baseline_score * RISK_WEIGHT_BASELINE
        + asset_score * RISK_WEIGHT_ASSET
    )
    return round(min(composite, 100.0), 1)

# EN: Open the saved machine learning model.
# VI: Mở mô hình máy học đã lưu.
def load_model_bundle(model_path):
    return joblib.load(model_path)

# EN: Turn a probability number into a severity word.
# VI: Đổi số xác suất thành chữ mức nguy hiểm.
def severity_from_probability(suspicious_probability):
    if suspicious_probability > SEVERITY_CRITICAL_MIN_PROB:
        return "CRITICAL"
    if suspicious_probability > SEVERITY_HIGH_MIN_PROB:
        return "HIGH"
    if suspicious_probability > SEVERITY_MEDIUM_MIN_PROB:
        return "MEDIUM"
    return "LOW"

# EN: Predict normal or suspicious from scan records.
# VI: Đoán bình thường hay đáng nghi từ dữ liệu scan.
def predict_from_records(records, model_path, output_csv=None, baseline_diff=None):
    bundle = load_model_bundle(model_path)
    model = bundle["model"]
    features = bundle["features"]

    df = records_to_dataframe(records)

    if df.empty:
        raise RuntimeError("No reachable hosts with open ports were found")

    missing = [f for f in features if f not in df.columns]
    for m in missing:
        df[m] = 0

    X = df[features]
    predictions = model.predict(X)

    suspicious_probs = None
    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        if "suspicious" in classes:
            suspicious_index = classes.index("suspicious")
            suspicious_probs = model.predict_proba(X)[:, suspicious_index]

    df["prediction"] = predictions

    if suspicious_probs is not None:
        df["predicted_probability_suspicious"] = suspicious_probs
    else:
        df["predicted_probability_suspicious"] = 0.0

    # Compute unsupervised anomaly scores from Isolation Forest
    anomaly_detector = bundle.get("anomaly_detector")
    if anomaly_detector is not None:
        raw_scores = anomaly_detector.score_samples(X)
        score_min = float(raw_scores.min())
        score_max = float(raw_scores.max())
        if score_max > score_min:
            normalized = 1.0 - (raw_scores - score_min) / (score_max - score_min)
        else:
            normalized = [0.5] * len(raw_scores)
        df["anomaly_score"] = [round(float(s), 4) for s in normalized]
    else:
        df["anomaly_score"] = 0.0

    # Asset type first — needed for composite risk score
    df["asset_type"] = df.apply(classify_asset, axis=1)
    # Alert list as Python objects — needed for composite score and triage
    df["_alert_list"] = df.apply(generate_alerts_for_row, axis=1)
    # Composite risk score: ML prob + alert severity + anomaly + baseline change + asset criticality
    df["risk_score"] = df.apply(
        lambda row: _compute_composite_risk_score(row, baseline_diff), axis=1
    )
    df["severity"] = df["predicted_probability_suspicious"].apply(severity_from_probability)
    df["top_risk_ports"] = [risky_ports_from_record(record) for record in records]
    df["recommendations"] = df.apply(lambda row: " ; ".join(recommend_for_row(row)), axis=1)
    df["alerts"] = df["_alert_list"].apply(alerts_to_summary_string)
    df["triage_status"] = df.apply(
        lambda row: compute_triage_status(row, row["_alert_list"])
        if row["prediction"] == "suspicious"
        else TRIAGE_NONE,
        axis=1,
    )
    df.drop(columns=["_alert_list"], inplace=True)

    export_df = df[
        [
            "ip",
            "hostname",
            "prediction",
            "predicted_probability_suspicious",
            "risk_score",
            "severity",
            "triage_status",
            "asset_type",
            "anomaly_score",
            "open_port_count",
            "risky_port_count",
            "very_risky_port_count",
            "critical_port_count",
            "high_detail_risk_port_count",
            "cleartext_count",
            "admin_port_count",
            "db_count",
            "fileshare_count",
            "remote_access_count",
            "top_risk_ports",
            "alerts",
            "recommendations"
        ]
    ].copy()

    export_df = export_df.rename(
        columns={
            "predicted_probability_suspicious": "probability_suspicious"
        }
    )

    export_df["probability_suspicious"] = export_df["probability_suspicious"].round(4)

    if output_csv:
        export_df.to_csv(output_csv, index=False)

    return df
