# EN: Load the trained model and predict host risk.
# VI: Mở mô hình đã học rồi đoán máy có nguy hiểm không.

import joblib
import pandas as pd
from constants import SEVERITY_CRITICAL_MIN_PROB, SEVERITY_HIGH_MIN_PROB, SEVERITY_MEDIUM_MIN_PROB
from alerts import generate_alerts_for_row, alerts_to_summary_string
from asset_profiler import classify_asset
from features import records_to_dataframe
from port_intel import risky_ports_from_record
from recommender import recommend_for_row
from triage import compute_triage_status, TRIAGE_NONE

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
def predict_from_records(records, model_path, output_csv=None):
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

    df["severity"] = df["predicted_probability_suspicious"].apply(severity_from_probability)
    df["risk_score"] = (df["predicted_probability_suspicious"] * 100).round(1)
    df["top_risk_ports"] = [risky_ports_from_record(record) for record in records]
    df["recommendations"] = df.apply(lambda row: " ; ".join(recommend_for_row(row)), axis=1)
    df["alerts"] = df.apply(
        lambda row: alerts_to_summary_string(generate_alerts_for_row(row)), axis=1
    )
    df["asset_type"] = df.apply(classify_asset, axis=1)
    df["triage_status"] = df.apply(
        lambda row: compute_triage_status(row, generate_alerts_for_row(row))
        if row["prediction"] == "suspicious"
        else TRIAGE_NONE,
        axis=1,
    )

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
