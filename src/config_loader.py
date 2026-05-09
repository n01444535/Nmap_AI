# EN: Load config.yaml and apply user-defined overrides to scan records.
# VI: Đọc config.yaml và áp dụng cài đặt người dùng lên dữ liệu scan.

from pathlib import Path

_DEFAULT_CONFIG = {
    "trusted_hosts": [],
    "ignore_ports":  [],
}

# EN: Load config.yaml from the project root. Returns defaults if file is missing.
# VI: Đọc config.yaml từ thư mục gốc. Trả về mặc định nếu không có file.
def load_config(config_path=None):
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "config.yaml"

    config_path = Path(config_path)
    if not config_path.exists():
        return dict(_DEFAULT_CONFIG)

    try:
        import yaml
        with open(config_path, encoding="utf-8") as config_file:
            loaded = yaml.safe_load(config_file) or {}
        result = dict(_DEFAULT_CONFIG)
        result["trusted_hosts"] = [str(ip) for ip in loaded.get("trusted_hosts") or []]
        result["ignore_ports"]  = [int(p)  for p  in loaded.get("ignore_ports")  or []]
        return result
    except Exception:
        return dict(_DEFAULT_CONFIG)

# EN: Strip ignored ports and mark trusted hosts before the rest of the pipeline runs.
# VI: Xoá cổng bị bỏ qua và đánh dấu máy tin cậy trước khi pipeline chạy.
def apply_config_to_records(records, config):
    ignored_port_set = set(config.get("ignore_ports", []))
    trusted_host_set = set(config.get("trusted_hosts", []))

    processed_records = []
    for record in records:
        updated_record = dict(record)

        if ignored_port_set:
            updated_record["open_ports"] = [
                port_entry for port_entry in updated_record.get("open_ports", [])
                if port_entry.get("port") not in ignored_port_set
            ]

        updated_record["is_trusted"] = updated_record.get("ip", "") in trusted_host_set
        processed_records.append(updated_record)

    return processed_records

# EN: After prediction, override trusted hosts to normal with zero risk.
# VI: Sau khi dự đoán, ép máy tin cậy về bình thường với rủi ro bằng 0.
def override_trusted_predictions(df, config):
    trusted_host_set = set(config.get("trusted_hosts", []))
    if not trusted_host_set:
        return df

    from triage import TRIAGE_NONE
    trusted_mask = df["ip"].isin(trusted_host_set)
    df.loc[trusted_mask, "prediction"] = "normal"
    df.loc[trusted_mask, "predicted_probability_suspicious"] = 0.0
    df.loc[trusted_mask, "risk_score"] = 0.0
    df.loc[trusted_mask, "severity"] = "LOW"
    df.loc[trusted_mask, "triage_status"] = TRIAGE_NONE
    df.loc[trusted_mask, "alerts"] = ""
    return df
