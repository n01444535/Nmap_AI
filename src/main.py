# EN: Run the command-line workflow for scan, train, and predict.
# VI: Chạy lệnh chính để quét, học, và đoán.

import argparse
import os
import sys
from pathlib import Path


# EN: Load pandas or restart with the project Python.
# VI: Mở pandas hoặc chạy lại bằng Python của dự án.
def load_pandas_or_project_venv():
    try:
        import pandas as pandas_module
        return pandas_module
    except ModuleNotFoundError as e:
        if e.name != "pandas":
            raise

        project_dir = Path(__file__).resolve().parent
        candidates = [
            project_dir / "MyEnv" / "bin" / "python",
            project_dir / "MyEnv" / "Scripts" / "python.exe"
        ]

        current_python = Path(sys.executable).absolute()
        for candidate in candidates:
            if candidate.exists() and candidate.absolute() != current_python:
                os.execv(str(candidate), [str(candidate)] + sys.argv)

        raise


pd = load_pandas_or_project_venv()

from local_target import get_local_ip
from parser_nmap import extract_live_hosts_from_discovery, parse_nmap_service_scan
from predictor import predict_from_records
from sample_data import get_sample_records
from scanner import run_full_scan
from synthetic_data import get_synthetic_records
from scan_cache import (
    dedupe_records,
    get_cached_scan,
    load_learned_records,
    remember_records,
    save_cached_scan,
    save_full_result_snapshot,
    utc_now_iso
)
from trainer import print_metrics, train_models, write_feature_importance_report, write_metrics_report
from unknown_enrichment import enrich_unknown_ports
from utils import (
    dataframe_to_prediction_text,
    ensure_result_dir,
    ensure_data_dir,
    has_nmap,
    records_to_scan_text,
    save_json,
    write_port_details,
    write_txt
)
from features import records_to_dataframe
from labeling import heuristic_label_row

# EN: Get scan records from cache, Nmap, or sample data.
# VI: Lấy dữ liệu scan từ cache, Nmap, hoặc dữ liệu mẫu.
def collect_records(force_rescan=False, use_cache=True):
    result_dir = ensure_result_dir()
    data_dir = ensure_data_dir()
    local_ip = get_local_ip()

    discovery_xml = str(data_dir / "discovery.xml")
    service_xml = str(data_dir / "service_scan.xml")
    connected_json = str(data_dir / "connected_devices.json")

    scan_txt = str(result_dir / "scan_result.txt")
    mode_txt = str(result_dir / "scan_mode.txt")

    records = []
    scan_meta = {
        "target": local_ip,
        "source": "unknown",
        "cache_hit": False,
        "cache_saved_at": ""
    }

    if use_cache and not force_rescan:
        cached_entry = get_cached_scan(result_dir, local_ip)
        if cached_entry is not None:
            records = cached_entry.get("records", [])
            scan_meta.update(
                {
                    "source": "cache",
                    "cache_hit": True,
                    "cache_saved_at": cached_entry.get("saved_at", "")
                }
            )
            write_txt(
                "Cached deep scan mode. Nmap was skipped because this target was already scanned.\n"
                f"Cached at: {scan_meta['cache_saved_at']}\n"
                "Use python3 main.py full --rescan to force a fresh scan.\n",
                mode_txt
            )
            save_json(records, connected_json)
            write_txt(records_to_scan_text(records), scan_txt)
            return result_dir, data_dir, records, scan_meta

    if has_nmap():
        try:
            run_full_scan(local_ip, discovery_xml, service_xml)
            live_hosts = extract_live_hosts_from_discovery(discovery_xml)

            if live_hosts:
                records = parse_nmap_service_scan(service_xml)

            if records:
                scan_meta["source"] = "nmap"
                save_cached_scan(result_dir, local_ip, records)
                write_txt("Real deep scan mode using Nmap\n", mode_txt)
            else:
                records = get_sample_records(local_ip)
                scan_meta["source"] = "sample"
                write_txt("Fallback to sample data because real deep scan produced no usable records.\n", mode_txt)

        except KeyboardInterrupt as e:
            raise KeyboardInterrupt(str(e))
        except Exception as e:
            records = get_sample_records(local_ip)
            scan_meta["source"] = "sample"
            write_txt(f"Fallback to sample data because Nmap deep scan failed: {str(e)}\n", mode_txt)

    else:
        records = get_sample_records(local_ip)
        scan_meta["source"] = "sample"
        write_txt("Sample data mode because Nmap is not installed or not found in PATH\n", mode_txt)

    save_json(records, connected_json)
    write_txt(records_to_scan_text(records), scan_txt)

    return result_dir, data_dir, records, scan_meta

# EN: List the risky ports shown in training output.
# VI: Liệt kê cổng nguy hiểm để hiện trong dữ liệu học.
def get_top_risk_ports_for_training(row):
    ports = []

    if row.get("has_ftp", 0) == 1:
        ports.append("21")
    if row.get("has_telnet", 0) == 1:
        ports.append("23")
    if row.get("has_rpcbind", 0) == 1:
        ports.append("111")
    if row.get("has_tftp", 0) == 1:
        ports.append("69")
    if row.get("has_snmp", 0) == 1:
        ports.append("161")
    if row.get("has_smb", 0) == 1:
        ports.append("445")
    if row.get("has_rdp", 0) == 1:
        ports.append("3389")
    if row.get("has_vnc", 0) == 1:
        ports.append("5900")
    if row.get("has_winrm", 0) == 1:
        ports.append("5985/5986")
    if row.get("has_redis", 0) == 1:
        ports.append("6379")
    if row.get("has_mysql", 0) == 1:
        ports.append("3306")
    if row.get("has_postgresql", 0) == 1:
        ports.append("5432")
    if row.get("has_oracle", 0) == 1:
        ports.append("1521")
    if row.get("has_mssql", 0) == 1:
        ports.append("1433")
    if row.get("has_mongodb", 0) == 1:
        ports.append("27017")
    if row.get("has_elasticsearch", 0) == 1:
        ports.append("9200")
    if row.get("has_docker", 0) == 1:
        ports.append("2375/2376")
    if row.get("has_kubernetes_api", 0) == 1:
        ports.append("6443")
    if row.get("has_memcached", 0) == 1:
        ports.append("11211")

    return ";".join(ports) if ports else "None"

# EN: Write a short reason for the host risk.
# VI: Viết lý do ngắn vì sao máy có rủi ro.
def get_risk_summary(row):
    reasons = []

    if row.get("has_telnet", 0) == 1:
        reasons.append("Telnet exposed")
    if row.get("has_ftp", 0) == 1:
        reasons.append("FTP exposed")
    if row.get("has_smb", 0) == 1:
        reasons.append("SMB exposed")
    if row.get("has_rdp", 0) == 1:
        reasons.append("RDP exposed")
    if row.get("has_rpcbind", 0) == 1:
        reasons.append("RPC exposed")
    if row.get("has_redis", 0) == 1:
        reasons.append("Redis exposed")
    if row.get("has_tftp", 0) == 1:
        reasons.append("TFTP exposed")
    if row.get("has_snmp", 0) == 1:
        reasons.append("SNMP management exposed")
    if row.get("has_docker", 0) == 1:
        reasons.append("Docker API exposed")
    if row.get("has_kubernetes_api", 0) == 1:
        reasons.append("Kubernetes API exposed")
    if row.get("has_elasticsearch", 0) == 1:
        reasons.append("Elasticsearch exposed")
    if row.get("has_winrm", 0) == 1:
        reasons.append("WinRM exposed")
    if row.get("db_count", 0) > 0:
        reasons.append("Database service exposed")
    if row.get("fileshare_count", 0) > 0:
        reasons.append("File-sharing service exposed")
    if row.get("cleartext_count", 0) >= 2:
        reasons.append("Multiple clear-text services")
    if row.get("admin_port_count", 0) >= 2:
        reasons.append("Multiple admin services")
    if row.get("uncommon_open_count", 0) >= 2:
        reasons.append("Uncommon ports present")
    if row.get("remote_access_count", 0) >= 2:
        reasons.append("Multiple remote access services")

    return " ; ".join(reasons) if reasons else "Low-risk normal profile"

# EN: Build the data table used to train the model.
# VI: Tạo bảng dữ liệu để dạy mô hình.
def build_training_data(result_dir, real_records, include_learned=True, remember_current=True):
    real_df = records_to_dataframe(real_records)

    if real_df.empty:
        raise RuntimeError("No reachable hosts with open ports were found")

    real_df["label"] = real_df.apply(heuristic_label_row, axis=1)

    learned_count = 0
    records_for_training = real_records

    if include_learned:
        if remember_current:
            learned_records = remember_records(result_dir, real_records)
        else:
            learned_records = load_learned_records(result_dir)

        learned_count = len(learned_records)
        records_for_training = dedupe_records(real_records + learned_records)

    train_df = records_to_dataframe(records_for_training)
    train_df["label"] = train_df.apply(heuristic_label_row, axis=1)
    needs_augmentation = len(train_df) < 4 or train_df["label"].nunique() < 2

    if needs_augmentation:
        local_ip = get_local_ip()
        sample_records = get_sample_records(local_ip)
        sample_df = records_to_dataframe(sample_records)
        sample_df["label"] = sample_df.apply(heuristic_label_row, axis=1)

        train_df = pd.concat([train_df, sample_df], ignore_index=True)
        train_df = train_df.drop_duplicates().reset_index(drop=True)

        write_txt(
            "Real scan data was insufficient for machine learning training, so built-in sample records were added for training only.\n"
            f"Learned record memory available: {learned_count} records.\n",
            str(result_dir / "training_note.txt")
        )
    else:
        if include_learned:
            note = (
                "Training data came from current scan results plus learned scan memory.\n"
                f"Current scan records: {len(real_records)}\n"
                f"Learned record memory available: {learned_count}\n"
                f"Training records after dedupe: {len(train_df)}\n"
            )
        else:
            note = (
                "Training data came from the current scan or testcase records only.\n"
                f"Current records: {len(real_records)}\n"
                f"Training records after dedupe: {len(train_df)}\n"
            )
        write_txt(
            note,
            str(result_dir / "training_note.txt")
        )

    full_training_csv = str(result_dir / "training_data_full.csv")
    train_df.to_csv(full_training_csv, index=False)

    readable_df = train_df.copy()
    readable_df["top_risk_ports"] = readable_df.apply(get_top_risk_ports_for_training, axis=1)
    readable_df["risk_summary"] = readable_df.apply(get_risk_summary, axis=1)

    training_export_df = readable_df[
        [
            "ip",
            "hostname",
            "label",
            "open_port_count",
            "risky_port_count",
            "very_risky_port_count",
            "critical_port_count",
            "high_detail_risk_port_count",
            "remote_access_count",
            "cleartext_count",
            "admin_port_count",
            "db_count",
            "fileshare_count",
            "top_risk_ports",
            "risk_summary"
        ]
    ].copy()

    readable_training_csv = str(result_dir / "training_data.csv")
    training_export_df.to_csv(readable_training_csv, index=False)

    return real_df, train_df, full_training_csv

# EN: Add the current host features to one growing history CSV file.
# VI: Thêm dữ liệu máy hiện tại vào một file lịch sử CSV lớn dần.
def append_history_dataset(result_dir, records, mode, source):
    # EN: Convert scan records into the same number table used by the model.
    # VI: Đổi dữ liệu scan thành bảng số giống bảng để máy học.
    df = records_to_dataframe(records)

    if df.empty:
        return None

    # EN: Add simple labels and run info before saving history.
    # VI: Thêm nhãn và thông tin lần chạy trước khi lưu lịch sử.
    df["label"] = df.apply(heuristic_label_row, axis=1)
    df["run_at"] = utc_now_iso()
    df["mode"] = mode
    df["source"] = source

    # EN: Append new rows so old learning data stays available.
    # VI: Ghi thêm dòng mới để dữ liệu học cũ vẫn còn.
    history_csv = result_dir / "history_dataset.csv"
    write_header = not history_csv.exists()
    df.to_csv(history_csv, mode="a", header=write_header, index=False)
    return history_csv

# EN: Save a small report that explains the latest history dataset size.
# VI: Lưu báo cáo nhỏ nói file lịch sử đang có bao nhiêu dòng.
def write_history_dataset_note(result_dir, history_csv):
    output_path = result_dir / "history_dataset_note.txt"

    if history_csv is None or not history_csv.exists():
        write_txt("No history dataset was written because there were no host records.\n", str(output_path))
        return

    # EN: Count data rows, not the CSV header row.
    # VI: Đếm dòng dữ liệu, không tính dòng tiêu đề CSV.
    try:
        row_count = sum(1 for _ in open(history_csv, "r", encoding="utf-8")) - 1
    except Exception:
        row_count = 0

    write_txt(
        "History dataset keeps one row per host from offline analyze or full runs.\n"
        f"Current rows: {max(row_count, 0)}\n",
        str(output_path)
    )

# EN: Turn a probability number into a severity word.
# VI: Đổi số xác suất thành chữ mức nguy hiểm.
def severity_from_probability(p):
    if p > 0.98:
        return "CRITICAL"
    if p > 0.95:
        return "HIGH"
    if p > 0.85:
        return "MEDIUM"
    return "LOW"

# EN: Print suspicious hosts on the screen.
# VI: In các máy đáng nghi ra màn hình.
def print_suspicious_summary(df):
    suspicious_df = df[df["prediction"] == "suspicious"]

    print("\n================ AI SECURITY ALERT SUMMARY ================\n")

    if suspicious_df.empty:
        print("No suspicious hosts detected.\n")
        print("==========================================================\n")
        return

    suspicious_df = suspicious_df.sort_values(
        "predicted_probability_suspicious",
        ascending=False
    )

    for i, (_, row) in enumerate(suspicious_df.iterrows(), 1):
        probability = row.get("predicted_probability_suspicious", 0.0)
        severity = severity_from_probability(probability)

        print(f"[{i}] {row['ip']} ({row['hostname']})")
        print(f"AI Severity: {severity} | AI Confidence: {probability:.3f}")
        print(f"Top Risk Ports: {row.get('top_risk_ports', 'None')}")
        print("AI Recommendations:")

        recommendations = str(row["recommendations"]).split(";")
        for recommendation in recommendations:
            recommendation = recommendation.strip()
            if recommendation:
                print(f" - {recommendation}")

        print("-" * 58)

    print("\n==========================================================\n")

# EN: Print a simple summary when nothing is suspicious.
# VI: In tóm tắt khi không thấy máy đáng nghi.
def print_real_scan_normal_summary(records):
    print("\n================ REAL DEEP SCAN SUMMARY ================\n")

    if not records:
        print("No active hosts with open ports were found.\n")
        print("=======================================================\n")
        return

    print("Scanned Hosts:")
    for i, record in enumerate(records, 1):
        ip = record.get("ip", "unknown")
        hostname = record.get("hostname", "")
        if hostname:
            print(f"[{i}] {ip} ({hostname})")
        else:
            print(f"[{i}] {ip}")

    print("\nAI Result:")
    print("No suspicious hosts were detected from the current real deep scan.")
    print("The observed hosts appear normal based on the available scan evidence.")

    print("\n=======================================================\n")

# EN: Run only the scan command.
# VI: Chỉ chạy lệnh quét.
def command_scan():
    result_dir, _, records, _ = collect_records()
    write_port_details(records, str(result_dir / "port_details.csv"), str(result_dir / "port_details.txt"))
    print(records_to_scan_text(records))

# EN: Run scan and show the training table.
# VI: Quét rồi hiện bảng để máy học.
def command_build_training():
    result_dir, _, records, scan_meta = collect_records()
    remember_current = scan_meta.get("source") in {"nmap", "cache"}
    _, train_df, _ = build_training_data(result_dir, records, remember_current=remember_current)
    print(train_df.to_string(index=False))

# EN: Train a model from saved training data.
# VI: Dạy mô hình từ dữ liệu đã lưu.
def command_train():
    result_dir = ensure_result_dir()
    training_csv = str(result_dir / "training_data_full.csv")
    output_model = str(result_dir / "best_model.joblib")
    metrics_report = str(result_dir / "metrics.txt")
    feature_importance_report = str(result_dir / "feature_importance.txt")

    bundle, note = train_models(training_csv, output_model)
    write_metrics_report(bundle, metrics_report, note)
    write_feature_importance_report(bundle, feature_importance_report)
    print_metrics(bundle, note)

# EN: Generate fake safe training data without scanning a network.
# VI: Tạo dữ liệu học giả an toàn mà không quét mạng.
def command_generate_dataset():
    result_dir = ensure_result_dir()
    records = get_synthetic_records()

    # EN: Save the fake records so the student can read what was created.
    # VI: Lưu dữ liệu giả để học sinh có thể mở ra xem.
    save_json(records, str(result_dir / "synthetic_records.json"))
    write_txt(records_to_scan_text(records), str(result_dir / "synthetic_scan_result.txt"))
    write_port_details(
        records,
        str(result_dir / "synthetic_port_details.csv"),
        str(result_dir / "synthetic_port_details.txt")
    )

    # EN: Put the fake records into the normal training CSV files.
    # VI: Đưa dữ liệu giả vào các file CSV train bình thường.
    history_csv = append_history_dataset(result_dir, records, "generate-dataset", "synthetic")
    write_history_dataset_note(result_dir, history_csv)
    _, train_df, training_csv = build_training_data(
        result_dir,
        records,
        include_learned=False,
        remember_current=False
    )

    # EN: Train immediately so the model has both normal and suspicious examples.
    # VI: Train ngay để mô hình có cả ví dụ bình thường và đáng nghi.
    output_model = str(result_dir / "best_model.joblib")
    metrics_report = str(result_dir / "metrics.txt")
    feature_importance_report = str(result_dir / "feature_importance.txt")
    bundle, note = train_models(training_csv, output_model)
    write_metrics_report(bundle, metrics_report, note)
    write_feature_importance_report(bundle, feature_importance_report)

    # EN: Predict against the fake records only, so real scan reports are not overwritten.
    # VI: Dự đoán trên dữ liệu giả riêng, để không ghi đè báo cáo scan thật.
    if bundle is not None:
        synthetic_predictions_csv = str(result_dir / "synthetic_predictions.csv")
        synthetic_predictions_txt = str(result_dir / "synthetic_prediction_result.txt")
        pred_df = predict_from_records(records, output_model, synthetic_predictions_csv)
        write_txt(dataframe_to_prediction_text(pred_df), synthetic_predictions_txt)

    label_counts = train_df["label"].value_counts().to_dict()
    normal_count = label_counts.get("normal", 0)
    suspicious_count = label_counts.get("suspicious", 0)
    print("Synthetic dataset generated without scanning the network.")
    print(f"Rows: {len(train_df)} | normal: {normal_count} | suspicious: {suspicious_count}")
    print("Wrote result/training_data.csv and result/training_data_full.csv")
    print("Trained result/best_model.joblib from the synthetic dataset")

# EN: Run scan and predict risk with the saved model.
# VI: Quét rồi dùng mô hình đã lưu để đoán rủi ro.
def command_predict():
    result_dir, _, records, _ = collect_records()
    model_path = str(result_dir / "best_model.joblib")
    output_csv = str(result_dir / "predictions.csv")
    output_txt = str(result_dir / "prediction_result.txt")

    write_port_details(records, str(result_dir / "port_details.csv"), str(result_dir / "port_details.txt"))
    df = predict_from_records(records, model_path, output_csv)
    write_txt(dataframe_to_prediction_text(df), output_txt)
    print_suspicious_summary(df)

# EN: Analyze an existing Nmap XML file without running any scan.
# VI: Phân tích file XML Nmap có sẵn mà không quét gì hết.
def command_analyze(xml_path):
    result_dir = ensure_result_dir()
    data_dir = ensure_data_dir()
    xml_file = Path(xml_path)

    if not xml_file.exists():
        raise RuntimeError(f"Nmap XML file not found: {xml_path}")

    # EN: Read the saved XML file only, so this command never starts a scan.
    # VI: Chỉ đọc file XML đã có, nên lệnh này không bắt đầu quét mạng.
    records = parse_nmap_service_scan(str(xml_file))

    # EN: Guess unknown ports without calling Nmap again.
    # VI: Đoán port chưa rõ mà không gọi Nmap lần nữa.
    records, unknown_enrich_meta = enrich_unknown_ports(
        records,
        data_dir,
        skip_scan=True,
        allow_nmap=False
    )

    # EN: Rebuild the normal report files from the offline XML data.
    # VI: Tạo lại các file báo cáo từ dữ liệu XML offline.
    save_json(records, str(data_dir / "connected_devices.json"))
    write_txt(f"Offline analyze mode using XML file: {xml_file}\n", str(result_dir / "scan_mode.txt"))
    write_txt(records_to_scan_text(records), str(result_dir / "scan_result.txt"))
    write_port_details(records, str(result_dir / "port_details.csv"), str(result_dir / "port_details.txt"))

    # EN: Save these offline records into the growing learning history.
    # VI: Lưu dữ liệu offline này vào lịch sử học đang lớn dần.
    history_csv = append_history_dataset(result_dir, records, "analyze", "offline_xml")
    write_history_dataset_note(result_dir, history_csv)

    # EN: Build a fresh training table from this XML without using learned scan memory.
    # VI: Tạo bảng học mới từ XML này mà không dùng bộ nhớ scan cũ.
    _, _, training_csv = build_training_data(
        result_dir,
        records,
        include_learned=False,
        remember_current=False
    )

    output_model = str(result_dir / "best_model.joblib")
    metrics_report = str(result_dir / "metrics.txt")
    feature_importance_report = str(result_dir / "feature_importance.txt")
    output_csv = str(result_dir / "predictions.csv")
    output_txt = str(result_dir / "prediction_result.txt")

    bundle, note = train_models(training_csv, output_model)
    write_metrics_report(bundle, metrics_report, note)

    # EN: Save a simple report that says which features the AI used most.
    # VI: Lưu báo cáo đơn giản nói AI dùng dấu hiệu nào nhiều nhất.
    write_feature_importance_report(bundle, feature_importance_report)

    if bundle is None:
        write_txt(
            "Offline XML was parsed, but model training was skipped because there was not enough label variety.\n",
            output_txt
        )
        write_txt("", output_csv)
        save_full_result_snapshot(
            result_dir,
            str(xml_file),
            "analyze",
            "offline_xml",
            records,
            predictions=[],
            extra={"training_note": note, "unknown_enrichment": unknown_enrich_meta}
        )
        print("Offline XML analysis finished. Model training was skipped.\n")
        return

    pred_df = predict_from_records(records, output_model, output_csv)
    write_txt(dataframe_to_prediction_text(pred_df), output_txt)
    snapshot_path = save_full_result_snapshot(
        result_dir,
        str(xml_file),
        "analyze",
        "offline_xml",
        records,
        predictions=pred_df.to_dict("records"),
        extra={"model": bundle.get("model_name", ""), "unknown_enrichment": unknown_enrich_meta}
    )

    print_suspicious_summary(pred_df)
    print(f"Saved offline analysis snapshot: {snapshot_path}")

# EN: Run the full scan, train, predict, and report flow.
# VI: Chạy đủ quét, học, đoán, và làm báo cáo.
def command_full(mode="real", force_rescan=False, skip_unknown_enrich=False):
    result_dir = ensure_result_dir()
    data_dir = ensure_data_dir()
    scan_meta = {
        "target": "testcase" if mode == "testcase" else get_local_ip(),
        "source": "testcase" if mode == "testcase" else "unknown",
        "cache_hit": False
    }

    if mode == "testcase":
        discovery_xml = Path("data/testcase/internet_cafe_discovery.xml")
        service_xml = Path("data/testcase/internet_cafe_service_scan.xml")

        if not discovery_xml.exists() or not service_xml.exists():
            raise RuntimeError("Test case XML files not found. Run python3 test_case_records.py first.")

        records = parse_nmap_service_scan(str(service_xml))

        save_json(records, str(data_dir / "connected_devices.json"))
        write_txt("Test case mode using Nmap-style XML data\n", str(result_dir / "scan_mode.txt"))
        write_txt(records_to_scan_text(records), str(result_dir / "scan_result.txt"))
    else:
        _, _, records, scan_meta = collect_records(force_rescan=force_rescan)

    allow_unknown_nmap = mode == "real" and scan_meta.get("source") in {"nmap", "cache"} and has_nmap()
    records, unknown_enrich_meta = enrich_unknown_ports(
        records,
        data_dir,
        skip_scan=skip_unknown_enrich or mode != "real",
        allow_nmap=allow_unknown_nmap
    )

    save_json(records, str(data_dir / "connected_devices.json"))
    write_txt(records_to_scan_text(records), str(result_dir / "scan_result.txt"))

    if mode == "real" and scan_meta.get("source") in {"nmap", "cache"}:
        cache_source = "nmap_enriched" if unknown_enrich_meta.get("ran_scan") else scan_meta.get("source", "nmap")
        save_cached_scan(result_dir, scan_meta.get("target", get_local_ip()), records, source=cache_source)

    write_port_details(records, str(result_dir / "port_details.csv"), str(result_dir / "port_details.txt"))
    # EN: Store this run in a long-term table for future ML learning.
    # VI: Lưu lần chạy này vào bảng dài hạn để máy học sau này.
    history_csv = append_history_dataset(result_dir, records, mode, scan_meta.get("source", "unknown"))
    write_history_dataset_note(result_dir, history_csv)

    remember_current = mode == "real" and scan_meta.get("source") in {"nmap", "cache"}
    _, _, training_csv = build_training_data(
        result_dir,
        records,
        include_learned=mode == "real",
        remember_current=remember_current
    )

    output_model = str(result_dir / "best_model.joblib")
    metrics_report = str(result_dir / "metrics.txt")
    feature_importance_report = str(result_dir / "feature_importance.txt")
    output_csv = str(result_dir / "predictions.csv")
    output_txt = str(result_dir / "prediction_result.txt")

    bundle, note = train_models(training_csv, output_model)
    write_metrics_report(bundle, metrics_report, note)
    # EN: Save why the trained model made its decisions.
    # VI: Lưu lý do mô hình đã học dựa vào dấu hiệu nào.
    write_feature_importance_report(bundle, feature_importance_report)

    if bundle is None:
        write_txt(
            "No suspicious hosts were detected from the current real deep scan. "
            "The observed hosts appear normal based on the available scan evidence.\n",
            output_txt
        )
        write_txt("", output_csv)
        save_full_result_snapshot(
            result_dir,
            scan_meta.get("target", "testcase"),
            mode,
            scan_meta.get("source", "unknown"),
            records,
            predictions=[],
            extra={"training_note": note, "unknown_enrichment": unknown_enrich_meta}
        )

        if mode == "real":
            print_real_scan_normal_summary(records)
        else:
            print("No suspicious hosts detected.\n")

        return

    pred_df = predict_from_records(records, output_model, output_csv)
    write_txt(dataframe_to_prediction_text(pred_df), output_txt)
    snapshot_path = save_full_result_snapshot(
        result_dir,
        scan_meta.get("target", "testcase"),
        mode,
        scan_meta.get("source", "unknown"),
        records,
        predictions=pred_df.to_dict("records"),
        extra={
            "model": bundle.get("model_name", ""),
            "cache_hit": scan_meta.get("cache_hit", False),
            "cache_saved_at": scan_meta.get("cache_saved_at", ""),
            "unknown_enrichment": unknown_enrich_meta
        }
    )

    if mode == "real" and (pred_df["prediction"] == "suspicious").sum() == 0:
        print_real_scan_normal_summary(records)
    else:
        print_suspicious_summary(pred_df)

    print(f"Saved full result snapshot: {snapshot_path}")

# EN: Add normal help flags plus the easy --h shortcut.
# VI: Thêm cờ hướng dẫn bình thường và cả --h cho dễ nhớ.
def add_help_flags(parser_obj):
    parser_obj.add_argument(
        "-h",
        "--help",
        "--h",
        action="help",
        help="Show this help message and exit"
    )

# EN: Read the user command and call the right function.
# VI: Đọc lệnh người dùng rồi gọi đúng hàm.
def main():
    # EN: Explain the tool before the user picks a command.
    # VI: Giải thích công cụ trước khi người dùng chọn lệnh.
    parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Nmap_AI - scan, learn, and predict network risk.\n\n"
            "Usage:\n"
            "  python3 main.py --h\n"
            "  python3 main.py <command> [options]\n\n"
            "Most used command:\n"
            "  python3 main.py full\n\n"
            "What full means:\n"
            "  full = deep workflow: scan/cache -> enrich unknown ports -> train AI -> predict -> write reports.\n"
            "  If cache exists, full can reuse old scan data so it is much faster.\n"
            "  Use --rescan when you really want a fresh Nmap scan.\n\n"
            "Complete command guide:\n"
            "  full [real]\n"
            "      Deep workflow for real data. It may scan, or it may reuse cached scan data.\n"
            "      Writes reports, datasets, model, predictions, and full result snapshot.\n\n"
            "  full testcase\n"
            "      Uses local testcase XML files. Good for class/demo testing without real network scan.\n\n"
            "  full --rescan\n"
            "      Ignores scan cache and runs a fresh Nmap scan.\n\n"
            "  full --skip-unknown-enrich\n"
            "      Skips the second-stage scan for unknown ports to save time.\n\n"
            "  scan\n"
            "      Collects scan records and writes scan_result plus port_details only.\n\n"
            "  build-training\n"
            "      Builds training_data.csv and training_data_full.csv from saved scan records.\n\n"
            "  generate-dataset\n"
            "      Creates safe fake normal/risky host data and trains the model from it.\n"
            "      This command does not run Nmap and does not scan the network.\n\n"
            "  train\n"
            "      Trains the ML model from result/training_data_full.csv.\n"
            "      Writes best_model.joblib, metrics.txt, and feature_importance.txt.\n\n"
            "  predict\n"
            "      Uses the saved model to predict risk.\n"
            "      Writes prediction_result.txt and predictions.csv.\n\n"
            "  analyze <xml_path>\n"
            "      Reads an existing Nmap XML file, builds reports, updates dataset, and predicts risk.\n"
            "      This command does not run Nmap and does not scan the network."
        ),
        epilog=(
            "Examples:\n"
            "  python3 main.py --h\n"
            "  python3 main.py scan\n"
            "  python3 main.py build-training\n"
            "  python3 main.py generate-dataset\n"
            "  python3 main.py train\n"
            "  python3 main.py predict\n"
            "  python3 main.py full\n"
            "  python3 main.py full --rescan\n"
            "  python3 main.py full --skip-unknown-enrich\n"
            "  python3 main.py full testcase\n"
            "  python3 main.py analyze data/service_scan.xml\n\n"
            "Safe note:\n"
            "  analyze reads an existing XML file and does not scan the network.\n"
            "  full may scan the network unless cached data is reused."
        )
    )
    add_help_flags(parser)

    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    scan_parser = sub.add_parser(
        "scan",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Run scan collection only, then write scan and port reports",
        description=(
            "scan - collect host/port records only.\n\n"
            "This command does not train the AI model and does not run prediction."
        )
    )
    add_help_flags(scan_parser)

    build_training_parser = sub.add_parser(
        "build-training",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Build training CSV files from scan records",
        description=(
            "build-training - create the dataset used by the AI model.\n\n"
            "This prepares training_data.csv and training_data_full.csv."
        )
    )
    add_help_flags(build_training_parser)

    train_parser = sub.add_parser(
        "train",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Train the ML model from saved training data",
        description=(
            "train - train the AI model from result/training_data_full.csv.\n\n"
            "This writes best_model.joblib, metrics.txt, and feature_importance.txt."
        )
    )
    add_help_flags(train_parser)

    generate_dataset_parser = sub.add_parser(
        "generate-dataset",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Create safe fake normal/risky dataset and train from it",
        description=(
            "generate-dataset - create safe synthetic ML data.\n\n"
            "This creates normal and suspicious fake hosts, writes training CSV files,\n"
            "and trains best_model.joblib without running Nmap or scanning any network."
        )
    )
    add_help_flags(generate_dataset_parser)

    predict_parser = sub.add_parser(
        "predict",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Predict risk using the saved model",
        description=(
            "predict - use the saved AI model to predict host risk.\n\n"
            "This writes prediction_result.txt and predictions.csv."
        )
    )
    add_help_flags(predict_parser)

    analyze_parser = sub.add_parser(
        "analyze",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Analyze an existing Nmap XML file without scanning",
        description=(
            "analyze - read an old Nmap XML file and build reports from it.\n\n"
            "This is the safe offline mode. It does not run Nmap and does not scan the network."
        )
    )
    add_help_flags(analyze_parser)
    analyze_parser.add_argument("xml_path", help="Path to an existing Nmap XML file to analyze without scanning")

    full_parser = sub.add_parser(
        "full",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Run the deep full workflow: scan/cache, train, predict, and report",
        description=(
            "full - deep full workflow.\n\n"
            "Steps:\n"
            "  1. collect scan records or reuse cache\n"
            "  2. enrich unknown ports when allowed\n"
            "  3. write port details and dataset files\n"
            "  4. train the AI model\n"
            "  5. predict suspicious hosts\n"
            "  6. save reports and snapshots\n\n"
            "Modes:\n"
            "  real      scan/use cache for your current network target\n"
            "  testcase  use local testcase XML files, no real network scan"
        ),
        epilog=(
            "Examples:\n"
            "  python3 main.py full\n"
            "  python3 main.py full --rescan\n"
            "  python3 main.py full --skip-unknown-enrich\n"
            "  python3 main.py full testcase"
        )
    )
    add_help_flags(full_parser)
    full_parser.add_argument(
        "mode",
        nargs="?",
        default="real",
        choices=["real", "testcase"],
        help="Run mode: real uses scan/cache, testcase uses local sample XML only"
    )
    full_parser.add_argument("--rescan", action="store_true", help="Ignore cached scan data and run Nmap again")
    full_parser.add_argument("--skip-unknown-enrich", action="store_true", help="Skip the targeted second-stage scan for unknown ports")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            command_scan()
            return

        if args.command == "build-training":
            command_build_training()
            return

        if args.command == "train":
            command_train()
            return

        if args.command == "generate-dataset":
            command_generate_dataset()
            return

        if args.command == "predict":
            command_predict()
            return

        if args.command == "analyze":
            command_analyze(args.xml_path)
            return

        if args.command == "full":
            command_full(args.mode, force_rescan=args.rescan, skip_unknown_enrich=args.skip_unknown_enrich)
            return

    except KeyboardInterrupt as e:
        message = str(e).strip() or "Command was cancelled by user."
        print(f"\n{message}\n")
        return

if __name__ == "__main__":
    main()
