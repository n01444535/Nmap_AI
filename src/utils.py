# EN: Share helper tools for commands, files, and reports.
# VI: Chia sẻ đồ nghề nhỏ để chạy lệnh, ghi file, và làm báo cáo.

import json
import re
import subprocess
import sys
import threading
import time
import pandas as pd
from pathlib import Path
from alerts import generate_alerts_for_row
from explainer import generate_explanation_for_row
from constants import PROGRESS_SPINNER_INTERVAL
from port_intel import enrich_port, port_detail_rows

# EN: Run a shell command and optionally show progress.
# VI: Chạy lệnh hệ thống và có thể hiện tiến độ.
def run_command(cmd, show_progress=False, timeout=None):
    if not show_progress:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if process.returncode != 0:
            raise RuntimeError(process.stderr.strip() or "Command failed")
        return process.stdout

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    progress_pattern = re.compile(r"About\s+(\d+(?:\.\d+)?)%\s+done")
    scan_progress = {
        "done": False,
        "percent": None
    }

    # EN: Read Nmap progress lines from error output.
    # VI: Đọc dòng tiến độ Nmap từ luồng lỗi.
    def read_stderr():
        while True:
            line = process.stderr.readline()
            if not line:
                break

            match = progress_pattern.search(line)
            if match:
                try:
                    scan_progress["percent"] = int(float(match.group(1)))
                except Exception:
                    pass

    # EN: Show a simple spinner or percent while waiting.
    # VI: Hiện vòng quay hoặc phần trăm khi chờ.
    def display_progress():
        spinner = ["|", "/", "-", "\\"]
        spinner_index = 0

        while not scan_progress["done"]:
            if scan_progress["percent"] is not None:
                sys.stdout.write(f"\rScan progressing... {scan_progress['percent']:3d}%")
            else:
                sys.stdout.write(f"\rScan progressing... {spinner[spinner_index % 4]}")
                spinner_index += 1

            sys.stdout.flush()
            time.sleep(PROGRESS_SPINNER_INTERVAL)

        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    display_thread = threading.Thread(target=display_progress, daemon=True)

    stderr_thread.start()
    display_thread.start()

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except Exception:
            process.kill()

        scan_progress["done"] = True
        stderr_thread.join()
        display_thread.join()

        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

        raise RuntimeError(f"Command timed out after {timeout} seconds")
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.wait(timeout=2)
        except Exception:
            process.kill()

        scan_progress["done"] = True
        stderr_thread.join()
        display_thread.join()

        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

        raise KeyboardInterrupt("Scan was cancelled by user.")

    state["done"] = True
    stderr_thread.join()
    display_thread.join()

    if process.returncode != 0:
        raise RuntimeError((stderr or "").strip() or "Command failed")

    return stdout

# EN: Check if Nmap is installed.
# VI: Kiểm tra máy có cài Nmap không.
def has_nmap():
    try:
        process = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        return process.returncode == 0
    except Exception:
        return False

# EN: Make sure the result folder exists.
# VI: Bảo đảm thư mục result có sẵn.
def ensure_result_dir():
    path = Path("result")
    path.mkdir(parents=True, exist_ok=True)
    return path

# EN: Make sure the data folder exists.
# VI: Bảo đảm thư mục data có sẵn.
def ensure_data_dir():
    path = Path("data")
    path.mkdir(parents=True, exist_ok=True)
    return path

# EN: Save data as pretty JSON.
# VI: Lưu dữ liệu thành JSON dễ nhìn.
def save_json(data, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

# EN: Write plain text into a file.
# VI: Ghi chữ thường vào file.
def write_txt(content, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

# EN: Turn scan records into readable text.
# VI: Đổi dữ liệu scan thành chữ dễ đọc.
def records_to_scan_text(records):
    if not records:
        return "No reachable devices with open ports found\n"

    lines = []
    for record in records:
        lines.append(f"IP: {record['ip']}")
        hostname = record.get("hostname", "")
        if hostname:
            lines.append(f"Hostname: {hostname}")
        lines.append("Open ports with successful connection:")
        for port in sorted(record["open_ports"], key=lambda x: x["port"]):
            enriched = enrich_port(port)
            service = port.get("service", "") or enriched["name"] or "unknown"
            product = port.get("product", "") or ""
            version = port.get("version", "") or ""
            text = f"{port['protocol']}/{port['port']}  {service}"
            extra = f"{product} {version}".strip()
            if extra:
                text = f"{text}  {extra}"
            lines.append(text)
            lines.append(f"  Risk: {enriched['risk_level'].upper()} | Category: {enriched['category']} | Score: {enriched['risk_score']}")
            lines.append(f"  Detail: {enriched['description']}")
            lines.append(f"  Action: {enriched['recommendation']}")
            if port.get("state_reason", ""):
                lines.append(f"  Nmap reason: {port['state_reason']}")
            if port.get("service_method", "") or port.get("service_confidence", ""):
                method = port.get("service_method", "") or "unknown"
                confidence = port.get("service_confidence", "") or "unknown"
                lines.append(f"  Detection: method={method}, confidence={confidence}")
            if port.get("extrainfo", ""):
                lines.append(f"  Extra info: {port['extrainfo']}")
            if enriched.get("script_summary", ""):
                lines.append(f"  NSE: {enriched['script_summary']}")
        lines.append("-" * 60)

    return "\n".join(lines) + "\n"

# EN: Turn port rows into the detailed text report.
# VI: Đổi dòng cổng thành báo cáo chữ chi tiết.
def records_to_port_detail_text(records):
    rows = port_detail_rows(records)

    if not rows:
        return "No detailed port data found\n"

    lines = []
    lines.append("================ DETAILED PORT REPORT ================\n\n")

    current_host = None
    for row in rows:
        host_key = (row["ip"], row["hostname"])
        if host_key != current_host:
            current_host = host_key
            hostname = f" ({row['hostname']})" if row["hostname"] else ""
            lines.append(f"Host: {row['ip']}{hostname}\n")

        lines.append(f"- {row['protocol']}/{row['port']} {row['service']}\n")
        lines.append(f"  Risk: {row['risk_level'].upper()} | Category: {row['category']} | Score: {row['risk_score']}\n")
        if row["product"] or row["version"]:
            lines.append(f"  Product: {row['product']} {row['version']}".rstrip() + "\n")
        if row["extrainfo"]:
            lines.append(f"  Extra: {row['extrainfo']}\n")
        if row["state_reason"]:
            lines.append(f"  Reason: {row['state_reason']}\n")
        if row["service_method"] or row["service_confidence"]:
            lines.append(f"  Detection: method={row['service_method'] or 'unknown'}, confidence={row['service_confidence'] or 'unknown'}\n")
        if row.get("service_source", ""):
            lines.append(f"  Service source: {row['service_source']}\n")
        if row.get("service_guess", "") or row.get("device_guess", ""):
            confidence = row.get("guess_confidence", "")
            confidence_text = f" | confidence={confidence}" if confidence != "" else ""
            lines.append(
                f"  Prediction: service={row.get('service_guess', '') or 'unknown'}; "
                f"device={row.get('device_guess', '') or 'unknown device'}{confidence_text}\n"
            )
            if row.get("guess_evidence", ""):
                lines.append(f"  Prediction evidence: {row['guess_evidence']}\n")
            lines.append("  Note: prediction fields are inferred hints, not confirmed Nmap service identification.\n")
        lines.append(f"  Detail: {row['description']}\n")
        lines.append(f"  Action: {row['recommendation']}\n")
        if row["script_summary"]:
            lines.append(f"  NSE: {row['script_summary']}\n")
        lines.append("\n")

    return "".join(lines)

# EN: Write both CSV and text port reports.
# VI: Ghi cả báo cáo cổng CSV và TXT.
def write_port_details(records, output_csv, output_txt):
    rows = port_detail_rows(records)
    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    write_txt(records_to_port_detail_text(records), output_txt)
    return df

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

# EN: Turn predictions into the final text report.
# VI: Đổi kết quả dự đoán thành báo cáo chữ cuối.
def dataframe_to_prediction_text(df):
    lines = []

    total = len(df)
    suspicious_df = df[df["prediction"] == "suspicious"]
    normal_df = df[df["prediction"] == "normal"]

    lines.append("================ NETWORK SECURITY ANALYSIS ================\n")
    lines.append(f"Total Hosts Scanned: {total}\n")
    lines.append(f"Normal Hosts: {len(normal_df)}\n")
    lines.append(f"Suspicious Hosts: {len(suspicious_df)}\n\n")

    if not suspicious_df.empty:
        top = suspicious_df.sort_values(
            "predicted_probability_suspicious",
            ascending=False
        ).head(3)

        lines.append("Top Suspicious Hosts:\n")
        for i, (_, row) in enumerate(top.iterrows(), 1):
            sev = severity_from_probability(row["predicted_probability_suspicious"])
            lines.append(f"{i}. {row['ip']} ({row['hostname']}) - {sev}\n")

    lines.append("\n==========================================================\n\n")

    lines.append("-------------------- HOST ANALYSIS ------------------------\n\n")
    lines.append(f"{'IP':<15} {'HOSTNAME':<20} {'STATUS':<12} {'PROB':<8} {'SEVERITY':<10} {'PORTS':<6} {'RISKS':<6}\n")
    lines.append("-" * 75 + "\n")

    for _, row in df.iterrows():
        sev = severity_from_probability(row["predicted_probability_suspicious"])
        lines.append(
            f"{row['ip']:<15} "
            f"{row['hostname']:<20} "
            f"{row['prediction'].upper():<12} "
            f"{row['predicted_probability_suspicious']:.2f}   "
            f"{sev:<10} "
            f"{row['open_port_count']:<6} "
            f"{row['risky_port_count']:<6}\n"
        )

    lines.append("\n")

    if not suspicious_df.empty:
        lines.append("================ SUSPICIOUS HOST DETAILS ==================\n\n")

        sorted_df = suspicious_df.sort_values(
            "predicted_probability_suspicious",
            ascending=False
        )

        for i, (_, row) in enumerate(sorted_df.iterrows(), 1):
            sev = severity_from_probability(row["predicted_probability_suspicious"])

            lines.append(f"[{i}] IP: {row['ip']}\n")
            lines.append(f"Hostname: {row['hostname']}\n")
            lines.append(f"Severity: {sev}\n")
            risk_score = row.get("risk_score", round(row["predicted_probability_suspicious"] * 100, 1))
            lines.append(f"Risk Score: {risk_score}/100\n")
            lines.append(f"Probability: {row['predicted_probability_suspicious']:.3f}\n\n")
            if "top_risk_ports" in row:
                lines.append(f"Top Risk Ports: {row['top_risk_ports']}\n\n")

            explanation_lines = generate_explanation_for_row(row)
            if explanation_lines:
                lines.append("Why flagged:\n")
                for explanation_line in explanation_lines:
                    lines.append(f"  {explanation_line}\n")
                lines.append("\n")

            host_alerts = generate_alerts_for_row(row)
            if host_alerts:
                lines.append("Security Alerts:\n")
                for alert in host_alerts:
                    lines.append(f"  [{alert['severity']}] {alert['title']}\n")
                    lines.append(f"    {alert['message']}\n")
                lines.append("\n")

            lines.append("Recommendations:\n")
            recs = row["recommendations"].split(";")
            for r in recs:
                lines.append(f"- {r.strip()}\n")

            lines.append("\n" + "-" * 55 + "\n\n")

    return "".join(lines)
