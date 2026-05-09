# EN: Save and compare host port baselines between scans.
# VI: Lưu và so sánh baseline cổng máy giữa các lần quét.

import json
from pathlib import Path


# EN: Write the current scan as the new baseline file.
# VI: Ghi lần quét hiện tại thành file baseline mới.
def save_baseline(records, baseline_path):
    profile = {}
    for record in records:
        ip = record.get("ip", "")
        if not ip:
            continue
        ports = sorted(set(p["port"] for p in record.get("open_ports", [])))
        profile[ip] = {
            "hostname": record.get("hostname", ""),
            "ports": ports,
        }
    with open(baseline_path, "w", encoding="utf-8") as baseline_file:
        json.dump(profile, baseline_file, indent=2)


# EN: Load baseline from disk; return None when file is missing.
# VI: Mở baseline từ ổ đĩa; trả None khi file không có.
def load_baseline(baseline_path):
    path = Path(baseline_path)
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as baseline_file:
        return json.load(baseline_file)


# EN: Compare current scan records to the saved baseline.
# VI: So sánh dữ liệu quét hiện tại với baseline đã lưu.
def compare_to_baseline(records, baseline_path):
    baseline = load_baseline(baseline_path)
    if baseline is None:
        return None

    current = {}
    for record in records:
        ip = record.get("ip", "")
        if not ip:
            continue
        ports = sorted(set(p["port"] for p in record.get("open_ports", [])))
        current[ip] = {
            "hostname": record.get("hostname", ""),
            "ports": ports,
        }

    new_hosts = [ip for ip in current if ip not in baseline]
    gone_hosts = [ip for ip in baseline if ip not in current]
    new_ports = {}
    closed_ports = {}
    unchanged_count = 0

    for ip, data in current.items():
        if ip not in baseline:
            continue
        base_port_set = set(baseline[ip]["ports"])
        curr_port_set = set(data["ports"])
        opened = sorted(curr_port_set - base_port_set)
        closed = sorted(base_port_set - curr_port_set)
        if opened:
            new_ports[ip] = opened
        if closed:
            closed_ports[ip] = closed
        if not opened and not closed:
            unchanged_count += 1

    return {
        "new_hosts": new_hosts,
        "gone_hosts": gone_hosts,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "unchanged_count": unchanged_count,
    }
