# EN: Save and compare host port baselines between scans.
# VI: Lưu và so sánh baseline cổng máy giữa các lần quét.

import json
from pathlib import Path


# EN: Write the current scan as the new baseline file, including service version info.
# VI: Ghi lần quét hiện tại thành file baseline mới, kèm thông tin phiên bản dịch vụ.
def save_baseline(records, baseline_path):
    profile = {}
    for record in records:
        ip = record.get("ip", "")
        if not ip:
            continue
        ports = sorted(set(p["port"] for p in record.get("open_ports", [])))
        services = {}
        for port_entry in record.get("open_ports", []):
            port_str = str(port_entry["port"])
            services[port_str] = {
                "service": port_entry.get("service", ""),
                "product": port_entry.get("product", ""),
                "version": port_entry.get("version", ""),
            }
        profile[ip] = {
            "hostname": record.get("hostname", ""),
            "ports": ports,
            "services": services,
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
        services = {}
        for port_entry in record.get("open_ports", []):
            port_str = str(port_entry["port"])
            services[port_str] = {
                "service": port_entry.get("service", ""),
                "product": port_entry.get("product", ""),
                "version": port_entry.get("version", ""),
            }
        current[ip] = {
            "hostname": record.get("hostname", ""),
            "ports": ports,
            "services": services,
        }

    new_hosts = [ip for ip in current if ip not in baseline]
    gone_hosts = [ip for ip in baseline if ip not in current]
    new_ports = {}
    closed_ports = {}
    version_changes = {}
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

        # Detect service version changes on ports that were already open
        base_services = baseline[ip].get("services", {})
        curr_services = data.get("services", {})
        port_version_changes = []
        for port_str, curr_svc in curr_services.items():
            if port_str not in base_services:
                continue
            base_svc = base_services[port_str]
            base_ver = f"{base_svc.get('product', '')} {base_svc.get('version', '')}".strip()
            curr_ver = f"{curr_svc.get('product', '')} {curr_svc.get('version', '')}".strip()
            if base_ver and curr_ver and base_ver != curr_ver:
                port_version_changes.append({
                    "port": int(port_str),
                    "service": curr_svc.get("service", ""),
                    "from_version": base_ver,
                    "to_version": curr_ver,
                })
        if port_version_changes:
            version_changes[ip] = port_version_changes

    return {
        "new_hosts": new_hosts,
        "gone_hosts": gone_hosts,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "version_changes": version_changes,
        "unchanged_count": unchanged_count,
    }
