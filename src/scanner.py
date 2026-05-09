# EN: Build and run Nmap commands for different scan steps.
# VI: Tạo và chạy lệnh Nmap cho từng bước quét.

import xml.etree.ElementTree as ET
from pathlib import Path

from constants import (
    NMAP_FAST_MAX_RETRIES,
    NMAP_FAST_MIN_RATE,
    NMAP_SERVICE_MAX_RETRIES,
    NMAP_SERVICE_VERSION_INTENSITY,
)
from utils import run_command

# EN: Run Nmap to see if the target is alive.
# VI: Chạy Nmap để xem mục tiêu có bật không.
def run_discovery_scan(target_ip, output_xml):
    return run_command(
        ["nmap", "-sn", "--stats-every", "1s", "-oX", output_xml, target_ip],
        show_progress=True
    )

# EN: Phase 1 — fast TCP scan to find open ports only, no service detection.
# VI: Giai đoạn 1 — quét TCP nhanh chỉ để tìm cổng mở, không dò dịch vụ.
def run_fast_port_scan(target_ip, output_xml):
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-T4",
        "--min-rate", str(NMAP_FAST_MIN_RATE),
        "--max-retries", str(NMAP_FAST_MAX_RETRIES),
        "--open",
        "-p-",
        "--stats-every", "1s",
        "-oX", output_xml,
        target_ip,
    ]
    return run_command(cmd, show_progress=True)

# EN: Extract open port numbers from an Nmap XML file.
# VI: Lấy danh sách số cổng mở từ file XML của Nmap.
def extract_open_ports_from_xml(xml_path):
    if not Path(xml_path).exists():
        return []
    try:
        root = ET.parse(xml_path).getroot()
        open_port_numbers = set()
        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    open_port_numbers.add(int(port_el.get("portid", 0)))
        return sorted(open_port_numbers)
    except Exception:
        return []

# EN: Phase 2 — deep service detection on a specific port list (or all ports as fallback).
# VI: Giai đoạn 2 — dò sâu dịch vụ chỉ trên cổng đã biết mở (hoặc toàn bộ nếu không có danh sách).
def run_service_scan(target_ip, output_xml, port_list=None):
    deep_scripts = ",".join([
        "default",
        "safe",
        "banner",
        "http-title",
        "http-server-header",
        "ssl-cert",
        "smb-os-discovery",
    ])
    port_arg = ",".join(str(p) for p in port_list) if port_list else "-"
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "--version-intensity", str(NMAP_SERVICE_VERSION_INTENSITY),
        "--reason",
        "--script", deep_scripts,
        "--script-timeout", "15s",
        "--stats-every", "1s",
        "--open",
        "-T4",
        "--max-retries", str(NMAP_SERVICE_MAX_RETRIES),
        "-p", port_arg,
        "-oX", output_xml,
        target_ip,
    ]
    return run_command(cmd, show_progress=True)

# EN: Run Nmap again only on unnamed ports.
# VI: Chạy Nmap lại chỉ trên cổng chưa có tên.
def run_unknown_port_scan(target_ip, ports, output_xml):
    unknown_scripts = ",".join([
        "banner",
        "http-title",
        "http-server-header",
        "ssl-cert",
        "rtsp-methods",
        "eppc-enum-processes",
        "upnp-info",
    ])
    port_list_str = ",".join(str(p) for p in sorted(set(int(p) for p in ports)))
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "--version-intensity", str(NMAP_SERVICE_VERSION_INTENSITY),
        "--reason",
        "--script", unknown_scripts,
        "--script-timeout", "20s",
        "--host-timeout", "90s",
        "--stats-every", "1s",
        "--open",
        "-T4",
        "--max-retries", str(NMAP_SERVICE_MAX_RETRIES),
        "-p", port_list_str,
        "-oX", output_xml,
        target_ip,
    ]
    return run_command(cmd, show_progress=True, timeout=95)

# EN: Run discovery then two-phase service scan (fast port find → targeted service detect).
# VI: Chạy tìm máy rồi quét hai giai đoạn (tìm cổng nhanh → dò dịch vụ đúng cổng).
def run_full_scan(target_ip, discovery_xml, service_xml):
    run_discovery_scan(target_ip, discovery_xml)

    fast_ports_xml = service_xml.replace(".xml", "_fast_ports.xml")
    run_fast_port_scan(target_ip, fast_ports_xml)
    open_port_numbers = extract_open_ports_from_xml(fast_ports_xml)

    if open_port_numbers:
        run_service_scan(target_ip, service_xml, port_list=open_port_numbers)
    else:
        run_service_scan(target_ip, service_xml, port_list=None)
