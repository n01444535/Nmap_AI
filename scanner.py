# EN: Build and run Nmap commands for different scan steps.
# VI: Tạo và chạy lệnh Nmap cho từng bước quét.

from utils import run_command

# EN: Run Nmap to see if the target is alive.
# VI: Chạy Nmap để xem mục tiêu có bật không.
def run_discovery_scan(target_ip, output_xml):
    return run_command(
        ["nmap", "-sn", "--stats-every", "1s", "-oX", output_xml, target_ip],
        show_progress=True
    )

# EN: Run the deep Nmap service scan.
# VI: Chạy Nmap quét sâu dịch vụ.
def run_service_scan(target_ip, output_xml):
    deep_scripts = ",".join(
        [
            "default",
            "safe",
            "banner",
            "http-title",
            "http-server-header",
            "ssl-cert",
            "ssl-enum-ciphers",
            "smb-os-discovery"
        ]
    )
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "--version-all",
        "--reason",
        "--script", deep_scripts,
        "--script-timeout", "20s",
        "--stats-every", "1s",
        "--open",
        "-T3",
        "--max-retries", "3",
        "-p-",
        "-oX",
        output_xml,
        target_ip
    ]
    return run_command(cmd, show_progress=True)

# EN: Run Nmap again only on unnamed ports.
# VI: Chạy Nmap lại chỉ trên cổng chưa có tên.
def run_unknown_port_scan(target_ip, ports, output_xml):
    unknown_scripts = ",".join(
        [
            "banner",
            "http-title",
            "http-server-header",
            "ssl-cert",
            "ssl-enum-ciphers",
            "rtsp-methods",
            "eppc-enum-processes",
            "upnp-info"
        ]
    )
    port_list = ",".join(str(p) for p in sorted(set(int(p) for p in ports)))
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "--version-all",
        "--reason",
        "--script", unknown_scripts,
        "--script-timeout", "20s",
        "--host-timeout", "90s",
        "--stats-every", "1s",
        "--open",
        "-T3",
        "--max-retries", "3",
        "-p", port_list,
        "-oX",
        output_xml,
        target_ip
    ]
    return run_command(cmd, show_progress=True, timeout=95)

# EN: Run discovery and service scan together.
# VI: Chạy quét tìm máy và quét dịch vụ cùng nhau.
def run_full_scan(target_ip, discovery_xml, service_xml):
    run_discovery_scan(target_ip, discovery_xml)
    run_service_scan(target_ip, service_xml)
