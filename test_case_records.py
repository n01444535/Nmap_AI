# EN: Build a fake internet cafe network for testing.
# VI: Tạo mạng quán net giả để kiểm thử.

from pathlib import Path
import xml.etree.ElementTree as ET

# EN: Build one fake host for the testcase XML.
# VI: Tạo một máy giả cho file XML kiểm thử.
def build_host(ip, hostname, ports):
    host = ET.Element("host")

    status = ET.SubElement(host, "status")
    status.set("state", "up")

    address = ET.SubElement(host, "address")
    address.set("addr", ip)
    address.set("addrtype", "ipv4")

    hostnames = ET.SubElement(host, "hostnames")
    hostname_el = ET.SubElement(hostnames, "hostname")
    hostname_el.set("name", hostname)
    hostname_el.set("type", "PTR")

    ports_el = ET.SubElement(host, "ports")

    for port_info in ports:
        port_el = ET.SubElement(ports_el, "port")
        port_el.set("protocol", port_info["protocol"])
        port_el.set("portid", str(port_info["port"]))

        state_el = ET.SubElement(port_el, "state")
        state_el.set("state", "open")

        service_el = ET.SubElement(port_el, "service")
        service_el.set("name", port_info["service"])

        if port_info.get("product", ""):
            service_el.set("product", port_info["product"])

        if port_info.get("version", ""):
            service_el.set("version", port_info["version"])

    return host

# EN: Return normal web ports.
# VI: Trả về các cổng web bình thường.
def web_pair():
    return [
        {"protocol": "tcp", "port": 80, "service": "http", "product": "Apache", "version": "2.4"},
        {"protocol": "tcp", "port": 443, "service": "https", "product": "Apache", "version": "2.4"}
    ]

# EN: Return SSH and HTTPS ports.
# VI: Trả về cổng SSH và HTTPS.
def ssh_https():
    return [
        {"protocol": "tcp", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.0"},
        {"protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.24"}
    ]

# EN: Return only an SSH port.
# VI: Trả về chỉ một cổng SSH.
def ssh_only():
    return [
        {"protocol": "tcp", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9"}
    ]

# EN: Return ports for a gaming-like client.
# VI: Trả về cổng giống máy chơi game.
def gaming_client():
    return [
        {"protocol": "tcp", "port": 27015, "service": "unknown", "product": "", "version": ""},
        {"protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.24"}
    ]

# EN: Return ports for a printer.
# VI: Trả về cổng cho máy in.
def printer_ports():
    return [
        {"protocol": "tcp", "port": 80, "service": "http", "product": "Printer-Web", "version": "3.2"},
        {"protocol": "tcp", "port": 631, "service": "ipp", "product": "CUPS", "version": "2.4"}
    ]

# EN: Return ports for a camera.
# VI: Trả về cổng cho camera.
def camera_ports():
    return [
        {"protocol": "tcp", "port": 80, "service": "http", "product": "Cam-Web", "version": "1.8"},
        {"protocol": "tcp", "port": 554, "service": "rtsp", "product": "CamStream", "version": "2.0"}
    ]

# EN: Return ports for a payment terminal.
# VI: Trả về cổng cho máy bán hàng.
def pos_ports():
    return [
        {"protocol": "tcp", "port": 443, "service": "https", "product": "POS-Web", "version": "5.1"},
        {"protocol": "tcp", "port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0"}
    ]

# EN: Return ports for a storage box.
# VI: Trả về cổng cho hộp lưu trữ.
def nas_ports():
    return [
        {"protocol": "tcp", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.0"},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 2049, "service": "nfs", "product": "", "version": ""}
    ]

# EN: Return ports for a Wi-Fi controller.
# VI: Trả về cổng cho bộ điều khiển Wi-Fi.
def wifi_controller_ports():
    return [
        {"protocol": "tcp", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.1"},
        {"protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.24"},
        {"protocol": "tcp", "port": 8080, "service": "http-proxy", "product": "", "version": ""}
    ]

# EN: Return a small risky malware pattern.
# VI: Trả về mẫu máy nhiễm nhẹ.
def infected_low():
    return [
        {"protocol": "tcp", "port": 21, "service": "ftp", "product": "vsftpd", "version": "3.0"},
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 3000, "service": "unknown", "product": "", "version": ""},
        {"protocol": "tcp", "port": 5000, "service": "rtsp", "product": "", "version": ""}
    ]

# EN: Return a medium risky malware pattern.
# VI: Trả về mẫu máy nhiễm vừa.
def infected_mid():
    return [
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 111, "service": "rpcbind", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 7000, "service": "unknown", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot A.
def pivot_a():
    return [
        {"protocol": "tcp", "port": 21, "service": "ftp", "product": "", "version": ""},
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 8081, "service": "unknown", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot B.
def pivot_b():
    return [
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 5900, "service": "vnc", "product": "", "version": ""},
        {"protocol": "tcp", "port": 7001, "service": "unknown", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot C.
def pivot_c():
    return [
        {"protocol": "tcp", "port": 21, "service": "ftp", "product": "", "version": ""},
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 111, "service": "rpcbind", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot D.
def pivot_d():
    return [
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 5000, "service": "rtsp", "product": "", "version": ""},
        {"protocol": "tcp", "port": 5001, "service": "unknown", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot E.
def pivot_e():
    return [
        {"protocol": "tcp", "port": 21, "service": "ftp", "product": "", "version": ""},
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 6379, "service": "redis", "product": "Redis", "version": "7.0"}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot F.
def pivot_f():
    return [
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 111, "service": "rpcbind", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 5900, "service": "vnc", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot G.
def pivot_g():
    return [
        {"protocol": "tcp", "port": 21, "service": "ftp", "product": "", "version": ""},
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 8080, "service": "http-proxy", "product": "", "version": ""}
    ]

# EN: Return one pivot attack port pattern.
# VI: Trả về mẫu cổng tấn công pivot H.
def pivot_h():
    return [
        {"protocol": "tcp", "port": 23, "service": "telnet", "product": "", "version": ""},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""},
        {"protocol": "tcp", "port": 7000, "service": "unknown", "product": "", "version": ""}
    ]

# EN: Return ports for a data relay host.
# VI: Trả về cổng cho máy chuyển dữ liệu ra ngoài.
def exfiltration_relay():
    return [
        {"protocol": "tcp", "port": 21, "service": "ftp", "product": "", "version": ""},
        {"protocol": "tcp", "port": 53, "service": "domain", "product": "", "version": ""},
        {"protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.24"},
        {"protocol": "tcp", "port": 8088, "service": "unknown", "product": "", "version": ""},
        {"protocol": "tcp", "port": 9001, "service": "unknown", "product": "", "version": ""}
    ]

# EN: Return ports for an admin server.
# VI: Trả về cổng cho máy quản trị.
def admin_server():
    return [
        {"protocol": "tcp", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.0"},
        {"protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.24"},
        {"protocol": "tcp", "port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.15"},
        {"protocol": "tcp", "port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0"},
        {"protocol": "tcp", "port": 3389, "service": "ms-wbt-server", "product": "", "version": ""}
    ]

# EN: Write fake Nmap XML testcase files.
# VI: Ghi file XML Nmap giả để kiểm thử.
def build_testcase_files():
    base_dir = Path("data/testcase")
    base_dir.mkdir(parents=True, exist_ok=True)

    discovery_root = ET.Element("nmaprun")
    service_root = ET.Element("nmaprun")

    for i in range(1, 31):
        if i % 4 == 1:
            ports = web_pair()
        elif i % 4 == 2:
            ports = ssh_https()
        elif i % 4 == 3:
            ports = ssh_only()
        else:
            ports = gaming_client()

        ip = f"10.10.0.{i}"
        hostname = f"client-pc-{i:02d}"

        discovery_root.append(build_host(ip, hostname, []))
        service_root.append(build_host(ip, hostname, ports))

    for i in range(31, 41):
        if i % 3 == 1:
            ports = web_pair()
        elif i % 3 == 2:
            ports = printer_ports()
        else:
            ports = camera_ports()

        ip = f"10.10.0.{i}"
        hostname = f"client-pc-{i:02d}"

        discovery_root.append(build_host(ip, hostname, []))
        service_root.append(build_host(ip, hostname, ports))

    infra_hosts = [
        ("10.10.0.101", "printer-01", printer_ports()),
        ("10.10.0.102", "printer-02", printer_ports()),
        ("10.10.0.110", "camera-01", camera_ports()),
        ("10.10.0.111", "camera-02", camera_ports()),
        ("10.10.0.120", "pos-terminal-01", pos_ports()),
        ("10.10.0.121", "pos-terminal-02", pos_ports()),
        ("10.10.0.130", "nas-storage-01", nas_ports()),
        ("10.10.0.140", "wifi-controller", wifi_controller_ports())
    ]

    for ip, hostname, ports in infra_hosts:
        discovery_root.append(build_host(ip, hostname, []))
        service_root.append(build_host(ip, hostname, ports))

    suspicious_hosts = [
        ("10.10.0.201", "client-pc-41-malware", infected_low()),
        ("10.10.0.202", "client-pc-42-malware", infected_mid()),
        ("10.10.0.203", "client-pc-43-pivot", pivot_a()),
        ("10.10.0.204", "client-pc-44-pivot", pivot_b()),
        ("10.10.0.205", "client-pc-45-pivot", pivot_c()),
        ("10.10.0.206", "client-pc-46-pivot", pivot_d()),
        ("10.10.0.207", "client-pc-47-pivot", pivot_e()),
        ("10.10.0.208", "client-pc-48-pivot", pivot_f()),
        ("10.10.0.209", "client-pc-49-pivot", pivot_g()),
        ("10.10.0.210", "client-pc-50-pivot", pivot_h()),
        ("10.10.0.220", "relay-exfiltration-node", exfiltration_relay())
    ]

    for ip, hostname, ports in suspicious_hosts:
        discovery_root.append(build_host(ip, hostname, []))
        service_root.append(build_host(ip, hostname, ports))

    discovery_root.append(build_host("10.10.0.250", "admin-server", []))
    service_root.append(build_host("10.10.0.250", "admin-server", admin_server()))

    discovery_tree = ET.ElementTree(discovery_root)
    service_tree = ET.ElementTree(service_root)

    discovery_path = base_dir / "internet_cafe_discovery.xml"
    service_path = base_dir / "internet_cafe_service_scan.xml"

    discovery_tree.write(discovery_path, encoding="utf-8", xml_declaration=True)
    service_tree.write(service_path, encoding="utf-8", xml_declaration=True)

    print(f"Created: {discovery_path}")
    print(f"Created: {service_path}")

if __name__ == "__main__":
    build_testcase_files()
