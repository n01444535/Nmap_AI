# EN: Read Nmap XML files and turn them into Python records.
# VI: Đọc file XML của Nmap rồi đổi thành dữ liệu Python.

import xml.etree.ElementTree as ET


# EN: Read extra host information from Nmap XML.
# VI: Đọc thông tin thêm của máy từ XML Nmap.
def get_host_metadata(host):
    metadata = {
        "mac": "",
        "vendor": "",
        "os_matches": []
    }

    for address in host.findall("address"):
        if address.get("addrtype") == "mac":
            metadata["mac"] = address.get("addr", "")
            metadata["vendor"] = address.get("vendor", "")
            break

    os_el = host.find("os")
    if os_el is not None:
        for osmatch in os_el.findall("osmatch"):
            metadata["os_matches"].append(
                {
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", "")
                }
            )

    return metadata


# EN: Read script results for one port.
# VI: Đọc kết quả script của một cổng.
def parse_port_scripts(port_el):
    scripts = []
    for script_el in port_el.findall("script"):
        scripts.append(
            {
                "id": script_el.get("id", ""),
                "output": script_el.get("output", "")
            }
        )
    return scripts

# EN: Find hosts that Nmap says are online.
# VI: Tìm máy mà Nmap nói đang bật.
def extract_live_hosts_from_discovery(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = None
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                addr = address.get("addr")
                break
        if addr:
            hosts.append(addr)
    return hosts

# EN: Read open ports and services from Nmap XML.
# VI: Đọc cổng mở và dịch vụ từ XML Nmap.
def parse_nmap_service_scan(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    host_records = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = None
        hostname = ""
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr")
                break
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname_el = hostnames.find("hostname")
            if hostname_el is not None:
                hostname = hostname_el.get("name", "")
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        open_ports = []
        for port_el in ports_el.findall("port"):
            protocol = port_el.get("protocol", "")
            portid = int(port_el.get("portid", "0"))
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            state_reason = state_el.get("reason", "")
            service_el = port_el.find("service")
            service_name = ""
            service_product = ""
            service_version = ""
            service_extrainfo = ""
            service_method = ""
            service_confidence = ""
            service_ostype = ""
            service_tunnel = ""
            if service_el is not None:
                service_name = service_el.get("name", "")
                service_product = service_el.get("product", "")
                service_version = service_el.get("version", "")
                service_extrainfo = service_el.get("extrainfo", "")
                service_method = service_el.get("method", "")
                service_confidence = service_el.get("conf", "")
                service_ostype = service_el.get("ostype", "")
                service_tunnel = service_el.get("tunnel", "")
            open_ports.append(
                {
                    "protocol": protocol,
                    "port": portid,
                    "service": service_name,
                    "service_source": "nmap",
                    "product": service_product,
                    "version": service_version,
                    "extrainfo": service_extrainfo,
                    "service_method": service_method,
                    "service_confidence": service_confidence,
                    "service_ostype": service_ostype,
                    "tunnel": service_tunnel,
                    "state_reason": state_reason,
                    "scripts": parse_port_scripts(port_el)
                }
            )
        if ip and open_ports:
            metadata = get_host_metadata(host)
            host_records.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": metadata["mac"],
                    "vendor": metadata["vendor"],
                    "os_matches": metadata["os_matches"],
                    "open_ports": open_ports
                }
            )
    return host_records
