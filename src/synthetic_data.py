# EN: Build safe fake scan records for machine learning practice.
# VI: Tạo dữ liệu scan giả an toàn để tập cho máy học.

# EN: Turn one port number and service name into a normal port record.
# VI: Đổi một số cổng và tên dịch vụ thành dữ liệu cổng bình thường.
def make_port(port, service, product="", version="", tunnel=""):
    return {
        "protocol": "tcp",
        "port": port,
        "service": service,
        "product": product,
        "version": version,
        "tunnel": tunnel,
        "state_reason": "synthetic",
        "service_method": "synthetic",
        "service_confidence": "10",
        "service_source": "synthetic",
        "scripts": []
    }


# EN: Turn one host story into the same shape as an Nmap parsed record.
# VI: Đổi một câu chuyện máy thành dạng giống dữ liệu Nmap đã đọc.
def make_host(ip, hostname, ports):
    return {
        "ip": ip,
        "hostname": hostname,
        "open_ports": ports
    }


# EN: Return many normal and risky fake hosts without scanning any network.
# VI: Trả về nhiều máy giả bình thường và nguy hiểm mà không quét mạng.
def get_synthetic_records():
    records = [
        make_host(
            "10.10.10.10",
            "home-laptop-safe",
            [
                make_port(22, "ssh", "OpenSSH", "9.x"),
                make_port(443, "https", "nginx", "stable", "ssl")
            ]
        ),
        make_host(
            "10.10.10.11",
            "home-phone-safe",
            [
                make_port(62078, "iphone-sync"),
                make_port(49152, "unknown")
            ]
        ),
        make_host(
            "10.10.10.12",
            "printer-normal",
            [
                make_port(631, "ipp", "CUPS", ""),
                make_port(9100, "jetdirect")
            ]
        ),
        make_host(
            "10.10.10.13",
            "web-server-normal",
            [
                make_port(80, "http", "nginx", ""),
                make_port(443, "https", "nginx", "", "ssl")
            ]
        ),
        make_host(
            "10.10.10.14",
            "mail-server-normal",
            [
                make_port(25, "smtp", "Postfix", ""),
                make_port(587, "submission", "Postfix", "", "ssl"),
                make_port(993, "imaps", "Dovecot", "", "ssl")
            ]
        ),
        make_host(
            "10.10.10.15",
            "dev-api-normal",
            [
                make_port(22, "ssh", "OpenSSH", ""),
                make_port(8080, "http-alt", "Gunicorn", "")
            ]
        ),
        make_host(
            "10.10.10.16",
            "camera-iot-watch",
            [
                make_port(554, "rtsp", "IP Camera", ""),
                make_port(80, "http", "camera-web", "")
            ]
        ),
        make_host(
            "10.10.10.17",
            "macbook-normal",
            [
                make_port(22, "ssh", "OpenSSH", ""),
                make_port(5000, "airplay"),
                make_port(7000, "airplay")
            ]
        ),
        make_host(
            "10.10.10.18",
            "dns-normal",
            [
                make_port(53, "domain", "dnsmasq", ""),
                make_port(443, "https", "admin-ui", "", "ssl")
            ]
        ),
        make_host(
            "10.10.10.19",
            "nas-careful",
            [
                make_port(22, "ssh", "OpenSSH", ""),
                make_port(443, "https", "nas-ui", "", "ssl"),
                make_port(2049, "nfs", "nfsd", "")
            ]
        ),
        make_host(
            "10.10.20.20",
            "old-router-risky",
            [
                make_port(23, "telnet", "BusyBox", ""),
                make_port(80, "http", "router-web", ""),
                make_port(161, "snmp", "SNMP", "v2c")
            ]
        ),
        make_host(
            "10.10.20.21",
            "file-server-risky",
            [
                make_port(21, "ftp", "vsftpd", ""),
                make_port(445, "microsoft-ds", "Samba", ""),
                make_port(139, "netbios-ssn", "Samba", "")
            ]
        ),
        make_host(
            "10.10.20.22",
            "windows-admin-risky",
            [
                make_port(3389, "ms-wbt-server", "RDP", ""),
                make_port(5985, "winrm", "Microsoft HTTPAPI", ""),
                make_port(445, "microsoft-ds", "Windows SMB", "")
            ]
        ),
        make_host(
            "10.10.20.23",
            "database-risky",
            [
                make_port(3306, "mysql", "MySQL", "8"),
                make_port(5432, "postgresql", "PostgreSQL", "15"),
                make_port(6379, "redis", "Redis", "")
            ]
        ),
        make_host(
            "10.10.20.24",
            "container-risky",
            [
                make_port(2375, "docker", "Docker API", ""),
                make_port(6443, "kubernetes-api", "Kubernetes", ""),
                make_port(10250, "kubelet")
            ]
        ),
        make_host(
            "10.10.20.25",
            "search-risky",
            [
                make_port(9200, "elasticsearch", "Elasticsearch", ""),
                make_port(5601, "kibana", "Kibana", ""),
                make_port(9300, "elasticsearch-node")
            ]
        ),
        make_host(
            "10.10.20.26",
            "iot-risky",
            [
                make_port(1883, "mqtt", "Mosquitto", ""),
                make_port(554, "rtsp", "Camera", ""),
                make_port(23, "telnet", "BusyBox", "")
            ]
        ),
        make_host(
            "10.10.20.27",
            "legacy-risky",
            [
                make_port(69, "tftp", "tftpd", ""),
                make_port(111, "rpcbind", "rpcbind", ""),
                make_port(2049, "nfs", "nfsd", "")
            ]
        ),
        make_host(
            "10.10.20.28",
            "desktop-risky",
            [
                make_port(5900, "vnc", "VNC", ""),
                make_port(22, "ssh", "OpenSSH", ""),
                make_port(8080, "http-alt", "admin-panel", "")
            ]
        ),
        make_host(
            "10.10.20.29",
            "cache-risky",
            [
                make_port(11211, "memcached", "Memcached", ""),
                make_port(6379, "redis", "Redis", ""),
                make_port(80, "http", "status-page", "")
            ]
        )
    ]

    return records
