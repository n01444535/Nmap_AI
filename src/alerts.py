# EN: Generate structured security alerts from host feature rows.
# VI: Tạo cảnh báo bảo mật có cấu trúc từ các dòng đặc điểm máy.

from constants import (
    MIN_CLEARTEXT_COUNT_THRESHOLD,
    MIN_ADMIN_PORT_COUNT_THRESHOLD,
    MIN_OPEN_PORT_COUNT_THRESHOLD,
    MIN_UNCOMMON_PORT_COUNT_THRESHOLD,
    MIN_FILESHARE_COUNT_THRESHOLD,
    MIN_REMOTE_ACCESS_COUNT_THRESHOLD,
)

ALERT_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _make_alert(code, severity, title, message, ports=None):
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "message": message,
        "ports": ports or [],
    }


# EN: Produce all triggered alerts for one host row.
# VI: Tạo tất cả cảnh báo kích hoạt cho một dòng máy.
def generate_alerts_for_row(row):
    alerts = []

    if row.get("has_telnet", 0) == 1:
        alerts.append(_make_alert(
            "CLEARTEXT_REMOTE_ACCESS",
            "CRITICAL",
            "Cleartext Remote Access Detected",
            "Telnet (port 23) is open — login credentials are transmitted in plaintext",
            [23],
        ))

    if row.get("has_smb", 0) == 1:
        alerts.append(_make_alert(
            "HIGH_RISK_PORT_DETECTED",
            "CRITICAL",
            "High Risk Port Detected: SMB",
            "SMB (port 445) is exposed — primary vector for ransomware and lateral movement",
            [445],
        ))

    if row.get("has_rdp", 0) == 1:
        alerts.append(_make_alert(
            "HIGH_RISK_PORT_DETECTED",
            "CRITICAL",
            "High Risk Port Detected: RDP",
            "RDP (port 3389) is exposed — common brute-force and ransomware entry point",
            [3389],
        ))

    if row.get("has_vnc", 0) == 1:
        alerts.append(_make_alert(
            "HIGH_RISK_PORT_DETECTED",
            "CRITICAL",
            "High Risk Port Detected: VNC",
            "VNC (port 5900) is exposed — remote desktop access with often-weak authentication",
            [5900],
        ))

    if row.get("has_docker", 0) == 1:
        alerts.append(_make_alert(
            "CONTAINER_ADMIN_EXPOSED",
            "CRITICAL",
            "Container Admin API Exposed: Docker",
            "Docker API (port 2375/2376) is reachable — unauthenticated access can lead to full host takeover",
            [2375, 2376],
        ))

    if row.get("has_kubernetes_api", 0) == 1:
        alerts.append(_make_alert(
            "CONTAINER_ADMIN_EXPOSED",
            "CRITICAL",
            "Container Orchestration Exposed: Kubernetes",
            "Kubernetes API (port 6443) is reachable — cluster-wide compromise is possible",
            [6443],
        ))

    if row.get("has_redis", 0) == 1:
        alerts.append(_make_alert(
            "UNAUTHENTICATED_SERVICE_EXPOSED",
            "CRITICAL",
            "Unauthenticated Service Exposed: Redis",
            "Redis (port 6379) is accessible — often unauthenticated by default, enabling data theft or remote command execution",
            [6379],
        ))

    if row.get("has_elasticsearch", 0) == 1:
        alerts.append(_make_alert(
            "UNAUTHENTICATED_SERVICE_EXPOSED",
            "CRITICAL",
            "Unauthenticated Service Exposed: Elasticsearch",
            "Elasticsearch (port 9200) is exposed — indexed data and cluster metadata may be freely readable",
            [9200],
        ))

    db_ports = []
    for port_number, flag_name in [
        (1433, "has_mssql"),
        (1521, "has_oracle"),
        (27017, "has_mongodb"),
        (3306, "has_mysql"),
        (5432, "has_postgresql"),
    ]:
        if row.get(flag_name, 0) == 1:
            db_ports.append(port_number)
    if db_ports:
        db_port_list = ", ".join(str(p) for p in db_ports)
        alerts.append(_make_alert(
            "DATABASE_PORT_EXPOSED",
            "CRITICAL",
            "Database Port Exposed",
            f"Database service(s) on port(s) {db_port_list} are directly reachable — unauthorized data access risk",
            db_ports,
        ))

    if row.get("has_ftp", 0) == 1:
        alerts.append(_make_alert(
            "CLEARTEXT_PROTOCOL_IN_USE",
            "HIGH",
            "Cleartext Protocol in Use: FTP",
            "FTP (port 21) is open — file contents and credentials transmitted without encryption",
            [21],
        ))

    if row.get("has_tftp", 0) == 1:
        alerts.append(_make_alert(
            "HIGH_RISK_PORT_DETECTED",
            "HIGH",
            "High Risk Port Detected: TFTP",
            "TFTP (port 69) is open — no authentication; device configurations can be extracted",
            [69],
        ))

    if row.get("has_rpcbind", 0) == 1:
        alerts.append(_make_alert(
            "HIGH_RISK_PORT_DETECTED",
            "HIGH",
            "High Risk Port Detected: RPC Bind",
            "RPC bind (port 111) is open — exposes service mapping and supports lateral movement",
            [111],
        ))

    if row.get("has_snmp", 0) == 1:
        alerts.append(_make_alert(
            "MANAGEMENT_PROTOCOL_EXPOSED",
            "HIGH",
            "Management Protocol Exposed: SNMP",
            "SNMP (port 161) is open — device inventory and configuration metadata may be accessible with weak community strings",
            [161],
        ))

    if row.get("has_winrm", 0) == 1:
        alerts.append(_make_alert(
            "REMOTE_ADMIN_EXPOSED",
            "HIGH",
            "Remote Administration Exposed: WinRM",
            "WinRM (port 5985/5986) is open — Windows remote management is accessible",
            [5985, 5986],
        ))

    if row.get("has_memcached", 0) == 1:
        alerts.append(_make_alert(
            "UNAUTHENTICATED_SERVICE_EXPOSED",
            "HIGH",
            "Unauthenticated Cache Exposed: Memcached",
            "Memcached (port 11211) is accessible — cached data exposed and may support amplification attacks",
            [11211],
        ))

    if row.get("has_mqtt", 0) == 1:
        alerts.append(_make_alert(
            "IOT_CONTROL_CHANNEL_EXPOSED",
            "HIGH",
            "IoT Control Channel Exposed: MQTT",
            "MQTT (port 1883) is open — IoT device control may be accessible without authentication",
            [1883],
        ))

    if row.get("fileshare_count", 0) >= MIN_FILESHARE_COUNT_THRESHOLD and row.get("has_smb", 0) != 1:
        fileshare_ports = []
        if row.get("has_netbios", 0) == 1:
            fileshare_ports.extend([137, 138, 139])
        if row.get("has_nfs", 0) == 1:
            fileshare_ports.append(2049)
        alerts.append(_make_alert(
            "FILE_SHARE_CLUSTER_DETECTED",
            "HIGH",
            "File Share Cluster Detected",
            f"{row.get('fileshare_count', 0)} file-sharing services exposed — review export scope and restrict access",
            fileshare_ports,
        ))

    if row.get("cleartext_count", 0) >= MIN_CLEARTEXT_COUNT_THRESHOLD:
        alerts.append(_make_alert(
            "MULTIPLE_CLEARTEXT_SERVICES",
            "HIGH",
            "Multiple Cleartext Services Detected",
            f"{row.get('cleartext_count', 0)} unencrypted services found — credentials and session data exposed in transit",
            [],
        ))

    if row.get("admin_port_count", 0) >= MIN_ADMIN_PORT_COUNT_THRESHOLD:
        alerts.append(_make_alert(
            "ADMIN_SERVICE_CONCENTRATION",
            "HIGH",
            "Administrative Service Concentration",
            f"{row.get('admin_port_count', 0)} administrative ports open simultaneously — oversized management attack surface",
            [],
        ))

    if row.get("remote_access_count", 0) >= MIN_REMOTE_ACCESS_COUNT_THRESHOLD:
        alerts.append(_make_alert(
            "MULTIPLE_REMOTE_ACCESS_VECTORS",
            "HIGH",
            "Multiple Remote Access Vectors Exposed",
            f"{row.get('remote_access_count', 0)} remote access services open — compounded lateral movement risk",
            [],
        ))

    if row.get("open_port_count", 0) >= MIN_OPEN_PORT_COUNT_THRESHOLD:
        alerts.append(_make_alert(
            "EXCESSIVE_OPEN_PORTS",
            "MEDIUM",
            "Excessive Open Ports Detected",
            f"{row.get('open_port_count', 0)} ports are open — attack surface is unusually broad",
            [],
        ))

    if row.get("uncommon_open_count", 0) >= MIN_UNCOMMON_PORT_COUNT_THRESHOLD:
        alerts.append(_make_alert(
            "UNCOMMON_PORT_CLUSTER",
            "MEDIUM",
            "Uncommon Port Cluster Detected",
            f"{row.get('uncommon_open_count', 0)} non-standard ports are open — verify owning processes for possible backdoors",
            [],
        ))

    if row.get("has_ssh", 0) == 1:
        alerts.append(_make_alert(
            "REMOTE_SHELL_EXPOSED",
            "LOW",
            "Remote Shell Exposed: SSH",
            "SSH (port 22) is open — secure protocol but expands the remote access attack surface",
            [22],
        ))

    if row.get("has_http", 0) == 1:
        alerts.append(_make_alert(
            "UNENCRYPTED_WEB_SERVICE",
            "LOW",
            "Unencrypted Web Service: HTTP",
            "HTTP (port 80) is open — traffic is unencrypted and may expose admin paths or application metadata",
            [80],
        ))

    if row.get("has_smtp", 0) == 1:
        alerts.append(_make_alert(
            "MAIL_SERVICE_EXPOSED",
            "LOW",
            "Mail Service Exposed: SMTP",
            "SMTP (port 25) is open — may be probed for open relay or mail-system enumeration",
            [25],
        ))

    if row.get("has_dns", 0) == 1:
        alerts.append(_make_alert(
            "DNS_SERVICE_EXPOSED",
            "LOW",
            "DNS Service Exposed",
            "DNS (port 53) is open — verify that recursive queries and zone transfers are restricted",
            [53],
        ))

    if row.get("has_rtsp", 0) == 1 or row.get("has_printer", 0) == 1:
        iot_ports = []
        label_parts = []
        if row.get("has_rtsp", 0) == 1:
            iot_ports.append(554)
            label_parts.append("RTSP camera/media stream")
        if row.get("has_printer", 0) == 1:
            iot_ports.append(631)
            label_parts.append("IPP printer service")
        alerts.append(_make_alert(
            "IOT_DEVICE_DETECTED",
            "LOW",
            "IoT/Peripheral Device Detected",
            f"{' and '.join(label_parts)} detected — verify default credentials are changed",
            iot_ports,
        ))

    alerts.sort(key=lambda alert_item: ALERT_SEVERITY_RANK.get(alert_item["severity"], 99))
    return alerts


# EN: Collapse alerts into one semicolon-separated summary string for CSV storage.
# VI: Gộp cảnh báo thành một chuỗi ngắn phân tách bằng dấu chấm phẩy để lưu CSV.
def alerts_to_summary_string(alerts):
    if not alerts:
        return "No alerts"
    return " ; ".join(f"[{a['severity']}] {a['title']}" for a in alerts)
