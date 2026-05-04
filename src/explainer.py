# EN: Build a human-readable explanation for why a host was flagged.
# VI: Tạo giải thích dễ đọc vì sao một máy bị đánh dấu nghi ngờ.

from constants import VERY_HIGH_RISK_PORTS

# EN: Map each feature flag to the port numbers and a short plain-English description.
# VI: Ánh xạ từng cờ đặc điểm sang số cổng và mô tả tiếng Anh ngắn gọn.
_SERVICE_MAP = [
    ("has_telnet",        [23],         "Telnet",          "cleartext remote shell — passwords sent in plaintext"),
    ("has_ftp",           [21],         "FTP",             "cleartext file transfer — credentials visible on the wire"),
    ("has_tftp",          [69],         "TFTP",            "unauthenticated file transfer — device configs can be stolen"),
    ("has_rpcbind",       [111],        "RPC Bind",        "service mapper — enables lateral movement enumeration"),
    ("has_snmp",          [161],        "SNMP",            "management protocol — leaks device inventory with weak community strings"),
    ("has_smb",           [445],        "SMB",             "Windows file sharing — primary ransomware and lateral movement vector"),
    ("has_rdp",           [3389],       "RDP",             "Windows remote desktop — common brute-force and ransomware entry"),
    ("has_vnc",           [5900],       "VNC",             "remote desktop — often lacks strong authentication"),
    ("has_winrm",         [5985, 5986], "WinRM",           "Windows remote management — admin access from network"),
    ("has_redis",         [6379],       "Redis",           "in-memory database — unauthenticated by default in many deployments"),
    ("has_elasticsearch", [9200],       "Elasticsearch",   "search index — data readable without auth in many versions"),
    ("has_memcached",     [11211],      "Memcached",       "cache service — no authentication, supports DDoS amplification"),
    ("has_mqtt",          [1883],       "MQTT",            "IoT control channel — device commands accessible without auth"),
    ("has_docker",        [2375, 2376], "Docker API",      "container management — unauthenticated access yields full host control"),
    ("has_kubernetes_api",[6443],       "Kubernetes API",  "container orchestration — cluster-wide compromise if exposed"),
    ("has_mssql",         [1433],       "MSSQL",           "Microsoft SQL Server — direct database query access"),
    ("has_oracle",        [1521],       "Oracle DB",       "Oracle listener — service enumeration and query access"),
    ("has_mysql",         [3306],       "MySQL",           "relational database — direct query access from network"),
    ("has_postgresql",    [5432],       "PostgreSQL",      "relational database — direct query access from network"),
    ("has_mongodb",       [27017],      "MongoDB",         "document store — historically exposed without auth in default installs"),
    ("has_netbios",       [137,138,139],"NetBIOS",         "legacy Windows networking — leaks host and domain information"),
    ("has_nfs",           [2049],       "NFS",             "network file system — file access if exports are too broad"),
]

# EN: Map each attack technique to the feature flags that enable it.
# VI: Ánh xạ từng kỹ thuật tấn công sang các cờ đặc điểm kích hoạt nó.
_TECHNIQUE_MAP = [
    (
        "Brute Force",
        "attacker repeatedly tries credentials to gain unauthorized access",
        [
            ("has_ssh",        [22],         "SSH"),
            ("has_telnet",     [23],         "Telnet"),
            ("has_ftp",        [21],         "FTP"),
            ("has_rdp",        [3389],       "RDP"),
            ("has_vnc",        [5900],       "VNC"),
            ("has_smb",        [445],        "SMB"),
            ("has_winrm",      [5985, 5986], "WinRM"),
            ("has_mssql",      [1433],       "MSSQL"),
            ("has_mysql",      [3306],       "MySQL"),
            ("has_postgresql", [5432],       "PostgreSQL"),
            ("has_mongodb",    [27017],      "MongoDB"),
            ("has_redis",      [6379],       "Redis"),
        ],
    ),
    (
        "Lateral Movement",
        "attacker moves through the network after initial compromise",
        [
            ("has_smb",            [445],        "SMB"),
            ("has_rdp",            [3389],       "RDP"),
            ("has_winrm",          [5985, 5986], "WinRM"),
            ("has_rpcbind",        [111],        "RPC Bind"),
            ("has_netbios",        [137,138,139],"NetBIOS"),
            ("has_ssh",            [22],         "SSH"),
            ("has_vnc",            [5900],       "VNC"),
            ("has_docker",         [2375, 2376], "Docker API"),
            ("has_kubernetes_api", [6443],       "Kubernetes API"),
        ],
    ),
    (
        "Reconnaissance",
        "attacker probes services to map the network and gather intelligence",
        [
            ("has_snmp",          [161],        "SNMP"),
            ("has_rpcbind",       [111],        "RPC Bind"),
            ("has_netbios",       [137,138,139],"NetBIOS"),
            ("has_ldap",          [389],        "LDAP"),
            ("has_dns",           [53],         "DNS"),
            ("has_nfs",           [2049],       "NFS"),
            ("has_ftp",           [21],         "FTP"),
            ("has_telnet",        [23],         "Telnet"),
            ("has_elasticsearch", [9200],       "Elasticsearch"),
            ("has_redis",         [6379],       "Redis"),
            ("has_mongodb",       [27017],      "MongoDB"),
        ],
    ),
]

_DANGEROUS_COMBINATIONS = [
    (
        lambda r: r.get("has_smb", 0) == 1 and r.get("has_rdp", 0) == 1,
        "SMB (445) + RDP (3389) both open — classic ransomware lateral movement path",
    ),
    (
        lambda r: r.get("has_telnet", 0) == 1 and r.get("has_ftp", 0) == 1,
        "Telnet (23) + FTP (21) — two cleartext credential channels active simultaneously",
    ),
    (
        lambda r: r.get("has_rdp", 0) == 1 and r.get("has_vnc", 0) == 1,
        "RDP (3389) + VNC (5900) — two remote desktop services exposed, doubling brute-force risk",
    ),
    (
        lambda r: r.get("has_redis", 0) == 1 and r.get("has_docker", 0) == 1,
        "Redis (6379) + Docker API (2375/2376) — cache abuse can pivot directly into container takeover",
    ),
    (
        lambda r: r.get("has_kubernetes_api", 0) == 1 and r.get("db_count", 0) > 0,
        "Kubernetes API (6443) + database port — orchestration layer and data store both reachable",
    ),
    (
        lambda r: r.get("has_smb", 0) == 1 and r.get("has_netbios", 0) == 1,
        "SMB (445) + NetBIOS (137-139) — full Windows file-sharing stack exposed to the network",
    ),
    (
        lambda r: r.get("has_mongodb", 0) == 1 and r.get("has_elasticsearch", 0) == 1,
        "MongoDB (27017) + Elasticsearch (9200) — two data stores with historically weak default authentication",
    ),
    (
        lambda r: r.get("db_count", 0) >= 2,
        lambda r: f"{r.get('db_count', 0)} database ports open simultaneously — multiple data stores directly reachable",
    ),
    (
        lambda r: r.get("has_docker", 0) == 1 and r.get("has_kubernetes_api", 0) == 1,
        "Docker API + Kubernetes API both exposed — full container infrastructure accessible",
    ),
    (
        lambda r: r.get("has_telnet", 0) == 1 and r.get("has_smb", 0) == 1,
        "Telnet (23) + SMB (445) — cleartext access combined with a primary ransomware vector",
    ),
]


# EN: Collect all flagged services from the feature row.
# VI: Thu thập tất cả dịch vụ bị đánh dấu từ dòng đặc điểm.
def _collect_detected_services(row):
    detected = []
    for flag, ports, service_name, description in _SERVICE_MAP:
        if row.get(flag, 0) == 1:
            detected.append((ports, service_name, description))
    return detected


# EN: Build one explanation block for a host row.
# VI: Tạo một khối giải thích cho một dòng máy.
def generate_explanation_for_row(row):
    lines = []
    detected_services = _collect_detected_services(row)

    all_detected_ports = sorted(set(p for ports, _, _ in detected_services for p in ports))
    risky_detected_count = sum(
        1 for p in all_detected_ports if p in VERY_HIGH_RISK_PORTS
    )

    if all_detected_ports:
        port_preview = ", ".join(str(p) for p in all_detected_ports[:7])
        if len(all_detected_ports) > 7:
            port_preview += f" (+{len(all_detected_ports) - 7} more)"
        lines.append(
            f"Flagged because: {len(all_detected_ports)} known high-risk port(s) detected "
            f"({risky_detected_count} critical/very-high): {port_preview}"
        )
    else:
        open_count = row.get("open_port_count", 0)
        uncommon = row.get("uncommon_open_count", 0)
        lines.append(
            f"Flagged because: {open_count} open port(s) with {uncommon} uncommon/non-standard port(s)"
        )

    if detected_services:
        lines.append("")
        lines.append("Detected high-risk services:")
        for ports, service_name, description in detected_services:
            port_str = "/".join(str(p) for p in ports)
            lines.append(f"  • {service_name:<18} port {port_str:<12}  {description}")

    active_combinations = []
    for condition, message in _DANGEROUS_COMBINATIONS:
        if condition(row):
            text = message(row) if callable(message) else message
            active_combinations.append(text)

    if active_combinations:
        lines.append("")
        lines.append("Dangerous service combinations:")
        for combo_text in active_combinations:
            lines.append(f"  • {combo_text}")

    patterns = []
    cleartext_count = row.get("cleartext_count", 0)
    if cleartext_count >= 2:
        patterns.append(
            f"{cleartext_count} cleartext protocol(s) active — authentication data transmitted without encryption"
        )
    admin_count = row.get("admin_port_count", 0)
    if admin_count >= 2:
        patterns.append(
            f"{admin_count} administrative port(s) open — management attack surface is oversized"
        )
    remote_count = row.get("remote_access_count", 0)
    if remote_count >= 2:
        patterns.append(
            f"{remote_count} remote access service(s) open — multiple lateral movement entry points"
        )
    fileshare_count = row.get("fileshare_count", 0)
    if fileshare_count >= 2:
        patterns.append(
            f"{fileshare_count} file-sharing service(s) exposed — internal storage reachable from network"
        )
    uncommon_count = row.get("uncommon_open_count", 0)
    if uncommon_count >= 3:
        patterns.append(
            f"{uncommon_count} non-standard port(s) open — possible backdoors or undocumented services"
        )

    if patterns:
        lines.append("")
        lines.append("Exposure patterns:")
        for pattern_text in patterns:
            lines.append(f"  • {pattern_text}")

    technique_hits = []
    for technique_name, technique_desc, flag_entries in _TECHNIQUE_MAP:
        matched = []
        for flag, ports, service_name in flag_entries:
            if row.get(flag, 0) == 1:
                port_str = "/".join(str(p) for p in ports)
                matched.append(f"{service_name} ({port_str})")
        if matched:
            technique_hits.append((technique_name, technique_desc, matched))

    if technique_hits:
        lines.append("")
        lines.append("Real-world attack mapping:")
        for technique_name, technique_desc, matched in technique_hits:
            services_str = ", ".join(matched)
            lines.append(f"  • {technique_name:<20}  {services_str}")
            lines.append(f"    {'':20}  ↳ {technique_desc}")

    total_ports = row.get("open_port_count", 0)
    risky_ports = row.get("risky_port_count", 0)
    critical_ports = row.get("critical_port_count", 0)

    summary_parts = []
    if total_ports > 0:
        summary_parts.append(f"{total_ports} total open port(s)")
    if risky_ports > 0:
        pct = int(risky_ports / total_ports * 100) if total_ports > 0 else 0
        summary_parts.append(f"{risky_ports} rated high/critical risk ({pct}%)")
    if critical_ports > 0:
        summary_parts.append(f"{critical_ports} classified critical severity")

    if summary_parts:
        lines.append("")
        lines.append("Attack surface: " + " | ".join(summary_parts))

    return lines
