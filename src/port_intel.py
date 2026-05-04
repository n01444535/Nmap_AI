# EN: Explain ports, risks, and guessed device details.
# VI: Giải thích cổng, mức nguy hiểm, và đoán loại thiết bị.

from constants import SCRIPT_OUTPUT_MAX_LENGTH

PORT_PROFILES = {
    20: ("ftp-data", "file_transfer", "medium", "FTP data channel can expose file transfers.", "Disable FTP when possible or restrict it to trusted networks."),
    21: ("ftp", "file_transfer", "high", "Plain FTP often sends credentials and data without encryption.", "Replace FTP with SFTP/FTPS or restrict access behind VPN."),
    22: ("ssh", "remote_access", "medium", "SSH is secure when patched, key-based, and not publicly exposed unnecessarily.", "Use keys, disable password login where possible, and restrict source IPs."),
    23: ("telnet", "remote_access", "critical", "Telnet sends credentials in clear text and is unsafe on modern networks.", "Disable Telnet and replace it with SSH."),
    25: ("smtp", "mail", "medium", "SMTP can be abused for relay or mail-system probing.", "Require authentication, disable open relay, and restrict administration access."),
    53: ("dns", "dns", "medium", "DNS exposure can leak internal names or support amplification if misconfigured.", "Restrict recursion and expose only required DNS services."),
    69: ("tftp", "file_transfer", "high", "TFTP has no authentication and is commonly abused for device config theft.", "Disable TFTP unless required and isolate it to a management VLAN."),
    80: ("http", "web", "low", "HTTP is unencrypted and may expose web admin panels or application metadata.", "Redirect to HTTPS and protect admin paths."),
    110: ("pop3", "mail", "medium", "POP3 can expose mail credentials when not wrapped in TLS.", "Prefer POP3S or modern authenticated mail access."),
    111: ("rpcbind", "rpc", "high", "RPC bind exposes service mapping and often supports lateral movement.", "Restrict RPC services to trusted hosts."),
    135: ("msrpc", "windows_rpc", "high", "Windows RPC exposure increases attack surface for enumeration and lateral movement.", "Block from untrusted networks and patch Windows services."),
    137: ("netbios-ns", "fileshare", "high", "NetBIOS name service leaks Windows host and domain information.", "Disable NetBIOS where possible or restrict to trusted LANs."),
    138: ("netbios-dgm", "fileshare", "high", "NetBIOS datagram service expands legacy Windows exposure.", "Disable NetBIOS where possible or restrict to trusted LANs."),
    139: ("netbios-ssn", "fileshare", "high", "NetBIOS session service exposes legacy file-sharing paths.", "Disable legacy SMB/NetBIOS or restrict to trusted LANs."),
    143: ("imap", "mail", "medium", "IMAP can expose mailbox access when not protected by TLS.", "Prefer IMAPS and enforce strong authentication."),
    161: ("snmp", "management", "high", "SNMP can leak device inventory, interfaces, and secrets when community strings are weak.", "Use SNMPv3 and restrict polling hosts."),
    389: ("ldap", "directory", "medium", "LDAP can expose directory data and authentication surfaces.", "Require TLS/signing and restrict anonymous binds."),
    443: ("https", "web", "low", "HTTPS is expected for web services but may still expose admin panels.", "Keep TLS and web software patched."),
    445: ("smb", "fileshare", "critical", "SMB is a high-value lateral movement and ransomware target.", "Restrict SMB to trusted subnets and disable SMBv1."),
    465: ("smtps", "mail", "low", "SMTPS is encrypted but still exposes mail infrastructure.", "Patch mail services and require authentication."),
    514: ("syslog", "logging", "medium", "Syslog can leak infrastructure data or accept forged logs.", "Restrict log ingestion to known senders."),
    554: ("rtsp", "iot_media", "medium", "RTSP often appears on cameras and media devices with weak credentials.", "Change defaults and isolate cameras or media devices."),
    587: ("submission", "mail", "low", "Mail submission should require authentication and TLS.", "Require TLS and disable unauthenticated relay."),
    631: ("ipp", "printer", "medium", "Printer services can expose device management and document metadata.", "Restrict printer access and disable web admin from untrusted networks."),
    993: ("imaps", "mail", "low", "IMAPS is encrypted but still exposes mailbox access.", "Patch mail services and enforce MFA where possible."),
    995: ("pop3s", "mail", "low", "POP3S is encrypted but still exposes mailbox access.", "Patch mail services and enforce strong authentication."),
    1433: ("mssql", "database", "critical", "Microsoft SQL Server should rarely be exposed broadly.", "Restrict SQL Server to application hosts and require strong authentication."),
    1521: ("oracle", "database", "critical", "Oracle database listener exposure can reveal database services.", "Restrict database listener access to trusted application hosts."),
    1723: ("pptp", "vpn", "high", "PPTP is considered weak and should be replaced.", "Replace PPTP with a modern VPN protocol."),
    1883: ("mqtt", "iot_messaging", "high", "MQTT often controls IoT devices and may allow unauthenticated publish/subscribe.", "Require authentication, TLS, and topic ACLs."),
    2049: ("nfs", "fileshare", "high", "NFS can expose file systems when exports are too broad.", "Restrict exports and require trusted clients."),
    2375: ("docker", "container_admin", "critical", "Unauthenticated Docker API exposure can lead to host takeover.", "Disable public Docker API or require TLS client certificates."),
    2376: ("docker-tls", "container_admin", "high", "Docker API is highly sensitive even when TLS is enabled.", "Restrict Docker API to trusted automation hosts."),
    27017: ("mongodb", "database", "critical", "MongoDB exposure can leak databases when authentication is weak.", "Bind to private interfaces and enforce authentication."),
    3306: ("mysql", "database", "critical", "MySQL should not be broadly exposed outside trusted app networks.", "Restrict MySQL to application hosts and require strong credentials."),
    3389: ("rdp", "remote_access", "critical", "RDP is a common brute-force and lateral movement target.", "Restrict RDP with VPN, MFA, and account lockout."),
    5000: ("upnp/rtsp/web", "iot_media", "medium", "Port 5000 is commonly used by device admin, RTSP, or dev services.", "Verify the owning process and restrict access if not required."),
    5432: ("postgresql", "database", "critical", "PostgreSQL should not be broadly exposed outside trusted app networks.", "Restrict PostgreSQL to application hosts and require strong credentials."),
    5601: ("kibana", "admin_console", "high", "Kibana can expose logs, dashboards, and sensitive operational data.", "Require SSO/authentication and restrict to admin networks."),
    5900: ("vnc", "remote_access", "critical", "VNC often lacks strong authentication and exposes desktop access.", "Disable VNC or restrict it through VPN with strong authentication."),
    5985: ("winrm", "windows_admin", "high", "WinRM exposes Windows remote administration.", "Restrict WinRM to management hosts and require secure authentication."),
    5986: ("winrm-https", "windows_admin", "high", "WinRM over HTTPS still exposes Windows remote administration.", "Restrict WinRM to management hosts and monitor usage."),
    6379: ("redis", "database", "critical", "Redis exposure can lead to data theft or remote command abuse when unauthenticated.", "Bind Redis privately and require authentication."),
    6443: ("kubernetes-api", "container_admin", "critical", "Kubernetes API exposure is highly sensitive.", "Restrict API access and enforce strong RBAC."),
    8080: ("http-alt", "web", "medium", "Alternate HTTP ports often host admin panels, proxies, or dev apps.", "Identify the application and protect admin access."),
    8443: ("https-alt", "web", "medium", "Alternate HTTPS ports often host admin panels or device consoles.", "Identify the application and protect admin access."),
    9000: ("admin/web", "admin_console", "high", "Port 9000 often hosts admin consoles or developer services.", "Verify the service and restrict it if not public-facing."),
    9200: ("elasticsearch", "database", "critical", "Elasticsearch exposure can leak indexed data and cluster metadata.", "Restrict Elasticsearch and require authentication."),
    11211: ("memcached", "cache", "high", "Memcached exposure can leak cached data and support amplification attacks.", "Bind Memcached privately and block UDP/TCP from untrusted networks."),
    27015: ("game/server", "gaming", "low", "Game or custom service ports are usually low risk but should be verified.", "Confirm the owning service and close it if unused."),
}

RISK_SCORES = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

CATEGORY_ALIASES = {
    "ftp": ("file_transfer", "remote_access"),
    "ssh": ("remote_access",),
    "telnet": ("remote_access", "cleartext"),
    "smtp": ("mail",),
    "imap": ("mail",),
    "pop": ("mail",),
    "http": ("web",),
    "ssl": ("encrypted",),
    "https": ("web", "encrypted"),
    "smb": ("fileshare",),
    "microsoft-ds": ("fileshare",),
    "netbios": ("fileshare",),
    "nfs": ("fileshare",),
    "rpc": ("rpc",),
    "mysql": ("database",),
    "postgres": ("database",),
    "mssql": ("database",),
    "oracle": ("database",),
    "redis": ("database",),
    "mongodb": ("database",),
    "elasticsearch": ("database",),
    "rdp": ("remote_access",),
    "vnc": ("remote_access",),
    "snmp": ("management",),
    "ldap": ("directory",),
    "mqtt": ("iot_messaging",),
    "rtsp": ("iot_media",),
    "ipp": ("printer",),
    "docker": ("container_admin",),
    "kubernetes": ("container_admin",),
    "winrm": ("windows_admin",),
}

CLEARTEXT_PORTS = {20, 21, 23, 25, 69, 80, 110, 143, 161, 389, 514, 1883}
ADMIN_PORTS = {22, 23, 135, 161, 445, 2375, 2376, 3389, 5601, 5900, 5985, 5986, 6443, 8080, 8443, 9000}
IOT_PORTS = {554, 631, 1883, 5000}


# EN: Get the known name and risk for a port.
# VI: Lấy tên và rủi ro đã biết của một cổng.
def get_port_profile(port, service_name=""):
    profile = PORT_PROFILES.get(int(port))
    service = (service_name or "").lower()

    if profile:
        name, category, risk, description, recommendation = profile
    else:
        name = service or "unknown"
        category = "other"
        risk = "low"
        description = "No specific high-risk profile is known for this port."
        recommendation = "Verify the owning service and close the port if it is not required."

    inferred_categories = []
    for token, categories in CATEGORY_ALIASES.items():
        if token in service:
            inferred_categories.extend(categories)

    if inferred_categories and category == "other":
        category = inferred_categories[0]

    if "cleartext" in inferred_categories and RISK_SCORES[risk] < RISK_SCORES["high"]:
        risk = "high"

    return {
        "name": name,
        "category": category,
        "risk_level": risk,
        "risk_score": RISK_SCORES.get(risk, 1),
        "description": description,
        "recommendation": recommendation,
    }


# EN: Make long script output short.
# VI: Rút gọn kết quả script dài.
def summarize_scripts(scripts, limit=3):
    parts = []
    for script in scripts or []:
        script_id = script.get("id", "script")
        output = " ".join((script.get("output") or "").split())
        if len(output) > SCRIPT_OUTPUT_MAX_LENGTH:
            output = output[:SCRIPT_OUTPUT_MAX_LENGTH - 3] + "..."
        parts.append(f"{script_id}: {output}" if output else script_id)
        if len(parts) >= limit:
            break
    return " | ".join(parts)


# EN: Add risk and summary details to one port.
# VI: Thêm rủi ro và tóm tắt cho một cổng.
def enrich_port(port_info):
    profile = get_port_profile(port_info.get("port", 0), port_info.get("service", ""))
    enriched = dict(port_info)
    enriched.update(profile)
    enriched["script_summary"] = summarize_scripts(port_info.get("scripts", []))
    return enriched


# EN: List high-risk ports for one host.
# VI: Liệt kê cổng nguy hiểm của một máy.
def risky_ports_from_record(record):
    risky = []
    for port_info in record.get("open_ports", []):
        enriched = enrich_port(port_info)
        if enriched["risk_score"] >= RISK_SCORES["high"]:
            risky.append(f"{enriched['port']}/{enriched['risk_level']}")
    return ";".join(risky) if risky else "None"


# EN: Build rows for the detailed port report.
# VI: Tạo các dòng cho báo cáo cổng chi tiết.
def port_detail_rows(records):
    rows = []
    for record in records:
        for port_info in sorted(record.get("open_ports", []), key=lambda item: item.get("port", 0)):
            enriched = enrich_port(port_info)
            service = port_info.get("service", "") or enriched["name"]
            default_source = "guess" if (service or "").lower() in {"", "unknown"} else "nmap"
            rows.append(
                {
                    "ip": record.get("ip", ""),
                    "hostname": record.get("hostname", ""),
                    "protocol": port_info.get("protocol", ""),
                    "port": port_info.get("port", ""),
                    "service": service,
                    "service_source": port_info.get("service_source", default_source),
                    "service_guess": port_info.get("service_guess", ""),
                    "device_guess": port_info.get("device_guess", ""),
                    "guess_confidence": port_info.get("guess_confidence", ""),
                    "guess_evidence": port_info.get("guess_evidence", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                    "tunnel": port_info.get("tunnel", ""),
                    "state_reason": port_info.get("state_reason", ""),
                    "service_method": port_info.get("service_method", ""),
                    "service_confidence": port_info.get("service_confidence", ""),
                    "category": enriched["category"],
                    "risk_level": enriched["risk_level"],
                    "risk_score": enriched["risk_score"],
                    "description": enriched["description"],
                    "recommendation": enriched["recommendation"],
                    "script_summary": enriched["script_summary"],
                }
            )
    return rows
