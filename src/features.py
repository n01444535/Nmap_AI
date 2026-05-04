# EN: Turn Nmap records into numbers for machine learning.
# VI: Đổi dữ liệu Nmap thành con số để máy học dùng.

from collections import Counter
import pandas as pd
from constants import COMMON_WEB_PORTS, DB_PORTS, FILESHARE_PORTS, HIGH_RISK_PORTS, MAIL_PORTS, REMOTE_ACCESS_PORTS, VERY_HIGH_RISK_PORTS
from port_intel import ADMIN_PORTS, CLEARTEXT_PORTS, IOT_PORTS, get_port_profile

# EN: Put a service name into an easy group.
# VI: Xếp tên dịch vụ vào một nhóm dễ hiểu.
def service_bucket(service_name):
    name = (service_name or "").lower()
    if "http" in name or "https" in name:
        return "web"
    if "ssh" in name or "telnet" in name or "ftp" in name or "rdp" in name or "vnc" in name or "winrm" in name:
        return "remote"
    if "smtp" in name or "imap" in name or "pop" in name:
        return "mail"
    if "mysql" in name or "postgres" in name or "mssql" in name or "oracle" in name or "redis" in name or "mongo" in name or "elastic" in name:
        return "database"
    if "smb" in name or "microsoft-ds" in name or "netbios" in name or "nfs" in name or "rpcbind" in name:
        return "fileshare"
    if "domain" in name or "dns" in name:
        return "dns"
    if "snmp" in name:
        return "management"
    if "rtsp" in name or "mqtt" in name or "ipp" in name:
        return "iot"
    return "other"

# EN: Count useful signals from one scanned host.
# VI: Đếm dấu hiệu quan trọng từ một máy đã quét.
def extract_features_from_host_record(record):
    open_ports = record["open_ports"]
    ports = [p["port"] for p in open_ports]
    services = [p.get("service", "") for p in open_ports]
    port_set = set(ports)
    buckets = Counter(service_bucket(s) for s in services)
    profiles = [get_port_profile(p.get("port", 0), p.get("service", "")) for p in open_ports]
    profile_categories = Counter(profile["category"] for profile in profiles)
    risk_scores = [profile["risk_score"] for profile in profiles]
    risky_count = sum(1 for p in ports if p in HIGH_RISK_PORTS)
    very_risky_count = sum(1 for p in ports if p in VERY_HIGH_RISK_PORTS)
    uncommon_open_count = sum(1 for p in ports if p > 1024 and p not in {1433, 1521, 1883, 2049, 2375, 2376, 27017, 3306, 3389, 5432, 5601, 5900, 5985, 5986, 6379, 6443, 8080, 8443, 9000, 9200, 11211})
    remote_access_count = sum(1 for p in ports if p in REMOTE_ACCESS_PORTS)
    mail_count = sum(1 for p in ports if p in MAIL_PORTS)
    db_count = sum(1 for p in ports if p in DB_PORTS)
    fileshare_count = sum(1 for p in ports if p in FILESHARE_PORTS)
    web_count = sum(1 for p in ports if p in COMMON_WEB_PORTS)
    cleartext_count = sum(1 for p in ports if p in CLEARTEXT_PORTS)
    admin_port_count = sum(1 for p in ports if p in ADMIN_PORTS)
    iot_port_count = sum(1 for p in ports if p in IOT_PORTS)
    critical_profile_count = sum(1 for score in risk_scores if score >= 4)
    high_profile_count = sum(1 for score in risk_scores if score >= 3)
    nse_script_count = sum(len(p.get("scripts", [])) for p in open_ports)
    versioned_service_count = sum(1 for p in open_ports if p.get("product", "") or p.get("version", ""))
    unknown_service_count = sum(1 for s in services if not s or s == "unknown")
    encrypted_service_count = sum(1 for p in open_ports if p.get("tunnel", "") == "ssl" or p.get("port") in {443, 465, 993, 995, 8443, 5986})
    max_port_risk_score = max(risk_scores) if risk_scores else 0
    avg_port_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    return {
        "ip": record["ip"],
        "hostname": record.get("hostname", ""),
        "open_port_count": len(ports),
        "risky_port_count": risky_count,
        "very_risky_port_count": very_risky_count,
        "critical_port_count": critical_profile_count,
        "high_detail_risk_port_count": high_profile_count,
        "max_port_risk_score": max_port_risk_score,
        "avg_port_risk_score": avg_port_risk_score,
        "uncommon_open_count": uncommon_open_count,
        "remote_access_count": remote_access_count,
        "cleartext_count": cleartext_count,
        "admin_port_count": admin_port_count,
        "iot_port_count": iot_port_count,
        "mail_count": mail_count,
        "db_count": db_count,
        "fileshare_count": fileshare_count,
        "web_count": web_count,
        "versioned_service_count": versioned_service_count,
        "unknown_service_count": unknown_service_count,
        "encrypted_service_count": encrypted_service_count,
        "nse_script_count": nse_script_count,
        "service_web_count": buckets["web"],
        "service_remote_count": buckets["remote"],
        "service_mail_count": buckets["mail"],
        "service_database_count": buckets["database"],
        "service_fileshare_count": buckets["fileshare"],
        "service_dns_count": buckets["dns"],
        "service_management_count": buckets["management"],
        "service_iot_count": buckets["iot"],
        "service_other_count": buckets["other"],
        "profile_remote_access_count": profile_categories["remote_access"],
        "profile_database_count": profile_categories["database"],
        "profile_fileshare_count": profile_categories["fileshare"],
        "profile_admin_console_count": profile_categories["admin_console"],
        "profile_container_admin_count": profile_categories["container_admin"],
        "has_ftp": int(21 in port_set),
        "has_ssh": int(22 in port_set),
        "has_telnet": int(23 in port_set),
        "has_smtp": int(25 in port_set),
        "has_dns": int(53 in port_set),
        "has_tftp": int(69 in port_set),
        "has_http": int(80 in port_set),
        "has_pop3": int(110 in port_set),
        "has_rpcbind": int(111 in port_set),
        "has_netbios": int(any(p in port_set for p in [137, 138, 139])),
        "has_imap": int(143 in port_set),
        "has_snmp": int(161 in port_set),
        "has_ldap": int(389 in port_set),
        "has_https": int(443 in port_set),
        "has_smb": int(445 in port_set),
        "has_rtsp": int(554 in port_set),
        "has_printer": int(631 in port_set),
        "has_mssql": int(1433 in port_set),
        "has_oracle": int(1521 in port_set),
        "has_mqtt": int(1883 in port_set),
        "has_nfs": int(2049 in port_set),
        "has_docker": int(any(p in port_set for p in [2375, 2376])),
        "has_mongodb": int(27017 in port_set),
        "has_mysql": int(3306 in port_set),
        "has_rdp": int(3389 in port_set),
        "has_postgresql": int(5432 in port_set),
        "has_kibana": int(5601 in port_set),
        "has_vnc": int(5900 in port_set),
        "has_winrm": int(any(p in port_set for p in [5985, 5986])),
        "has_redis": int(6379 in port_set),
        "has_kubernetes_api": int(6443 in port_set),
        "has_elasticsearch": int(9200 in port_set),
        "has_memcached": int(11211 in port_set),
        "has_http_alt": int(any(p in port_set for p in [8080, 8443]))
    }

# EN: Turn many host records into a table.
# VI: Đổi nhiều máy thành một bảng.
def records_to_dataframe(records):
    rows = [extract_features_from_host_record(r) for r in records]
    return pd.DataFrame(rows)

# EN: Choose only the columns used for learning.
# VI: Chọn các cột dùng để máy học.
def feature_columns(df):
    excluded = {"ip", "hostname", "label", "prediction", "predicted_probability_suspicious", "recommendations"}
    return [c for c in df.columns if c not in excluded]
