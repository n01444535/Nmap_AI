# EN: Give each host a simple normal or suspicious label.
# VI: Gắn nhãn bình thường hoặc đáng nghi cho từng máy.

# EN: Make a simple rule-based risk label.
# VI: Dùng luật đơn giản để gắn nhãn nguy hiểm.
def heuristic_label_row(row):
    score = 0
    if row.get("has_telnet", 0) == 1:
        score += 4
    if row.get("has_ftp", 0) == 1:
        score += 2
    if row.get("has_smb", 0) == 1:
        score += 3
    if row.get("has_rpcbind", 0) == 1:
        score += 2
    if row.get("has_redis", 0) == 1:
        score += 3
    if row.get("has_vnc", 0) == 1:
        score += 2
    if row.get("has_rdp", 0) == 1:
        score += 2
    if row.get("has_tftp", 0) == 1:
        score += 3
    if row.get("has_snmp", 0) == 1:
        score += 2
    if row.get("has_mqtt", 0) == 1:
        score += 2
    if row.get("has_docker", 0) == 1:
        score += 4
    if row.get("has_kubernetes_api", 0) == 1:
        score += 4
    if row.get("has_elasticsearch", 0) == 1:
        score += 3
    if row.get("has_memcached", 0) == 1:
        score += 3
    if row.get("has_winrm", 0) == 1:
        score += 2
    if row.get("db_count", 0) >= 2:
        score += 2
    if row.get("fileshare_count", 0) >= 2:
        score += 2
    if row.get("remote_access_count", 0) >= 2:
        score += 2
    if row.get("very_risky_port_count", 0) >= 3:
        score += 3
    if row.get("critical_port_count", 0) >= 1:
        score += 2
    if row.get("cleartext_count", 0) >= 2:
        score += 2
    if row.get("admin_port_count", 0) >= 2:
        score += 2
    if row.get("open_port_count", 0) >= 8:
        score += 2
    if row.get("uncommon_open_count", 0) >= 3:
        score += 2
    return "suspicious" if score >= 5 else "normal"
