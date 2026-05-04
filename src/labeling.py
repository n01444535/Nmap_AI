# EN: Give each host a simple normal or suspicious label.
# VI: Gắn nhãn bình thường hoặc đáng nghi cho từng máy.

from constants import (
    SUSPICIOUS_SCORE_THRESHOLD,
    MIN_DB_COUNT_THRESHOLD, MIN_FILESHARE_COUNT_THRESHOLD,
    MIN_REMOTE_ACCESS_COUNT_THRESHOLD, MIN_VERY_RISKY_COUNT_THRESHOLD,
    MIN_CRITICAL_PORT_COUNT_THRESHOLD, MIN_CLEARTEXT_COUNT_THRESHOLD,
    MIN_ADMIN_PORT_COUNT_THRESHOLD, MIN_OPEN_PORT_COUNT_THRESHOLD,
    MIN_UNCOMMON_PORT_COUNT_THRESHOLD,
    MULTI_COUNT_RISK_SCORE, VERY_RISKY_COUNT_RISK_SCORE,
)

SERVICE_RISK_SCORES = {
    "has_telnet": 4,
    "has_ftp": 2,
    "has_smb": 3,
    "has_rpcbind": 2,
    "has_redis": 3,
    "has_vnc": 2,
    "has_rdp": 2,
    "has_tftp": 3,
    "has_snmp": 2,
    "has_mqtt": 2,
    "has_docker": 4,
    "has_kubernetes_api": 4,
    "has_elasticsearch": 3,
    "has_memcached": 3,
    "has_winrm": 2,
}

# EN: Make a simple rule-based risk label.
# VI: Dùng luật đơn giản để gắn nhãn nguy hiểm.
def heuristic_label_row(row):
    risk_score = sum(
        score for flag, score in SERVICE_RISK_SCORES.items()
        if row.get(flag, 0) == 1
    )
    if row.get("db_count", 0) >= MIN_DB_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("fileshare_count", 0) >= MIN_FILESHARE_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("remote_access_count", 0) >= MIN_REMOTE_ACCESS_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("very_risky_port_count", 0) >= MIN_VERY_RISKY_COUNT_THRESHOLD:
        risk_score += VERY_RISKY_COUNT_RISK_SCORE
    if row.get("critical_port_count", 0) >= MIN_CRITICAL_PORT_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("cleartext_count", 0) >= MIN_CLEARTEXT_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("admin_port_count", 0) >= MIN_ADMIN_PORT_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("open_port_count", 0) >= MIN_OPEN_PORT_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    if row.get("uncommon_open_count", 0) >= MIN_UNCOMMON_PORT_COUNT_THRESHOLD:
        risk_score += MULTI_COUNT_RISK_SCORE
    return "suspicious" if risk_score >= SUSPICIOUS_SCORE_THRESHOLD else "normal"
