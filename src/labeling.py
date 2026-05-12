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
    LABEL_CONFIDENCE_MIDPOINT, LABEL_CONFIDENCE_MAX_BOOST, LABEL_CONFIDENCE_DISTANCE_SCALE,
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

# EN: Compute the raw heuristic risk score for one host row.
# VI: Tính điểm rủi ro heuristic thô cho một dòng máy.
def _compute_heuristic_risk_score(row):
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
    return risk_score


# EN: Make a simple rule-based risk label.
# VI: Dùng luật đơn giản để gắn nhãn nguy hiểm.
def heuristic_label_row(row):
    return "suspicious" if _compute_heuristic_risk_score(row) >= SUSPICIOUS_SCORE_THRESHOLD else "normal"


# EN: Return how confident the heuristic label is (0.5 = borderline, 1.0 = clear-cut).
# VI: Trả về độ chắc chắn của nhãn heuristic — 0.5 là ranh giới, 1.0 là rõ ràng.
def heuristic_confidence_row(row):
    risk_score = _compute_heuristic_risk_score(row)
    distance = abs(risk_score - SUSPICIOUS_SCORE_THRESHOLD)
    return round(
        LABEL_CONFIDENCE_MIDPOINT + min(distance / LABEL_CONFIDENCE_DISTANCE_SCALE, LABEL_CONFIDENCE_MAX_BOOST),
        3,
    )
