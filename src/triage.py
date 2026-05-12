# EN: Assign a SOC triage status to each suspicious host.
# VI: Gán trạng thái phân loại SOC cho từng máy đáng nghi.

from constants import SEVERITY_CRITICAL_MIN_PROB, SEVERITY_HIGH_MIN_PROB, SEVERITY_MEDIUM_MIN_PROB

TRIAGE_IMMEDIATE_ACTION = "Immediate Action"
TRIAGE_URGENT = "Urgent"
TRIAGE_INVESTIGATE = "Investigate"
TRIAGE_MONITOR = "Monitor"
TRIAGE_NONE = "—"

# EN: Map triage level to a short one-line action guidance.
# VI: Ánh xạ mức phân loại sang hướng dẫn hành động ngắn.
TRIAGE_GUIDANCE = {
    TRIAGE_IMMEDIATE_ACTION: "Isolate or block the host and begin incident response now",
    TRIAGE_URGENT: "Escalate immediately — restrict network access and begin log analysis",
    TRIAGE_INVESTIGATE: "Review open ports, service versions, and authentication logs",
    TRIAGE_MONITOR: "Capture traffic and watch for unusual outbound connections",
}

# EN: Compute the triage status for one suspicious host.
# VI: Tính trạng thái phân loại cho một máy đáng nghi.
def compute_triage_status(row, alerts):
    prob = row.get("predicted_probability_suspicious", 0.0)
    has_critical_alert = any(a["severity"] == "CRITICAL" for a in alerts)
    has_high_alert = any(a["severity"] == "HIGH" for a in alerts)
    has_medium_alert = any(a["severity"] == "MEDIUM" for a in alerts)

    if has_critical_alert or prob > SEVERITY_CRITICAL_MIN_PROB:
        return TRIAGE_IMMEDIATE_ACTION

    if has_high_alert or prob > SEVERITY_HIGH_MIN_PROB:
        return TRIAGE_URGENT

    if has_medium_alert or prob > SEVERITY_MEDIUM_MIN_PROB:
        return TRIAGE_INVESTIGATE

    if row.get("prediction") == "suspicious" or alerts:
        return TRIAGE_MONITOR

    return TRIAGE_NONE
