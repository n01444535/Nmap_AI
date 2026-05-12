# EN: Detect cross-host attack patterns from prediction results.
# VI: Phát hiện mẫu tấn công liên máy từ kết quả dự đoán.

from constants import (
    PATTERN_MIN_LATERAL_MOVEMENT_HOSTS,
    PATTERN_MIN_SMB_CLUSTER_HOSTS,
    PATTERN_MIN_CLEARTEXT_HOSTS,
    PATTERN_MIN_DB_CLUSTER_HOSTS,
    PATTERN_MIN_CONTAINER_HOSTS,
    PATTERN_MIN_REMOTE_ACCESS_CLUSTER_HOSTS,
    PATTERN_MIN_CRITICAL_MASS_HOSTS,
)


def _host_has_lateral_movement_pair(row):
    return row.get("has_smb", 0) == 1 and row.get("has_rdp", 0) == 1


def _host_has_smb_exposed(row):
    return row.get("has_smb", 0) == 1


def _host_has_cleartext_protocol(row):
    return row.get("has_telnet", 0) == 1 or row.get("has_ftp", 0) == 1


def _host_has_database_port(row):
    return row.get("db_count", 0) >= 1


def _host_has_container_api(row):
    return row.get("has_docker", 0) == 1 or row.get("has_kubernetes_api", 0) == 1


def _host_has_multiple_remote_vectors(row):
    return row.get("remote_access_count", 0) >= 2


def _host_is_critical_severity(row):
    return row.get("severity", "") == "CRITICAL"


_PATTERN_SPECS = [
    {
        "pattern_id": "lateral_movement_campaign",
        "name": "Lateral Movement Campaign",
        "severity": "CRITICAL",
        "description_template": (
            "{n} hosts expose both SMB (445) and RDP (3389) simultaneously — "
            "the ransomware lateral movement pathway is active at network scale"
        ),
        "mitre": "TA0008 Lateral Movement, T1021.002 SMB/Windows Admin Shares",
        "recommendation": (
            "Segment the network, block direct SMB/RDP between hosts, "
            "enforce MFA on all remote access endpoints"
        ),
        "host_filter": _host_has_lateral_movement_pair,
        "min_hosts": PATTERN_MIN_LATERAL_MOVEMENT_HOSTS,
    },
    {
        "pattern_id": "smb_worm_propagation_conditions",
        "name": "SMB Worm Propagation Conditions",
        "severity": "CRITICAL",
        "description_template": (
            "{n} hosts expose SMB (445) — sufficient density for autonomous worm "
            "self-propagation (EternalBlue / WannaCry-style spread)"
        ),
        "mitre": "T1210 Exploitation of Remote Services, TA0008 Lateral Movement",
        "recommendation": (
            "Apply MS17-010 patches, disable SMBv1, restrict SMB to storage servers only "
            "and block it between workstations"
        ),
        "host_filter": _host_has_smb_exposed,
        "min_hosts": PATTERN_MIN_SMB_CLUSTER_HOSTS,
    },
    {
        "pattern_id": "cleartext_credential_spray_surface",
        "name": "Cleartext Credential Spray Surface",
        "severity": "HIGH",
        "description_template": (
            "{n} hosts expose Telnet or FTP — credentials are transmitted in plaintext, "
            "enabling passive network-wide credential harvesting"
        ),
        "mitre": "T1110 Brute Force, T1040 Network Sniffing",
        "recommendation": (
            "Disable Telnet and FTP across the entire network segment, "
            "replace with SSH and SFTP/FTPS"
        ),
        "host_filter": _host_has_cleartext_protocol,
        "min_hosts": PATTERN_MIN_CLEARTEXT_HOSTS,
    },
    {
        "pattern_id": "database_exposure_cluster",
        "name": "Database Exposure Cluster",
        "severity": "HIGH",
        "description_template": (
            "{n} hosts expose database listener ports — an attacker can enumerate, "
            "dump, or ransom multiple databases in a single campaign"
        ),
        "mitre": "T1213 Data from Information Repositories, TA0010 Exfiltration",
        "recommendation": (
            "Move all database ports behind application-layer firewalls, "
            "disable public listener interfaces"
        ),
        "host_filter": _host_has_database_port,
        "min_hosts": PATTERN_MIN_DB_CLUSTER_HOSTS,
    },
    {
        "pattern_id": "container_orchestration_api_cluster",
        "name": "Container / Orchestration API Cluster",
        "severity": "CRITICAL",
        "description_template": (
            "{n} hosts expose Docker API or Kubernetes API — unauthenticated access "
            "allows full container escape and cluster-level takeover"
        ),
        "mitre": "T1611 Escape to Host, TA0004 Privilege Escalation",
        "recommendation": (
            "Bind Docker API to Unix socket only, enable Kubernetes RBAC and mutual TLS, "
            "never expose these APIs on network interfaces"
        ),
        "host_filter": _host_has_container_api,
        "min_hosts": PATTERN_MIN_CONTAINER_HOSTS,
    },
    {
        "pattern_id": "remote_access_vector_cluster",
        "name": "Remote Access Vector Cluster",
        "severity": "HIGH",
        "description_template": (
            "{n} hosts each expose multiple remote access protocols (SSH, RDP, VNC, WinRM) — "
            "broad credential brute-force surface across the network"
        ),
        "mitre": "T1110 Brute Force, T1021 Remote Services",
        "recommendation": (
            "Consolidate remote access through a single VPN gateway or bastion host, "
            "disable unused remote protocols"
        ),
        "host_filter": _host_has_multiple_remote_vectors,
        "min_hosts": PATTERN_MIN_REMOTE_ACCESS_CLUSTER_HOSTS,
    },
    {
        "pattern_id": "critical_host_mass_detected",
        "name": "Critical Severity Host Mass",
        "severity": "HIGH",
        "description_template": (
            "{n} hosts are classified CRITICAL — this scale suggests either a severely "
            "misconfigured network segment or an active compromise in progress"
        ),
        "mitre": None,
        "recommendation": (
            "Initiate immediate incident response triage — isolate the highest-risk hosts "
            "and begin forensic investigation"
        ),
        "host_filter": _host_is_critical_severity,
        "min_hosts": PATTERN_MIN_CRITICAL_MASS_HOSTS,
    },
]


def detect_network_patterns(predictions_df):
    """Scan all predicted hosts and return a list of active cross-host attack patterns."""
    detected_patterns = []
    for spec in _PATTERN_SPECS:
        matching_hosts = predictions_df[predictions_df.apply(spec["host_filter"], axis=1)]
        if len(matching_hosts) < spec["min_hosts"]:
            continue
        affected_host_list = [
            {"ip": row["ip"], "hostname": str(row.get("hostname", ""))}
            for _, row in matching_hosts.iterrows()
        ]
        detected_patterns.append({
            "pattern_id": spec["pattern_id"],
            "name": spec["name"],
            "severity": spec["severity"],
            "affected_count": len(affected_host_list),
            "affected_hosts": affected_host_list,
            "description": spec["description_template"].format(n=len(affected_host_list)),
            "mitre": spec.get("mitre"),
            "recommendation": spec["recommendation"],
        })
    return detected_patterns
