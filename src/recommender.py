# EN: Create simple security advice for each host.
# VI: Tạo lời khuyên bảo mật dễ hiểu cho từng máy.

from constants import (
    MIN_FILESHARE_COUNT_THRESHOLD, MIN_CLEARTEXT_COUNT_THRESHOLD,
    MIN_ADMIN_PORT_COUNT_THRESHOLD, MIN_OPEN_PORT_COUNT_THRESHOLD,
    MIN_UNCOMMON_PORT_COUNT_THRESHOLD,
)

# EN: Choose advice based on one host row.
# VI: Chọn lời khuyên dựa trên một dòng máy.
def recommend_for_row(row):
    recs = []
    if row.get("has_telnet", 0) == 1:
        recs.append("Disable Telnet and replace it with SSH")
    if row.get("has_ftp", 0) == 1:
        recs.append("Disable plain FTP or restrict it behind VPN and strong authentication")
    if row.get("has_smb", 0) == 1 or row.get("fileshare_count", 0) >= MIN_FILESHARE_COUNT_THRESHOLD:
        recs.append("Review SMB or file-sharing exposure and restrict it to trusted subnets")
    if row.get("has_rpcbind", 0) == 1:
        recs.append("Restrict RPC services and verify they are required")
    if row.get("has_tftp", 0) == 1:
        recs.append("Disable TFTP unless it is isolated to a trusted provisioning network")
    if row.get("has_snmp", 0) == 1:
        recs.append("Use SNMPv3 and restrict SNMP polling to trusted monitoring hosts")
    if row.get("has_redis", 0) == 1:
        recs.append("Bind Redis to localhost or private interfaces and enable authentication")
    if row.get("has_rdp", 0) == 1 or row.get("has_vnc", 0) == 1:
        recs.append("Restrict remote desktop services with firewall rules and MFA")
    if row.get("has_winrm", 0) == 1:
        recs.append("Limit WinRM to management hosts and monitor remote administration activity")
    if row.get("has_docker", 0) == 1:
        recs.append("Do not expose the Docker API publicly; require TLS client certificates if it must be enabled")
    if row.get("has_kubernetes_api", 0) == 1:
        recs.append("Restrict Kubernetes API access and verify RBAC permissions")
    if row.get("db_count", 0) > 0:
        recs.append("Do not expose database ports publicly unless strictly necessary")
    if row.get("has_elasticsearch", 0) == 1:
        recs.append("Require authentication on Elasticsearch and restrict cluster access")
    if row.get("has_mqtt", 0) == 1:
        recs.append("Require MQTT authentication, TLS, and topic-level ACLs")
    if row.get("has_memcached", 0) == 1:
        recs.append("Bind Memcached to private interfaces and block untrusted access")
    if row.get("cleartext_count", 0) >= MIN_CLEARTEXT_COUNT_THRESHOLD:
        recs.append("Replace clear-text services with encrypted alternatives where possible")
    if row.get("admin_port_count", 0) >= MIN_ADMIN_PORT_COUNT_THRESHOLD:
        recs.append("Move administrative services behind VPN or a management subnet")
    if row.get("open_port_count", 0) >= MIN_OPEN_PORT_COUNT_THRESHOLD:
        recs.append("Reduce unnecessary exposed services and close unused ports")
    if row.get("uncommon_open_count", 0) >= MIN_UNCOMMON_PORT_COUNT_THRESHOLD:
        recs.append("Investigate uncommon high ports and validate the owning processes")
    if not recs:
        recs.append("Keep patching services, minimize exposed ports, and continue monitoring")
    return recs
