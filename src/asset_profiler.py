# EN: Infer device role from open ports and service feature flags.
# VI: Suy ra vai trò thiết bị từ cổng mở và cờ dịch vụ.

ASSET_CONTAINER_HOST = "container_host"
ASSET_DATABASE_SERVER = "database_server"
ASSET_FILE_SERVER = "file_server"
ASSET_MAIL_SERVER = "mail_server"
ASSET_NETWORK_DEVICE = "network_device"
ASSET_PRINTER = "printer"
ASSET_IOT_CAMERA = "iot_camera"
ASSET_IOT_DEVICE = "iot_device"
ASSET_WORKSTATION = "workstation"
ASSET_SERVER = "server"
ASSET_UNKNOWN = "unknown"

MAX_PORTS_FOR_NETWORK_DEVICE = 5
MIN_DB_PORTS_FOR_DB_SERVER = 2

# EN: Return a short label for the device type.
# VI: Trả về nhãn ngắn cho loại thiết bị.
def classify_asset(row):
    if row.get("has_docker", 0) == 1 or row.get("has_kubernetes_api", 0) == 1:
        return ASSET_CONTAINER_HOST

    if row.get("db_count", 0) >= MIN_DB_PORTS_FOR_DB_SERVER:
        return ASSET_DATABASE_SERVER

    if row.get("has_printer", 0) == 1:
        return ASSET_PRINTER

    if row.get("has_rtsp", 0) == 1:
        return ASSET_IOT_CAMERA

    if row.get("has_mqtt", 0) == 1:
        return ASSET_IOT_DEVICE

    if row.get("fileshare_count", 0) >= 2:
        return ASSET_FILE_SERVER

    if row.get("has_smtp", 0) == 1:
        return ASSET_MAIL_SERVER

    if (
        row.get("has_snmp", 0) == 1
        and row.get("open_port_count", 0) <= MAX_PORTS_FOR_NETWORK_DEVICE
    ):
        return ASSET_NETWORK_DEVICE

    has_server_profile = row.get("has_ssh", 0) == 1 or row.get("has_http", 0) == 1
    has_remote_desktop = row.get("has_rdp", 0) == 1 or row.get("has_vnc", 0) == 1

    if has_remote_desktop and not has_server_profile:
        return ASSET_WORKSTATION

    if has_server_profile:
        return ASSET_SERVER

    if has_remote_desktop:
        return ASSET_WORKSTATION

    return ASSET_UNKNOWN
