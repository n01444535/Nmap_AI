# EN: Handle ports that Nmap could not name.
# VI: Xử lý các cổng mà Nmap chưa gọi được tên.

from pathlib import Path

from constants import (
    EPHEMERAL_PORT_MIN, MEDIA_SERVICE_PORTS, UNCOMMON_PORT_MIN,
    CONFIDENCE_NO_INFO, CONFIDENCE_EPHEMERAL_PORT, CONFIDENCE_MACOS_DYNAMIC,
    CONFIDENCE_APPLE_CONTINUITY, CONFIDENCE_MEDIA_STREAMING, CONFIDENCE_MEDIA_DYNAMIC,
    CONFIDENCE_PRINTER, CONFIDENCE_WEB_ADMIN, CONFIDENCE_MAX,
)
from parser_nmap import parse_nmap_service_scan
from scanner import run_unknown_port_scan


UNKNOWN_NAMES = {"", "unknown"}


# EN: Check if a port has no good service name.
# VI: Kiểm tra cổng chưa có tên dịch vụ rõ.
def is_unknown_port(port_info):
    return (port_info.get("service", "") or "").strip().lower() in UNKNOWN_NAMES


# EN: Check if an unknown port already has extra info.
# VI: Kiểm tra cổng lạ đã có thông tin thêm chưa.
def has_unknown_enrichment(port_info):
    if port_info.get("service_source") == "nmap_enriched":
        return True
    return bool(
        port_info.get("service_guess")
        or port_info.get("device_guess")
        or port_info.get("guess_evidence")
    )


# EN: See if any record still has unnamed ports.
# VI: Xem còn cổng chưa có tên trong dữ liệu không.
def records_need_unknown_enrichment(records):
    for record in records:
        for port_info in record.get("open_ports", []):
            if is_unknown_port(port_info) and not has_unknown_enrichment(port_info):
                return True
    return False


# EN: Mark where each service name came from.
# VI: Đánh dấu tên dịch vụ đến từ đâu.
def set_default_service_sources(records):
    for record in records:
        for port_info in record.get("open_ports", []):
            if port_info.get("service_source"):
                continue
            port_info["service_source"] = "guess" if is_unknown_port(port_info) else "nmap"
    return records


# EN: Group unnamed ports by host IP.
# VI: Gom cổng chưa có tên theo từng IP.
def collect_unknown_ports_by_host(records, only_missing_enrichment=True):
    targets = {}
    for record in records:
        ip = record.get("ip", "")
        if not ip:
            continue
        ports = []
        for port_info in record.get("open_ports", []):
            if not is_unknown_port(port_info):
                continue
            if only_missing_enrichment and has_unknown_enrichment(port_info):
                continue
            ports.append(port_info.get("port"))
        if ports:
            targets[ip] = sorted(set(int(port) for port in ports if port))
    return targets


# EN: Join script text so guessing can read it.
# VI: Ghép chữ script để phần đoán đọc được.
def script_text(port_info):
    script_tokens = []
    for script in port_info.get("scripts", []) or []:
        script_tokens.append(script.get("id", ""))
        script_tokens.append(script.get("output", ""))
    return " ".join(script_tokens).lower()


# EN: Collect host clues into one text.
# VI: Gom manh mối của máy vào một đoạn chữ.
def host_context_text(record):
    context_tokens = [record.get("hostname", ""), record.get("vendor", "")]
    for os_match in record.get("os_matches", []) or []:
        context_tokens.append(os_match.get("name", ""))
    for port_info in record.get("open_ports", []):
        context_tokens.extend(
            [
                port_info.get("service", ""),
                port_info.get("product", ""),
                port_info.get("version", ""),
                port_info.get("extrainfo", ""),
                script_text(port_info),
            ]
        )
    return " ".join(context_tokens).lower()


# EN: Guess the service and device for an unnamed port.
# VI: Đoán dịch vụ và loại máy cho cổng chưa có tên.
def guess_unknown_port(record, port_info):
    port = int(port_info.get("port", 0) or 0)
    context = host_context_text(record)
    open_ports = {int(p.get("port", 0) or 0) for p in record.get("open_ports", [])}
    services = {(p.get("service", "") or "").lower() for p in record.get("open_ports", [])}

    evidence = []
    service_guess = "unknown-service"
    device_guess = "unknown device"
    confidence = CONFIDENCE_NO_INFO

    apple_indicators = ["mac", "macbook", "mbp", "imac", "iphone", "ipad", "apple", "airtunes", "airplay", "eppc"]
    has_apple = any(token in context for token in apple_indicators) or 3031 in open_ports or "eppc" in services
    has_media = any(token in context for token in ["rtsp", "airtunes", "airplay", "upnp", "camera", "camstream"])
    has_printer = any(token in context for token in ["printer", "cups", "ipp"]) or 631 in open_ports
    has_web_admin = bool(open_ports & {80, 443, 5000, 5601, 8080, 8443, 9000})

    if port >= EPHEMERAL_PORT_MIN:
        service_guess = "ephemeral-local-service"
        confidence = CONFIDENCE_EPHEMERAL_PORT
        evidence.append("port is in the dynamic/private range 49152-65535")

    if has_apple:
        device_guess = "Apple/macOS device"
        evidence.append("host has Apple/macOS indicators from hostname, services, or scripts")
        if port >= EPHEMERAL_PORT_MIN:
            service_guess = "macos-dynamic-service"
            confidence = max(confidence, CONFIDENCE_MACOS_DYNAMIC)
        elif has_media:
            service_guess = "apple-continuity"
            confidence = max(confidence, CONFIDENCE_APPLE_CONTINUITY)

    if has_media and not has_apple:
        device_guess = "camera/IoT/media device"
        evidence.append("neighboring services or scripts include RTSP, AirTunes, UPnP, or camera-like signals")
        if port in MEDIA_SERVICE_PORTS:
            service_guess = "media-streaming-service"
            confidence = max(confidence, CONFIDENCE_MEDIA_STREAMING)
        elif port >= EPHEMERAL_PORT_MIN:
            service_guess = "media-device-dynamic-service"
            confidence = max(confidence, CONFIDENCE_MEDIA_DYNAMIC)

    if has_printer and not has_apple and not has_media:
        device_guess = "printer"
        service_guess = "printer-related-service" if port >= UNCOMMON_PORT_MIN else service_guess
        confidence = max(confidence, CONFIDENCE_PRINTER)
        evidence.append("host has printer or IPP/CUPS indicators")

    if device_guess == "unknown device" and has_web_admin:
        device_guess = "network appliance or web-managed device"
        confidence = max(confidence, CONFIDENCE_WEB_ADMIN)
        evidence.append("host exposes common web or admin ports")

    if not evidence:
        evidence.append("Nmap confirmed the port is open but did not return service metadata")

    return {
        "service_source": "guess",
        "service_guess": service_guess,
        "device_guess": device_guess,
        "guess_confidence": round(min(confidence, CONFIDENCE_MAX), 2),
        "guess_evidence": "; ".join(evidence),
    }


# EN: Add guesses to all still-unknown ports.
# VI: Thêm dự đoán cho các cổng vẫn chưa biết.
def apply_unknown_port_guesses(records):
    set_default_service_sources(records)
    for record in records:
        for port_info in record.get("open_ports", []):
            if is_unknown_port(port_info):
                port_info.update(guess_unknown_port(record, port_info))
    return records


# EN: Merge better Nmap names back into old records.
# VI: Gộp tên Nmap tốt hơn vào dữ liệu cũ.
def merge_enriched_records(records, enriched_records):
    by_host = {record.get("ip", ""): record for record in enriched_records}
    for record in records:
        enriched_record = by_host.get(record.get("ip", ""))
        if not enriched_record:
            continue
        enriched_ports = {
            (p.get("protocol", ""), int(p.get("port", 0) or 0)): p
            for p in enriched_record.get("open_ports", [])
        }
        for port_info in record.get("open_ports", []):
            key = (port_info.get("protocol", ""), int(port_info.get("port", 0) or 0))
            enriched_port = enriched_ports.get(key)
            if not enriched_port:
                continue
            enriched_service = (enriched_port.get("service", "") or "").strip().lower()
            if enriched_service in UNKNOWN_NAMES:
                continue
            port_info.setdefault("original_service", port_info.get("service", ""))
            for field in [
                "service",
                "product",
                "version",
                "extrainfo",
                "service_method",
                "service_confidence",
                "service_ostype",
                "tunnel",
                "state_reason",
                "scripts",
            ]:
                port_info[field] = enriched_port.get(field, "" if field != "scripts" else [])
            port_info["service_source"] = "nmap_enriched"
            port_info.pop("service_guess", None)
            port_info.pop("device_guess", None)
            port_info.pop("guess_confidence", None)
            port_info.pop("guess_evidence", None)
    return records


# EN: Scan and guess details for unnamed ports.
# VI: Quét và đoán thêm cho cổng chưa có tên.
def enrich_unknown_ports(records, data_dir, skip_scan=False, allow_nmap=True):
    set_default_service_sources(records)
    if not records_need_unknown_enrichment(records):
        return records, {"ran_scan": False, "unknown_hosts": 0, "unknown_ports": 0}

    targets = collect_unknown_ports_by_host(records)
    scan_meta = {
        "ran_scan": False,
        "unknown_hosts": len(targets),
        "unknown_ports": sum(len(ports) for ports in targets.values()),
        "errors": [],
    }

    if targets and not skip_scan and allow_nmap:
        all_enriched_records = []
        for ip, ports in targets.items():
            safe_ip = ip.replace(":", "_").replace(".", "_")
            output_xml = Path(data_dir) / f"unknown_port_scan_{safe_ip}.xml"
            if len(targets) == 1:
                output_xml = Path(data_dir) / "unknown_port_scan.xml"
            try:
                run_unknown_port_scan(ip, ports, str(output_xml))
                all_enriched_records.extend(parse_nmap_service_scan(str(output_xml)))
            except KeyboardInterrupt:
                raise
            except Exception as e:
                scan_meta["errors"].append(f"{ip}: {str(e)}")
        if all_enriched_records:
            merge_enriched_records(records, all_enriched_records)
            scan_meta["ran_scan"] = True

    apply_unknown_port_guesses(records)
    return records, scan_meta
