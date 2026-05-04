# EN: Save scan results so later runs can be faster.
# VI: Lưu kết quả quét để lần sau chạy nhanh hơn.

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

SCAN_PROFILE_VERSION = "deep-port-v2"
CACHE_FILE = "scan_cache.json"
LEARNED_FILE = "learned_records.json"
LATEST_FULL_RESULT_FILE = "latest_full_result.json"


# EN: Make a clean UTC time string.
# VI: Tạo dòng thời gian UTC gọn gàng.
def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# EN: Make a timestamp that is safe for file names.
# VI: Tạo thời gian an toàn để đặt tên file.
def safe_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# EN: Read JSON or return a safe default value.
# VI: Đọc JSON hoặc trả về giá trị mặc định an toàn.
def read_json(path, default):
    path = Path(path)
    if not path.exists():
        return deepcopy(default)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return deepcopy(default)


# EN: Write data as a JSON file.
# VI: Ghi dữ liệu thành file JSON.
def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# EN: Make a unique key for one target scan.
# VI: Tạo chìa khóa riêng cho một lần quét mục tiêu.
def cache_key(target, mode="real"):
    raw = f"{SCAN_PROFILE_VERSION}|{mode}|{target}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# EN: Load a saved scan if it still matches.
# VI: Lấy scan đã lưu nếu còn đúng.
def get_cached_scan(result_dir, target, mode="real"):
    cache_path = Path(result_dir) / CACHE_FILE
    data = read_json(cache_path, {"entries": {}})
    entry = data.get("entries", {}).get(cache_key(target, mode))

    if not entry:
        return None

    if entry.get("scan_profile_version") != SCAN_PROFILE_VERSION:
        return None

    records = entry.get("records", [])
    if not isinstance(records, list):
        return None

    return entry


# EN: Save scan records for a faster next run.
# VI: Lưu dữ liệu scan để lần sau nhanh hơn.
def save_cached_scan(result_dir, target, records, mode="real", source="nmap"):
    cache_path = Path(result_dir) / CACHE_FILE
    data = read_json(cache_path, {"entries": {}})
    entries = data.setdefault("entries", {})
    key = cache_key(target, mode)

    entry = {
        "target": target,
        "mode": mode,
        "source": source,
        "saved_at": utc_now_iso(),
        "scan_profile_version": SCAN_PROFILE_VERSION,
        "host_count": len(records),
        "records": records,
    }

    entries[key] = entry
    data["updated_at"] = entry["saved_at"]
    data["scan_profile_version"] = SCAN_PROFILE_VERSION
    write_json(cache_path, data)
    return entry


# EN: Make a fingerprint for one host record.
# VI: Tạo dấu tay cho một máy.
def record_signature(record):
    ports = []
    for port_info in record.get("open_ports", []):
        ports.append(
            (
                port_info.get("protocol", ""),
                int(port_info.get("port", 0)),
                port_info.get("service", ""),
                port_info.get("product", ""),
                port_info.get("version", ""),
            )
        )
    ports = sorted(ports)
    raw = json.dumps(
        {
            "ip": record.get("ip", ""),
            "hostname": record.get("hostname", ""),
            "ports": ports,
        },
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# EN: Remove repeated host records.
# VI: Bỏ các máy bị lặp.
def dedupe_records(records):
    seen = set()
    deduped = []
    for record in records:
        signature = record_signature(record)
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(record)
    return deduped


# EN: Load records remembered from older scans.
# VI: Lấy dữ liệu máy đã nhớ từ lần quét cũ.
def load_learned_records(result_dir):
    path = Path(result_dir) / LEARNED_FILE
    data = read_json(path, {"records": []})
    records = []
    for item in data.get("records", []):
        record = item.get("record")
        if isinstance(record, dict):
            records.append(record)
    return records


# EN: Store current records in learning memory.
# VI: Lưu dữ liệu hiện tại vào bộ nhớ học.
def remember_records(result_dir, records, source="full"):
    path = Path(result_dir) / LEARNED_FILE
    data = read_json(path, {"records": []})
    existing = {}

    for item in data.get("records", []):
        record = item.get("record")
        if not isinstance(record, dict):
            continue
        signature = item.get("signature") or record_signature(record)
        existing[signature] = item

    now = utc_now_iso()
    for record in records:
        signature = record_signature(record)
        previous = existing.get(signature, {})
        existing[signature] = {
            "signature": signature,
            "first_seen": previous.get("first_seen", now),
            "last_seen": now,
            "seen_count": int(previous.get("seen_count", 0)) + 1,
            "source": source,
            "record": record,
        }

    data = {
        "updated_at": now,
        "scan_profile_version": SCAN_PROFILE_VERSION,
        "records": list(existing.values()),
    }
    write_json(path, data)
    return [item["record"] for item in data["records"]]


# EN: Save one full run into latest and history files.
# VI: Lưu một lần chạy vào file mới nhất và lịch sử.
def save_full_result_snapshot(result_dir, target, mode, scan_source, records, predictions=None, extra=None):
    timestamp = safe_timestamp()
    history_dir = Path(result_dir) / "history"
    history_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "saved_at": utc_now_iso(),
        "target": target,
        "mode": mode,
        "scan_source": scan_source,
        "scan_profile_version": SCAN_PROFILE_VERSION,
        "host_count": len(records),
        "records": records,
        "predictions": predictions or [],
        "extra": extra or {},
    }

    latest_path = Path(result_dir) / LATEST_FULL_RESULT_FILE
    history_path = history_dir / f"full_scan_{timestamp}.json"
    write_json(latest_path, payload)
    write_json(history_path, payload)
    return history_path
