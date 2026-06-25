import json
import logging
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)


def _read_json_lines(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        logger.warning("File not found: %s", path)
        return []
    records = []
    with open(p) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("JSON parse error at %s:%d", path, i)
    return records


def parse_conn_log(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        results.append({
            "src_ip": rec.get("id.orig_h"),
            "dst_ip": rec.get("id.resp_h"),
            "dst_port": rec.get("id.resp_p"),
            "proto": rec.get("proto"),
            "service": rec.get("service"),
            "ts": rec.get("ts"),
            "duration": rec.get("duration"),
            "orig_bytes": rec.get("orig_bytes"),
            "resp_bytes": rec.get("resp_bytes"),
            "orig_pkts": rec.get("orig_pkts"),
            "resp_pkts": rec.get("resp_pkts"),
        })
    return results


def parse_weird_log(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        results.append({
            "src_ip": rec.get("id.orig_h"),
            "dst_ip": rec.get("id.resp_h"),
            "name": rec.get("name"),
            "ts": rec.get("ts"),
        })
    return results


def parse_http_log(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        results.append({
            "src_ip": rec.get("id.orig_h"),
            "dst_ip": rec.get("id.resp_h"),
            "method": rec.get("method"),
            "host": rec.get("host"),
            "uri": rec.get("uri"),
            "user_agent": rec.get("user_agent"),
            "status_code": rec.get("status_code"),
            "ts": rec.get("ts"),
        })
    return results


def parse_dns_log(path: str) -> list[dict]:
    results = []
    query_counts: Counter = Counter()
    for rec in _read_json_lines(path):
        query = rec.get("query")
        if query:
            query_counts[query] += 1
        results.append({
            "src_ip": rec.get("id.orig_h"),
            "query": query,
            "ts": rec.get("ts"),
        })
    for entry in results:
        q = entry["query"]
        entry["query_count"] = query_counts.get(q, 0) if q else 0
    return results


def parse_files_log(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        results.append({
            "src_ip": rec.get("id.orig_h"),
            "dst_ip": rec.get("id.resp_h"),
            "sha256": rec.get("sha256"),
            "md5": rec.get("md5"),
            "file_size": rec.get("seen_bytes") or rec.get("total_bytes"),
            "mime_type": rec.get("mime_type"),
        })
    return results


def parse_suricata_eve(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        if rec.get("event_type") != "alert":
            continue
        alert = rec.get("alert", {})
        results.append({
            "signature_id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "severity": alert.get("severity"),
            "src_ip": rec.get("src_ip"),
            "dest_ip": rec.get("dest_ip"),
            "dest_port": rec.get("dest_port"),
            "proto": rec.get("proto"),
            "timestamp": rec.get("timestamp"),
        })
    return results


def parse_dhcp_log(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        src_ip = rec.get("client_addr") or rec.get("assigned_addr")
        results.append({
            "src_ip": src_ip,
            "mac_address": rec.get("mac"),
            "host_name": rec.get("host_name"),
            "ts": rec.get("ts"),
        })
    return results


def parse_kerberos_log(path: str) -> list[dict]:
    results = []
    for rec in _read_json_lines(path):
        client = rec.get("client", "")
        username = client.split("/")[0] if client else None
        results.append({
            "src_ip": rec.get("id.orig_h"),
            "username": username,
            "ts": rec.get("ts"),
        })
    return results


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Parse Zeek/Suricata logs")
    ap.add_argument("--output-dir", default="output", help="Zeek log directory")
    ap.add_argument("--suricata-dir", default="suricata_output", help="Suricata log directory")
    args = ap.parse_args()

    od = args.output_dir
    sd = args.suricata_dir

    for name, func, path in [
        ("conn.log", parse_conn_log, f"{od}/conn.log"),
        ("weird.log", parse_weird_log, f"{od}/weird.log"),
        ("http.log", parse_http_log, f"{od}/http.log"),
        ("dns.log", parse_dns_log, f"{od}/dns.log"),
        ("files.log", parse_files_log, f"{od}/files.log"),
        ("eve.json (alerts)", parse_suricata_eve, f"{sd}/eve.json"),
        ("dhcp.log", parse_dhcp_log, f"{od}/dhcp.log"),
        ("kerberos.log", parse_kerberos_log, f"{od}/kerberos.log"),
    ]:
        result = func(path)
        print(f"[{name}] {len(result)}건 파싱됨")
        if result:
            print(f"  예시: {json.dumps(result[0], ensure_ascii=False)}")
