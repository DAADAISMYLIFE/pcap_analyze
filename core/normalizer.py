import logging
from collections import defaultdict

from .parsers import (
    parse_conn_log,
    parse_weird_log,
    parse_http_log,
    parse_dns_log,
    parse_files_log,
    parse_suricata_eve,
    parse_dhcp_log,
    parse_kerberos_log,
)
from .cve_mapper import build_cve_lookup, apply_cve_mapping
from .beacon_detector import detect_beaconing

logger = logging.getLogger(__name__)


def _build_content_indicators(http_entries: list[dict], dns_entries: list[dict], files_entries: list[dict]) -> list[dict]:
    indicators = []

    file_by_pair = defaultdict(list)
    for f in files_entries:
        key = (f.get("src_ip"), f.get("dst_ip"))
        file_by_pair[key].append(f)

    for h in http_entries:
        pair = (h.get("src_ip"), h.get("dst_ip"))
        matched_files = file_by_pair.get(pair, [])
        file_hash = None
        mime_type = None
        for f in matched_files:
            if f.get("sha256") or f.get("md5"):
                file_hash = f.get("sha256") or f.get("md5")
                mime_type = f.get("mime_type")
                break
        if not mime_type and matched_files:
            mime_type = matched_files[0].get("mime_type")

        indicators.append({
            "type": "http_download",
            "src_ip": h.get("src_ip"),
            "dst_ip": h.get("dst_ip"),
            "url": h.get("uri", "") if h.get("uri", "").startswith("http") else f"{h.get('host', '')}{h.get('uri', '')}",
            "method": h.get("method"),
            "user_agent": h.get("user_agent"),
            "status_code": h.get("status_code"),
            "file_hash": file_hash,
            "mime_type": mime_type,
            "ts": h.get("ts"),
        })

    seen_queries = {}
    for d in dns_entries:
        query = d.get("query")
        if not query:
            continue
        if query in seen_queries:
            continue
        seen_queries[query] = True
        indicators.append({
            "type": "dns_query",
            "src_ip": d.get("src_ip"),
            "dst_ip": None,
            "query": query,
            "query_count": d.get("query_count", 0),
            "ts": d.get("ts"),
        })

    return indicators


def _build_host_identification(dhcp_entries: list[dict], kerberos_entries: list[dict]) -> list[dict]:
    hosts = defaultdict(lambda: {"src_ip": None, "mac_address": None, "hostname": None, "username": None})

    for d in dhcp_entries:
        ip = d.get("src_ip")
        if not ip:
            continue
        hosts[ip]["src_ip"] = ip
        if d.get("mac_address"):
            hosts[ip]["mac_address"] = d["mac_address"]
        if d.get("host_name"):
            hosts[ip]["hostname"] = d["host_name"]

    for k in kerberos_entries:
        ip = k.get("src_ip")
        if not ip:
            continue
        hosts[ip]["src_ip"] = ip
        if k.get("username"):
            hosts[ip]["username"] = k["username"]

    return list(hosts.values())


def normalize_evidence(
    conn_log_path: str,
    weird_log_path: str,
    http_log_path: str,
    dns_log_path: str,
    files_log_path: str,
    eve_json_path: str,
    rules_dir: str = None,
    dhcp_log_path: str = None,
    kerberos_log_path: str = None,
) -> dict:
    flows = parse_conn_log(conn_log_path)
    logger.info("flows: %d건", len(flows))

    anomalies = parse_weird_log(weird_log_path)
    logger.info("anomalies: %d건", len(anomalies))

    alerts = parse_suricata_eve(eve_json_path)
    if rules_dir:
        cve_lookup = build_cve_lookup(rules_dir)
        alerts = apply_cve_mapping(alerts, cve_lookup)
    else:
        for a in alerts:
            a["cve"] = None
    logger.info("signature_alerts: %d건", len(alerts))

    behavioral = detect_beaconing(flows)
    logger.info("behavioral_alerts: %d건", len(behavioral))

    http_entries = parse_http_log(http_log_path)
    dns_entries = parse_dns_log(dns_log_path)
    files_entries = parse_files_log(files_log_path)
    content = _build_content_indicators(http_entries, dns_entries, files_entries)
    logger.info("content_indicators: %d건", len(content))

    dhcp_entries = parse_dhcp_log(dhcp_log_path) if dhcp_log_path else []
    kerberos_entries = parse_kerberos_log(kerberos_log_path) if kerberos_log_path else []
    host_id = _build_host_identification(dhcp_entries, kerberos_entries)
    logger.info("host_identification: %d건", len(host_id))

    return {
        "flows": flows,
        "anomalies": anomalies,
        "signature_alerts": alerts,
        "behavioral_alerts": behavioral,
        "content_indicators": content,
        "host_identification": host_id,
        "extra_metadata": {},
    }


if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Normalize all evidence into single JSON")
    ap.add_argument("--output-dir", default="output", help="Zeek log directory")
    ap.add_argument("--suricata-dir", default="suricata_output", help="Suricata log directory")
    ap.add_argument("--rules-dir", default=None, help="Suricata rules directory for CVE mapping")
    ap.add_argument("--out", default=None, help="Output JSON file path")
    args = ap.parse_args()

    od = args.output_dir
    sd = args.suricata_dir

    evidence = normalize_evidence(
        conn_log_path=f"{od}/conn.log",
        weird_log_path=f"{od}/weird.log",
        http_log_path=f"{od}/http.log",
        dns_log_path=f"{od}/dns.log",
        files_log_path=f"{od}/files.log",
        eve_json_path=f"{sd}/eve.json",
        rules_dir=args.rules_dir,
        dhcp_log_path=f"{od}/dhcp.log",
        kerberos_log_path=f"{od}/kerberos.log",
    )

    for key, val in evidence.items():
        if isinstance(val, list):
            print(f"  {key}: {len(val)}건")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(evidence, f, indent=2, ensure_ascii=False)
        print(f"\n저장: {args.out}")
