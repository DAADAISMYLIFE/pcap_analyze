import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    1: 0.5,
    2: 0.2,
    3: 0.05,
}

WEIGHT_CVE = 0.3
WEIGHT_BEACON = 0.2
WEIGHT_WEIRD = 0.1

KNOWN_BENIGN_SIDS = {
    2031071,  # ET INFO Microsoft Connection Test
    2200075,  # SURICATA UDPv4 invalid checksum
    2221004,  # SURICATA HTTP invalid response chunk len
    2221010,  # SURICATA HTTP unable to match response to request
    2221036,  # SURICATA HTTP Response excessive header repetition
}


def calculate_base_score(evidence: dict) -> dict[str, dict]:
    scores = defaultdict(lambda: {"score": 0.0, "reasons": []})

    for alert in evidence.get("signature_alerts", []):
        src = alert.get("src_ip")
        if not src:
            continue

        sid = alert.get("signature_id")
        if sid in KNOWN_BENIGN_SIDS:
            continue

        seen_sids = {r.get("_sid") for r in scores[src]["reasons"] if isinstance(r, dict)}
        if sid in seen_sids:
            for r in scores[src]["reasons"]:
                if isinstance(r, dict) and r.get("_sid") == sid:
                    r["count"] += 1
                    break
            continue

        severity = alert.get("severity", 3)
        weight = SEVERITY_WEIGHTS.get(severity, 0.05)
        scores[src]["score"] += weight

        reason = {
            "_sid": sid,
            "text": f"signature alert: {alert.get('signature')} (severity {severity})",
            "count": 1,
        }

        if alert.get("cve"):
            scores[src]["score"] += WEIGHT_CVE
            reason["text"] += f" [CVE: {alert['cve']}]"

        scores[src]["reasons"].append(reason)

    for b in evidence.get("behavioral_alerts", []):
        if b.get("suspected") is not True:
            continue
        src = b.get("src_ip")
        if not src:
            continue
        scores[src]["score"] += WEIGHT_BEACON
        scores[src]["reasons"].append({
            "text": f"beacon suspected: -> {b.get('dst_ip')} ({b.get('connection_count')}회, CV {b.get('cv')})",
            "count": 1,
        })

    for a in evidence.get("anomalies", []):
        src = a.get("src_ip")
        if not src:
            continue
        name = a.get("name", "")
        already = any(name in r.get("text", "") for r in scores[src]["reasons"] if isinstance(r, dict))
        if not already:
            scores[src]["score"] += WEIGHT_WEIRD
            scores[src]["reasons"].append({
                "text": f"anomaly: {name}",
                "count": 1,
            })

    result = {}
    for ip, data in scores.items():
        reasons_formatted = []
        for r in data["reasons"]:
            if r["count"] > 1:
                reasons_formatted.append(f"{r['text']} (x{r['count']})")
            else:
                reasons_formatted.append(r["text"])
        result[ip] = {
            "score": round(data["score"], 2),
            "reasons": reasons_formatted,
        }

    return dict(sorted(result.items(), key=lambda x: x[1]["score"], reverse=True))


if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Calculate risk scores from normalized evidence")
    ap.add_argument("--evidence", default=None, help="Path to evidence JSON file")
    ap.add_argument("--output-dir", default="output", help="Zeek log directory")
    ap.add_argument("--suricata-dir", default="suricata_output", help="Suricata log directory")
    ap.add_argument("--rules-dir", default=None, help="Suricata rules directory")
    args = ap.parse_args()

    if args.evidence:
        with open(args.evidence) as f:
            evidence = json.load(f)
    else:
        from core.normalizer import normalize_evidence
        od = args.output_dir
        sd = args.suricata_dir
        evidence = normalize_evidence(
            f"{od}/conn.log", f"{od}/weird.log", f"{od}/http.log",
            f"{od}/dns.log", f"{od}/files.log", f"{sd}/eve.json",
            rules_dir=args.rules_dir,
        )

    scores = calculate_base_score(evidence)
    print(f"\n위험도 점수 ({len(scores)}개 IP)")
    print("-" * 60)
    for ip, data in scores.items():
        print(f"\n[{ip}] score: {data['score']}")
        for r in data["reasons"]:
            print(f"  - {r}")
