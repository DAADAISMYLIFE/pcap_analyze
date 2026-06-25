import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_SID_RE = re.compile(r"sid:(\d+)")
_CVE_RE = re.compile(r"reference:cve,(\d{4}-\d+)")


def build_cve_lookup(rules_dir: str) -> dict[int, str]:
    d = Path(rules_dir)
    try:
        if not d.exists():
            logger.warning("Rules directory not found: %s", rules_dir)
            return {}
    except PermissionError:
        logger.warning("Permission denied: %s — try: sudo chmod -R o+r %s", rules_dir, rules_dir)
        return {}

    lookup = {}
    for rules_file in sorted(d.glob("*.rules")):
        try:
            text = rules_file.read_text(errors="replace")
        except Exception as e:
            logger.warning("Failed to read %s: %s", rules_file, e)
            continue

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            sid_match = _SID_RE.search(line)
            cve_match = _CVE_RE.search(line)

            if sid_match and cve_match:
                sid = int(sid_match.group(1))
                cve = f"CVE-{cve_match.group(1)}"
                lookup[sid] = cve

    logger.info("Built CVE lookup: %d entries from %s", len(lookup), rules_dir)
    return lookup


def apply_cve_mapping(alerts: list[dict], cve_lookup: dict[int, str]) -> list[dict]:
    results = []
    for alert in alerts:
        enriched = dict(alert)
        sid = alert.get("signature_id")
        enriched["cve"] = cve_lookup.get(sid) if sid else None
        results.append(enriched)
    return results


if __name__ == "__main__":
    import json
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Build CVE lookup from Suricata rules")
    ap.add_argument("--rules-dir", default="/usr/share/suricata/rules", help="Suricata rules directory")
    ap.add_argument("--eve-json", default="suricata_output/eve.json", help="Suricata eve.json path")
    args = ap.parse_args()

    lookup = build_cve_lookup(args.rules_dir)
    print(f"\nCVE lookup: {len(lookup)}건")
    for sid, cve in lookup.items():
        print(f"  SID {sid} -> {cve}")

    from core.parsers import parse_suricata_eve
    alerts = parse_suricata_eve(args.eve_json)
    enriched = apply_cve_mapping(alerts, lookup)

    matched = [a for a in enriched if a["cve"]]
    print(f"\nAlerts: {len(enriched)}건 중 CVE 매핑됨: {len(matched)}건")
    for a in matched:
        print(f"  {a['cve']} | {a['signature']} | {a['src_ip']} -> {a['dest_ip']}")
