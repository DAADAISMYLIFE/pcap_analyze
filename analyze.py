import argparse
import json
import logging
import sys
import time
from pathlib import Path

from core import run_all, normalize_evidence, calculate_base_score

logger = logging.getLogger(__name__)


def main():
    ap = argparse.ArgumentParser(description="pcap 보안 분석 파이프라인")
    ap.add_argument("--pcap-dir", default="input", help="pcap 파일 디렉터리")
    ap.add_argument("--pcap", default=None, help="단일 pcap 파일 경로 (--pcap-dir 대신)")
    ap.add_argument("--output-dir", default="output", help="Zeek 로그 출력 디렉터리")
    ap.add_argument("--suricata-dir", default="suricata_output", help="Suricata 로그 출력 디렉터리")
    ap.add_argument("--suricata-config", default="/etc/suricata/suricata.yaml", help="Suricata 설정 파일 경로")
    ap.add_argument("--rules-dir", default=None, help="Suricata 룰 디렉터리 (CVE 매핑용)")
    ap.add_argument("--result", default="evidence.json", help="최종 결과 JSON 경로")
    ap.add_argument("--skip-run", action="store_true", help="Zeek/Suricata 실행 건너뛰기 (기존 로그 사용)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    od = args.output_dir
    sd = args.suricata_dir

    # 1. Zeek/Suricata 실행
    if not args.skip_run:
        if args.pcap:
            pcaps = [args.pcap]
        else:
            pcaps = sorted(str(p) for p in Path(args.pcap_dir).glob("*.pcap"))
            if not pcaps:
                logger.error("pcap 파일 없음: %s", args.pcap_dir)
                sys.exit(1)

        print(f"[1/4] Zeek/Suricata 실행 ({len(pcaps)}개 pcap)")
        for pcap in pcaps:
            results = run_all(pcap, od, sd, suricata_config=args.suricata_config)
            for tool, success in results.items():
                status = "OK" if success else "FAILED (기존 로그 사용)"
                print(f"  {tool}: {status}")
    else:
        print("[1/4] Zeek/Suricata 실행 건너뜀 (--skip-run)")

    # 2. 정규화
    print("[2/4] 로그 파싱 및 정규화")
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

    # 3. 점수 계산
    print("[3/4] 위험도 점수 계산")
    scores = calculate_base_score(evidence)
    print(f"  {len(scores)}개 IP 점수 산출")

    # 4. 결과 저장
    output = {
        "evidence": evidence,
        "scores": scores,
    }
    with open(args.result, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[4/4] 결과 저장: {args.result}")

    # 요약
    print(f"\n{'='*60}")
    print("분석 완료")
    print(f"{'='*60}")
    if scores:
        for ip, data in scores.items():
            print(f"  [{ip}] score: {data['score']}")
            for r in data["reasons"]:
                print(f"    - {r}")
    else:
        print("  위험 IP 없음")


if __name__ == "__main__":
    main()
