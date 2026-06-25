import json
import logging
from datetime import datetime, timezone

import requests

import config
from llm_judge import compress_evidence, filter_low_priority

logger = logging.getLogger(__name__)


def _parse_ts(ts_value) -> float:
    if ts_value is None:
        return 0.0
    if isinstance(ts_value, (int, float)):
        return float(ts_value)
    try:
        dt = datetime.fromisoformat(ts_value)
        return dt.timestamp()
    except (ValueError, TypeError):
        pass
    import re
    m = re.match(r"(.+?)([+-]\d{4})$", ts_value)
    if m:
        try:
            fixed = m.group(1) + m.group(2)[:3] + ":" + m.group(2)[3:]
            dt = datetime.fromisoformat(fixed)
            return dt.timestamp()
        except (ValueError, TypeError):
            pass
    return 0.0


def _format_ts(epoch: float) -> str:
    if epoch <= 0:
        return "??:??:??"
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%H:%M:%S")


def build_timeline(evidence_data: dict, target_ips: list[str]) -> list[dict]:
    src = evidence_data.get("evidence", evidence_data)
    target_set = set(target_ips)
    events = []

    for a in src.get("signature_alerts", []):
        if a.get("src_ip") in target_set or a.get("dest_ip") in target_set:
            events.append({
                "ts": _parse_ts(a.get("timestamp")),
                "type": "signature_alert",
                "detail": f"[{a.get('severity', '?')}] {a.get('signature', '?')} ({a.get('src_ip')} -> {a.get('dest_ip')})",
            })

    for c in src.get("content_indicators", []):
        if c.get("src_ip") in target_set or c.get("dst_ip") in target_set:
            if c.get("type") == "http_download":
                detail = f"HTTP {c.get('method', '?')} {c.get('url', '?')} ({c.get('src_ip')} -> {c.get('dst_ip')}) ua={c.get('user_agent', '?')}"
            elif c.get("type") == "dns_query":
                detail = f"DNS query: {c.get('query', '?')} (x{c.get('query_count', 1)}) from {c.get('src_ip')}"
            else:
                detail = f"{c.get('type')}: {c.get('src_ip')} -> {c.get('dst_ip')}"
            events.append({
                "ts": _parse_ts(c.get("ts")),
                "type": c.get("type", "content"),
                "detail": detail,
            })

    for a in src.get("anomalies", []):
        if a.get("src_ip") in target_set or a.get("dst_ip") in target_set:
            events.append({
                "ts": _parse_ts(a.get("ts")),
                "type": "anomaly",
                "detail": f"anomaly: {a.get('name', '?')} ({a.get('src_ip')} -> {a.get('dst_ip')})",
            })

    events.sort(key=lambda e: e["ts"])
    return events


def _build_report_prompt(judgments: list[dict], timeline: list[dict], evidence_data: dict) -> str:
    src = evidence_data.get("evidence", evidence_data)
    host_id = src.get("host_identification", [])

    timeline_text = "\n".join(
        f"  {_format_ts(e['ts'])} - {e['detail']}" for e in timeline
    )

    return f"""다음 보안 분석 결과를 기반으로 인시던트 리포트를 작성하라.

[판단 결과]
{json.dumps(judgments, ensure_ascii=False, indent=2)}

[호스트 식별 정보]
{json.dumps(host_id, ensure_ascii=False, indent=2)}

[타임라인 — 시간순 이벤트 목록]
{timeline_text}

[리포트 형식 — 반드시 이 5개 섹션 순서대로 작성]
1. 요약: 전체 인시던트의 핵심을 2-3문장으로 요약
2. 타임라인: 위 타임라인 데이터의 순서를 바꾸지 말고 그대로 시간순 흐름으로 서술하라. 임의로 재구성하지 마라.
3. 감염 호스트별 상세: 각 감염 호스트의 hostname, username, MAC, 탐지된 시그니처, confidence, case_type
4. 공격자/C2 IP 목록: 외부 IP 주소 나열 및 해당 IP와의 통신 패턴
5. 권장 조치: 즉시 수행할 대응 조치 목록

한국어로 작성하라. 마크다운 형식으로 작성하라."""


def generate_incident_report(judgments: list[dict], evidence_data: dict, model: str = None, mock: bool = False) -> str:
    model = model or config.MODEL_NAME

    target_ips = [j["src_ip"] for j in judgments if j.get("is_attack") is True or j.get("is_attack") == "uncertain"]
    timeline = build_timeline(evidence_data, target_ips)
    print(f"[리포트] 타임라인: {len(timeline)}개 이벤트, 대상 IP: {len(target_ips)}개")

    prompt = _build_report_prompt(judgments, timeline, evidence_data)

    if mock:
        return f"""# 인시던트 리포트 (Mock)

## 1. 요약
{len(target_ips)}개 호스트에서 의심스러운 활동 탐지. 도구 조회 결과 없어 확정 불가 (Case B).

## 2. 타임라인
""" + "\n".join(f"- {_format_ts(e['ts'])} — {e['detail']}" for e in timeline[:20]) + f"""
... (총 {len(timeline)}개 이벤트)

## 3. 감염 호스트별 상세
""" + "\n".join(f"- **{j['src_ip']}**: confidence={j['confidence']}, case_type={j['case_type']}, attack_type={j.get('attack_type')}" for j in judgments) + """

## 4. 공격자/C2 IP 목록
(도구 조회 결과 없음 — CTI DB 연동 필요)

## 5. 권장 조치
- 해당 호스트 네트워크 격리
- 포렌식 이미지 확보
- 외부 IP 방화벽 차단
- CTI DB 연동 후 재분석
"""

    messages = [
        {"role": "system", "content": "너는 보안 인시던트 리포트를 작성하는 전문가다. 주어진 분석 결과와 타임라인을 기반으로 정확하고 실행 가능한 리포트를 작성한다."},
        {"role": "user", "content": prompt},
    ]

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "num_ctx": config.NUM_CTX,
            "num_predict": config.NUM_PREDICT,
        },
    }

    resp = requests.post(f"{config.OLLAMA_HOST}/api/chat", json=payload, timeout=300)
    resp.raise_for_status()
    return resp.json().get("message", {}).get("content", "")


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="인시던트 리포트 생성")
    ap.add_argument("--evidence", default="evidence.json")
    ap.add_argument("--judgments", default=None, help="판단 결과 JSON 파일")
    ap.add_argument("--mock", action="store_true")
    args = ap.parse_args()

    with open(args.evidence) as f:
        evidence_data = json.load(f)

    if args.judgments:
        with open(args.judgments) as f:
            judgments = json.load(f)
    else:
        from llm_judge import judge_evidence
        result = judge_evidence(evidence_data, mock=args.mock)
        judgments = result["validated_output"]

    report = generate_incident_report(judgments, evidence_data, mock=args.mock)
    print(report)
