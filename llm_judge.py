import copy
import json
import logging
from collections import defaultdict

import requests

import config
from tools import TOOL_SCHEMAS, AVAILABLE_TOOLS

logger = logging.getLogger(__name__)


def compress_evidence(evidence_data: dict) -> dict:
    src = evidence_data.get("evidence", evidence_data)

    compressed = {}

    for passthrough_key in ("host_identification", "extra_metadata"):
        if passthrough_key in src:
            compressed[passthrough_key] = src[passthrough_key]

    if "scores" in evidence_data:
        compressed["scores"] = evidence_data["scores"]
    elif "scores" in src:
        compressed["scores"] = src["scores"]

    compressed["behavioral_alerts"] = [
        b for b in src.get("behavioral_alerts", [])
        if b.get("suspected") is True
    ]

    group_configs = {
        "flows": ("src_ip", "dst_ip", "dst_port"),
        "anomalies": ("src_ip", "dst_ip", "name"),
        "signature_alerts": ("src_ip", "dest_ip", "signature"),
        "content_indicators": ("src_ip", "dst_ip", "type"),
    }

    for key, group_keys in group_configs.items():
        items = src.get(key, [])
        if len(items) <= 10:
            compressed[key] = items
            continue

        groups = defaultdict(lambda: {"count": 0, "representative": None})
        for item in items:
            gk = tuple(item.get(k) for k in group_keys)
            g = groups[gk]
            g["count"] += 1
            if g["representative"] is None:
                g["representative"] = dict(item)

        result = []
        for g in groups.values():
            entry = g["representative"]
            entry["occurrence_count"] = g["count"]
            result.append(entry)
        compressed[key] = result

    return compressed


def filter_low_priority(compressed: dict, evidence_data: dict) -> dict:
    src = evidence_data.get("evidence", evidence_data)
    scores = evidence_data.get("scores", src.get("scores", {}))

    important_ips = set()
    for ip, info in scores.items():
        if info.get("score", 0) >= 0.1:
            important_ips.add(ip)

    for b in src.get("behavioral_alerts", []):
        if b.get("suspected") is True:
            important_ips.add(b.get("src_ip"))
            important_ips.add(b.get("dst_ip"))
    important_ips.discard(None)

    filtered = dict(compressed)

    for key in ("flows", "behavioral_alerts"):
        before = filtered.get(key, [])
        after = [
            item for item in before
            if item.get("src_ip") in important_ips or item.get("dst_ip") in important_ips
        ]
        print(f"[filter] {key} (IP 필터): {len(before)} -> {len(after)} ({len(before) - len(after)}건 제외)")
        filtered[key] = after

    MAX_FLOWS = 50
    flows = filtered.get("flows", [])
    if len(flows) > MAX_FLOWS:
        flows_sorted = sorted(flows, key=lambda f: f.get("connection_count", f.get("occurrence_count", 1)), reverse=True)
        print(f"[filter] flows (상위 {MAX_FLOWS}개): {len(flows)} -> {MAX_FLOWS} ({len(flows) - MAX_FLOWS}건 제외)")
        filtered["flows"] = flows_sorted[:MAX_FLOWS]

    return filtered


_mock_turn = 0


def _call_ollama_mock(messages: list, model: str, tools: list = None) -> dict:
    global _mock_turn
    _mock_turn += 1

    if _mock_turn == 1 and tools:
        return {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "search_known_malware_signature", "arguments": {"signature_name": "ET MALWARE Win32/IcedID Requesting Encoded Binary M4"}}},
                    {"function": {"name": "lookup_threat_intel", "arguments": {"domain_or_ip": "188.166.154.118"}}},
                ],
            }
        }

    if _mock_turn == 2 and tools:
        return {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "lookup_threat_intel", "arguments": {"domain_or_ip": "157.245.142.66"}}},
                    {"function": {"name": "lookup_threat_intel", "arguments": {"domain_or_ip": "oceriesfornot.top"}}},
                ],
            }
        }

    compressed = None
    for m in messages:
        if m["role"] == "user" and m["content"].startswith("{"):
            try:
                compressed = json.loads(m["content"])
            except json.JSONDecodeError:
                pass
            break

    scores = {}
    host_id = []
    if compressed:
        scores = compressed.get("scores", {})
        host_id = compressed.get("host_identification", [])

    judgments = []
    for ip, info in scores.items():
        base_score = info.get("score", 0)
        host_info = {}
        for h in host_id:
            if h.get("src_ip") == ip:
                host_info = {k: v for k, v in h.items() if k != "src_ip"}
                break

        judgments.append({
            "src_ip": ip,
            "is_attack": True if base_score >= 0.3 else "uncertain",
            "confidence": min(base_score + 0.1, 1.0),
            "attack_type": None,
            "matched_cve": [],
            "host_info": host_info,
            "reasoning": f"base_score={base_score}. 도구 호출 결과 전부 'no match found'이므로 구체적 위협 유형 확정 불가. evidence의 시그니처 패턴과 반복 횟수 기반 행위 의심.",
            "case_type": "B",
        })

    return {
        "message": {
            "role": "assistant",
            "content": json.dumps(judgments, ensure_ascii=False),
        }
    }


def _call_ollama(messages: list, model: str, tools: list = None) -> dict:
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "num_ctx": config.NUM_CTX,
            "num_predict": config.NUM_PREDICT,
        },
    }
    if tools:
        payload["tools"] = tools
    else:
        payload["format"] = "json"

    resp = requests.post(
        f"{config.OLLAMA_HOST}/api/chat",
        json=payload,
        timeout=300,
    )
    resp.raise_for_status()
    return resp.json()


def _parse_response_json(text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1:
        text = text[start:end + 1]
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start:end + 1]

    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return [result]
        return result
    except json.JSONDecodeError:
        logger.error("Failed to parse LLM response as JSON: %s", text[:200])
        return []


def _post_validate(judgments: list[dict], tool_log: list[dict]) -> list[dict]:
    validated = copy.deepcopy(judgments)
    override_log = []

    tool_results_all_no_match = True
    for entry in tool_log:
        result = entry.get("result", {})
        if isinstance(result, dict) and result.get("result") != "no match found":
            tool_results_all_no_match = False
            break

    for item in validated:
        if item.get("case_type") != "A":
            continue

        has_cve = bool(item.get("matched_cve"))
        if has_cve:
            continue

        if tool_results_all_no_match or not tool_log:
            item["case_type"] = "B"
            suffix = " [POST_VALIDATION_OVERRIDE: 도구 조회 결과 없음, case_type을 A에서 B로 강제 조정함]"
            item["reasoning"] = item.get("reasoning", "") + suffix
            override_log.append({
                "action": "case_type_override",
                "src_ip": item.get("src_ip"),
                "original": "A",
                "corrected": "B",
                "reason": "all tool results were 'no match found' and no matched_cve in evidence",
            })

    return validated, override_log


_JSON_RETRY_MSG = "방금 답변은 JSON 형식이 아니었다. 설명 없이 오직 지정된 JSON 배열만 다시 출력해라."


def _finalize_response(raw_text: str, messages: list, call_fn, model: str, tool_log: list, turns: int) -> dict:
    raw_judgments = _parse_response_json(raw_text)

    if not raw_judgments:
        for retry in range(2):
            print(f"[JSON 파싱 실패] 재시도 {retry + 1}/2...")
            messages.append({"role": "assistant", "content": raw_text})
            messages.append({"role": "user", "content": _JSON_RETRY_MSG})
            result = call_fn(messages, model)
            raw_text = result.get("message", {}).get("content", "")
            raw_judgments = _parse_response_json(raw_text)
            if raw_judgments:
                print(f"[JSON 파싱 성공] 재시도 {retry + 1}회차에서 성공")
                break

    if not raw_judgments:
        print("[JSON 파싱 최종 실패] raw 텍스트를 그대로 반환")
        return {
            "raw_model_output": raw_text,
            "validated_output": [],
            "log": tool_log,
            "turns": turns,
        }

    validated_judgments, override_log = _post_validate(raw_judgments, tool_log)
    for entry in override_log:
        tool_log.append(entry)

    return {
        "raw_model_output": raw_judgments,
        "validated_output": validated_judgments,
        "log": tool_log,
        "turns": turns,
    }


def _extract_ip_evidence(compressed: dict, target_ip: str) -> dict:
    ip_evidence = {}
    for key in ("flows", "behavioral_alerts"):
        ip_evidence[key] = [
            item for item in compressed.get(key, [])
            if item.get("src_ip") == target_ip or item.get("dst_ip") == target_ip
        ]
    for key in ("anomalies", "signature_alerts", "content_indicators"):
        ip_evidence[key] = [
            item for item in compressed.get(key, [])
            if item.get("src_ip") == target_ip or item.get("dst_ip") == target_ip or item.get("dest_ip") == target_ip
        ]
    ip_evidence["host_identification"] = [
        h for h in compressed.get("host_identification", [])
        if h.get("src_ip") == target_ip
    ]
    scores = compressed.get("scores", {})
    if target_ip in scores:
        ip_evidence["scores"] = {target_ip: scores[target_ip]}
    else:
        ip_evidence["scores"] = {}
    return ip_evidence


def _judge_single_ip(ip: str, ip_evidence: dict, call_fn, model: str, system_prompt: str) -> dict:
    user_message = json.dumps(ip_evidence, ensure_ascii=False)
    print(f"\n{'='*50}")
    print(f"[{ip}] 판단 시작 (evidence {len(user_message)}자)")

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    tool_log = []

    for turn in range(config.MAX_TOOL_TURNS):
        print(f"  [Turn {turn + 1}/{config.MAX_TOOL_TURNS}] LLM 호출 시작...")
        result = call_fn(messages, model, tools=TOOL_SCHEMAS)
        msg = result.get("message", {})
        tool_calls = msg.get("tool_calls")
        print(f"  [Turn {turn + 1}/{config.MAX_TOOL_TURNS}] 응답 받음 — tool_calls: {'있음 (' + str(len(tool_calls)) + '건)' if tool_calls else '없음 (최종 응답)'}")

        if not tool_calls:
            raw_text = msg.get("content", "")
            return _finalize_response(raw_text, messages, call_fn, model, tool_log, turn + 1)

        messages.append(msg)

        for tc in tool_calls:
            func_name = tc["function"]["name"]
            func_args = tc["function"]["arguments"]
            print(f"    -> {func_name}({json.dumps(func_args, ensure_ascii=False)})")

            func = AVAILABLE_TOOLS.get(func_name)
            if func:
                tool_result = func(**func_args)
            else:
                tool_result = {"result": f"unknown tool: {func_name}", "source": "error"}

            print(f"       result: {tool_result['result']}")

            tool_log.append({
                "turn": turn + 1,
                "function": func_name,
                "arguments": func_args,
                "result": tool_result,
            })

            messages.append({
                "role": "tool",
                "content": json.dumps(tool_result, ensure_ascii=False),
            })

    print(f"  [최대 턴 도달] 도구 없이 최종 응답 강제 요청")
    messages.append({
        "role": "user",
        "content": "최대 도구 호출 횟수에 도달했다. 더 이상 도구를 호출하지 말고, 지금까지 수집한 정보만으로 최종 JSON 판단 결과를 즉시 출력하라.",
    })
    result = call_fn(messages, model)
    raw_text = result.get("message", {}).get("content", "")
    print(f"  [강제 마무리] 최종 응답 받음")
    return _finalize_response(raw_text, messages, call_fn, model, tool_log, config.MAX_TOOL_TURNS + 1)


def judge_evidence(evidence_data: dict, model: str = None, mock: bool = False) -> dict:
    global _mock_turn
    _mock_turn = 0
    model = model or config.MODEL_NAME
    call_fn = _call_ollama_mock if mock else _call_ollama
    system_prompt = config.load_system_prompt()
    compressed = compress_evidence(evidence_data)
    compressed = filter_low_priority(compressed, evidence_data)

    src = evidence_data.get("evidence", evidence_data)
    scores = evidence_data.get("scores", src.get("scores", {}))

    target_ips = set(scores.keys())
    for b in compressed.get("behavioral_alerts", []):
        if b.get("suspected") is True:
            target_ips.add(b.get("src_ip"))
    target_ips.discard(None)

    target_ips = sorted(target_ips, key=lambda ip: scores.get(ip, {}).get("score", 0), reverse=True)

    print(f"판단 대상: {len(target_ips)}개 IP")

    all_raw = []
    all_validated = []
    all_logs = []
    total_turns = 0

    for ip in target_ips:
        _mock_turn = 0
        ip_evidence = _extract_ip_evidence(compressed, ip)
        result = _judge_single_ip(ip, ip_evidence, call_fn, model, system_prompt)

        if isinstance(result.get("raw_model_output"), list):
            all_raw.extend(result["raw_model_output"])
        else:
            all_raw.append({"src_ip": ip, "raw_text": result.get("raw_model_output", "")})

        if isinstance(result.get("validated_output"), list):
            all_validated.extend(result["validated_output"])

        all_logs.extend(result.get("log", []))
        total_turns += result.get("turns", 0)

    print(f"\n{'='*50}")
    print(f"전체 완료: {len(target_ips)}개 IP, {total_turns} 턴")

    return {
        "raw_model_output": all_raw,
        "validated_output": all_validated,
        "log": all_logs,
        "turns": total_turns,
    }


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Phase 2: LLM 기반 위협 판단")
    ap.add_argument("--evidence", default="evidence.json", help="evidence JSON 경로")
    ap.add_argument("--model", default=None, help="모델명 (기본: config.MODEL_NAME)")
    ap.add_argument("--mock", action="store_true", help="Ollama 없이 mock 모드로 실행")
    args = ap.parse_args()

    with open(args.evidence) as f:
        data = json.load(f)

    mode = "MOCK" if args.mock else f"{args.model or config.MODEL_NAME} @ {config.OLLAMA_HOST}"
    print(f"Mode: {mode}")
    print()

    result = judge_evidence(data, model=args.model, mock=args.mock)

    print(f"Turns: {result['turns']}")
    print(f"Tool calls: {len([l for l in result['log'] if 'function' in l])}건")
    print()

    print("=== Tool Log ===")
    for entry in result["log"]:
        if "function" in entry:
            print(f"  [Turn {entry['turn']}] {entry['function']}({json.dumps(entry['arguments'], ensure_ascii=False)}) -> {entry['result']['result']}")
        elif entry.get("action") == "case_type_override":
            print(f"  [POST_VALIDATION] {entry['src_ip']}: {entry['original']} -> {entry['corrected']}")

    print()
    print("=== Validated Output ===")
    print(json.dumps(result["validated_output"], indent=2, ensure_ascii=False))
