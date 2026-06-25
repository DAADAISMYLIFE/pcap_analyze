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

    group_configs = {
        "flows": ("src_ip", "dst_ip", "dst_port"),
        "anomalies": ("src_ip", "dst_ip", "name"),
        "signature_alerts": ("src_ip", "dest_ip", "signature"),
        "behavioral_alerts": ("src_ip", "dst_ip", "suspected"),
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

    resp = requests.post(
        f"{config.OLLAMA_HOST}/api/chat",
        json=payload,
        timeout=600,
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


def judge_evidence(evidence_data: dict, model: str = None) -> dict:
    model = model or config.MODEL_NAME
    system_prompt = config.load_system_prompt()
    compressed = compress_evidence(evidence_data)
    user_message = json.dumps(compressed, ensure_ascii=False)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    tool_log = []

    for turn in range(config.MAX_TOOL_TURNS):
        logger.info("LLM call turn %d/%d", turn + 1, config.MAX_TOOL_TURNS)
        result = _call_ollama(messages, model, tools=TOOL_SCHEMAS)

        msg = result.get("message", {})
        tool_calls = msg.get("tool_calls")

        if not tool_calls:
            raw_text = msg.get("content", "")
            raw_judgments = _parse_response_json(raw_text)
            validated_judgments, override_log = _post_validate(raw_judgments, tool_log)

            for entry in override_log:
                tool_log.append(entry)

            return {
                "raw_model_output": raw_judgments,
                "validated_output": validated_judgments,
                "log": tool_log,
                "turns": turn + 1,
            }

        messages.append(msg)

        for tc in tool_calls:
            func_name = tc["function"]["name"]
            func_args = tc["function"]["arguments"]

            logger.info("Tool call: %s(%s)", func_name, json.dumps(func_args, ensure_ascii=False))

            func = AVAILABLE_TOOLS.get(func_name)
            if func:
                tool_result = func(**func_args)
            else:
                tool_result = {"result": f"unknown tool: {func_name}", "source": "error"}

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

    logger.warning("Max tool turns (%d) reached, forcing final call", config.MAX_TOOL_TURNS)
    result = _call_ollama(messages, model)
    raw_text = result.get("message", {}).get("content", "")
    raw_judgments = _parse_response_json(raw_text)
    validated_judgments, override_log = _post_validate(raw_judgments, tool_log)

    for entry in override_log:
        tool_log.append(entry)

    return {
        "raw_model_output": raw_judgments,
        "validated_output": validated_judgments,
        "log": tool_log,
        "turns": config.MAX_TOOL_TURNS,
    }


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Phase 2: LLM 기반 위협 판단")
    ap.add_argument("--evidence", default="evidence.json", help="evidence JSON 경로")
    ap.add_argument("--model", default=None, help="모델명 (기본: config.MODEL_NAME)")
    args = ap.parse_args()

    with open(args.evidence) as f:
        data = json.load(f)

    print(f"Model: {args.model or config.MODEL_NAME}")
    print(f"Ollama: {config.OLLAMA_HOST}")
    print()

    result = judge_evidence(data, model=args.model)

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
