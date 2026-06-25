import json
import logging
from collections import defaultdict
from pathlib import Path

import requests

import config
from tools import TOOL_SCHEMAS, TOOL_FUNCTIONS

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_PATH = Path(__file__).parent / "prompts" / "phase2_system.txt"


def compress_evidence(evidence: dict) -> dict:
    compressed = {}

    for key in ("anomalies", "host_identification"):
        compressed[key] = evidence.get(key, [])

    sig_groups = defaultdict(lambda: {"count": 0, "severity": None, "cve": None, "src_ip": None, "dest_ip": None})
    for a in evidence.get("signature_alerts", []):
        sid = a.get("signature_id")
        g = sig_groups[sid]
        g["count"] += 1
        g["signature"] = a.get("signature")
        g["severity"] = a.get("severity")
        g["cve"] = g["cve"] or a.get("cve")
        g["src_ip"] = a.get("src_ip")
        g["dest_ip"] = a.get("dest_ip")
    compressed["signature_alerts"] = [
        {**v, "signature_id": k, "occurrence_count": v.pop("count")}
        for k, v in sig_groups.items()
    ]

    compressed["behavioral_alerts"] = [
        b for b in evidence.get("behavioral_alerts", [])
        if b.get("suspected") is True or b.get("connection_count", 0) >= 5
    ]

    dns_indicators = []
    http_indicators = []
    for c in evidence.get("content_indicators", []):
        if c.get("type") == "dns_query":
            dns_indicators.append(c)
        elif c.get("type") == "http_download":
            http_indicators.append(c)

    seen_urls = set()
    deduped_http = []
    for h in http_indicators:
        url = h.get("url", "")
        if url not in seen_urls:
            seen_urls.add(url)
            deduped_http.append(h)

    compressed["content_indicators"] = deduped_http + dns_indicators

    flow_groups = defaultdict(lambda: {"count": 0, "proto": None, "service": None, "total_orig_bytes": 0, "total_resp_bytes": 0})
    for f in evidence.get("flows", []):
        key = (f.get("src_ip"), f.get("dst_ip"), f.get("dst_port"))
        g = flow_groups[key]
        g["count"] += 1
        g["proto"] = f.get("proto")
        g["service"] = f.get("service")
        g["total_orig_bytes"] += f.get("orig_bytes") or 0
        g["total_resp_bytes"] += f.get("resp_bytes") or 0
    compressed["flows"] = [
        {
            "src_ip": k[0], "dst_ip": k[1], "dst_port": k[2],
            "proto": v["proto"], "service": v["service"],
            "connection_count": v["count"],
            "total_orig_bytes": v["total_orig_bytes"],
            "total_resp_bytes": v["total_resp_bytes"],
        }
        for k, v in flow_groups.items()
    ]

    return compressed


def build_user_message(evidence: dict, scores: dict) -> str:
    compressed = compress_evidence(evidence)
    return json.dumps({
        "compressed_evidence": compressed,
        "scores": scores,
    }, ensure_ascii=False)


def call_ollama(messages: list, tools: list = None) -> dict:
    payload = {
        "model": config.MODEL_NAME,
        "messages": messages,
        "stream": False,
        "options": {
            "num_ctx": config.NUM_CTX,
            "temperature": config.TEMPERATURE,
        },
    }
    if tools:
        payload["tools"] = tools

    resp = requests.post(
        f"{config.OLLAMA_BASE_URL}/api/chat",
        json=payload,
        timeout=300,
    )
    resp.raise_for_status()
    return resp.json()


def run_judge(evidence: dict, scores: dict, max_tool_rounds: int = 10) -> dict:
    system_prompt = SYSTEM_PROMPT_PATH.read_text()
    user_message = build_user_message(evidence, scores)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    tool_log = []

    for round_num in range(max_tool_rounds):
        logger.info("LLM call round %d", round_num + 1)
        result = call_ollama(messages, tools=TOOL_SCHEMAS)

        msg = result.get("message", {})
        tool_calls = msg.get("tool_calls")

        if not tool_calls:
            final_content = msg.get("content", "")
            return {
                "raw_response": final_content,
                "tool_log": tool_log,
                "rounds": round_num + 1,
            }

        messages.append(msg)

        for tc in tool_calls:
            func_name = tc["function"]["name"]
            func_args = tc["function"]["arguments"]

            logger.info("Tool call: %s(%s)", func_name, json.dumps(func_args, ensure_ascii=False))

            func = TOOL_FUNCTIONS.get(func_name)
            if func:
                tool_result = func(**func_args)
            else:
                tool_result = {"error": f"unknown tool: {func_name}"}

            tool_log.append({
                "round": round_num + 1,
                "function": func_name,
                "arguments": func_args,
                "result": tool_result,
            })

            messages.append({
                "role": "tool",
                "content": json.dumps(tool_result, ensure_ascii=False),
            })

    final = call_ollama(messages)
    return {
        "raw_response": final.get("message", {}).get("content", ""),
        "tool_log": tool_log,
        "rounds": max_tool_rounds,
    }


def parse_judgment(raw_response: str) -> list[dict]:
    text = raw_response.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return [result]
        return result
    except json.JSONDecodeError:
        logger.error("Failed to parse LLM response as JSON")
        return []


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Phase 2: LLM 기반 위협 판단")
    ap.add_argument("--evidence", default="evidence.json", help="evidence JSON 경로")
    args = ap.parse_args()

    with open(args.evidence) as f:
        data = json.load(f)

    evidence = data["evidence"]
    scores = data["scores"]

    print(f"Evidence loaded: {len(scores)}개 IP 판단 대상")
    print(f"Model: {config.MODEL_NAME}")
    print(f"Ollama: {config.OLLAMA_BASE_URL}")
    print()

    result = run_judge(evidence, scores)
    print(f"Rounds: {result['rounds']}")
    print(f"Tool calls: {len(result['tool_log'])}건")
    print()

    for t in result["tool_log"]:
        print(f"  [{t['round']}] {t['function']}({json.dumps(t['arguments'], ensure_ascii=False)}) -> {t['result']['status']}")

    print()
    judgments = parse_judgment(result["raw_response"])
    print(json.dumps(judgments, indent=2, ensure_ascii=False))
