import json
import streamlit as st

import config
from llm_judge import run_judge, parse_judgment, compress_evidence

st.set_page_config(page_title="pcap 위협 분석", layout="wide")
st.title("pcap 위협 분석 — Phase 2 LLM 판단")

with st.sidebar:
    st.header("설정")
    config.OLLAMA_BASE_URL = st.text_input("Ollama URL", value=config.OLLAMA_BASE_URL)
    config.MODEL_NAME = st.text_input("Model", value=config.MODEL_NAME)
    config.NUM_CTX = st.number_input("Context Length", value=config.NUM_CTX, step=1024)
    config.TEMPERATURE = st.slider("Temperature", 0.0, 1.0, value=config.TEMPERATURE, step=0.1)

uploaded = st.file_uploader("evidence.json 업로드", type=["json"])

if uploaded:
    data = json.load(uploaded)
    evidence = data["evidence"]
    scores = data["scores"]

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("점수 요약")
        for ip, info in scores.items():
            with st.expander(f"{ip} — score: {info['score']}"):
                for r in info["reasons"]:
                    st.markdown(f"- {r}")

    with col2:
        st.subheader("호스트 식별")
        for h in evidence.get("host_identification", []):
            st.json(h)

    with st.expander("압축된 Evidence (LLM에 전달되는 데이터)"):
        compressed = compress_evidence(evidence)
        st.json(compressed)

    if st.button("LLM 판단 실행", type="primary"):
        with st.spinner(f"{config.MODEL_NAME} 분석 중..."):
            try:
                result = run_judge(evidence, scores)
            except Exception as e:
                st.error(f"Ollama 호출 실패: {e}")
                st.stop()

        st.success(f"완료 — {result['rounds']} 라운드, {len(result['tool_log'])}건 도구 호출")

        st.subheader("Tool Calling 로그")
        if result["tool_log"]:
            for t in result["tool_log"]:
                with st.expander(f"[Round {t['round']}] {t['function']}"):
                    st.markdown("**Arguments:**")
                    st.json(t["arguments"])
                    st.markdown("**Result:**")
                    st.json(t["result"])
        else:
            st.info("도구 호출 없음")

        st.subheader("최종 판단")
        judgments = parse_judgment(result["raw_response"])
        if judgments:
            for j in judgments:
                ip = j.get("src_ip", "?")
                is_attack = j.get("is_attack", False)
                confidence = j.get("confidence", 0)
                case_type = j.get("case_type", "?")

                status = "🔴 공격" if is_attack else "🟢 정상"
                st.markdown(f"### {ip} — {status} (confidence: {confidence}, case: {case_type})")

                if j.get("attack_type"):
                    st.markdown(f"**Attack Type:** {j['attack_type']}")
                if j.get("matched_cve"):
                    st.markdown(f"**CVE:** {', '.join(j['matched_cve'])}")
                if j.get("host_info"):
                    st.json(j["host_info"])
                st.markdown(f"**Reasoning:** {j.get('reasoning', '')}")
                st.divider()
        else:
            st.warning("JSON 파싱 실패 — 원본 응답:")
            st.code(result["raw_response"])

        with st.expander("원본 LLM 응답"):
            st.code(result["raw_response"])
