import json
import time

import streamlit as st

import config
from llm_judge import judge_evidence, compress_evidence

st.set_page_config(page_title="pcap 위협 분석", layout="wide")
st.title("pcap 위협 분석 — Phase 2 LLM 판단")

with st.sidebar:
    st.header("설정")
    model_name = st.text_input("Model", value=config.MODEL_NAME)
    ollama_host = st.text_input("Ollama Host", value=config.OLLAMA_HOST)
    config.OLLAMA_HOST = ollama_host
    config.MODEL_NAME = model_name

uploaded = st.file_uploader("evidence.json 업로드", type=["json"])

if uploaded:
    data = json.load(uploaded)
    evidence = data.get("evidence", data)
    scores = data.get("scores", {})

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
        compressed = compress_evidence(data)
        st.json(compressed)

    if st.button("판단 실행", type="primary"):
        start = time.time()
        with st.spinner(f"{config.MODEL_NAME} 분석 중..."):
            try:
                result = judge_evidence(data, model=config.MODEL_NAME)
            except Exception as e:
                st.error(f"Ollama 호출 실패: {e}")
                st.stop()
        elapsed = time.time() - start

        st.success(f"완료 — {result['turns']} 턴, {len([l for l in result['log'] if 'function' in l])}건 도구 호출, {elapsed:.1f}초 소요")

        st.subheader("최종 판단 결과 (검증 후)")
        validated = result["validated_output"]
        if validated:
            for j in validated:
                ip = j.get("src_ip", "?")
                is_attack = j.get("is_attack", False)
                confidence = j.get("confidence", 0)
                case_type = j.get("case_type", "?")

                if is_attack is True:
                    status = "🔴 공격"
                elif is_attack == "uncertain":
                    status = "🟡 불확실"
                else:
                    status = "🟢 정상"

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
            st.warning("판단 결과 파싱 실패")

        st.subheader("원본 모델 출력 (검증 전)")
        raw = result["raw_model_output"]
        has_override = any(
            e.get("action") == "case_type_override" for e in result["log"]
        )
        if has_override:
            st.warning("⚠️ 사후 검증에서 case_type이 수정된 항목이 있습니다")
        st.json(raw)

        st.subheader("Tool Calling 로그")
        tool_entries = [e for e in result["log"] if "function" in e]
        override_entries = [e for e in result["log"] if e.get("action") == "case_type_override"]

        if tool_entries:
            for t in tool_entries:
                with st.expander(f"[Turn {t['turn']}] {t['function']}"):
                    st.markdown("**Arguments:**")
                    st.json(t["arguments"])
                    st.markdown("**Result:**")
                    st.json(t["result"])
        else:
            st.info("도구 호출 없음")

        if override_entries:
            st.markdown("#### 사후 검증 수정")
            for o in override_entries:
                st.warning(f"{o['src_ip']}: case_type {o['original']} → {o['corrected']} ({o['reason']})")
