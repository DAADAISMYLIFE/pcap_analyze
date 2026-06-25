# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pcap 파일 → Zeek/Suricata 로그 → 위협 분석을 수행하는 보안 분석 파이프라인.
2주 해커톤 프로토타입. 현재 Phase 1 (LLM 없이 결정론적 분석만 구현).

## Development Commands

```bash
# Python 가상환경 활성화
source venv/bin/activate

# 의존성 설치 (pandas, numpy 필요)
pip install pandas numpy

# 테스트 실행
pip install pytest  # 최초 1회
pytest tests/
pytest tests/test_parsers.py -v          # 특정 파일
pytest tests/test_parsers.py::test_name  # 특정 테스트

# CLI 실행 (구현 후)
python analyze.py --pcap-dir input/ --output-dir output/ --suricata-dir suricata_output/

# Zeek 로그 생성 (pcap → JSON 로그)
docker run --rm -v $(pwd)/input:/pcap -v $(pwd)/output:/output zeek/zeek:latest \
  zeek -r /pcap/<file>.pcap LogAscii::use_json=T Log::default_logdir=/output

# Suricata 로그 생성 (pcap → eve.json)
suricata -r input/<file>.pcap -l suricata_output/
```

## Design Constraints (반드시 지킬 것)

1. **모든 함수는 순수 함수로 작성** — 입력: 파일 경로, 출력: dict/JSON. 웹/LLM 형식에 의존하지 않는다.
   나중에 FastAPI 백엔드와 LLM tool calling에서 그대로 재사용할 것.
2. **탐지는 Zeek/Suricata, 통계는 pandas/numpy** — LLM이 없으므로 재현 가능한 결정론적 로직만.
3. **Graceful degradation** — 로그 파일 누락/빈 파일/파싱 실패 시 에러 throw 하지 않고 로그 남기고 빈 리스트 반환.

## Environment

- WSL2 Ubuntu, Python 3.10.12
- Zeek: Docker (`zeek/zeek:latest`)
- Suricata 8.0.5: 로컬 설치. 현재 bundled rules만 있음 (30개, `/usr/share/suricata/rules/`).
  ET Open 룰셋은 `suricata-update`로 별도 설치 필요 → 설치하면 `/var/lib/suricata/rules/`에 생성됨.
- 가상환경: `venv/` 사용 (`.venv/`도 있으나 비어있음)

## Log Format Reference (실제 필드명)

Zeek 로그는 JSON lines 형식. 필드명이 직관적이지 않으므로 매핑 참고:

| 의미 | Zeek conn.log 실제 키 |
|------|----------------------|
| src_ip | `id.orig_h` |
| dst_ip | `id.resp_h` |
| src_port | `id.orig_p` |
| dst_port | `id.resp_p` |
| timestamp | `ts` (epoch float) |
| duration | `duration` |
| orig_bytes | `orig_bytes` |
| resp_bytes | `resp_bytes` |
| orig_pkts | `orig_pkts` |
| resp_pkts | `resp_pkts` |
| protocol | `proto` |
| service | `service` |

Suricata eve.json: 각 줄이 JSON 객체. `event_type` 필드로 레코드 타입 구분.
Alert는 `event_type: "alert"`이고, alert 상세는 `alert.signature_id`, `alert.signature`, `alert.severity` 등 nested.

## Test Data

`input/2017-10-21-traffic-analysis-exercise.pcap`: malware-traffic-analysis.net 샘플.
Chthonic 뱅킹 트로이얀 감염 + 기술지원 스캠 시나리오. 정답 라벨 확보됨 — 파이프라인 검증용.

이미 생성된 로그: `output/`(Zeek conn/weird/http/dns/files/dhcp 등), `suricata_output/`(eve.json, fast.log).

## Phase 1 구현 범위 (현재)

### 구현할 모듈들
1. **로그 파서**: `parse_conn_log`, `parse_weird_log`, `parse_http_log`, `parse_dns_log`, `parse_files_log` — 각각 path → list[dict]
2. **Suricata 파서**: `parse_suricata_eve(path)` — alert만 필터링, signature_id/signature/severity/src_ip/dest_ip/dest_port/proto/timestamp 추출
3. **CVE 매핑**: `build_cve_lookup(rules_dir)` — `.rules` 파일에서 `sid:(\d+)` ↔ `reference:cve,([\d-]+)` 매핑 테이블 생성. `apply_cve_mapping(alerts, lookup)` — alert에 cve 필드 추가
4. **비콘(C2) 탐지**: `detect_beaconing(flows)` — (src,dst) 쌍별 접속 간격의 변동계수(CV) 계산. CV<0.2 & 5회 이상이면 suspected
5. **정규화**: `normalize_evidence(...)` — 전체 파서 결과를 `{flows, anomalies, signature_alerts, behavioral_alerts, content_indicators, extra_metadata}` 스키마로 통합
6. **Confidence score** (선택): `calculate_base_score(evidence)` — IP별 가중합 (severity alert +0.4, CVE +0.3, 비콘 +0.2, weird +0.1)
7. **CLI**: `analyze.py` — argparse로 디렉터리 받아서 1→6 순차 실행, `result.json` 출력

### 테스트 요구사항
- 파서: unit test (pytest)
- 비콘 탐지: 규칙적 간격(의심), 불규칙 간격(정상), 연결 수 부족(보류) 3개 케이스
- 통합: 실제 데이터로 `analyze.py` 전체 실행 → `result.json` 생성 확인

## Scope 제외 (Phase 1에서 하지 말 것)

- LLM 연동, tool calling, RAG/Vector DB
- 웹 UI, FastAPI 백엔드
- 적대적 검증, Docker 기반 RCE 재현
- 실시간 처리
