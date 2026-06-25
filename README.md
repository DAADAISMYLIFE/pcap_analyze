# pcap_analyze

pcap 파일을 입력받아 Zeek/Suricata 로그를 생성하고, 위협 분석 evidence를 자동으로 추출하는 보안 분석 파이프라인.

프로토타입 — 현재 Phase 1 (LLM 없이 결정론적 분석).
GPU 서버 확보 후 Phase 2에서 sLLM 기반 종합 판단을 붙일 예정.

## 설치

```bash
# Python 가상환경
python3 -m venv venv
source venv/bin/activate
pip install pandas numpy pytest

# Zeek (Docker)
docker pull zeek/zeek:latest

# Suricata (로컬 설치 필요)
# config 파일 권한 문제 시:
sudo cp /etc/suricata/suricata.yaml ~/pcap_analyze/suricata.yaml

# ET Open 룰셋 (CVE 매핑용, 선택)
sudo suricata-update
sudo chmod -R o+rX /var/lib/suricata /var/lib/suricata/rules
```

## 사용법

```bash
# pcap 파일을 input/에 넣고 전체 파이프라인 실행
python3 analyze.py

# Suricata config 경로 지정 (권한 문제 시)
python3 analyze.py --suricata-config ~/pcap_analyze/suricata.yaml

# CVE 매핑 포함
python3 analyze.py --suricata-config ~/pcap_analyze/suricata.yaml --rules-dir /var/lib/suricata/rules

# Zeek/Suricata 실행 건너뛰기 (이미 로그가 있을 때)
python3 analyze.py --skip-run

# 특정 pcap 지정
python3 analyze.py --pcap input/sample.pcap
```

실행 결과는 `evidence.json`에 저장됨.

## 파이프라인 구조

```
pcap 파일
  │
  ├─ runner.py ──────── Zeek(Docker) + Suricata(로컬) 실행
  │                      → output/ (Zeek 로그) + suricata_output/ (eve.json)
  │
  ├─ parsers.py ─────── 로그 파싱, 필드명 정규화
  │                      conn / weird / http / dns / files / dhcp / kerberos / suricata eve
  │
  ├─ cve_mapper.py ──── Suricata 룰에서 SID↔CVE 매핑 테이블 생성, alert에 CVE 라벨 부착
  │
  ├─ beacon_detector.py  (src_ip, dst_ip) 쌍별 접속 간격 변동계수 계산 → C2 비콘 패턴 탐지
  │
  ├─ normalizer.py ──── 모든 결과를 하나의 evidence dict로 통합
  │
  └─ scorer.py ──────── IP별 위험도 가중합 (severity 가중치 + CVE + 비콘 + anomaly)
```

## Evidence 스키마

```json
{
  "evidence": {
    "flows": [],              // conn.log 기반 연결 정보
    "anomalies": [],          // weird.log 기반 구조적 이상
    "signature_alerts": [],   // Suricata alert + CVE 매핑
    "behavioral_alerts": [],  // 비콘(C2) 탐지 결과
    "content_indicators": [], // HTTP 다운로드 + DNS 조회 조합
    "host_identification": [],// DHCP + Kerberos 기반 호스트/사용자 식별
    "extra_metadata": {}
  },
  "scores": {
    "10.0.1.95": {
      "score": 1.5,
      "reasons": ["signature alert: ... (severity 1)", "anomaly: ..."]
    }
  }
}
```

## 점수 계산 로직

| 항목 | 가중치 |
|------|--------|
| signature alert (severity 1) | +0.5 |
| signature alert (severity 2) | +0.2 |
| signature alert (severity 3) | +0.05 |
| CVE 매핑 있음 | +0.3 |
| 비콘 의심 (CV < 0.2) | +0.2 |
| anomaly (weird.log) | +0.1 |

- 같은 IP에서 같은 signature_id는 1회만 카운트 (반복 횟수는 별도 기록)
- 알려진 정상 SID는 화이트리스트로 제외 (Microsoft Connection Test 등)
- 점수는 우선순위 정렬용이며, 최종 위험도 판단은 Phase 2(LLM)에서 수행

## 개별 모듈 실행

```bash
python3 -m core.parsers              # 로그 파싱 결과 확인
python3 -m core.beacon_detector      # 비콘 탐지 결과
python3 -m core.cve_mapper --rules-dir /var/lib/suricata/rules  # CVE 매핑
python3 -m core.scorer               # 점수 계산
```

## 테스트

```bash
pytest tests/ -v          # 전체 (87개)
pytest tests/test_parsers.py -v      # 파서만
pytest tests/test_scorer.py -v       # 점수 계산만
```

## 디렉터리 구조

```
pcap_analyze/
  analyze.py              # CLI 진입점
  core/                   # 분석 모듈 패키지
    parsers.py            #   Zeek/Suricata 로그 파서 (8종)
    runner.py             #   Zeek/Suricata 실행기
    cve_mapper.py         #   SID→CVE 매핑
    beacon_detector.py    #   C2 비콘 탐지
    normalizer.py         #   evidence 통합
    scorer.py             #   위험도 점수 계산
  tests/                  # pytest (87개)
  input/                  # pcap 파일 넣는 곳
  output/                 # Zeek 로그 출력
  suricata_output/        # Suricata 로그 출력
```

## 환경 요구사항

- Python 3.10+
- Docker (Zeek 실행용)
- Suricata 8.x (로컬 설치)
- pandas, numpy
