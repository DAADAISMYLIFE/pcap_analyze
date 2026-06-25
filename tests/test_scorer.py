import pytest

from core.scorer import calculate_base_score, SEVERITY_WEIGHTS, WEIGHT_CVE, WEIGHT_BEACON, WEIGHT_WEIRD, KNOWN_BENIGN_SIDS


class TestCalculateBaseScore:
    def test_severity_weights(self):
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "Critical", "severity": 1, "cve": None},
            ],
            "behavioral_alerts": [],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert scores["10.0.0.1"]["score"] == SEVERITY_WEIGHTS[1]

    def test_severity_levels(self):
        for sev, weight in SEVERITY_WEIGHTS.items():
            evidence = {
                "signature_alerts": [
                    {"src_ip": "10.0.0.1", "signature_id": 9000 + sev, "signature": f"Sev{sev}", "severity": sev, "cve": None},
                ],
                "behavioral_alerts": [],
                "anomalies": [],
            }
            scores = calculate_base_score(evidence)
            assert scores["10.0.0.1"]["score"] == weight

    def test_signature_with_cve(self):
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "Exploit", "severity": 1, "cve": "CVE-2021-44228"},
            ],
            "behavioral_alerts": [],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert scores["10.0.0.1"]["score"] == SEVERITY_WEIGHTS[1] + WEIGHT_CVE
        assert any("CVE-2021-44228" in r for r in scores["10.0.0.1"]["reasons"])

    def test_dedup_same_signature(self):
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "Same Alert", "severity": 2, "cve": None},
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "Same Alert", "severity": 2, "cve": None},
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "Same Alert", "severity": 2, "cve": None},
            ],
            "behavioral_alerts": [],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert scores["10.0.0.1"]["score"] == SEVERITY_WEIGHTS[2]
        assert any("x3" in r for r in scores["10.0.0.1"]["reasons"])

    def test_benign_sid_excluded(self):
        benign_sid = next(iter(KNOWN_BENIGN_SIDS))
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": benign_sid, "signature": "Benign", "severity": 3, "cve": None},
            ],
            "behavioral_alerts": [],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert len(scores) == 0

    def test_beacon_suspected(self):
        evidence = {
            "signature_alerts": [],
            "behavioral_alerts": [
                {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "suspected": True, "connection_count": 10, "cv": 0.05},
            ],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert scores["10.0.0.1"]["score"] == WEIGHT_BEACON

    def test_beacon_not_suspected_ignored(self):
        evidence = {
            "signature_alerts": [],
            "behavioral_alerts": [
                {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "suspected": False, "connection_count": 10, "cv": 0.5},
            ],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert len(scores) == 0

    def test_anomaly(self):
        evidence = {
            "signature_alerts": [],
            "behavioral_alerts": [],
            "anomalies": [
                {"src_ip": "10.0.0.1", "name": "bad_checksum", "ts": 1.0},
            ],
        }
        scores = calculate_base_score(evidence)
        assert scores["10.0.0.1"]["score"] == WEIGHT_WEIRD

    def test_combined_score(self):
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "Alert", "severity": 1, "cve": "CVE-2024-1234"},
            ],
            "behavioral_alerts": [
                {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "suspected": True, "connection_count": 10, "cv": 0.05},
            ],
            "anomalies": [
                {"src_ip": "10.0.0.1", "name": "bad_checksum", "ts": 1.0},
            ],
        }
        scores = calculate_base_score(evidence)
        expected = SEVERITY_WEIGHTS[1] + WEIGHT_CVE + WEIGHT_BEACON + WEIGHT_WEIRD
        assert scores["10.0.0.1"]["score"] == round(expected, 2)

    def test_rce_beats_noisy_info(self):
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "RCE Exploit", "severity": 1, "cve": "CVE-2021-44228"},
                {"src_ip": "10.0.0.2", "signature_id": 9002, "signature": "Info Alert A", "severity": 3, "cve": None},
                {"src_ip": "10.0.0.2", "signature_id": 9003, "signature": "Info Alert B", "severity": 3, "cve": None},
                {"src_ip": "10.0.0.2", "signature_id": 9004, "signature": "Info Alert C", "severity": 3, "cve": None},
            ],
            "behavioral_alerts": [],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        assert scores["10.0.0.1"]["score"] > scores["10.0.0.2"]["score"]

    def test_sorted_by_score_desc(self):
        evidence = {
            "signature_alerts": [
                {"src_ip": "10.0.0.1", "signature_id": 9001, "signature": "A", "severity": 3, "cve": None},
                {"src_ip": "10.0.0.2", "signature_id": 9002, "signature": "B", "severity": 1, "cve": None},
            ],
            "behavioral_alerts": [],
            "anomalies": [],
        }
        scores = calculate_base_score(evidence)
        ips = list(scores.keys())
        assert ips[0] == "10.0.0.2"

    def test_empty_evidence(self):
        evidence = {"signature_alerts": [], "behavioral_alerts": [], "anomalies": []}
        scores = calculate_base_score(evidence)
        assert scores == {}
