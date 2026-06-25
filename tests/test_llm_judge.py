import json
from unittest.mock import patch, MagicMock

import pytest

from llm_judge import compress_evidence, judge_evidence, _post_validate, _parse_response_json


class TestCompressEvidence:
    def test_under_threshold_unchanged(self):
        evidence = {
            "evidence": {
                "flows": [{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 80}],
                "anomalies": [{"src_ip": "10.0.0.1", "name": "bad_checksum"}],
                "signature_alerts": [],
                "behavioral_alerts": [],
                "content_indicators": [],
                "host_identification": [{"src_ip": "10.0.0.1", "hostname": "pc1"}],
            },
            "scores": {"10.0.0.1": {"score": 0.5, "reasons": []}},
        }
        result = compress_evidence(evidence)
        assert len(result["flows"]) == 1
        assert result["flows"][0]["src_ip"] == "10.0.0.1"
        assert "occurrence_count" not in result["flows"][0]
        assert result["scores"]["10.0.0.1"]["score"] == 0.5
        assert result["host_identification"][0]["hostname"] == "pc1"

    def test_over_threshold_grouped(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 80, "orig_bytes": 100}
            for _ in range(15)
        ]
        evidence = {
            "evidence": {
                "flows": flows,
                "anomalies": [],
                "signature_alerts": [],
                "behavioral_alerts": [],
                "content_indicators": [],
                "host_identification": [],
            },
        }
        result = compress_evidence(evidence)
        assert len(result["flows"]) == 1
        assert result["flows"][0]["occurrence_count"] == 15

    def test_mixed_groups(self):
        flows = (
            [{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 80} for _ in range(8)]
            + [{"src_ip": "10.0.0.1", "dst_ip": "5.6.7.8", "dst_port": 443} for _ in range(5)]
        )
        evidence = {"evidence": {"flows": flows, "anomalies": [], "signature_alerts": [], "behavioral_alerts": [], "content_indicators": [], "host_identification": []}}
        result = compress_evidence(evidence)
        assert len(result["flows"]) == 2
        counts = {f["dst_ip"]: f["occurrence_count"] for f in result["flows"]}
        assert counts["1.2.3.4"] == 8
        assert counts["5.6.7.8"] == 5

    def test_flat_evidence_no_nested_key(self):
        evidence = {
            "flows": [{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 80}],
            "anomalies": [],
            "signature_alerts": [],
            "behavioral_alerts": [],
            "content_indicators": [],
            "host_identification": [],
        }
        result = compress_evidence(evidence)
        assert len(result["flows"]) == 1

    def test_exactly_ten_unchanged(self):
        alerts = [
            {"src_ip": "10.0.0.1", "dest_ip": f"1.2.3.{i}", "signature": f"sig_{i}"}
            for i in range(10)
        ]
        evidence = {"evidence": {"flows": [], "anomalies": [], "signature_alerts": alerts, "behavioral_alerts": [], "content_indicators": [], "host_identification": []}}
        result = compress_evidence(evidence)
        assert len(result["signature_alerts"]) == 10
        assert "occurrence_count" not in result["signature_alerts"][0]


class TestPostValidate:
    def test_no_override_case_b(self):
        judgments = [{"src_ip": "10.0.0.1", "case_type": "B", "matched_cve": [], "reasoning": "test"}]
        tool_log = [{"function": "lookup_threat_intel", "result": {"result": "no match found"}}]
        validated, overrides = _post_validate(judgments, tool_log)
        assert validated[0]["case_type"] == "B"
        assert len(overrides) == 0

    def test_override_a_to_b_no_match(self):
        judgments = [{"src_ip": "10.0.0.1", "case_type": "A", "matched_cve": [], "reasoning": "test"}]
        tool_log = [{"function": "lookup_threat_intel", "result": {"result": "no match found"}}]
        validated, overrides = _post_validate(judgments, tool_log)
        assert validated[0]["case_type"] == "B"
        assert "POST_VALIDATION_OVERRIDE" in validated[0]["reasoning"]
        assert len(overrides) == 1

    def test_no_override_a_with_cve(self):
        judgments = [{"src_ip": "10.0.0.1", "case_type": "A", "matched_cve": ["CVE-2021-44228"], "reasoning": "test"}]
        tool_log = [{"function": "get_cve_detail", "result": {"result": "no match found"}}]
        validated, overrides = _post_validate(judgments, tool_log)
        assert validated[0]["case_type"] == "A"
        assert len(overrides) == 0

    def test_no_override_a_with_real_tool_result(self):
        judgments = [{"src_ip": "10.0.0.1", "case_type": "A", "matched_cve": [], "reasoning": "test"}]
        tool_log = [{"function": "lookup_threat_intel", "result": {"result": "known malicious: IcedID C2"}}]
        validated, overrides = _post_validate(judgments, tool_log)
        assert validated[0]["case_type"] == "A"
        assert len(overrides) == 0

    def test_override_no_tool_calls(self):
        judgments = [{"src_ip": "10.0.0.1", "case_type": "A", "matched_cve": [], "reasoning": "test"}]
        validated, overrides = _post_validate(judgments, [])
        assert validated[0]["case_type"] == "B"
        assert len(overrides) == 1

    def test_original_not_mutated(self):
        judgments = [{"src_ip": "10.0.0.1", "case_type": "A", "matched_cve": [], "reasoning": "test"}]
        _post_validate(judgments, [])
        assert judgments[0]["case_type"] == "A"


class TestParseResponseJson:
    def test_json_array(self):
        result = _parse_response_json('[{"src_ip": "10.0.0.1"}]')
        assert len(result) == 1

    def test_json_object(self):
        result = _parse_response_json('{"src_ip": "10.0.0.1"}')
        assert len(result) == 1

    def test_markdown_wrapped(self):
        result = _parse_response_json('```json\n[{"src_ip": "10.0.0.1"}]\n```')
        assert len(result) == 1

    def test_text_before_json(self):
        result = _parse_response_json('Here is the result:\n[{"src_ip": "10.0.0.1"}]')
        assert len(result) == 1

    def test_invalid_json(self):
        result = _parse_response_json('not json at all')
        assert result == []


class TestJudgeEvidence:
    def _make_evidence(self):
        return {
            "evidence": {
                "flows": [],
                "anomalies": [],
                "signature_alerts": [{"src_ip": "10.0.0.1", "dest_ip": "1.2.3.4", "signature": "ET MALWARE Test", "severity": 1, "cve": None, "signature_id": 9001}],
                "behavioral_alerts": [],
                "content_indicators": [],
                "host_identification": [],
            },
            "scores": {"10.0.0.1": {"score": 0.5, "reasons": ["test"]}},
        }

    def test_mock_full_pipeline(self):
        evidence = self._make_evidence()
        result = judge_evidence(evidence, mock=True)
        assert result["turns"] >= 1
        assert len(result["validated_output"]) >= 1
        assert result["validated_output"][0]["case_type"] == "B"
        assert "report" in result

    def test_mock_tool_calls_logged(self):
        evidence = self._make_evidence()
        result = judge_evidence(evidence, mock=True)
        tool_calls = [l for l in result["log"] if "function" in l]
        assert len(tool_calls) > 0
        assert "report" in result

    def test_post_validation_override(self):
        evidence = self._make_evidence()
        result = judge_evidence(evidence, mock=True)
        assert result["validated_output"][0]["case_type"] == "B"
        assert "report" in result
