import os
import pytest

from core.cve_mapper import build_cve_lookup, apply_cve_mapping

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(autouse=True)
def fixtures_dir():
    os.makedirs(FIXTURES_DIR, exist_ok=True)


def _write_rules(filename, content):
    path = os.path.join(FIXTURES_DIR, filename)
    with open(path, "w") as f:
        f.write(content)
    return path


class TestBuildCveLookup:
    def test_basic(self):
        _write_rules("test.rules",
            'alert http any any -> any any (msg:"Test exploit"; reference:cve,2021-44228; sid:1001; rev:1;)\n'
            'alert tcp any any -> any any (msg:"Another"; reference:cve,2014-0160; sid:1002; rev:1;)\n'
        )
        lookup = build_cve_lookup(FIXTURES_DIR)
        assert lookup[1001] == "CVE-2021-44228"
        assert lookup[1002] == "CVE-2014-0160"

    def test_no_cve_reference(self):
        _write_rules("nocve.rules",
            'alert tcp any any -> any any (msg:"No CVE here"; sid:2001; rev:1;)\n'
        )
        lookup = build_cve_lookup(FIXTURES_DIR)
        assert 2001 not in lookup

    def test_comment_lines_ignored(self):
        _write_rules("comments.rules",
            '# This is a comment\n'
            '# alert http any any -> any any (msg:"Commented"; reference:cve,2020-1234; sid:3001; rev:1;)\n'
            'alert http any any -> any any (msg:"Active"; reference:cve,2020-5678; sid:3002; rev:1;)\n'
        )
        lookup = build_cve_lookup(FIXTURES_DIR)
        assert 3001 not in lookup
        assert lookup[3002] == "CVE-2020-5678"

    def test_empty_directory(self, tmp_path):
        lookup = build_cve_lookup(str(tmp_path))
        assert lookup == {}

    def test_nonexistent_directory(self):
        lookup = build_cve_lookup("/nonexistent/rules")
        assert lookup == {}

    def test_multiple_references_first_cve(self):
        _write_rules("multi.rules",
            'alert http any any -> any any (msg:"Multi ref"; reference:cve,2023-1111; reference:url,example.com; sid:4001; rev:1;)\n'
        )
        lookup = build_cve_lookup(FIXTURES_DIR)
        assert lookup[4001] == "CVE-2023-1111"


class TestApplyCveMapping:
    def test_match(self):
        alerts = [
            {"signature_id": 1001, "signature": "Test", "src_ip": "10.0.0.1"},
        ]
        lookup = {1001: "CVE-2021-44228"}
        result = apply_cve_mapping(alerts, lookup)
        assert result[0]["cve"] == "CVE-2021-44228"
        assert result[0]["signature"] == "Test"

    def test_no_match(self):
        alerts = [
            {"signature_id": 9999, "signature": "Unknown", "src_ip": "10.0.0.1"},
        ]
        lookup = {1001: "CVE-2021-44228"}
        result = apply_cve_mapping(alerts, lookup)
        assert result[0]["cve"] is None

    def test_missing_sid(self):
        alerts = [{"signature": "No SID", "src_ip": "10.0.0.1"}]
        result = apply_cve_mapping(alerts, {})
        assert result[0]["cve"] is None

    def test_empty_alerts(self):
        result = apply_cve_mapping([], {1001: "CVE-2021-44228"})
        assert result == []

    def test_original_not_mutated(self):
        alerts = [{"signature_id": 1001, "src_ip": "10.0.0.1"}]
        apply_cve_mapping(alerts, {1001: "CVE-2021-44228"})
        assert "cve" not in alerts[0]


# --- 실제 룰 테스트 ---

REAL_RULES_DIR = "/usr/share/suricata/rules"


@pytest.mark.skipif(
    not os.path.exists(REAL_RULES_DIR),
    reason="Suricata rules not available",
)
class TestRealRules:
    def test_parses_without_error(self):
        lookup = build_cve_lookup(REAL_RULES_DIR)
        assert isinstance(lookup, dict)

    def test_heartbleed_mapping(self):
        lookup = build_cve_lookup(REAL_RULES_DIR)
        heartbleed_sids = [sid for sid, cve in lookup.items() if cve == "CVE-2014-0160"]
        assert len(heartbleed_sids) > 0
