import json
import os

import pytest

from core.normalizer import normalize_evidence, _build_content_indicators, _build_host_identification

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(autouse=True)
def fixtures_dir():
    os.makedirs(FIXTURES_DIR, exist_ok=True)


def _write_jsonl(filename, records):
    path = os.path.join(FIXTURES_DIR, filename)
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    return path


class TestBuildContentIndicators:
    def test_http_download(self):
        http = [{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "host": "evil.com", "uri": "/malware.exe", "method": "GET", "user_agent": "Mozilla", "status_code": 200, "ts": 1.0}]
        files = [{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "sha256": "abc123", "md5": None, "mime_type": "application/exe"}]
        dns = []
        result = _build_content_indicators(http, dns, files)
        assert len(result) == 1
        r = result[0]
        assert r["type"] == "http_download"
        assert r["url"] == "evil.com/malware.exe"
        assert r["file_hash"] == "abc123"
        assert r["mime_type"] == "application/exe"

    def test_dns_query_dedup(self):
        http = []
        files = []
        dns = [
            {"src_ip": "10.0.0.1", "query": "evil.com", "query_count": 5, "ts": 1.0},
            {"src_ip": "10.0.0.1", "query": "evil.com", "query_count": 5, "ts": 2.0},
            {"src_ip": "10.0.0.1", "query": "good.com", "query_count": 1, "ts": 3.0},
        ]
        result = _build_content_indicators(http, dns, files)
        dns_results = [r for r in result if r["type"] == "dns_query"]
        assert len(dns_results) == 2
        queries = {r["query"] for r in dns_results}
        assert queries == {"evil.com", "good.com"}

    def test_no_file_match(self):
        http = [{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "host": "example.com", "uri": "/", "method": "GET", "user_agent": "Mozilla", "status_code": 200, "ts": 1.0}]
        files = []
        dns = []
        result = _build_content_indicators(http, dns, files)
        assert result[0]["file_hash"] is None
        assert result[0]["mime_type"] is None

    def test_empty_all(self):
        result = _build_content_indicators([], [], [])
        assert result == []


class TestBuildHostIdentification:
    def test_merge_dhcp_and_kerberos(self):
        dhcp = [{"src_ip": "10.0.0.1", "mac_address": "aa:bb:cc:dd:ee:ff", "host_name": "workstation-1"}]
        kerb = [{"src_ip": "10.0.0.1", "username": "jdoe"}]
        result = _build_host_identification(dhcp, kerb)
        assert len(result) == 1
        r = result[0]
        assert r["src_ip"] == "10.0.0.1"
        assert r["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert r["hostname"] == "workstation-1"
        assert r["username"] == "jdoe"

    def test_dhcp_only(self):
        dhcp = [{"src_ip": "10.0.0.1", "mac_address": "aa:bb:cc:dd:ee:ff", "host_name": "pc1"}]
        result = _build_host_identification(dhcp, [])
        assert len(result) == 1
        assert result[0]["username"] is None

    def test_kerberos_only(self):
        kerb = [{"src_ip": "10.0.0.1", "username": "admin"}]
        result = _build_host_identification([], kerb)
        assert len(result) == 1
        assert result[0]["mac_address"] is None
        assert result[0]["username"] == "admin"

    def test_multiple_ips(self):
        dhcp = [
            {"src_ip": "10.0.0.1", "mac_address": "aa:bb:cc:dd:ee:ff", "host_name": "pc1"},
            {"src_ip": "10.0.0.2", "mac_address": "11:22:33:44:55:66", "host_name": "pc2"},
        ]
        kerb = [{"src_ip": "10.0.0.1", "username": "jdoe"}]
        result = _build_host_identification(dhcp, kerb)
        assert len(result) == 2

    def test_empty(self):
        result = _build_host_identification([], [])
        assert result == []


class TestNormalizeEvidence:
    def _make_fixtures(self):
        conn = _write_jsonl("norm_conn.log", [
            {"ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": "1.2.3.4", "id.resp_p": 80, "proto": "tcp", "service": "http", "duration": 0.5, "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 2, "resp_pkts": 3},
        ])
        weird = _write_jsonl("norm_weird.log", [
            {"ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": "1.2.3.4", "name": "bad_checksum"},
        ])
        http = _write_jsonl("norm_http.log", [
            {"ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": "1.2.3.4", "method": "GET", "host": "evil.com", "uri": "/payload", "user_agent": "Mozilla", "status_code": 200},
        ])
        dns = _write_jsonl("norm_dns.log", [
            {"ts": 1.0, "id.orig_h": "10.0.0.1", "query": "evil.com"},
        ])
        files = _write_jsonl("norm_files.log", [
            {"id.orig_h": "10.0.0.1", "id.resp_h": "1.2.3.4", "seen_bytes": 500, "mime_type": "text/html"},
        ])
        eve = _write_jsonl("norm_eve.json", [
            {"event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "1.2.3.4", "dest_port": 80, "proto": "TCP", "timestamp": "2024-01-01T00:00:00", "alert": {"signature_id": 9999, "signature": "Test Alert", "severity": 2}},
        ])
        return conn, weird, http, dns, files, eve

    def test_all_categories_present(self):
        conn, weird, http, dns, files, eve = self._make_fixtures()
        result = normalize_evidence(conn, weird, http, dns, files, eve)
        assert "flows" in result
        assert "anomalies" in result
        assert "signature_alerts" in result
        assert "behavioral_alerts" in result
        assert "content_indicators" in result
        assert "host_identification" in result
        assert "extra_metadata" in result
        assert len(result["flows"]) == 1
        assert len(result["anomalies"]) == 1
        assert len(result["signature_alerts"]) == 1
        assert len(result["content_indicators"]) > 0

    def test_missing_log_files(self):
        _, _, _, _, _, eve = self._make_fixtures()
        result = normalize_evidence(
            "/nonexistent/conn.log",
            "/nonexistent/weird.log",
            "/nonexistent/http.log",
            "/nonexistent/dns.log",
            "/nonexistent/files.log",
            eve,
        )
        assert result["flows"] == []
        assert result["anomalies"] == []
        assert result["content_indicators"] == []
        assert len(result["signature_alerts"]) == 1

    def test_alerts_have_cve_field(self):
        conn, weird, http, dns, files, eve = self._make_fixtures()
        result = normalize_evidence(conn, weird, http, dns, files, eve)
        for alert in result["signature_alerts"]:
            assert "cve" in alert


# --- 실제 데이터 ---

REAL_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "output")
REAL_SURICATA = os.path.join(os.path.dirname(__file__), "..", "suricata_output")


@pytest.mark.skipif(
    not os.path.exists(os.path.join(REAL_OUTPUT, "conn.log")),
    reason="Real test data not available",
)
class TestRealData:
    def test_full_pipeline(self):
        result = normalize_evidence(
            f"{REAL_OUTPUT}/conn.log",
            f"{REAL_OUTPUT}/weird.log",
            f"{REAL_OUTPUT}/http.log",
            f"{REAL_OUTPUT}/dns.log",
            f"{REAL_OUTPUT}/files.log",
            f"{REAL_SURICATA}/eve.json",
            dhcp_log_path=f"{REAL_OUTPUT}/dhcp.log",
            kerberos_log_path=f"{REAL_OUTPUT}/kerberos.log",
        )
        assert len(result["flows"]) > 0
        assert len(result["anomalies"]) > 0
        assert len(result["behavioral_alerts"]) > 0
        assert len(result["content_indicators"]) > 0
        assert "host_identification" in result
        assert result["extra_metadata"] == {}
