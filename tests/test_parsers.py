import json
import os
import tempfile

import pytest

from core.parsers import (
    parse_conn_log,
    parse_weird_log,
    parse_http_log,
    parse_dns_log,
    parse_files_log,
    parse_suricata_eve,
    parse_dhcp_log,
    parse_kerberos_log,
)

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


# --- conn.log ---

class TestParseConnLog:
    def test_basic(self):
        path = _write_jsonl("conn.log", [
            {
                "ts": 1508561515.7, "id.orig_h": "10.0.1.95", "id.orig_p": 49672,
                "id.resp_h": "65.52.108.254", "id.resp_p": 443, "proto": "tcp",
                "service": "ssl", "duration": 0.302, "orig_bytes": 3019,
                "resp_bytes": 3892, "orig_pkts": 11, "resp_pkts": 13,
            }
        ])
        result = parse_conn_log(path)
        assert len(result) == 1
        r = result[0]
        assert r["src_ip"] == "10.0.1.95"
        assert r["dst_ip"] == "65.52.108.254"
        assert r["dst_port"] == 443
        assert r["proto"] == "tcp"
        assert r["service"] == "ssl"
        assert r["ts"] == 1508561515.7
        assert r["orig_bytes"] == 3019
        assert r["resp_bytes"] == 3892
        assert r["orig_pkts"] == 11
        assert r["resp_pkts"] == 13

    def test_missing_file(self):
        result = parse_conn_log("/nonexistent/conn.log")
        assert result == []

    def test_empty_file(self):
        path = _write_jsonl("conn_empty.log", [])
        result = parse_conn_log(path)
        assert result == []


# --- weird.log ---

class TestParseWeirdLog:
    def test_basic(self):
        path = _write_jsonl("weird.log", [
            {
                "ts": 1508561513.3, "id.orig_h": "0.0.0.0", "id.orig_p": 68,
                "id.resp_h": "255.255.255.255", "id.resp_p": 67,
                "name": "bad_UDP_checksum",
            }
        ])
        result = parse_weird_log(path)
        assert len(result) == 1
        assert result[0]["name"] == "bad_UDP_checksum"
        assert result[0]["src_ip"] == "0.0.0.0"

    def test_missing_file(self):
        assert parse_weird_log("/nonexistent/weird.log") == []


# --- http.log ---

class TestParseHttpLog:
    def test_basic(self):
        path = _write_jsonl("http.log", [
            {
                "ts": 1508561515.5, "id.orig_h": "10.0.1.95", "id.resp_h": "23.79.213.47",
                "method": "GET", "host": "cdn.example.com", "uri": "/index.html",
                "user_agent": "Mozilla/5.0", "status_code": 200,
            }
        ])
        result = parse_http_log(path)
        assert len(result) == 1
        r = result[0]
        assert r["method"] == "GET"
        assert r["host"] == "cdn.example.com"
        assert r["uri"] == "/index.html"
        assert r["user_agent"] == "Mozilla/5.0"
        assert r["status_code"] == 200

    def test_missing_file(self):
        assert parse_http_log("/nonexistent/http.log") == []


# --- dns.log ---

class TestParseDnsLog:
    def test_basic_with_query_count(self):
        path = _write_jsonl("dns.log", [
            {"ts": 1.0, "id.orig_h": "10.0.1.95", "query": "evil.com"},
            {"ts": 2.0, "id.orig_h": "10.0.1.95", "query": "evil.com"},
            {"ts": 3.0, "id.orig_h": "10.0.1.95", "query": "google.com"},
        ])
        result = parse_dns_log(path)
        assert len(result) == 3
        evil_entries = [r for r in result if r["query"] == "evil.com"]
        assert all(r["query_count"] == 2 for r in evil_entries)
        google_entries = [r for r in result if r["query"] == "google.com"]
        assert all(r["query_count"] == 1 for r in google_entries)

    def test_missing_query_field(self):
        path = _write_jsonl("dns_noquery.log", [
            {"ts": 1.0, "id.orig_h": "10.0.1.95"},
        ])
        result = parse_dns_log(path)
        assert len(result) == 1
        assert result[0]["query"] is None
        assert result[0]["query_count"] == 0

    def test_missing_file(self):
        assert parse_dns_log("/nonexistent/dns.log") == []


# --- files.log ---

class TestParseFilesLog:
    def test_with_hash(self):
        path = _write_jsonl("files.log", [
            {
                "id.orig_h": "10.0.1.95", "id.resp_h": "1.2.3.4",
                "sha256": "abcd1234", "md5": "ef56",
                "seen_bytes": 1024, "mime_type": "application/pdf",
            }
        ])
        result = parse_files_log(path)
        assert len(result) == 1
        assert result[0]["sha256"] == "abcd1234"
        assert result[0]["file_size"] == 1024
        assert result[0]["mime_type"] == "application/pdf"

    def test_without_hash(self):
        path = _write_jsonl("files_nohash.log", [
            {
                "id.orig_h": "10.0.1.95", "id.resp_h": "1.2.3.4",
                "seen_bytes": 500, "mime_type": "text/html",
            }
        ])
        result = parse_files_log(path)
        assert len(result) == 1
        assert result[0]["sha256"] is None
        assert result[0]["md5"] is None

    def test_missing_file(self):
        assert parse_files_log("/nonexistent/files.log") == []


# --- suricata eve.json ---

class TestParseSuricataEve:
    def test_filters_alerts_only(self):
        path = _write_jsonl("eve.json", [
            {"event_type": "dns", "src_ip": "10.0.1.95"},
            {
                "event_type": "alert", "src_ip": "10.0.1.95",
                "dest_ip": "1.2.3.4", "dest_port": 443, "proto": "TCP",
                "timestamp": "2017-10-21T13:51:55.843121+0900",
                "alert": {
                    "signature_id": 2028370, "rev": 2,
                    "signature": "ET JA3 Hash - Possible Malware",
                    "severity": 3,
                },
            },
            {"event_type": "flow", "src_ip": "10.0.1.95"},
        ])
        result = parse_suricata_eve(path)
        assert len(result) == 1
        r = result[0]
        assert r["signature_id"] == 2028370
        assert r["signature"] == "ET JA3 Hash - Possible Malware"
        assert r["severity"] == 3
        assert r["src_ip"] == "10.0.1.95"
        assert r["dest_ip"] == "1.2.3.4"
        assert r["proto"] == "TCP"

    def test_missing_file(self):
        assert parse_suricata_eve("/nonexistent/eve.json") == []


# --- 실제 데이터 통합 테스트 ---

# --- dhcp.log ---

class TestParseDhcpLog:
    def test_basic(self):
        path = _write_jsonl("dhcp.log", [
            {
                "ts": 1.0, "client_addr": "10.0.0.5", "mac": "00:e0:4c:68:08:00",
                "host_name": "workstation-1",
            }
        ])
        result = parse_dhcp_log(path)
        assert len(result) == 1
        r = result[0]
        assert r["src_ip"] == "10.0.0.5"
        assert r["mac_address"] == "00:e0:4c:68:08:00"
        assert r["host_name"] == "workstation-1"

    def test_assigned_addr_fallback(self):
        path = _write_jsonl("dhcp_assigned.log", [
            {"ts": 1.0, "assigned_addr": "10.0.0.10", "mac": "aa:bb:cc:dd:ee:ff", "host_name": "pc2"},
        ])
        result = parse_dhcp_log(path)
        assert result[0]["src_ip"] == "10.0.0.10"

    def test_missing_file(self):
        assert parse_dhcp_log("/nonexistent/dhcp.log") == []


# --- kerberos.log ---

class TestParseKerberosLog:
    def test_basic(self):
        path = _write_jsonl("kerberos.log", [
            {
                "ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.1",
                "client": "jdoe/EXAMPLE.COM", "service": "krbtgt/EXAMPLE.COM",
            }
        ])
        result = parse_kerberos_log(path)
        assert len(result) == 1
        assert result[0]["src_ip"] == "10.0.0.5"
        assert result[0]["username"] == "jdoe"

    def test_no_realm(self):
        path = _write_jsonl("kerb_norealm.log", [
            {"ts": 1.0, "id.orig_h": "10.0.0.5", "client": "admin"},
        ])
        result = parse_kerberos_log(path)
        assert result[0]["username"] == "admin"

    def test_no_client(self):
        path = _write_jsonl("kerb_noclient.log", [
            {"ts": 1.0, "id.orig_h": "10.0.0.5"},
        ])
        result = parse_kerberos_log(path)
        assert result[0]["username"] is None

    def test_missing_file(self):
        assert parse_kerberos_log("/nonexistent/kerberos.log") == []


# --- 실제 데이터 통합 테스트 ---

REAL_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "output")
REAL_SURICATA = os.path.join(os.path.dirname(__file__), "..", "suricata_output")


@pytest.mark.skipif(
    not os.path.exists(os.path.join(REAL_OUTPUT, "conn.log")),
    reason="Real test data not available",
)
class TestRealData:
    def test_conn_log(self):
        result = parse_conn_log(os.path.join(REAL_OUTPUT, "conn.log"))
        assert len(result) > 0
        assert all(r["src_ip"] is not None for r in result)

    def test_weird_log(self):
        result = parse_weird_log(os.path.join(REAL_OUTPUT, "weird.log"))
        assert len(result) > 0

    def test_http_log(self):
        result = parse_http_log(os.path.join(REAL_OUTPUT, "http.log"))
        assert len(result) > 0
        assert any(r["method"] is not None for r in result)

    def test_dns_log(self):
        result = parse_dns_log(os.path.join(REAL_OUTPUT, "dns.log"))
        assert len(result) > 0
        has_count = any(r["query_count"] > 1 for r in result)
        assert has_count, "Expected at least one domain queried more than once"

    def test_files_log(self):
        result = parse_files_log(os.path.join(REAL_OUTPUT, "files.log"))
        assert len(result) > 0

    def test_suricata_eve(self):
        result = parse_suricata_eve(os.path.join(REAL_SURICATA, "eve.json"))
        assert len(result) > 0
        assert all(r["signature_id"] is not None for r in result)

    def test_dhcp_log(self):
        path = os.path.join(REAL_OUTPUT, "dhcp.log")
        if not os.path.exists(path):
            pytest.skip("dhcp.log not available")
        result = parse_dhcp_log(path)
        assert len(result) > 0

    def test_kerberos_log(self):
        path = os.path.join(REAL_OUTPUT, "kerberos.log")
        if not os.path.exists(path):
            pytest.skip("kerberos.log not available")
        result = parse_kerberos_log(path)
        assert len(result) > 0
        assert any(r["username"] is not None for r in result)
