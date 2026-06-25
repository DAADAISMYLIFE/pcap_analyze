import pytest

from report_generator import build_timeline, _parse_ts


class TestParseTs:
    def test_epoch_float(self):
        assert _parse_ts(1634913054.055) == 1634913054.055

    def test_iso_string(self):
        result = _parse_ts("2021-10-22T23:33:59.076948+0900")
        assert abs(result - 1634913239.076948) < 1.0

    def test_none(self):
        assert _parse_ts(None) == 0.0

    def test_invalid_string(self):
        assert _parse_ts("not a timestamp") == 0.0


class TestBuildTimeline:
    def test_filters_by_target_ips(self):
        evidence = {
            "evidence": {
                "signature_alerts": [
                    {"src_ip": "10.0.0.1", "dest_ip": "1.2.3.4", "timestamp": "2021-10-22T14:00:00+0000", "signature": "Test Alert", "severity": 1},
                    {"src_ip": "10.0.0.99", "dest_ip": "5.6.7.8", "timestamp": "2021-10-22T14:01:00+0000", "signature": "Other Alert", "severity": 3},
                ],
                "content_indicators": [],
                "anomalies": [],
            }
        }
        result = build_timeline(evidence, ["10.0.0.1"])
        assert len(result) == 1
        assert "Test Alert" in result[0]["detail"]

    def test_sorted_by_timestamp(self):
        evidence = {
            "evidence": {
                "signature_alerts": [
                    {"src_ip": "10.0.0.1", "dest_ip": "1.2.3.4", "timestamp": "2021-10-22T14:30:00+0000", "signature": "Late", "severity": 1},
                ],
                "content_indicators": [
                    {"type": "dns_query", "src_ip": "10.0.0.1", "dst_ip": None, "query": "evil.com", "query_count": 3, "ts": 1634911200.0},
                ],
                "anomalies": [
                    {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "name": "bad_checksum", "ts": 1634911500.0},
                ],
            }
        }
        result = build_timeline(evidence, ["10.0.0.1"])
        assert len(result) == 3
        assert result[0]["type"] == "dns_query"
        assert result[1]["type"] == "anomaly"
        assert result[2]["type"] == "signature_alert"

    def test_mixed_timestamp_formats(self):
        evidence = {
            "evidence": {
                "signature_alerts": [
                    {"src_ip": "10.0.0.1", "dest_ip": "1.2.3.4", "timestamp": "2021-10-22T14:00:00+0000", "signature": "ISO", "severity": 1},
                ],
                "content_indicators": [],
                "anomalies": [
                    {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "name": "epoch_event", "ts": 1634914800.0},
                ],
            }
        }
        result = build_timeline(evidence, ["10.0.0.1"])
        assert len(result) == 2
        assert result[0]["ts"] < result[1]["ts"]

    def test_empty_evidence(self):
        evidence = {"evidence": {"signature_alerts": [], "content_indicators": [], "anomalies": []}}
        result = build_timeline(evidence, ["10.0.0.1"])
        assert result == []

    def test_no_matching_ips(self):
        evidence = {
            "evidence": {
                "signature_alerts": [
                    {"src_ip": "10.0.0.99", "dest_ip": "1.2.3.4", "timestamp": "2021-10-22T14:00:00+0000", "signature": "Test", "severity": 1},
                ],
                "content_indicators": [],
                "anomalies": [],
            }
        }
        result = build_timeline(evidence, ["10.0.0.1"])
        assert result == []

    def test_dst_ip_match(self):
        evidence = {
            "evidence": {
                "signature_alerts": [],
                "content_indicators": [],
                "anomalies": [
                    {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "name": "inbound_anomaly", "ts": 1000.0},
                ],
            }
        }
        result = build_timeline(evidence, ["10.0.0.1"])
        assert len(result) == 1
