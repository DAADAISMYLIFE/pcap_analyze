import pytest

from core.beacon_detector import detect_beaconing


class TestDetectBeaconing:
    def test_regular_interval_suspected(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 110.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 120.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 130.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 140.0},
        ]
        results = detect_beaconing(flows)
        assert len(results) == 1
        r = results[0]
        assert r["suspected"] is True
        assert r["connection_count"] == 5
        assert r["cv"] < 0.2

    def test_irregular_interval_not_suspected(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 105.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 200.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 205.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 500.0},
        ]
        results = detect_beaconing(flows)
        assert len(results) == 1
        assert results[0]["suspected"] is False

    def test_too_few_connections_pending(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 110.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 120.0},
        ]
        results = detect_beaconing(flows)
        assert len(results) == 1
        assert results[0]["suspected"] is None

    def test_single_connection_pending(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0},
        ]
        results = detect_beaconing(flows)
        assert len(results) == 1
        assert results[0]["suspected"] is None
        assert results[0]["mean_interval"] is None

    def test_multiple_pairs(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 110.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 120.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 130.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 140.0},
            {"src_ip": "10.0.0.2", "dst_ip": "5.6.7.8", "ts": 100.0},
            {"src_ip": "10.0.0.2", "dst_ip": "5.6.7.8", "ts": 300.0},
        ]
        results = detect_beaconing(flows)
        assert len(results) == 2

    def test_empty_flows(self):
        assert detect_beaconing([]) == []

    def test_very_short_interval_not_suspected(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0000},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0002},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0004},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0006},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0008},
        ]
        results = detect_beaconing(flows)
        assert len(results) == 1
        r = results[0]
        assert r["suspected"] is False
        assert r["note"] == "interval too short, likely simultaneous requests"

    def test_custom_threshold(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 100.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 110.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 121.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 130.0},
            {"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "ts": 141.0},
        ]
        strict = detect_beaconing(flows, cv_threshold=0.05)
        loose = detect_beaconing(flows, cv_threshold=0.5)
        assert strict[0]["suspected"] is False
        assert loose[0]["suspected"] is True
