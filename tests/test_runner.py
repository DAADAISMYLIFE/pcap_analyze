import os
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from core.runner import run_zeek, run_suricata, run_all


class TestRunZeek:
    def test_pcap_not_found(self):
        assert run_zeek("/nonexistent/file.pcap", "/tmp/out") is False

    def test_docker_not_found(self):
        with patch("core.runner.shutil.which", return_value=None):
            assert run_zeek("input/2017-10-21-traffic-analysis-exercise.pcap", "/tmp/out") is False

    def test_success(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        out = tmp_path / "output"

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("core.runner.shutil.which", return_value="/usr/bin/docker"), \
             patch("core.runner.subprocess.run", return_value=mock_result) as mock_run:
            assert run_zeek(str(pcap), str(out)) is True
            cmd = mock_run.call_args[0][0]
            assert "docker" in cmd
            assert "zeek" in cmd

    def test_failure(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error"

        with patch("core.runner.shutil.which", return_value="/usr/bin/docker"), \
             patch("core.runner.subprocess.run", return_value=mock_result):
            assert run_zeek(str(pcap), str(tmp_path / "out")) is False

    def test_timeout(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()

        with patch("core.runner.shutil.which", return_value="/usr/bin/docker"), \
             patch("core.runner.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300)):
            assert run_zeek(str(pcap), str(tmp_path / "out")) is False


class TestRunSuricata:
    def test_pcap_not_found(self):
        assert run_suricata("/nonexistent/file.pcap", "/tmp/out") is False

    def test_suricata_not_found(self):
        with patch("core.runner.shutil.which", return_value=None):
            assert run_suricata("input/2017-10-21-traffic-analysis-exercise.pcap", "/tmp/out") is False

    def test_success(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("core.runner.shutil.which", return_value="/usr/bin/suricata"), \
             patch("core.runner.subprocess.run", return_value=mock_result):
            assert run_suricata(str(pcap), str(tmp_path / "out")) is True

    def test_permission_error(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()

        with patch("core.runner.shutil.which", return_value="/usr/bin/suricata"), \
             patch("core.runner.subprocess.run", side_effect=PermissionError("denied")):
            assert run_suricata(str(pcap), str(tmp_path / "out")) is False


class TestRunAll:
    def test_both_fail_no_existing_logs(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        out = str(tmp_path / "output")
        suri = str(tmp_path / "suricata")

        with patch("core.runner.run_zeek", return_value=False), \
             patch("core.runner.run_suricata", return_value=False):
            results = run_all(str(pcap), out, suri)
            assert results["zeek"] is False
            assert results["suricata"] is False

    def test_both_fail_existing_logs(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.touch()
        out = tmp_path / "output"
        out.mkdir()
        (out / "conn.log").touch()
        suri = tmp_path / "suricata"
        suri.mkdir()
        (suri / "eve.json").touch()

        with patch("core.runner.run_zeek", return_value=False), \
             patch("core.runner.run_suricata", return_value=False):
            results = run_all(str(pcap), str(out), str(suri))
            assert results["zeek"] is False
            assert results["suricata"] is False
