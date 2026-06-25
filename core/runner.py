import logging
import subprocess
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def run_zeek(pcap_path: str, output_dir: str) -> bool:
    pcap = Path(pcap_path).resolve()
    out = Path(output_dir).resolve()

    if not pcap.exists():
        logger.error("pcap not found: %s", pcap)
        return False

    out.mkdir(parents=True, exist_ok=True)

    if not shutil.which("docker"):
        logger.error("docker not found — Zeek requires Docker")
        return False

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap.parent}:/pcap:ro",
        "-v", f"{out}:/output",
        "zeek/zeek:latest",
        "zeek", "-r", f"/pcap/{pcap.name}",
        "LogAscii::use_json=T",
        "Log::default_logdir=/output",
    ]

    logger.info("Running Zeek: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.error("Zeek failed (exit %d): %s", result.returncode, result.stderr)
            return False
        logger.info("Zeek completed. Logs in %s", out)
        return True
    except subprocess.TimeoutExpired:
        logger.error("Zeek timed out (300s)")
        return False
    except Exception as e:
        logger.error("Zeek execution error: %s", e)
        return False


def run_suricata(pcap_path: str, output_dir: str, config_path: str = "/etc/suricata/suricata.yaml") -> bool:
    pcap = Path(pcap_path).resolve()
    out = Path(output_dir).resolve()

    if not pcap.exists():
        logger.error("pcap not found: %s", pcap)
        return False

    out.mkdir(parents=True, exist_ok=True)

    if not shutil.which("suricata"):
        logger.error("suricata not found in PATH")
        return False

    cmd = [
        "suricata",
        "-r", str(pcap),
        "-l", str(out),
        "-c", config_path,
    ]

    logger.info("Running Suricata: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.error("Suricata failed (exit %d): %s", result.returncode, result.stderr)
            return False
        logger.info("Suricata completed. Logs in %s", out)
        return True
    except subprocess.TimeoutExpired:
        logger.error("Suricata timed out (300s)")
        return False
    except PermissionError:
        logger.error("Suricata permission denied — try running with sudo or fix /etc/suricata/ permissions")
        return False
    except Exception as e:
        logger.error("Suricata execution error: %s", e)
        return False


def run_all(pcap_path: str, output_dir: str = "output", suricata_dir: str = "suricata_output", suricata_config: str = "/etc/suricata/suricata.yaml") -> dict:
    results = {}

    results["zeek"] = run_zeek(pcap_path, output_dir)
    results["suricata"] = run_suricata(pcap_path, suricata_dir, config_path=suricata_config)

    if not results["zeek"]:
        if list(Path(output_dir).glob("*.log")):
            logger.warning("Zeek failed but existing logs found in %s — continuing with those", output_dir)
        else:
            logger.error("Zeek failed and no existing logs found")

    if not results["suricata"]:
        if Path(suricata_dir, "eve.json").exists():
            logger.warning("Suricata failed but existing eve.json found in %s — continuing with that", suricata_dir)
        else:
            logger.error("Suricata failed and no existing eve.json found")

    return results


if __name__ == "__main__":
    import argparse
    import glob

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Run Zeek and Suricata on pcap files")
    ap.add_argument("--pcap-dir", default="input", help="Directory containing pcap files")
    ap.add_argument("--pcap", help="Single pcap file path (overrides --pcap-dir)")
    ap.add_argument("--output-dir", default="output", help="Zeek log output directory")
    ap.add_argument("--suricata-dir", default="suricata_output", help="Suricata log output directory")
    args = ap.parse_args()

    if args.pcap:
        pcaps = [args.pcap]
    else:
        pcaps = sorted(glob.glob(f"{args.pcap_dir}/*.pcap"))
        if not pcaps:
            logger.error("No pcap files found in %s", args.pcap_dir)
            exit(1)
        print(f"Found {len(pcaps)} pcap file(s)")

    for pcap in pcaps:
        print(f"\n{'='*60}")
        print(f"Processing: {pcap}")
        print(f"{'='*60}")
        results = run_all(pcap, args.output_dir, args.suricata_dir)
        for tool, success in results.items():
            status = "OK" if success else "FAILED (using existing logs if available)"
            print(f"  {tool}: {status}")
