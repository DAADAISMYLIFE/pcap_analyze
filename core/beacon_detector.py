import logging

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


def detect_beaconing(flows: list[dict], min_connections: int = 5, cv_threshold: float = 0.2, min_interval_sec: float = 1.0) -> list[dict]:
    if not flows:
        return []

    df = pd.DataFrame(flows)

    required = {"src_ip", "dst_ip", "ts"}
    if not required.issubset(df.columns):
        logger.warning("flows missing required fields: %s", required - set(df.columns))
        return []

    df = df.dropna(subset=["src_ip", "dst_ip", "ts"])
    df = df.sort_values("ts")

    results = []
    for (src, dst), group in df.groupby(["src_ip", "dst_ip"]):
        timestamps = group["ts"].values
        count = len(timestamps)

        if count < 2:
            results.append({
                "src_ip": src,
                "dst_ip": dst,
                "connection_count": count,
                "mean_interval": None,
                "cv": None,
                "suspected": None,
                "note": None,
            })
            continue

        intervals = np.diff(timestamps)
        mean_interval = float(np.mean(intervals))
        std_interval = float(np.std(intervals))
        cv = std_interval / mean_interval if mean_interval > 0 else None

        note = None
        if count < min_connections:
            suspected = None
        elif mean_interval < min_interval_sec:
            suspected = False
            note = "interval too short, likely simultaneous requests"
        elif cv is not None and cv < cv_threshold:
            suspected = True
        else:
            suspected = False

        results.append({
            "src_ip": src,
            "dst_ip": dst,
            "connection_count": count,
            "mean_interval": round(mean_interval, 4),
            "cv": round(cv, 4) if cv is not None else None,
            "suspected": suspected,
            "note": note,
        })

    return results


if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Detect beaconing (C2) patterns")
    ap.add_argument("--conn-log", default="output/conn.log", help="Zeek conn.log path")
    ap.add_argument("--min-conn", type=int, default=5, help="Minimum connections to judge")
    ap.add_argument("--cv-threshold", type=float, default=0.2, help="CV threshold for suspected")
    args = ap.parse_args()

    from core.parsers import parse_conn_log
    flows = parse_conn_log(args.conn_log)
    print(f"flows: {len(flows)}건")

    results = detect_beaconing(flows, args.min_conn, args.cv_threshold)
    suspected = [r for r in results if r["suspected"] is True]
    not_suspected = [r for r in results if r["suspected"] is False]
    pending = [r for r in results if r["suspected"] is None]

    print(f"\n총 {len(results)}개 IP 쌍 분석")
    print(f"  의심: {len(suspected)}건")
    print(f"  정상: {len(not_suspected)}건")
    print(f"  판단 보류: {len(pending)}건")

    if suspected:
        print("\n[의심 목록]")
        for r in sorted(suspected, key=lambda x: x["cv"]):
            print(f"  {r['src_ip']} -> {r['dst_ip']} | {r['connection_count']}회 | 평균간격 {r['mean_interval']}s | CV {r['cv']}")
