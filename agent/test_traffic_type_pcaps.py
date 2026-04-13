#!/usr/bin/env python3
"""
Replay PCAPs and validate traffic-type inference end-to-end.

Example:
    python test_traffic_type_pcaps.py --server http://localhost:8000 --pcap-path ./pcaps
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import requests

from replay_pcap import find_pcap_files, replay_single_pcap
from aegisnet_pipeline.storage import PipelineStorage

EXPECTED_LABELS = {"DNS", "FTP", "SSH", "VPN", "HTTPS", "other"}


def fetch_overview(server: str) -> dict:
    url = f"{server.rstrip('/')}/api/traffic-types/overview?limit=200"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    return resp.json()


def wait_for_count_growth(server: str, baseline: int, timeout_seconds: int) -> dict:
    deadline = time.time() + timeout_seconds
    latest = {}
    while time.time() < deadline:
        latest = fetch_overview(server)
        total = int(latest.get("total_predictions") or 0)
        if total > baseline:
            return latest
        time.sleep(2)
    return latest


def main() -> int:
    parser = argparse.ArgumentParser(description="PCAP-based validation for traffic-type inference")
    parser.add_argument("--server", default="http://localhost:8000", help="Cloud backend URL")
    parser.add_argument("--pcap-path", required=True, help="PCAP file or directory")
    parser.add_argument("--delay-between-files", type=int, default=1, help="Delay between PCAP files in seconds")
    parser.add_argument("--wait-timeout", type=int, default=60, help="Max seconds to wait for new predictions")
    args = parser.parse_args()

    pcap_files = find_pcap_files(args.pcap_path)
    if not pcap_files:
        print(f"[FAIL] No .pcap/.pcapng files found in: {args.pcap_path}")
        return 1

    storage = PipelineStorage(Path("data/traffic_type_test_temp.db"), server_url=args.server)
    if not storage.check_backend_health():
        print(f"[FAIL] Backend is not reachable at {args.server}")
        return 1

    before = fetch_overview(args.server)
    baseline_total = int(before.get("total_predictions") or 0)

    print("=" * 70)
    print("Traffic Type PCAP Validation")
    print(f"Backend     : {args.server}")
    print(f"PCAP files  : {len(pcap_files)}")
    print(f"Baseline DB : {baseline_total} classified flows")
    print("=" * 70)

    replayed_flows = 0
    for idx, pcap in enumerate(pcap_files, start=1):
        print(f"[{idx}/{len(pcap_files)}] Replaying {pcap}")
        replayed_flows += int(replay_single_pcap(pcap, storage) or 0)
        if idx < len(pcap_files) and args.delay_between_files > 0:
            time.sleep(args.delay_between_files)

    after = wait_for_count_growth(args.server, baseline_total, args.wait_timeout)
    total_after = int(after.get("total_predictions") or 0)
    known_labels = set(after.get("known_labels") or [])
    distribution = after.get("distribution") or []
    recent = after.get("recent") or []

    failures = []

    if total_after <= baseline_total:
        failures.append(
            f"No new traffic-type predictions observed (before={baseline_total}, after={total_after})."
        )

    if known_labels != EXPECTED_LABELS:
        failures.append(
            f"Known labels mismatch. Expected {sorted(EXPECTED_LABELS)}, got {sorted(known_labels)}."
        )

    bad_dist_labels = [row.get("label") for row in distribution if row.get("label") not in EXPECTED_LABELS]
    if bad_dist_labels:
        failures.append(f"Unexpected labels in distribution: {bad_dist_labels}")

    bad_recent_labels = [row.get("traffic_type") for row in recent if row.get("traffic_type") not in EXPECTED_LABELS]
    if bad_recent_labels:
        failures.append(f"Unexpected labels in recent predictions: {bad_recent_labels[:10]}")

    if not recent:
        failures.append("No recent prediction rows returned by /api/traffic-types/overview.")

    print("\nValidation Summary")
    print(f"- Replayed flows          : {replayed_flows}")
    print(f"- Total predictions (new) : {total_after - baseline_total}")
    print(f"- Model loaded            : {bool(after.get('model_loaded'))}")

    if failures:
        print("\n[FAIL] Traffic-type validation failed:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("\n[PASS] Traffic-type inference is active and labels are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
