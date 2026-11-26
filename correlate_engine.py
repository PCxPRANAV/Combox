#!/usr/bin/env python3
"""
Tri-Layer Forensic Correlation Engine
--------------------------------------
Correlates Zeek conn.log (Network), Volatility 3 netscan (Memory), and a
fixed Host-layer narrative describing the lab's lure -> beacon -> rename
sequence, into a single unified timeline.json for the dashboard.

Usage:
    python3 correlate_engine.py --conn conn.log --netscan vol_netscan.txt \
        --attacker-ip 192.168.56.10 --out timeline.json
"""
import argparse
import json
from datetime import datetime, timezone


def parse_zeek_conn(conn_log_path):
    """Parses a Zeek conn.log (tab-separated, '#'-prefixed header/comments)."""
    events = []
    try:
        with open(conn_log_path, "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 7:
                    continue
                try:
                    ts = float(parts[0])
                    iso_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                except ValueError:
                    iso_time = None
                events.append({
                    "timestamp": iso_time,
                    "layer": "Network",
                    "source_ip": parts[2],
                    "source_port": parts[3],
                    "dest_ip": parts[4],
                    "dest_port": parts[5],
                    "protocol": parts[6],
                    "event_type": "Network Session",
                    "mitre_id": "T1071.001",
                    "details": f"Connection {parts[2]}:{parts[3]} -> {parts[4]}:{parts[5]} ({parts[6]})",
                })
    except FileNotFoundError:
        print(f"[-] Notice: {conn_log_path} not found, skipping network layer.")
    return events


def parse_volatility_netscan(netscan_path, attacker_ip):
    """Parses Volatility 3 'windows.netscan' plain-text output."""
    events = []
    try:
        with open(netscan_path, "r", errors="ignore") as f:
            for line in f:
                if attacker_ip in line:
                    tokens = line.split()
                    if len(tokens) < 8:
                        continue
                    events.append({
                        "layer": "RAM",
                        "protocol": tokens[1] if len(tokens) > 1 else "Unknown",
                        "local_socket": tokens[2] if len(tokens) > 2 else "Unknown",
                        "foreign_socket": tokens[4] if len(tokens) > 4 else "Unknown",
                        "pid": tokens[7] if len(tokens) > 7 else "Unknown",
                        "process_name": tokens[8] if len(tokens) > 8 else "powershell.exe",
                        "event_type": "Memory Socket Anchor",
                        "mitre_id": "T1071.001",
                        "details": f"PID {tokens[7] if len(tokens) > 7 else '?'} active socket found in kernel pool",
                    })
    except FileNotFoundError:
        print(f"[-] Notice: {netscan_path} not found, skipping memory layer.")
    return events


def build_host_anchors():
    """
    Fixed narrative for the Host layer, matching the safe lab sequence:
    lure double-click -> visible PowerShell -> HTTP GET -> local rename script.
    Replace the timestamps below with the actual times from your own run
    (read them off the Sysmon export) before presenting results.
    """
    return [
        {
            "timestamp": "2025-03-30T10:14:02Z",
            "layer": "Host",
            "event_type": "Process Create",
            "pid": "4892",
            "image": "powershell.exe",
            "mitre_id": "T1204.002",
            "details": "Lure double-clicked: Invoice_March2025.pdf.lnk spawned a visible powershell.exe",
        },
        {
            "timestamp": "2025-03-30T10:14:07Z",
            "layer": "Host",
            "event_type": "File Rename",
            "pid": "4892",
            "target_directory": "C:\\CanaryData",
            "mitre_id": "T1486",
            "details": "Sysmon Event ID 11: 5 canary files renamed to .locked (contents unmodified - simulation only)",
        },
    ]


def synthesize_timeline(net_records, mem_records, host_records):
    timeline = list(host_records)

    for net in net_records:
        entry = dict(net)
        for mem in mem_records:
            if mem.get("foreign_socket", "").split(":")[0] == net.get("dest_ip"):
                entry["attributed_pid"] = mem["pid"]
                entry["process_name"] = mem["process_name"]
                break
        timeline.append(entry)

    timeline.extend(mem_records)
    timeline.sort(key=lambda x: x.get("timestamp") or "")
    return timeline


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Tri-layer forensic correlation engine")
    ap.add_argument("--conn", default="conn.log", help="Path to Zeek conn.log")
    ap.add_argument("--netscan", default="vol_netscan.txt", help="Path to Volatility netscan output")
    ap.add_argument("--attacker-ip", default="192.168.56.10", help="Attacker VM IP")
    ap.add_argument("--out", default="timeline.json", help="Output JSON path")
    args = ap.parse_args()

    print("[*] Running Tri-Layer Forensic Cross-Correlation...")
    net_data = parse_zeek_conn(args.conn)
    mem_data = parse_volatility_netscan(args.netscan, args.attacker_ip)
    host_data = build_host_anchors()

    unified = synthesize_timeline(net_data, mem_data, host_data)

    with open(args.out, "w") as f:
        json.dump(unified, f, indent=2)

    print(f"[+] Correlation complete. Exported {len(unified)} events to {args.out}")
