#!/usr/bin/env python3
"""
lateral_detect.py

Reads Zeek logs (conn.log in TSV or JSON-lines format) and produces minimal outputs:
1) derived/lateral_findings.json  (LLM-friendly structured findings)
2) derived/evidence.csv           (every claim must reference evidence_id(s))

Designed for SC4063 Part 2: Lateral Movement & Discovery

Folder expectation (from run_zeek_logs.py):
<out>/<pcap_stem>/zeek/conn.log (or conn.*)
Writes:
<out>/<pcap_stem>/derived/lateral_findings.json
<out>/<pcap_stem>/derived/evidence.csv

Usage:
python lateral_detect.py \
  --zeek-dir ./artifacts/34936-sensor-250309-00002493_redacted/zeek \
  --out-dir  ./artifacts/34936-sensor-250309-00002493_redacted/derived \
  --pcap-name 34936-sensor-250309-00002493_redacted.pcap

Notes:
- Works whether conn.log is Zeek TSV (default) OR Zeek JSON-lines (--json in zeek runner).
- Focuses on lateral movement/discovery signals:
  * fan-out scanning to TCP/445 and TCP/135
  * follow-on “deeper” sessions (bytes/duration)
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

RFC1918_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

PORTS_OF_INTEREST = {445, 135, 3389, 5985, 5986}


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in RFC1918_NETS)
    except ValueError:
        return False


def to_int(s: object, default: int = 0) -> int:
    try:
        if s is None:
            return default
        if isinstance(s, (int, float)):
            return int(s)
        s2 = str(s).strip()
        if s2 in ("", "-", "(empty)"):
            return default
        return int(float(s2))
    except Exception:
        return default


def to_float(s: object, default: float = 0.0) -> float:
    try:
        if s is None:
            return default
        if isinstance(s, (int, float)):
            return float(s)
        s2 = str(s).strip()
        if s2 in ("", "-", "(empty)"):
            return default
        return float(s2)
    except Exception:
        return default


def epoch_to_iso8601(ts: float) -> str:
    # Zeek ts is typically epoch seconds
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def bucket_epoch(ts: float, bucket_seconds: int) -> int:
    return int(ts // bucket_seconds) * bucket_seconds


@dataclass
class ConnRow:
    line_no: int
    ts: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str

    @property
    def total_bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes

    def five_tuple(self) -> str:
        return f"{self.orig_h}:{self.orig_p} -> {self.resp_h}:{self.resp_p} ({self.proto})"


def detect_conn_format(conn_path: Path) -> str:
    """
    Returns: "jsonl" or "tsv"
    Zeek JSON logs are usually JSON objects per line.
    TSV logs have #fields header and tab-separated rows.
    """
    with conn_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                # Zeek TSV header/comment
                return "tsv"
            if line.startswith("{") and line.endswith("}"):
                return "jsonl"
            # If it's not obviously JSON, assume TSV
            return "tsv"
    return "tsv"


def iter_conn_jsonl(conn_path: Path) -> Iterator[ConnRow]:
    with conn_path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if not (line.startswith("{") and line.endswith("}")):
                continue
            obj = json.loads(line)

            yield ConnRow(
                line_no=i,
                ts=to_float(obj.get("ts"), 0.0),
                orig_h=str(obj.get("id.orig_h", "")),
                orig_p=to_int(obj.get("id.orig_p"), 0),
                resp_h=str(obj.get("id.resp_h", "")),
                resp_p=to_int(obj.get("id.resp_p"), 0),
                proto=str(obj.get("proto", "")),
                duration=to_float(obj.get("duration"), 0.0),
                orig_bytes=to_int(obj.get("orig_bytes"), 0),
                resp_bytes=to_int(obj.get("resp_bytes"), 0),
                conn_state=str(obj.get("conn_state", "")),
            )


def iter_conn_tsv(conn_path: Path) -> Iterator[ConnRow]:
    """
    Parses Zeek TSV conn.log:
    - header lines start with '#'
    - '#fields' defines field order
    - rows are tab-separated
    """
    fields: List[str] = []
    with conn_path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                # Example: #fields ts uid id.orig_h ...
                parts = line.split("\t")
                fields = parts[1:]  # after "#fields"
                continue
            if line.startswith("#"):
                continue
            if not fields:
                # If no header seen, cannot parse reliably
                continue

            parts = line.split("\t")
            if len(parts) != len(fields):
                continue
            obj = dict(zip(fields, parts))

            yield ConnRow(
                line_no=i,
                ts=to_float(obj.get("ts"), 0.0),
                orig_h=str(obj.get("id.orig_h", "")),
                orig_p=to_int(obj.get("id.orig_p"), 0),
                resp_h=str(obj.get("id.resp_h", "")),
                resp_p=to_int(obj.get("id.resp_p"), 0),
                proto=str(obj.get("proto", "")),
                duration=to_float(obj.get("duration"), 0.0),
                orig_bytes=to_int(obj.get("orig_bytes"), 0),
                resp_bytes=to_int(obj.get("resp_bytes"), 0),
                conn_state=str(obj.get("conn_state", "")),
            )


def iter_conn_rows(conn_path: Path) -> Iterator[ConnRow]:
    fmt = detect_conn_format(conn_path)
    if fmt == "jsonl":
        yield from iter_conn_jsonl(conn_path)
    else:
        yield from iter_conn_tsv(conn_path)


def find_conn_log(zeek_dir: Path) -> Path:
    """
    Prefer conn.log; otherwise any file starting with conn.
    """
    direct = zeek_dir / "conn.log"
    if direct.exists():
        return direct

    candidates = sorted([p for p in zeek_dir.iterdir() if p.is_file() and p.name.startswith("conn")])
    if not candidates:
        raise FileNotFoundError(f"No conn log found in {zeek_dir}. Expected conn.log or conn*.")
    return candidates[0]


def write_evidence_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        # still write header
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "evidence_id",
                    "log_source",
                    "ts_iso8601",
                    "ts_epoch",
                    "five_tuple",
                    "duration_sec",
                    "orig_bytes",
                    "resp_bytes",
                    "total_bytes",
                    "conn_state",
                    "src_ip",
                    "dst_ip",
                    "dst_port",
                    "proto",
                    "zeek_line_no",
                ],
            )
            writer.writeheader()
        return

    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Lateral Movement minimal outputs from Zeek conn logs.")
    ap.add_argument("--zeek-dir", required=True, help="Path to Zeek log directory (contains conn.log).")
    ap.add_argument("--out-dir", required=True, help="Output directory for derived artifacts.")
    ap.add_argument("--pcap-name", default="", help="Optional: original PCAP filename for metadata.")
    ap.add_argument("--bucket-sec", type=int, default=60, help="Time bucket size for scan detection.")
    ap.add_argument("--scan-unique-thresh", type=int, default=25, help="Unique dst threshold (445 or 135) per bucket.")
    ap.add_argument("--scan-totalconns-thresh", type=int, default=100, help="Total connections threshold per bucket.")
    ap.add_argument("--lateral-bytes-thresh", type=int, default=50_000, help="Total bytes threshold for 'deeper sessions'.")
    ap.add_argument("--lateral-dur-thresh", type=float, default=30.0, help="Duration threshold (sec) for 'deeper sessions'.")
    ap.add_argument("--max-evidence-per-window", type=int, default=30, help="Max evidence rows stored per scan window.")
    ap.add_argument("--max-lateral-sessions", type=int, default=200, help="Max lateral sessions stored (top by bytes).")

    args = ap.parse_args()

    zeek_dir = Path(args.zeek_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    conn_path = find_conn_log(zeek_dir)

    # Aggregation structures
    # key: (src_ip, bucket_epoch) -> stats
    agg: Dict[Tuple[str, int], Dict[str, object]] = {}

    # Store candidate evidence for scan windows (we will filter later)
    per_window_rows: Dict[Tuple[str, int], List[ConnRow]] = {}

    # Store candidate lateral sessions (we will rank later)
    lateral_candidates: List[ConnRow] = []

    min_ts: Optional[float] = None
    max_ts: Optional[float] = None

    for row in iter_conn_rows(conn_path):
        # Basic sanity
        if row.ts <= 0:
            continue
        if not row.orig_h or not row.resp_h:
            continue

        # Time range
        min_ts = row.ts if min_ts is None else min(min_ts, row.ts)
        max_ts = row.ts if max_ts is None else max(max_ts, row.ts)

        # Internal-to-internal
        if not (is_internal(row.orig_h) and is_internal(row.resp_h)):
            continue

        # Only ports of interest for your module
        if row.resp_p not in PORTS_OF_INTEREST:
            continue

        b = bucket_epoch(row.ts, args.bucket_sec)
        key = (row.orig_h, b)

        if key not in agg:
            agg[key] = {
                "src_ip": row.orig_h,
                "bucket": b,
                "total_conns": 0,
                "unique_dsts": set(),
                "unique_445": set(),
                "unique_135": set(),
                "top_ports": {},
                "sum_total_bytes": 0,
            }

        s = agg[key]
        s["total_conns"] = int(s["total_conns"]) + 1
        s["unique_dsts"].add(row.resp_h)
        if row.resp_p == 445:
            s["unique_445"].add(row.resp_h)
        if row.resp_p == 135:
            s["unique_135"].add(row.resp_h)
        s["sum_total_bytes"] = int(s["sum_total_bytes"]) + row.total_bytes

        tp = s["top_ports"]
        tp[row.resp_p] = tp.get(row.resp_p, 0) + 1

        # Keep some raw rows per window for later evidence export
        per_window_rows.setdefault(key, []).append(row)

        # Candidate lateral session heuristic
        if (row.total_bytes >= args.lateral_bytes_thresh) or (row.duration >= args.lateral_dur_thresh):
            lateral_candidates.append(row)

    # If nothing parsed
    if not agg:
        # Still produce empty outputs (so your pipeline does not break)
        findings = {
            "module": "lateral_movement",
            "pcap": args.pcap_name,
            "zeek_dir": str(zeek_dir),
            "time_range_utc": [
                epoch_to_iso8601(min_ts) if min_ts else "",
                epoch_to_iso8601(max_ts) if max_ts else "",
            ],
            "suspected_scanners": [],
            "candidate_lateral_sessions": [],
            "mitre_mapping_suggestions": [
                {"tactic": "Discovery", "technique": "Network Service Scanning", "id": "T1046"},
                {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
            ],
            "notes": [
                "No qualifying internal-to-internal connections on ports of interest were found in conn log.",
            ],
        }
        (out_dir / "lateral_findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
        write_evidence_csv(out_dir / "evidence.csv", [])
        return 0

    # Identify scan windows
    scan_windows: List[Dict[str, object]] = []
    for (src, b), s in agg.items():
        unique_445 = len(s["unique_445"])
        unique_135 = len(s["unique_135"])
        total_conns = int(s["total_conns"])

        scan_flag = (unique_445 >= args.scan_unique_thresh) or (unique_135 >= args.scan_unique_thresh) or (
            total_conns >= args.scan_totalconns_thresh
        )
        if not scan_flag:
            continue

        # Sort ports by hits
        top_ports_sorted = sorted(s["top_ports"].items(), key=lambda kv: kv[1], reverse=True)
        top_ports = [p for p, _ in top_ports_sorted[:5]]

        scan_windows.append(
            {
                "src_ip": src,
                "bucket_epoch": b,
                "start": epoch_to_iso8601(float(b)),
                "end": epoch_to_iso8601(float(b + args.bucket_sec)),
                "unique_dst_445": unique_445,
                "unique_dst_135": unique_135,
                "total_conns": total_conns,
                "top_ports": top_ports,
                "sum_total_bytes": int(s["sum_total_bytes"]),
                "evidence_refs": [],  # filled later
            }
        )

    # Rank scan windows by "noisiness"
    scan_windows.sort(key=lambda w: (w["unique_dst_445"] + w["unique_dst_135"], w["total_conns"]), reverse=True)

    # Rank lateral sessions by bytes
    lateral_candidates.sort(key=lambda r: r.total_bytes, reverse=True)
    lateral_candidates = lateral_candidates[: args.max_lateral_sessions]

    # Build evidence rows
    evidence_rows: List[Dict[str, object]] = []
    evidence_counter = 0

    def add_evidence(row: ConnRow, log_source: str = "conn.log") -> str:
        nonlocal evidence_counter
        evidence_counter += 1
        evid = f"EVID-{evidence_counter:04d}"
        evidence_rows.append(
            {
                "evidence_id": evid,
                "log_source": log_source,
                "ts_iso8601": epoch_to_iso8601(row.ts),
                "ts_epoch": row.ts,
                "five_tuple": row.five_tuple(),
                "duration_sec": row.duration,
                "orig_bytes": row.orig_bytes,
                "resp_bytes": row.resp_bytes,
                "total_bytes": row.total_bytes,
                "conn_state": row.conn_state,
                "src_ip": row.orig_h,
                "dst_ip": row.resp_h,
                "dst_port": row.resp_p,
                "proto": row.proto,
                "zeek_line_no": row.line_no,
            }
        )
        return evid

    # Evidence for scan windows: take up to N “representative” rows per window,
    # prioritizing ports 445/135.
    for w in scan_windows[:50]:  # cap number of windows included
        key = (w["src_ip"], int(w["bucket_epoch"]))
        rows = per_window_rows.get(key, [])
        # sort: prioritize 445/135, then earliest in the bucket
        rows_sorted = sorted(rows, key=lambda r: (0 if r.resp_p in (445, 135) else 1, r.ts))
        rows_sorted = rows_sorted[: args.max_evidence_per_window]

        refs: List[str] = []
        for r in rows_sorted:
            refs.append(add_evidence(r))
        w["evidence_refs"] = refs

    # Candidate lateral sessions: add evidence refs for each session
    lateral_sessions_out: List[Dict[str, object]] = []
    for r in lateral_candidates:
        evid = add_evidence(r)
        lateral_sessions_out.append(
            {
                "src_ip": r.orig_h,
                "dst_ip": r.resp_h,
                "dst_port": r.resp_p,
                "proto": r.proto,
                "first_seen": epoch_to_iso8601(r.ts),
                "duration_sec": r.duration,
                "total_bytes": r.total_bytes,
                "evidence_refs": [evid],
            }
        )

    # Group scan windows by src_ip into suspected_scanners
    scanners: Dict[str, List[Dict[str, object]]] = {}
    for w in scan_windows[:50]:
        scanners.setdefault(w["src_ip"], []).append(w)

    suspected_scanners = [{"src_ip": src, "windows": wins} for src, wins in scanners.items()]

    findings = {
        "module": "lateral_movement",
        "pcap": args.pcap_name,
        "zeek_dir": str(zeek_dir),
        "time_range_utc": [epoch_to_iso8601(min_ts or 0.0), epoch_to_iso8601(max_ts or 0.0)],
        "parameters": {
            "bucket_sec": args.bucket_sec,
            "scan_unique_thresh": args.scan_unique_thresh,
            "scan_totalconns_thresh": args.scan_totalconns_thresh,
            "lateral_bytes_thresh": args.lateral_bytes_thresh,
            "lateral_dur_thresh": args.lateral_dur_thresh,
        },
        "suspected_scanners": suspected_scanners,
        "candidate_lateral_sessions": lateral_sessions_out,
        "mitre_mapping_suggestions": [
            {"tactic": "Discovery", "technique": "Network Service Scanning", "id": "T1046"},
            {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
        ],
        "notes": [
            "All findings are derived from Zeek conn logs on ports of interest (445/135/3389/5985/5986).",
            "Every claim should reference evidence_ids from evidence.csv to prevent hallucinations.",
        ],
    }

    # Write outputs
    (out_dir / "lateral_findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    write_evidence_csv(out_dir / "evidence.csv", evidence_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())