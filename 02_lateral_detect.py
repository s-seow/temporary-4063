# lateral_detect.py

"""
Reads Zeek logs and produces minimal outputs:
1) derived/lateral_findings.json  (LLM-friendly structured findings)
2) derived/evidence.csv           (every claim must reference evidence_id(s))

Designed for SC4063 Part 2: Lateral Movement & Discovery

Inputs (from run_zeek_logs.py):
<out>/<pcap_stem>/zeek/conn.log (or conn.*)
<out>/<pcap_stem>/zeek/dce_rpc.log (or dce_rpc.*)   [optional but recommended]

Writes:
<out>/<pcap_stem>/derived/lateral_findings.json
<out>/<pcap_stem>/derived/evidence.csv

Notes:
- Works with Zeek TSV (default) OR Zeek JSON-lines (--json in zeek runner).
- Lateral movement/discovery signals:
  * fan-out scanning to TCP/445 and TCP/135 (conn.log)
  * follow-on “deeper” sessions (bytes/duration) (conn.log)
  * DCERPC operations suggesting account creation or group modification (dce_rpc.log)
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


RFC1918_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

PORTS_OF_INTEREST = {445, 135, 3389, 5985, 5986}

# Evidence CSV schema (fixed so conn + dce_rpc rows can coexist)
EVIDENCE_FIELDS = [
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
    # DCERPC-specific (blank for conn evidence)
    "dce_rpc_named_pipe",
    "dce_rpc_endpoint",
    "dce_rpc_operation",
]

# Heuristic operation keywords for user/group changes (case-insensitive matching)
DCE_CREATE_USER_KWS = [
    "createuser",
    "createsuser",
    "samrcreateuser",
    "samrcreateuser2",
    "samrcreateuser2in",
    "createsuser2",
]
DCE_GROUP_MOD_KWS = [
    "addmember",
    "addmembertogroup",
    "addusertogroup",
    "addgroupmember",
    "deletemember",
    "removeuserfromgroup",
    "removemember",
    "setmembers",
    "setmember",
]
DCE_ACCOUNT_MOD_KWS = [
    "setuserinfo",
    "setuserinformation",
    "setinformationuser",
    "setaliasinformation",
    "setgroupinformation",
    "rename",
    "deleteuser",
    "deletegroup",
    "deletealias",
    "setsecurityobject",
    "setsecurity",
    "setdomaininfo",
]
# Some Zeek builds populate endpoint with strings that include these for SAMR/LSA
DCE_SENSITIVE_ENDPOINT_HINTS = ["samr", "lsarpc", "netlogon"]


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
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def bucket_epoch(ts: float, bucket_seconds: int) -> int:
    return int(ts // bucket_seconds) * bucket_seconds


# -------------------------
# conn.log parsing
# -------------------------
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


def detect_format(log_path: Path) -> str:
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                return "tsv"
            if line.startswith("{") and line.endswith("}"):
                return "jsonl"
            return "tsv"
    return "tsv"


def iter_tsv_rows(log_path: Path) -> Iterator[Tuple[int, Dict[str, str]]]:
    fields: List[str] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                parts = line.split("\t")
                fields = parts[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            parts = line.split("\t")
            if len(parts) != len(fields):
                continue
            yield i, dict(zip(fields, parts))


def iter_jsonl_rows(log_path: Path) -> Iterator[Tuple[int, Dict[str, object]]]:
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if not (line.startswith("{") and line.endswith("}")):
                continue
            yield i, json.loads(line)


def iter_conn_rows(conn_path: Path) -> Iterator[ConnRow]:
    fmt = detect_format(conn_path)
    if fmt == "jsonl":
        for i, obj in iter_jsonl_rows(conn_path):
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
    else:
        for i, obj in iter_tsv_rows(conn_path):
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


def find_log(zeek_dir: Path, prefix: str) -> Optional[Path]:
    direct = zeek_dir / f"{prefix}.log"
    if direct.exists():
        return direct
    candidates = sorted([p for p in zeek_dir.iterdir() if p.is_file() and p.name.startswith(prefix)])
    if not candidates:
        return None
    return candidates[0]


# -------------------------
# dce_rpc.log parsing
# -------------------------
@dataclass
class DceRpcRow:
    line_no: int
    ts: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    named_pipe: str
    endpoint: str
    operation: str

    def five_tuple(self) -> str:
        # dce_rpc log often still contains orig/resp ports; proto is typically tcp under the hood
        return f"{self.orig_h}:{self.orig_p} -> {self.resp_h}:{self.resp_p} (dce_rpc)"


def iter_dce_rpc_rows(dce_path: Path) -> Iterator[DceRpcRow]:
    fmt = detect_format(dce_path)

    def get_str(obj: Dict[str, object], *keys: str) -> str:
        for k in keys:
            if k in obj and obj.get(k) not in (None, "-", "(empty)"):
                return str(obj.get(k))
        return ""

    if fmt == "jsonl":
        for i, obj in iter_jsonl_rows(dce_path):
            yield DceRpcRow(
                line_no=i,
                ts=to_float(obj.get("ts"), 0.0),
                orig_h=get_str(obj, "id.orig_h", "orig_h", "src", "src_ip"),
                orig_p=to_int(obj.get("id.orig_p") or obj.get("orig_p") or 0, 0),
                resp_h=get_str(obj, "id.resp_h", "resp_h", "dst", "dst_ip"),
                resp_p=to_int(obj.get("id.resp_p") or obj.get("resp_p") or 0, 0),
                named_pipe=get_str(obj, "named_pipe", "pipe"),
                endpoint=get_str(obj, "endpoint", "interface"),
                operation=get_str(obj, "operation", "op", "op_name"),
            )
    else:
        for i, obj in iter_tsv_rows(dce_path):
            yield DceRpcRow(
                line_no=i,
                ts=to_float(obj.get("ts"), 0.0),
                orig_h=str(obj.get("id.orig_h", "")),
                orig_p=to_int(obj.get("id.orig_p"), 0),
                resp_h=str(obj.get("id.resp_h", "")),
                resp_p=to_int(obj.get("id.resp_p"), 0),
                named_pipe=str(obj.get("named_pipe", "")),
                endpoint=str(obj.get("endpoint", "")),
                operation=str(obj.get("operation", "")),
            )


def classify_dce_rpc(op: str, endpoint: str) -> Optional[str]:
    """
    Returns a label if the operation looks like account creation or group modification,
    else None. Heuristic string matching only.
    """
    op_l = (op or "").lower().replace("_", "").replace("-", "")
    ep_l = (endpoint or "").lower()

    # If operation is empty, we don't guess by opnum here (keeps false positives down).
    if not op_l and not ep_l:
        return None

    for kw in DCE_CREATE_USER_KWS:
        if kw in op_l:
            return "possible_account_creation"
    for kw in DCE_GROUP_MOD_KWS:
        if kw in op_l:
            return "possible_group_membership_or_modification"
    for kw in DCE_ACCOUNT_MOD_KWS:
        if kw in op_l:
            return "possible_account_or_group_modification"

    # Endpoint hint only (lower confidence)
    for hint in DCE_SENSITIVE_ENDPOINT_HINTS:
        if hint in ep_l and op_l:
            # endpoint indicates SAMR/LSA family and we do have some op name
            return "possible_account_or_group_change"

    return None


def write_evidence_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EVIDENCE_FIELDS)
        writer.writeheader()
        for r in rows:
            # Ensure all keys exist
            out = {k: r.get(k, "") for k in EVIDENCE_FIELDS}
            writer.writerow(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Lateral Movement minimal outputs from Zeek logs.")
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
    ap.add_argument("--max-dce-events", type=int, default=300, help="Max suspicious DCERPC events stored.")

    args = ap.parse_args()

    zeek_dir = Path(args.zeek_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    conn_path = find_log(zeek_dir, "conn")
    if not conn_path:
        raise FileNotFoundError(f"No conn log found in {zeek_dir}. Expected conn.log or conn*.")

    dce_path = find_log(zeek_dir, "dce_rpc")  # optional

    # Aggregation structures for conn scanning
    agg: Dict[Tuple[str, int], Dict[str, object]] = {}
    per_window_rows: Dict[Tuple[str, int], List[ConnRow]] = {}
    lateral_candidates: List[ConnRow] = []

    # DCERPC suspicious events
    dce_suspicious: List[Dict[str, object]] = []

    min_ts: Optional[float] = None
    max_ts: Optional[float] = None

    # -------------------------
    # Parse conn.log
    # -------------------------
    for row in iter_conn_rows(conn_path):
        if row.ts <= 0:
            continue
        if not row.orig_h or not row.resp_h:
            continue

        min_ts = row.ts if min_ts is None else min(min_ts, row.ts)
        max_ts = row.ts if max_ts is None else max(max_ts, row.ts)

        # internal-to-internal only (lateral/discovery)
        if not (is_internal(row.orig_h) and is_internal(row.resp_h)):
            continue

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

        per_window_rows.setdefault(key, []).append(row)

        if (row.total_bytes >= args.lateral_bytes_thresh) or (row.duration >= args.lateral_dur_thresh):
            lateral_candidates.append(row)

    # -------------------------
    # Parse dce_rpc.log (optional)
    # -------------------------
    if dce_path:
        for r in iter_dce_rpc_rows(dce_path):
            if r.ts <= 0:
                continue
            if not r.orig_h or not r.resp_h:
                continue

            min_ts = r.ts if min_ts is None else min(min_ts, r.ts)
            max_ts = r.ts if max_ts is None else max(max_ts, r.ts)

            # lateral focus: internal-to-internal only
            if not (is_internal(r.orig_h) and is_internal(r.resp_h)):
                continue

            label = classify_dce_rpc(r.operation, r.endpoint)
            if not label:
                continue

            dce_suspicious.append(
                {
                    "label": label,
                    "src_ip": r.orig_h,
                    "dst_ip": r.resp_h,
                    "dst_port": r.resp_p,
                    "named_pipe": r.named_pipe,
                    "endpoint": r.endpoint,
                    "operation": r.operation,
                    "first_seen": epoch_to_iso8601(r.ts),
                    "zeek_line_no": r.line_no,
                    "evidence_refs": [],
                }
            )

        # keep it bounded
        dce_suspicious = dce_suspicious[: args.max_dce_events]

    # If nothing parsed for conn signals AND no dce events, still produce empty outputs
    if not agg and not dce_suspicious:
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
            "dce_rpc_suspicious_activity": [],
            "mitre_mapping_suggestions": [
                {"tactic": "Discovery", "technique": "Network Service Scanning", "id": "T1046"},
                {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
                {"tactic": "Persistence", "technique": "Create Account", "id": "T1136"},
                {"tactic": "Persistence", "technique": "Account Manipulation", "id": "T1098"},
            ],
            "notes": [
                "No qualifying internal-to-internal conn.log activity on ports of interest and no suspicious dce_rpc operations were found.",
            ],
        }
        (out_dir / "lateral_findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
        write_evidence_csv(out_dir / "evidence.csv", [])
        return 0

    # -------------------------
    # Scan windows from conn.log
    # -------------------------
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
                "evidence_refs": [],
            }
        )

    scan_windows.sort(key=lambda w: (w["unique_dst_445"] + w["unique_dst_135"], w["total_conns"]), reverse=True)

    lateral_candidates.sort(key=lambda r: r.total_bytes, reverse=True)
    lateral_candidates = lateral_candidates[: args.max_lateral_sessions]

    # -------------------------
    # Evidence rows (conn + dce_rpc)
    # -------------------------
    evidence_rows: List[Dict[str, object]] = []
    evidence_counter = 0

    def add_conn_evidence(row: ConnRow) -> str:
        nonlocal evidence_counter
        evidence_counter += 1
        evid = f"EVID-{evidence_counter:04d}"
        evidence_rows.append(
            {
                "evidence_id": evid,
                "log_source": "conn.log",
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
                "dce_rpc_named_pipe": "",
                "dce_rpc_endpoint": "",
                "dce_rpc_operation": "",
            }
        )
        return evid

    def add_dce_evidence(item: Dict[str, object]) -> str:
        nonlocal evidence_counter
        evidence_counter += 1
        evid = f"EVID-{evidence_counter:04d}"
        evidence_rows.append(
            {
                "evidence_id": evid,
                "log_source": "dce_rpc.log",
                "ts_iso8601": str(item.get("first_seen", "")),
                "ts_epoch": 0.0,  # keep blank-ish; optional
                "five_tuple": f"{item.get('src_ip','')} -> {item.get('dst_ip','')} (dce_rpc)",
                "duration_sec": "",
                "orig_bytes": "",
                "resp_bytes": "",
                "total_bytes": "",
                "conn_state": "",
                "src_ip": item.get("src_ip", ""),
                "dst_ip": item.get("dst_ip", ""),
                "dst_port": item.get("dst_port", ""),
                "proto": "dce_rpc",
                "zeek_line_no": item.get("zeek_line_no", ""),
                "dce_rpc_named_pipe": item.get("named_pipe", ""),
                "dce_rpc_endpoint": item.get("endpoint", ""),
                "dce_rpc_operation": item.get("operation", ""),
            }
        )
        return evid

    # Evidence for scan windows
    for w in scan_windows[:50]:
        key = (w["src_ip"], int(w["bucket_epoch"]))
        rows = per_window_rows.get(key, [])
        rows_sorted = sorted(rows, key=lambda r: (0 if r.resp_p in (445, 135) else 1, r.ts))
        rows_sorted = rows_sorted[: args.max_evidence_per_window]

        refs: List[str] = []
        for r in rows_sorted:
            refs.append(add_conn_evidence(r))
        w["evidence_refs"] = refs

    # Evidence for lateral sessions
    lateral_sessions_out: List[Dict[str, object]] = []
    for r in lateral_candidates:
        evid = add_conn_evidence(r)
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

    # Evidence for DCERPC suspicious events
    dce_out: List[Dict[str, object]] = []
    for item in dce_suspicious:
        evid = add_dce_evidence(item)
        item["evidence_refs"] = [evid]
        dce_out.append(item)

    # Group scan windows by src_ip
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
            "max_dce_events": args.max_dce_events,
        },
        "suspected_scanners": suspected_scanners,
        "candidate_lateral_sessions": lateral_sessions_out,
        "dce_rpc_suspicious_activity": dce_out,
        "mitre_mapping_suggestions": [
            {"tactic": "Discovery", "technique": "Network Service Scanning", "id": "T1046"},
            {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
            {"tactic": "Persistence", "technique": "Create Account", "id": "T1136"},
            {"tactic": "Persistence", "technique": "Account Manipulation", "id": "T1098"},
        ],
        "notes": [
            "Conn-based scan findings are inferred from fan-out to ports 445/135 in conn.log (behavioral scan detection; not tool fingerprinting).",
            "DCERPC findings are heuristic string matches on dce_rpc.log operation/endpoint fields and should be treated as 'possible' indicators.",
            "Every claim references evidence_ids from evidence.csv to minimize hallucination risk in the report generator.",
        ],
    }

    (out_dir / "lateral_findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    write_evidence_csv(out_dir / "evidence.csv", evidence_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())