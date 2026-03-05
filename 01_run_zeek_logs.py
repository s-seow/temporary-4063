# run_zeek_logs.py

"""
Purpose
-------
Generate Zeek logs from one or more PCAP files in a consistent folder structure,
so you can later run analytics (e.g., lateral-movement detection) on conn.log,
dce_rpc.log, smb*.log, dns.log, http.log, etc.

Key features
------------
- Accepts 1+ PCAP paths (files or folders)
- Outputs logs into: <output_dir>/<pcap_stem>/zeek/
- Optional JSON logs (recommended for downstream tooling)
- Optional auto-loading of Windows RPC/SMB scripts to help ensure dce_rpc.log exists
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

# These are Zeek script entrypoints (paths inside Zeek's script tree).
# Loading them helps ensure the corresponding logs exist (version-dependent, but generally safe).
DEFAULT_WINDOWS_RPC_SCRIPTS = [
    "base/protocols/dce-rpc/main.zeek",  # helps produce dce_rpc.log
    "base/protocols/smb/main.zeek",      # helps produce smb* logs
]


def which_zeek() -> Optional[str]:
    """Return Zeek binary path if found, else None."""
    return shutil.which("zeek")


def is_pcap_file(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() in PCAP_EXTS


def discover_pcaps(inputs: List[Path], recursive: bool) -> List[Path]:
    pcaps: List[Path] = []
    for item in inputs:
        if item.is_file() and is_pcap_file(item):
            pcaps.append(item.resolve())
        elif item.is_dir():
            if recursive:
                for f in item.rglob("*"):
                    if is_pcap_file(f):
                        pcaps.append(f.resolve())
            else:
                for f in item.iterdir():
                    if is_pcap_file(f):
                        pcaps.append(f.resolve())
        else:
            # Ignore missing/unknown items here; caller validates separately.
            pass
    # Stable deterministic ordering
    pcaps = sorted(set(pcaps), key=lambda x: str(x).lower())
    return pcaps


def safe_stem(pcap_path: Path) -> str:
    """
    Create a stable folder name for outputs.
    Example: foo.bar.pcap -> foo.bar
    """
    return pcap_path.name.removesuffix(pcap_path.suffix)


def build_zeek_cmd(
    zeek_bin: str,
    pcap_path: Path,
    out_dir: Path,
    json_logs: bool,
    extra_scripts: List[str],
    ignore_checksums: bool,
    ensure_windows_rpc_scripts: bool,
) -> List[str]:
    """
    Build a Zeek command that writes logs into out_dir and optionally uses JSON.
    """
    out_dir_str = str(out_dir).replace("\\", "\\\\").replace('"', '\\"')

    # Zeek runtime "redef" settings (executed via -e).
    # - Log::default_logdir ensures logs go where we want.
    # - JSON logs are easier for later parsing; ISO8601 timestamps are human-friendly.
    zeek_redefs = [f'redef Log::default_logdir = "{out_dir_str}";']

    if json_logs:
        zeek_redefs += [
            "redef LogAscii::use_json = T;",
            "redef LogAscii::json_timestamps = JSON::TS_ISO8601;",
        ]

    cmd = [zeek_bin]
    if ignore_checksums:
        cmd.append("-C")
    cmd += ["-r", str(pcap_path)]
    cmd += ["-e", " ".join(zeek_redefs)]

    # Optionally auto-load scripts that help ensure dce_rpc.log and SMB logs exist.
    scripts_to_load: List[str] = []
    if ensure_windows_rpc_scripts:
        scripts_to_load.extend(DEFAULT_WINDOWS_RPC_SCRIPTS)

    # Append user-provided scripts (and avoid duplicates while preserving order).
    scripts_to_load.extend(extra_scripts)

    seen = set()
    for s in scripts_to_load:
        s_norm = s.strip()
        if not s_norm:
            continue
        if s_norm in seen:
            continue
        seen.add(s_norm)
        cmd += ["-s", s_norm]

    return cmd


def run_cmd(cmd: List[str], timeout_sec: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Run a subprocess command. Returns (returncode, stdout, stderr).
    """
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_sec,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def summarize_outputs(zeek_log_dir: Path) -> List[str]:
    """
    Return a list of Zeek log filenames produced (top-level).
    """
    if not zeek_log_dir.exists():
        return []
    files = [p.name for p in zeek_log_dir.iterdir() if p.is_file()]
    return sorted(files, key=lambda x: x.lower())


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate Zeek logs from PCAP(s) into a consistent output structure."
    )
    ap.add_argument(
        "--pcap",
        nargs="+",
        required=True,
        help="One or more PCAP paths (file(s) and/or folder(s)).",
    )
    ap.add_argument(
        "--out",
        required=True,
        help="Output base directory. Logs go to: <out>/<pcap_stem>/zeek/",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Generate Zeek logs in JSON (recommended for downstream parsing).",
    )
    ap.add_argument(
        "--recursive",
        action="store_true",
        help="If a folder is provided in --pcap, discover PCAPs recursively.",
    )
    ap.add_argument(
        "--ignore-checksums",
        action="store_true",
        help="Pass -C to Zeek (ignore bad checksums). Often useful for captures.",
    )
    ap.add_argument(
        "--script",
        action="append",
        default=[],
        help="Extra Zeek script(s) to load. Can be repeated. Example: --script ./local.zeek",
    )
    ap.add_argument(
        "--no-windows-rpc-scripts",
        action="store_true",
        help="Disable auto-loading scripts that help produce dce_rpc.log and SMB logs.",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Optional timeout per PCAP run, seconds. 0 means no timeout.",
    )

    args = ap.parse_args()

    zeek_bin = which_zeek()
    if not zeek_bin:
        print(
            "ERROR: Zeek binary not found on PATH.\n"
            "Install Zeek (or use SIFT/Security Onion which bundles it), then re-run.\n",
            file=sys.stderr,
        )
        return 2

    out_base = Path(args.out).resolve()
    out_base.mkdir(parents=True, exist_ok=True)

    inputs = [Path(p).expanduser().resolve() for p in args.pcap]
    missing = [str(p) for p in inputs if not p.exists()]
    if missing:
        print("ERROR: The following --pcap paths do not exist:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 2

    pcaps = discover_pcaps(inputs, recursive=args.recursive)
    if not pcaps:
        print(
            "ERROR: No PCAP files discovered. Supported extensions: .pcap, .pcapng, .cap",
            file=sys.stderr,
        )
        return 2

    timeout_sec = args.timeout if args.timeout and args.timeout > 0 else None
    ensure_windows_rpc_scripts = not args.no_windows_rpc_scripts

    print(f"Zeek: {zeek_bin}")
    print(f"Output base: {out_base}")
    print(f"JSON logs: {args.json}")
    print(f"Auto-load Windows RPC/SMB scripts: {ensure_windows_rpc_scripts}")
    print(f"PCAPs discovered: {len(pcaps)}\n")

    failures = 0

    for idx, pcap_path in enumerate(pcaps, start=1):
        stem = safe_stem(pcap_path)
        zeek_log_dir = out_base / stem / "zeek"
        zeek_log_dir.mkdir(parents=True, exist_ok=True)

        meta_dir = out_base / stem / "meta"
        meta_dir.mkdir(parents=True, exist_ok=True)

        cmd = build_zeek_cmd(
            zeek_bin=zeek_bin,
            pcap_path=pcap_path,
            out_dir=zeek_log_dir,
            json_logs=args.json,
            extra_scripts=args.script,
            ignore_checksums=args.ignore_checksums,
            ensure_windows_rpc_scripts=ensure_windows_rpc_scripts,
        )

        started = dt.datetime.now()
        print(f"[{idx}/{len(pcaps)}] Processing: {pcap_path}")
        print(f"  -> Logs: {zeek_log_dir}")
        write_text(meta_dir / "zeek_command.txt", " ".join(cmd) + "\n")

        try:
            rc, stdout, stderr = run_cmd(cmd, timeout_sec=timeout_sec)
        except subprocess.TimeoutExpired:
            failures += 1
            print(f"  !! TIMEOUT after {timeout_sec}s\n", file=sys.stderr)
            write_text(meta_dir / "zeek_run_status.txt", "TIMEOUT\n")
            continue

        finished = dt.datetime.now()
        dur = (finished - started).total_seconds()

        write_text(meta_dir / "zeek_stdout.txt", stdout)
        write_text(meta_dir / "zeek_stderr.txt", stderr)
        write_text(meta_dir / "zeek_run_status.txt", f"returncode={rc}\nseconds={dur}\n")

        produced = summarize_outputs(zeek_log_dir)
        write_text(meta_dir / "produced_logs.txt", "\n".join(produced) + ("\n" if produced else ""))

        if rc != 0:
            failures += 1
            print(f"  !! Zeek failed (return code {rc}). See: {meta_dir / 'zeek_stderr.txt'}\n", file=sys.stderr)
            continue

        interesting = [f for f in produced if any(
            f.startswith(x) for x in ("conn.", "dns.", "http.", "ssl.", "dce_rpc.", "kerberos.", "ntlm.", "smb")
        )]
        print(f"  OK ({dur:.1f}s). Logs produced: {len(produced)}")
        if interesting:
            print(f"  Key logs: {', '.join(interesting[:12])}" + (" ..." if len(interesting) > 12 else ""))
        print()

    if failures:
        print(f"Done with {failures} failure(s). Check meta/* for error details.", file=sys.stderr)
        return 1

    print("Done. All PCAPs processed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())