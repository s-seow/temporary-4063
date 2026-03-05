# llm_summarize_lateral.py

"""
Consumes:
  - lateral_findings.json
  - evidence.csv
Produces:
  - lateral_narrative.md
  - lateral_summary.json

Guardrails:
- LLM only sees findings JSON + compact evidence lines
- Every claim must cite [EVID-0001]
- We validate that cited IDs exist in evidence.csv

Supports:
- OpenAI (OPENAI_API_KEY, OPENAI_MODEL optional)
- Azure OpenAI (AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_VERSION, AZURE_OPENAI_DEPLOYMENT optional)

.env loading:
- This script auto-loads environment variables from a `.env` file located in the SAME directory as this script (repo root),
  if present. Existing environment variables are NOT overridden.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

# --- LLM client (OpenAI Python SDK v1.x) ---
try:
    from openai import OpenAI, AzureOpenAI
except Exception:
    OpenAI = None  # type: ignore
    AzureOpenAI = None  # type: ignore


EVID_PATTERN = re.compile(r"\[EVID-\d{4}\]")


@dataclass
class EvidenceRow:
    evidence_id: str
    log_source: str
    ts_iso8601: str
    five_tuple: str
    duration_sec: str
    orig_bytes: str
    resp_bytes: str
    total_bytes: str
    conn_state: str
    src_ip: str
    dst_ip: str
    dst_port: str
    proto: str
    zeek_line_no: str
    # DCERPC extras (blank for conn evidence)
    dce_rpc_named_pipe: str
    dce_rpc_endpoint: str
    dce_rpc_operation: str


def load_dotenv(dotenv_path: Path) -> None:
    """
    Minimal .env loader (no external dependency).
    - Loads KEY=VALUE lines
    - Ignores empty lines and comments starting with '#'
    - Strips surrounding quotes from values
    - Does NOT override existing environment variables
    """
    if not dotenv_path.exists() or not dotenv_path.is_file():
        return

    try:
        for raw in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()

            if not key:
                continue
            if key in os.environ and os.environ[key].strip() != "":
                continue  # do not override existing env vars

            # Remove surrounding single/double quotes if present
            if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
                val = val[1:-1]

            os.environ[key] = val
    except Exception:
        # If .env is malformed, fail silently (keeps runtime predictable).
        return


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_evidence_csv(path: Path) -> Tuple[Dict[str, EvidenceRow], List[EvidenceRow]]:
    rows_by_id: Dict[str, EvidenceRow] = {}
    rows_list: List[EvidenceRow] = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            evid = (r.get("evidence_id") or "").strip()
            if not evid:
                continue
            row = EvidenceRow(
                evidence_id=evid,
                log_source=(r.get("log_source") or "").strip(),
                ts_iso8601=(r.get("ts_iso8601") or "").strip(),
                five_tuple=(r.get("five_tuple") or "").strip(),
                duration_sec=str(r.get("duration_sec") or "").strip(),
                orig_bytes=str(r.get("orig_bytes") or "").strip(),
                resp_bytes=str(r.get("resp_bytes") or "").strip(),
                total_bytes=str(r.get("total_bytes") or "").strip(),
                conn_state=(r.get("conn_state") or "").strip(),
                src_ip=(r.get("src_ip") or "").strip(),
                dst_ip=(r.get("dst_ip") or "").strip(),
                dst_port=str(r.get("dst_port") or "").strip(),
                proto=(r.get("proto") or "").strip(),
                zeek_line_no=str(r.get("zeek_line_no") or "").strip(),
                dce_rpc_named_pipe=(r.get("dce_rpc_named_pipe") or "").strip(),
                dce_rpc_endpoint=(r.get("dce_rpc_endpoint") or "").strip(),
                dce_rpc_operation=(r.get("dce_rpc_operation") or "").strip(),
            )
            rows_by_id[evid] = row
            rows_list.append(row)
    return rows_by_id, rows_list


def build_evidence_brief(rows: List[EvidenceRow], max_rows: int = 250) -> str:
    """
    Compact evidence appendix for the LLM.
    Includes DCERPC fields when log_source is dce_rpc.log (or proto is dce_rpc).
    """
    rows = rows[:max_rows]
    lines: List[str] = []

    for r in rows:
        base = (
            f"{r.evidence_id} | {r.ts_iso8601} | {r.five_tuple} | "
            f"dur={r.duration_sec}s bytes={r.total_bytes} state={r.conn_state} "
            f"src={r.src_ip} dst={r.dst_ip}:{r.dst_port} proto={r.proto} "
            f"log={r.log_source} line={r.zeek_line_no}"
        )

        if r.log_source.lower().startswith("dce_rpc") or r.proto.lower() == "dce_rpc":
            extra = []
            if r.dce_rpc_endpoint:
                extra.append(f"endpoint={r.dce_rpc_endpoint}")
            if r.dce_rpc_named_pipe:
                extra.append(f"pipe={r.dce_rpc_named_pipe}")
            if r.dce_rpc_operation:
                extra.append(f"op={r.dce_rpc_operation}")
            if extra:
                base += " | " + " ".join(extra)

        lines.append(base)

    return "\n".join(lines)


def validate_citations(text: str, valid_ids: Set[str]) -> Tuple[bool, List[str]]:
    cited = set(EVID_PATTERN.findall(text))
    cited_ids = {c.strip("[]") for c in cited}
    missing = sorted([cid for cid in cited_ids if cid not in valid_ids])
    ok = len(missing) == 0
    return ok, missing


def make_prompt(findings: dict, evidence_brief: str) -> Tuple[str, str]:
    system_prompt = (
        "You are a digital forensics report writer focused on NETWORK PCAP evidence.\n"
        "You must be conservative, precise, and evidence-bound.\n"
        "CRITICAL RULES:\n"
        "1) You may ONLY use facts present in the provided JSON findings and evidence lines.\n"
        "2) Every factual claim must include at least one evidence citation like [EVID-0001].\n"
        "3) Do NOT guess host roles (e.g., Domain Controller) unless supported by evidence.\n"
        "4) If evidence is insufficient, explicitly say 'Insufficient evidence' and do not conclude.\n"
        "5) Keep language professional for an investigation report.\n"
        "6) Do not provide attack instructions; focus strictly on what was observed.\n"
    )

    user_prompt = (
        "TASK:\n"
        "Write a 'Lateral Movement & Discovery' section for a network forensic report.\n\n"
        "The analysis is based on:\n"
        "- conn.log indicators (e.g., noisy scanning to ports 445/135)\n"
        "- dce_rpc.log indicators (e.g., RPC operations suggestive of account creation or group modification)\n\n"
        "You are given:\n"
        "A) Structured findings JSON (from deterministic analytics)\n"
        "B) Evidence lines (each with ID, timestamp, 5-tuple, bytes/duration, Zeek line numbers; "
        "DCERPC lines may include endpoint/pipe/operation fields)\n\n"
        "OUTPUT REQUIREMENTS:\n"
        "1) Produce Markdown with these headings:\n"
        "   - Overview\n"
        "   - Timeline (bullets with timestamps)\n"
        "   - Key Observations (what was seen + why it indicates discovery/lateral movement)\n"
        "   - Affected Hosts (tables: suspected scanner(s) and key RPC pairs if relevant)\n"
        "   - MITRE ATT&CK Mapping (tactic/technique IDs; only if justified)\n"
        "   - Confidence & Limitations\n"
        "2) Every bullet/statement must contain at least one evidence citation: [EVID-0001]\n"
        "3) Avoid naming specific tools unless evidence explicitly supports it; use 'consistent with'.\n"
        "4) Keep it concise but complete (around 300–800 words).\n\n"
        "FINDINGS JSON:\n"
        f"{json.dumps(findings, indent=2)}\n\n"
        "EVIDENCE LINES:\n"
        f"{evidence_brief}\n"
    )
    return system_prompt, user_prompt


def create_client(provider: str):
    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("Missing OPENAI_API_KEY environment variable (set it in .env or your shell).")
        if OpenAI is None:
            raise RuntimeError("openai Python package not installed. Run: pip install openai")
        return OpenAI(api_key=api_key)

    if provider == "azure":
        api_key = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", "").strip() or "2024-10-21"
        if not api_key or not endpoint:
            raise RuntimeError("Missing AZURE_OPENAI_API_KEY and/or AZURE_OPENAI_ENDPOINT env vars.")
        if AzureOpenAI is None:
            raise RuntimeError("openai Python package not installed. Run: pip install openai")
        return AzureOpenAI(api_key=api_key, azure_endpoint=endpoint, api_version=api_version)

    raise ValueError("provider must be 'openai' or 'azure'")


def resolve_model(provider: str, cli_model: str) -> str:
    """
    OpenAI:
      - uses --model if provided; else uses OPENAI_MODEL
    Azure:
      - uses --model if provided; else uses AZURE_OPENAI_DEPLOYMENT
    """
    m = (cli_model or "").strip()

    if provider == "azure":
        if not m:
            m = os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip()
        if not m:
            raise RuntimeError("For provider=azure, set AZURE_OPENAI_DEPLOYMENT or pass --model <deployment-name>.")
        return m

    # provider == openai
    if not m:
        m = os.getenv("OPENAI_MODEL", "").strip()
    if not m:
        raise RuntimeError("For provider=openai, pass --model <model-name> or set OPENAI_MODEL.")
    return m


def call_llm(client, model: str, system_prompt: str, user_prompt: str) -> str:
    resp = client.chat.completions.create(
        model=model,
        temperature=0.2,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return resp.choices[0].message.content or ""


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="LLM summarizer for lateral movement findings (evidence-bound).")
    ap.add_argument("--findings", required=True, help="Path to lateral_findings.json")
    ap.add_argument("--evidence", required=True, help="Path to evidence.csv")
    ap.add_argument("--out-dir", required=True, help="Output directory (writes lateral_narrative.md, lateral_summary.json)")
    ap.add_argument("--provider", choices=["openai", "azure"], default="openai", help="LLM provider")
    ap.add_argument(
        "--model",
        default="",
        help="OpenAI model name (OpenAI provider). Optional if OPENAI_MODEL is set. "
             "For Azure, optional if AZURE_OPENAI_DEPLOYMENT is set.",
    )
    ap.add_argument("--max-evidence-rows", type=int, default=250, help="Max evidence lines given to the LLM")
    ap.add_argument("--retry", type=int, default=1, help="Retry count if citation validation fails")

    args = ap.parse_args()

    # Load .env from repo root (same directory as this script)
    script_dir = Path(__file__).resolve().parent
    load_dotenv(script_dir / ".env")

    findings_path = Path(args.findings).resolve()
    evidence_path = Path(args.evidence).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = load_json(findings_path)
    evidence_by_id, evidence_rows = load_evidence_csv(evidence_path)

    valid_ids = set(evidence_by_id.keys())
    if not valid_ids:
        print("ERROR: evidence.csv has no evidence_id rows. Cannot run LLM step safely.", file=sys.stderr)
        return 2

    evidence_brief = build_evidence_brief(evidence_rows, max_rows=args.max_evidence_rows)
    system_prompt, user_prompt = make_prompt(findings, evidence_brief)

    try:
        model_name = resolve_model(args.provider, args.model)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    client = create_client(args.provider)

    last_text = ""
    for attempt in range(1, args.retry + 2):
        text = call_llm(client, model_name, system_prompt, user_prompt)
        last_text = text.strip()

        ok, missing = validate_citations(last_text, valid_ids)
        if ok:
            break

        if attempt <= args.retry + 1:
            user_prompt = (
                user_prompt
                + "\n\nVALIDATION ERROR:\n"
                + f"You cited evidence IDs that do not exist: {missing}\n"
                + "Rewrite the entire output. Use ONLY evidence IDs present in the evidence lines.\n"
                + "If you cannot support a claim with a valid ID, remove the claim.\n"
            )

    ok, missing = validate_citations(last_text, valid_ids)
    if not ok:
        print("ERROR: LLM output contains invalid evidence IDs:", missing, file=sys.stderr)
        write_text(out_dir / "lateral_narrative.raw.md", last_text)
        return 1

    write_text(out_dir / "lateral_narrative.md", last_text + "\n")

    summary = {
        "module": "lateral_movement",
        "input_findings": str(findings_path),
        "input_evidence": str(evidence_path),
        "output_markdown": str((out_dir / "lateral_narrative.md").resolve()),
        "model_or_deployment": model_name,
        "provider": args.provider,
        "env_expected": {
            "openai": ["OPENAI_API_KEY", "OPENAI_MODEL (optional)"],
            "azure": ["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_VERSION (optional)", "AZURE_OPENAI_DEPLOYMENT (optional)"],
        },
        "notes": [
            "All statements in lateral_narrative.md must be backed by evidence IDs present in evidence.csv.",
            "If your narrative needs more context, increase --max-evidence-rows or improve the deterministic detector output.",
            "This script loads a .env file from the repo root (same folder as this script) if present.",
        ],
    }
    write_text(out_dir / "lateral_summary.json", json.dumps(summary, indent=2) + "\n")

    print(f"OK: Wrote {out_dir / 'lateral_narrative.md'}")
    print(f"OK: Wrote {out_dir / 'lateral_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())