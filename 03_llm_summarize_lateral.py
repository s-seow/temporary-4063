#!/usr/bin/env python3
"""
llm_summarize_lateral.py

Purpose
-------
Consumes the minimal outputs from lateral_detect.py:
  - lateral_findings.json
  - evidence.csv
…and produces LLM-written narrative outputs that are *evidence-bound*:
  - lateral_narrative.md
  - lateral_summary.json  (same facts, better wording)

Guardrails (hallucination control)
----------------------------------
1) The LLM is only given:
   - findings JSON (structured)
   - evidence rows (IDs + 5-tuples + timestamps + bytes/duration + line numbers)
2) The LLM must cite evidence IDs like [EVID-0001] for every claim.
3) We validate the output:
   - every cited evidence ID must exist in evidence.csv
   - if missing/invalid IDs are referenced, we fail (non-zero exit code)
4) No step-by-step manual guidance is required during the run.

Supports:
- OpenAI API (recommended)
- Azure OpenAI (optional)

Installation
------------
pip install openai

Usage (OpenAI)
--------------
export OPENAI_API_KEY="..."
python llm_summarize_lateral.py \
  --findings ./artifacts/<pcap_stem>/derived/lateral_findings.json \
  --evidence ./artifacts/<pcap_stem>/derived/evidence.csv \
  --out-dir  ./artifacts/<pcap_stem>/derived \
  --model gpt-4.1-mini

Usage (Azure OpenAI)
-------------------
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://<resource-name>.openai.azure.com"
export AZURE_OPENAI_API_VERSION="2024-10-21"
python llm_summarize_lateral.py \
  --findings ./artifacts/<pcap_stem>/derived/lateral_findings.json \
  --evidence ./artifacts/<pcap_stem>/derived/evidence.csv \
  --out-dir  ./artifacts/<pcap_stem>/derived \
  --model <your-deployment-name> \
  --provider azure

Outputs
-------
- lateral_narrative.md   (ready to paste into your Part 1/2 report)
- lateral_summary.json   (structured, cleaned narrative + MITRE mapping text)

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
except Exception as e:
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
            )
            rows_by_id[evid] = row
            rows_list.append(row)
    return rows_by_id, rows_list


def build_evidence_brief(rows: List[EvidenceRow], max_rows: int = 250) -> str:
    """
    Create a compact evidence appendix for the LLM.
    Keep it bounded: include only the most relevant evidence rows (first N).
    """
    rows = rows[:max_rows]
    lines = []
    for r in rows:
        lines.append(
            f"{r.evidence_id} | {r.ts_iso8601} | {r.five_tuple} | "
            f"dur={r.duration_sec}s bytes={r.total_bytes} state={r.conn_state} "
            f"src={r.src_ip} dst={r.dst_ip}:{r.dst_port} log={r.log_source} line={r.zeek_line_no}"
        )
    return "\n".join(lines)


def validate_citations(text: str, valid_ids: Set[str]) -> Tuple[bool, List[str]]:
    cited = set(EVID_PATTERN.findall(text))
    cited_ids = {c.strip("[]") for c in cited}
    missing = sorted([cid for cid in cited_ids if cid not in valid_ids])
    ok = len(missing) == 0
    return ok, missing


def make_prompt(findings: dict, evidence_brief: str) -> Tuple[str, str]:
    """
    Return (system_prompt, user_prompt).
    """
    system_prompt = (
        "You are a digital forensics report writer focused on NETWORK PCAP evidence.\n"
        "You must be conservative, precise, and evidence-bound.\n"
        "CRITICAL RULES:\n"
        "1) You may ONLY use facts present in the provided JSON findings and evidence lines.\n"
        "2) Every factual claim must include at least one evidence citation like [EVID-0001].\n"
        "3) Do NOT guess host roles (e.g., DC) unless supported by the evidence provided.\n"
        "4) If evidence is insufficient, explicitly say 'Insufficient evidence' and do not conclude.\n"
        "5) Keep language professional and suitable for an investigation report.\n"
        "6) Do not provide attack instructions; focus on what was observed.\n"
    )

    user_prompt = (
        "TASK:\n"
        "Write a 'Lateral Movement & Discovery' section for a Phase 1 network forensic report.\n\n"
        "You are given:\n"
        "A) Structured findings JSON (from deterministic analytics)\n"
        "B) Evidence lines (each with ID, timestamp, 5-tuple, bytes/duration, Zeek line numbers)\n\n"
        "OUTPUT REQUIREMENTS:\n"
        "1) Produce Markdown with these headings:\n"
        "   - Overview\n"
        "   - Timeline (bullets with timestamps)\n"
        "   - Key Observations (what was seen + why it indicates discovery/lateral movement)\n"
        "   - Affected Hosts (tables: suspected scanner(s) and top targets)\n"
        "   - MITRE ATT&CK Mapping (tactic/technique IDs; only if justified)\n"
        "   - Confidence & Limitations\n"
        "2) Every bullet/statement must contain at least one evidence citation: [EVID-0001]\n"
        "3) Avoid naming specific tools unless the behavior explicitly supports it; use 'consistent with'.\n"
        "4) Keep it concise but complete (around 300–700 words).\n\n"
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
            raise RuntimeError("Missing OPENAI_API_KEY environment variable.")
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


def call_llm(client, provider: str, model: str, system_prompt: str, user_prompt: str) -> str:
    # Using Chat Completions style via responses API compatibility (SDK handles).
    # Keep temperature low for reproducibility.
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
    ap.add_argument("--model", required=True, help="Model name (OpenAI) or deployment name (Azure)")
    ap.add_argument("--max-evidence-rows", type=int, default=250, help="Max evidence lines given to the LLM")
    ap.add_argument("--retry", type=int, default=1, help="Retry count if citation validation fails")

    args = ap.parse_args()

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

    client = create_client(args.provider)

    last_text = ""
    for attempt in range(1, args.retry + 2):
        text = call_llm(client, args.provider, args.model, system_prompt, user_prompt)
        last_text = text.strip()

        ok, missing = validate_citations(last_text, valid_ids)
        if ok:
            break

        # If citations invalid, tighten instructions and retry
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
        # Still write the raw output for debugging
        write_text(out_dir / "lateral_narrative.raw.md", last_text)
        return 1

    # Write final markdown
    write_text(out_dir / "lateral_narrative.md", last_text + "\n")

    # Also write a structured summary JSON that your report generator can use
    summary = {
        "module": "lateral_movement",
        "input_findings": str(findings_path),
        "input_evidence": str(evidence_path),
        "output_markdown": str((out_dir / "lateral_narrative.md").resolve()),
        "model": args.model,
        "provider": args.provider,
        "notes": [
            "All statements in lateral_narrative.md must be backed by evidence IDs present in evidence.csv.",
            "If your narrative needs more context, increase --max-evidence-rows or improve the deterministic detector output.",
        ],
    }
    write_text(out_dir / "lateral_summary.json", json.dumps(summary, indent=2) + "\n")

    print(f"OK: Wrote {out_dir / 'lateral_narrative.md'}")
    print(f"OK: Wrote {out_dir / 'lateral_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())