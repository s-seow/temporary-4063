# SC4063 Group Project — Part 2 (Lateral Movement & Discovery Pipeline)

This repository contains a small, evidence-bound pipeline to analyze PCAP files for **Lateral Movement & Discovery** using **Zeek** + deterministic parsing + an optional LLM report-writing step.

The pipeline is designed to support the Part 2 hints:

- **Discovery / scanning**: rapid connection attempts to **TCP/445 (SMB)** and **TCP/135 (RPC)** across the subnet (behavior consistent with tools like SoftPerfect Network Scanner / NetExec).
- **Account / group changes**: **DCERPC** activity suggestive of account creation or group modification (heuristic based on `dce_rpc.log` fields).

---

## Repository Files (Core)

- `01_run_zeek_logs.py`  
  Runs Zeek against one or more PCAPs and writes Zeek logs in a structured output directory.

- `02_lateral_detect.py`  
  Parses Zeek logs and produces:
  - `lateral_findings.json` (LLM-friendly structured findings)
  - `evidence.csv` (evidence rows referenced by ID)

  Detection coverage:
  - **Noisy scanning** to ports **445/135** (from `conn.log`)
  - **Follow-on deeper sessions** (large bytes or long duration) (from `conn.log`)
  - **DCERPC user/group change indicators** (from `dce_rpc.log`)

- `03_llm_summarize_lateral.py`  
  Optional. Consumes:
  - `lateral_findings.json`
  - `evidence.csv`

  Produces:
  - `lateral_narrative.md` (evidence-cited markdown section)
  - `lateral_summary.json`

  Guardrail: validates that every cited `[EVID-####]` exists in `evidence.csv`.

---

## Prerequisites

### 1) Zeek installed

### 2) Python 3.9+ recommended

### 3) LLM step dependencies

---

## Step 1 — Generate Zeek logs (inputs in `./files/`, outputs in `./artifacts/`)
```bash
python 01_run_zeek_logs.py --pcap ./files --out ./artifacts --json --recursive
```

## Step 2 — Run lateral detection (repeat per PCAP output folder)
```bash
python 02_lateral_detect.py --zeek-dir ./artifacts/<pcap_stem>/zeek --out-dir ./artifacts/<pcap_stem>/derived --pcap-name <pcap_filename>.pcap
```

## Step 3 (Optional) — Generate evidence-bound narrative (Azure OpenAI)
```bash
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://<resource-name>.openai.azure.com"
export AZURE_OPENAI_API_VERSION="2024-10-21"
python 03_llm_summarize_lateral.py --findings ./artifacts/<pcap_stem>/derived/lateral_findings.json --evidence ./artifacts/<pcap_stem>/derived/evidence.csv --out-dir ./artifacts/<pcap_stem>/derived --model <your-azure-deployment-name> --provider azure
```
