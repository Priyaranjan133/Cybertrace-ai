# 🛡️ CyberTrace AI

A Streamlit digital-forensics workbench: examine suspicious **emails, files and logs** in one place,
correlate indicators across evidence, rebuild an incident **timeline**, and export a **forensic report**
while keeping the original evidence intact.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open the app, click **Load demo case** on the dashboard, then explore each page. The demo is a phishing
email plus an SSH brute-force log that share an attacker IP (`203.0.113.45`, a reserved documentation
address) - all synthetic and harmless.

## Modules

| Page | What it does |
|---|---|
| Case Management | Cases, evidence acquisition (SHA-256/SHA-1/MD5, read-only storage), integrity re-verification, hash-chained audit log |
| Email Forensics | `.eml` parsing, SPF/DKIM/DMARC results, routing hops, link & attachment inspection, explainable phishing score |
| File Forensics | Signature-based type detection, extension mismatch, double-extension/RTLO, entropy, PDF/Office/ZIP indicators, metadata |
| Log Investigation | Linux auth/syslog and CSV (Windows Security export): brute force, password spraying, success-after-failure, off-hours, privilege changes |
| Threat Intelligence | IOC extraction, cross-evidence correlation, relationship graph, optional VirusTotal lookups (kept separate from facts) |
| Incident Timeline | UTC-normalised merged timeline with time-zone display and a suspicious-sequence view |
| Forensic Reports | Editable summary (rule-based, optional LLM), PDF report, CSV exports |

Every score comes with the list of reasons behind it - nothing is a black box.

## Project layout

```
app.py                 dashboard
pages/                 the seven Streamlit pages
modules/               analysis engines (email, file, log, IOC, correlation, reports, AI, UI helpers)
database/db_manager.py SQLite: cases, evidence, results, hash-chained audit log
sample_data/           harmless demo evidence (regenerate with scripts/make_samples.py)
tests/                 unit tests (pytest or `python -m unittest`)
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Deploy on Streamlit Community Cloud

1. Push this folder to a GitHub repository (the `.gitignore` keeps `data/` and secrets out).
2. At share.streamlit.io choose **Create app**, pick the repo, branch, and set the main file to `app.py`.
3. Under **Advanced settings → Secrets** paste (at minimum):
   ```toml
   APP_PASSWORD = "a-long-passphrase"
   ```
4. Deploy.

**Read before hosting publicly**

- Community Cloud storage is **ephemeral** - the SQLite database and stored evidence reset when the app
  restarts. That is fine for a portfolio demo. For real casework use private hosting with persistent storage
  (set `CYBERTRACE_DATA` to a mounted volume) and move to PostgreSQL.
- **Do not upload real or sensitive evidence to a public cloud deployment.** Keep `APP_PASSWORD` set.
- Files are only read as bytes: never executed, rendered or extracted to disk. For genuinely malicious
  samples still use an isolated analysis environment.
- Lookups (VirusTotal) and the optional LLM mode send data to third parties - enable them only where permitted.

## Design notes & limitations

- Evidence is stored read-only, named by hash prefix, and its SHA-256 is re-checked before every analysis;
  a mismatch blocks the analysis and is logged.
- The audit log is hash-chained, so edited/deleted rows are detected. This supports integrity checks but does
  **not alone establish legal admissibility**.
- Syslog lines carry no year or time zone; they are treated as UTC using the year you set on the Log page.
- Phishing/file/log scores are heuristic indicators for an investigator to validate, not verdicts.
- Not included: raw packet (PCAP/Zeek) parsing, `.evtx` binary logs, multi-user accounts. Natural next steps.
