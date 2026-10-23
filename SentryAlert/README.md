# SentryAlert

Beginner-friendly vulnerability intelligence dashboard built with Streamlit.

## Features
- NVD CVE discovery with date windows, server-side keyword search, pagination, and per-page severity filters
- CVSS severity and score with links to official NVD records
- CISA Known Exploited Vulnerabilities catalog and search
- OSV.dev open-source package/version advisory lookup
- Local SQLite lookup history and CSV/JSON exports
- Dashboard summary charts

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Visit http://localhost:8501 if it does not open automatically.

## Data sources
- https://nvd.nist.gov/developers/vulnerabilities
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://osv.dev/docs/

## Limitations
This is an advisory aggregation and package-version lookup tool, **not** an exploit scanner or universal zero-day detector. The first-page charts are explicitly sampled. NVD has API rate limits. No secrets or API keys are required. Only test systems you own or are authorized to assess.
