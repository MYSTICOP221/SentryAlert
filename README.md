# 🛡️ SentryAlert v2

**Vulnerability intelligence dashboard and passive open-source dependency scanner** built with Python and Streamlit.

SentryAlert combines publicly available CVE intelligence from NVD, CISA's Known Exploited Vulnerabilities (KEV) catalog, and OSV package advisories. It is intended for exploring security advisories and checking declared open-source dependency versions against known vulnerabilities.

## Features

- **Security dashboard:** dark SOC-inspired interface, NVD CVE explorer, severity filters, charts, pagination, and CSV exports.
- **CISA KEV:** browse vulnerabilities listed as known exploited by CISA.
- **Dependency scanner:** query OSV for exact dependency versions in supported manifests, up to **250 unique packages per scan**, with CSV/JSON exports.
- **Package lookup:** look up supported packages in OSV; individual lookups can be stored in a local SQLite database.
- **GitHub alerts:** scheduled GitHub Actions workflow checks for newly added CISA KEV entries and can open GitHub Issues.
- **Tests and deployment:** pytest tests, GitHub Actions CI, and Streamlit Community Cloud configuration.

## Technology

Python · Streamlit · Requests · Pandas · SQLite · NVD API · CISA KEV · OSV API · pytest · GitHub Actions

## Repository layout

```text
SentryAlert/                         # GitHub repository root
├── .github/
│   └── workflows/
│       ├── kev-alerts.yml
│       └── tests.yml
└── SentryAlert/                     # Application folder
    ├── .streamlit/
    │   └── config.toml
    ├── sentryalert/
    │   ├── __init__.py
    │   ├── alerts.py
    │   └── scanner.py
    ├── tests/
    │   └── test_scanner.py
    ├── app.py
    ├── requirements.txt
    ├── README.md
    └── .gitignore
```

**Important:** Run the application from the **inner** `SentryAlert/` folder, where `app.py` and `requirements.txt` live.

## Run locally (Windows PowerShell)

### Prerequisites

- Python 3.11+ and an internet connection. Python 3.12 is a reasonable choice for deployment compatibility.
- Git, if you are cloning the repository.

### 1. Clone and enter the application folder

```powershell
git clone https://github.com/MYSTICOP221/SentryAlert.git
cd SentryAlert\SentryAlert
```

If you already have the project, **do not clone it again**. Open a terminal in your existing *inner* `SentryAlert` folder instead. For the original development setup, that folder is `C:\Users\midhu\Downloads\SentryAlert\SentryAlert`, and its existing virtual environment is one directory above it. You do not need to recreate that environment.

### 2. Create a virtual environment (recommended, one time only)

```powershell
python -m venv .venv
```

A virtual environment isolates the app's dependencies from other Python projects. It is **recommended, not mandatory**, and must **not** be committed to GitHub. Do not recreate it every time you run the app.

### 3. Install and run (no activation required)

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open **http://localhost:8501** in your browser. Stop the server with **Ctrl+C**.

Alternatively, activate the environment with `.\.venv\Scripts\Activate.ps1`, then use `python -m pip install -r requirements.txt` and `python -m streamlit run app.py`.

**Already installed the dependencies?** Skip the installation step and run Streamlit directly. If you prefer not to use a virtual environment, you can run `python -m pip install -r requirements.txt` and `python -m streamlit run app.py` from the inner application folder using your regular Python installation.

## Dependency vulnerability scanner

Supported filenames and formats:

| Ecosystem | Filename | Requirements |
|---|---|---|
| Python / PyPI | `requirements.txt` | Exact version pins such as `requests==2.19.0` |
| JavaScript / npm | `package-lock.json` | npm lockfile |
| JavaScript / npm | `npm-shrinkwrap.json` | npm shrinkwrap lockfile |
| PHP / Packagist | `composer.lock` | Composer lockfile |

**The filename must match exactly.** For example, `test-requirements.txt` is **not** accepted by the current version of the scanner. Rename the test file to `requirements.txt` before uploading.

To test without installing vulnerable software, create a text file named **`requirements.txt`** containing:

```text
requests==2.19.0
urllib3==1.24.1
Jinja2==2.10
```

1. Start the app and open **Dependency Scanner**.
2. Upload the test `requirements.txt` file.
3. Start the scan and review any OSV advisory matches.
4. Export the findings as CSV or JSON if desired.

These versions are deliberately outdated. **Do not install them.** Results depend on OSV's coverage and API availability. The scanner checks declared package versions; it does not execute packages or scan your computer or network.

## Run tests

From the inner application folder:

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest -q
```

If you aren't using a virtual environment, substitute `python` for `.\.venv\Scripts\python.exe`.

## Automated CISA KEV alerts

The workflow is located at `.github/workflows/kev-alerts.yml` **in the repository root**.

1. On GitHub, enable **Issues** in the repository's settings.
2. Open **Actions → CISA KEV alerts → Run workflow** to test it manually.
3. If the job cannot create issues, check the workflow's permissions and repository Actions settings. The workflow requests `issues: write` and uses the built-in `GITHUB_TOKEN`.
4. Check the run logs and the repository's **Issues** tab.

The workflow is scheduled daily around **09:17 UTC**, subject to GitHub scheduling delays. A successful run may create **no issues** when there are no new entries. The current deduplication logic checks up to 100 existing issues; large repositories may need pagination improvements.

**Scope:** these alerts concern new entries in CISA's KEV catalog, **not every new CVE** and not vulnerabilities detected on a user's device.

## Deploy to Streamlit Community Cloud

1. Push the project to GitHub.
2. Visit [Streamlit Community Cloud](https://share.streamlit.io/) and sign in.
3. Create an app from GitHub using:

| Setting | Value |
|---|---|
| Repository | `MYSTICOP221/SentryAlert` |
| Branch | `main` |
| Main file path | `SentryAlert/app.py` |

4. Deploy and inspect the app logs if startup or API calls fail.

The hosted dashboard and the GitHub Actions alert workflow are separate services. Local SQLite data on Streamlit Community Cloud may be reset on restart or redeployment; persistent multi-user history requires managed storage and authentication.

## Security, privacy, and limitations

- SentryAlert performs **passive advisory matching**, not penetration testing, active network scanning, exploit verification, or zero-day detection.
- Missing advisory matches **do not prove software is secure**. Verify reported affected versions and mitigations with authoritative vendor advisories.
- Avoid uploading confidential dependency manifests to a public deployment unless you understand how the app and OSV process package information.
- Never commit API keys, credentials, `.env` files, local SQLite databases, `.venv/`, or private scan results. The project's `.gitignore` is intended to exclude common local files.
- External APIs can be unavailable or rate-limited.

## Data sources

- [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OSV](https://osv.dev/)

## Future improvements

Additional ecosystems, SBOM support, more robust advisory prioritization, email/webhook notifications, persistent cloud storage, authentication, and expanded test coverage.

## License

No license has been added. All rights are reserved by default until a license specifies reuse permissions.
