# 🛡️ SentryAlert v2

**Cybersecurity Vulnerability Intelligence Dashboard & Open-Source Dependency Scanner**

SentryAlert is a Python-based cybersecurity dashboard built with Streamlit. It combines real-world vulnerability intelligence from NVD, CISA, and OSV with dependency vulnerability scanning, automated alerts, and interactive visualizations.

The project is designed to help developers, students, and security enthusiasts explore publicly disclosed vulnerabilities and identify known security issues in open-source dependencies.

## ✨ Features

### 1. Security Intelligence Dashboard
- Dark, Security Operations Center (SOC)-inspired interface.
- Latest publicly disclosed CVEs from the National Vulnerability Database (NVD).
- CVSS severity scores and vulnerability descriptions.
- Searchable vulnerability explorer with filters and pagination.
- Interactive charts, security metrics, and CSV exports.

### 2. CISA Known Exploited Vulnerabilities
- Integration with CISA's Known Exploited Vulnerabilities (KEV) catalog.
- Identification of vulnerabilities with evidence of exploitation in the wild.
- Relevant vulnerability details for security prioritization.

### 3. Dependency Vulnerability Scanner
- Scan supported dependency files for known security advisories.
- Supported file formats:
  - Python: `requirements.txt` with exact `==` version pins.
  - JavaScript: `package-lock.json` and `npm-shrinkwrap.json`.
  - PHP: `composer.lock`.
- Uses the OSV vulnerability database for package and version matching.
- Supports up to 250 packages per batch scan.
- Export scan findings as CSV or JSON.

### 4. Automated Security Alerts
- GitHub Actions workflow for monitoring CISA KEV catalog additions.
- Scheduled daily vulnerability checks.
- Creates GitHub Issues for newly identified KEV entries when configured.
- Uses GitHub's built-in workflow authentication.

### 5. Additional Features
- SQLite history for individual dependency lookups.
- Automated tests using pytest.
- GitHub Actions continuous integration.
- Streamlit Community Cloud deployment support.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application development |
| Streamlit | Interactive web dashboard |
| Pandas | Data processing |
| Requests | External API communication |
| SQLite | Local lookup history |
| NVD API | CVE vulnerability intelligence |
| CISA KEV | Known exploited vulnerability intelligence |
| OSV API | Open-source dependency vulnerability matching |
| Pytest | Automated testing |
| GitHub Actions | CI and automated alerts |

## 📁 Project Structure

```text
SentryAlert/
├── .github/
│   └── workflows/
│       ├── kev-alerts.yml
│       └── tests.yml
│
└── SentryAlert/
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

The application is located in the inner `SentryAlert/` directory, while GitHub Actions workflows are located at the repository root.

## 🚀 Installation and Local Setup

### Prerequisites

- Python 3.11 or newer, with compatible dependencies.
- Git.
- Internet connection for vulnerability API requests.

### Step 1 — Clone the repository

```powershell
git clone https://github.com/MYSTICOP221/SentryAlert.git
cd SentryAlert\SentryAlert
```

### Step 2 — Create a virtual environment

```powershell
python -m venv .venv
```

### Step 3 — Activate the virtual environment

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can run the virtual environment's Python executable directly without activating it.

### Step 4 — Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### Step 5 — Launch SentryAlert

```powershell
python -m streamlit run app.py
```

Open the dashboard in your browser:

**http://localhost:8501**

To stop the application, press `Ctrl + C` in the terminal.

## 🔎 How to Use the Dependency Scanner

1. Launch the SentryAlert dashboard.
2. Open the **Dependency Scanner** section.
3. Upload a supported dependency file.
4. Start the vulnerability scan.
5. Review matched advisories, affected packages, and available severity information.
6. Export the results as CSV or JSON.

### Example Python dependency file

Create a file named `test-requirements.txt`:

```text
requests==2.19.0
urllib3==1.24.1
Jinja2==2.10
```

Upload this file to test the scanner using intentionally outdated package versions.

**Note:** Do not install these outdated dependencies. The file is intended only for scanner testing.

The scanner identifies published vulnerability advisories associated with declared package versions. It does not execute the dependencies or perform active exploitation.

## 🧪 Running Automated Tests

From the inner `SentryAlert/` directory:

```powershell
python -m pip install pytest
python -m pytest -q
```

The repository also contains a GitHub Actions workflow for automated test execution.

## 🔔 Automated Vulnerability Alerts

SentryAlert includes a GitHub Actions workflow that checks for newly added entries in the CISA KEV catalog.

### Enable alerts

1. Open the GitHub repository.
2. Go to **Settings → General → Features** and enable **Issues**.
3. Go to **Settings → Actions → General** and ensure GitHub Actions is enabled.
4. Ensure the workflow has permission to create issues using `issues: write` or the required repository workflow permissions.
5. Open **Actions → CISA KEV alerts**.
6. Select **Run workflow** to execute a manual test.

The workflow is configured to run daily at approximately **09:17 UTC**, although GitHub may delay scheduled jobs.

When new KEV entries are identified, the workflow can create GitHub Issues to record them. It checks up to 100 existing issues for duplicates, so larger repositories may require improved pagination.

**Important:** Automated alerts cover newly added CISA KEV catalog entries, not every newly published CVE or vulnerabilities on a user's computer.

## ☁️ Deploying SentryAlert Online

SentryAlert can be deployed using Streamlit Community Cloud.

### Deployment steps

1. Push the latest project files to GitHub.
2. Visit https://share.streamlit.io/.
3. Sign in using GitHub.
4. Choose to deploy an application from an existing GitHub repository.
5. Configure the application:

| Setting | Value |
|---|---|
| Repository | `MYSTICOP221/SentryAlert` |
| Branch | `main` |
| Main file path | `SentryAlert/app.py` |

6. Click **Deploy**.
7. Wait for Streamlit to install dependencies and start the application.

The GitHub Actions alert workflow runs separately from the hosted Streamlit application.

**Cloud storage limitation:** SQLite history stored on the application filesystem may be lost after restarts or redeployments. Persistent multi-user storage requires a managed database and appropriate authentication.

## 🌐 Data Sources

SentryAlert uses publicly available cybersecurity intelligence sources:

- **National Vulnerability Database (NVD):** https://nvd.nist.gov/developers/vulnerabilities
- **CISA Known Exploited Vulnerabilities:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Open Source Vulnerabilities (OSV):** https://osv.dev/

API availability, request limits, and advisory coverage may affect results.

## 🔐 Security and Privacy

SentryAlert performs passive vulnerability intelligence and dependency advisory matching.

It does **not** provide:
- Active network vulnerability scanning.
- Penetration testing or exploitation.
- Zero-day vulnerability discovery.
- A guarantee that scanned software is secure.

Vulnerability findings should be reviewed against affected version ranges, deployment conditions, and vendor remediation guidance.

The `.gitignore` excludes local virtual environments, environment files, Python caches, Streamlit secrets, and SQLite database files.

Never commit API keys, passwords, private scan results, or other sensitive information.

When using the public dashboard, avoid uploading confidential dependency files unless you understand how the application and OSV API process the supplied package information.

## 🗺️ Future Improvements

- Support for additional dependency ecosystems.
- SBOM (Software Bill of Materials) scanning.
- Improved vulnerability prioritization.
- Email or webhook-based security notifications.
- Persistent cloud database integration.
- Authentication and user-specific scan history.
- Additional automated scanner tests.

## 📜 License

No open-source license has been added yet. All rights are reserved by default.

A license may be added in the future to specify permissions for using, modifying, and distributing the project.

---

**SentryAlert v2 — Security Intelligence, Dependency Analysis, and Vulnerability Awareness.**
