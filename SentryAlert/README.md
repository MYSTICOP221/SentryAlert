# 🛡️ SentryAlert v2

**Security intelligence dashboard and passive open-source dependency vulnerability scanner.** Built with Python and Streamlit.

## Features

- **SOC-style dark dashboard** with CVE metrics, charts, searchable NVD explorer, pagination, and CSV exports.
- **CISA KEV** catalog for vulnerabilities known to have been exploited in the wild.
- **OSV single-package lookup** for supported package ecosystems.
- **Project dependency scanner:** upload `requirements.txt` (exact `==` pins), `package-lock.json`, `npm-shrinkwrap.json`, or `composer.lock`. Scans up to 250 packages in one OSV batch request and exports findings as CSV/JSON.
- **Automated daily alerts:** GitHub Actions creates GitHub Issues for newly added CISA KEV entries (when enabled).
- **Local SQLite history** for individual dependency lookups.
- **Cloud deployment ready:** `.streamlit/config.toml` for Streamlit Community Cloud.
- **Tests and CI** with pytest and GitHub Actions.

## Run locally (Windows PowerShell)

```powershell
cd C:\Users\midhu\Downloads\SentryAlert
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open http://localhost:8501. If Windows blocks activation, you can skip activation and use `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.\.venv\Scripts\python.exe -m streamlit run app.py`.

## Run tests

```powershell
python -m pip install pytest
python -m pytest -q
```

## Upgrade an existing GitHub repository

Your current Git repository is `Downloads\SentryAlert`, but your application is in `Downloads\SentryAlert\SentryAlert`. The included `UPGRADE_WINDOWS.ps1` handles this structure: it copies app files to the inner folder and GitHub workflows to the **outer repository root** (required by GitHub Actions). Keep your local `.venv` and database; don't upload them.

After extracting the ZIP to `Downloads\SentryAlert-v2`, open PowerShell in that extracted folder and run:

```powershell
.\UPGRADE_WINDOWS.ps1
```

Review the staged changes before committing.

```powershell
git add SentryAlert/app.py SentryAlert/requirements.txt SentryAlert/README.md SentryAlert/.gitignore SentryAlert/sentryalert SentryAlert/tests SentryAlert/.streamlit .github
git status
git commit -m "Release SentryAlert v2: scanner, alerts and cloud deployment"
git push origin main
```

## Automated GitHub alerts

1. On GitHub, open your SentryAlert repository → **Settings → General → Features**, enable **Issues**.
2. Under **Settings → Actions → General**, ensure workflows are allowed and workflow permissions permit **Read and write permissions** (or otherwise allow `issues: write` for the workflow).
3. Push `.github/workflows/kev-alerts.yml` to your **default branch**.
4. Open **Actions → CISA KEV alerts → Run workflow** to test manually. The schedule runs daily around 09:17 UTC; GitHub may delay scheduled runs.
5. Each newly listed KEV CVE is posted as a GitHub Issue. The job checks existing issues (up to 100) to avoid duplicates; for very busy repositories, improve pagination before relying on deduplication.

No personal access token is needed for GitHub Actions; it uses the repository-provided `GITHUB_TOKEN`. GitHub Issues notifications depend on your GitHub notification settings. **This workflow alerts on new KEV catalog additions, not every new CVE or a scan of your own machine.**

## Deploy the dashboard online

1. Push the v2 code to GitHub.
2. Go to [Streamlit Community Cloud](https://share.streamlit.io/) and sign in with GitHub.
3. Select **Create app** → **Deploy a public app from GitHub** (wording may vary).
4. Choose repository `MYSTICOP221/SentryAlert`, branch `main`, and entry point **`SentryAlert/app.py`** (your existing repository has a nested application folder).
5. Choose a public app URL and click **Deploy**.
6. Check the app logs if dependencies or API requests fail. The GitHub alert workflow is separate from the deployed app.

> Cloud filesystem persistence is not guaranteed: local SQLite history may reset after restarts and is not a multi-user account system. For persistent history, add a managed database and authentication. Do not upload private lockfiles to a public demo unless you are comfortable sharing package names and versions with the app provider and OSV.

## Sources and limitations

- NVD: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV: https://osv.dev/

SentryAlert performs **passive advisory matching**, not live network scanning, penetration testing, or zero-day discovery. An advisory match needs manual verification of affected version ranges, environment, and mitigations. Missing results do not prove a package is secure. NVD rate limits may apply; try again later if requests fail.

## Security and privacy

`.gitignore` excludes `.venv`, `.env`, `.streamlit/secrets.toml`, Python caches, and SQLite databases. Never commit secrets, tokens, or private scan results.

## License

No license is granted by default. Add a license if you want to authorize others to reuse your code.
