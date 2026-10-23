"""SentryAlert: public vulnerability intelligence and dependency advisory lookup."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from sentryalert.scanner import parse_manifest, scan_packages, flatten_findings

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/query"
DB_PATH = Path(__file__).with_name("sentryalert.db")
PAGE_SIZE = 100

st.set_page_config(page_title="SentryAlert | Security Operations", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""<style>
.block-container{padding-top:1.2rem;max-width:1500px;padding-bottom:4rem}
[data-testid="stMetric"]{background:linear-gradient(145deg,#15253d,#0d1829);border:1px solid #294362;border-radius:15px;padding:18px;box-shadow:0 5px 18px #02091440}
[data-testid="stMetricLabel"]{color:#9fb5d2}
[data-testid="stMetricValue"]{color:#e7f5ff}
[data-testid="stSidebar"]{background:#0b1627;border-right:1px solid #253a52}
[data-testid="stTabs"] button{font-weight:600}
h1,h2,h3{letter-spacing:-.035em}
h1{background:linear-gradient(100deg,#e7f5ff,#38bdf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.small-note{color:#8491a5;font-size:.85rem}
.hero{padding:24px 26px;border:1px solid #28445e;border-radius:18px;background:radial-gradient(circle at 90% 0%,#104063,#101b2c 60%);margin-bottom:20px}
.hero-title{font-size:2rem;font-weight:800;color:#e7f5ff}
.hero-sub{color:#9cb6d2;margin-top:8px}
</style>""", unsafe_allow_html=True)



def db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS lookups
        (id INTEGER PRIMARY KEY AUTOINCREMENT, checked_at TEXT NOT NULL,
         ecosystem TEXT NOT NULL, package TEXT NOT NULL, version TEXT NOT NULL,
         findings INTEGER NOT NULL, result_json TEXT NOT NULL)""")
    conn.commit()
    return conn


@st.cache_data(ttl=1800, show_spinner=False)
def get_nvd(start_iso, end_iso, page, keyword):
    params = {
        "pubStartDate": start_iso,
        "pubEndDate": end_iso,
        "startIndex": page * PAGE_SIZE,
        "resultsPerPage": PAGE_SIZE,
        "noRejected": "",
    }
    if keyword.strip():
        params["keywordSearch"] = keyword.strip()
    r = requests.get(NVD_URL, params=params, timeout=35,
                     headers={"User-Agent": "SentryAlert/1.0 (educational project)"})
    r.raise_for_status()
    return r.json()


@st.cache_data(ttl=3600, show_spinner=False)
def get_kev():
    r = requests.get(KEV_URL, timeout=35,
                     headers={"User-Agent": "SentryAlert/1.0 (educational project)"})
    r.raise_for_status()
    return r.json()


@st.cache_data(ttl=1800, show_spinner=False)
def query_osv(ecosystem, package, version):
    r = requests.post(OSV_URL, json={
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem}
    }, timeout=35, headers={"User-Agent": "SentryAlert/1.0 (educational project)"})
    r.raise_for_status()
    return r.json()


def get_cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            preferred = next((x for x in entries if x.get("type") == "Primary"), entries[0])
            data = preferred.get("cvssData", {})
            severity = data.get("baseSeverity", preferred.get("baseSeverity", "UNKNOWN"))
            return severity.upper(), data.get("baseScore"), data.get("version", "?")
    return "UNKNOWN", None, "N/A"


def description(cve):
    return next((x.get("value", "") for x in cve.get("descriptions", [])
                 if x.get("lang") == "en"), "No English description provided")


def to_rows(entries, kev_ids):
    rows = []
    for entry in entries:
        cve = entry.get("cve", {})
        severity, score, version = get_cvss(cve)
        rows.append({"CVE": cve.get("id", "?"), "Severity": severity,
                     "Score": score, "CVSS": version,
                     "Published": cve.get("published", "")[:10],
                     "Description": description(cve),
                     "In CISA KEV": cve.get("id") in kev_ids})
    return rows


def error_message(exc):
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        if exc.response.status_code == 403:
            return "Access denied (HTTP 403). The data provider may be rate limiting requests. Wait and retry."
        if exc.response.status_code == 429:
            return "Rate limit reached (HTTP 429). Please wait before retrying."
    return str(exc)


st.markdown("""<div class="hero"><div class="hero-title">🛡️ SENTRYALERT <span style="color:#38bdf8;font-size:1rem">/ SOC CONSOLE v2</span></div><div class="hero-sub">Security intelligence · CISA exploitation signals · Software composition analysis · Automated alerting</div></div>""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Intelligence controls")
    days = st.slider("Publication window (days)", min_value=1, max_value=90, value=10)
    keyword = st.text_input("Search all NVD records in window", placeholder="PHP, Apache, CVE-2026-...")
    severity_choice = st.selectbox("Severity (loaded page)",
                                   ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    only_kev = st.checkbox("Known exploited only (loaded page)")
    if st.button("↻ Refresh cached intelligence", width="stretch"):
        get_nvd.clear()
        get_kev.clear()
        st.rerun()
    st.divider()
    st.caption("NVD results are paged; severity and KEV filters operate on the currently loaded page. Keyword search is server-side across the chosen date window.")
    st.caption("Public advisory data is not proof an individual server is vulnerable.")

tab_overview, tab_explorer, tab_kev, tab_packages, tab_scan, tab_history, tab_about = st.tabs([
    "📊 Overview", "🔎 CVE Explorer", "🚨 Exploited (KEV)",
    "📦 Dependency Checker", "🧪 Project Scanner", "🕘 Lookup History", "ℹ️ About"
])

end = datetime.now(timezone.utc)
start = end - timedelta(days=days)
start_iso = start.strftime("%Y-%m-%dT%H:%M:%S.000")
end_iso = end.strftime("%Y-%m-%dT%H:%M:%S.000")

# CISA data is optional: NVD explorer still works if its feed is unavailable.
kev_data, kev_error = None, None
try:
    kev_data = get_kev()
except (requests.RequestException, ValueError) as exc:
    kev_error = error_message(exc)
kev_records = kev_data.get("vulnerabilities", []) if kev_data else []
kev_ids = {x.get("cveID") for x in kev_records}

with tab_explorer:
    st.subheader("Explore published CVEs")
    page = st.number_input("Page (starting at 1)", min_value=1, value=1, step=1)
    try:
        with st.spinner("Retrieving CVEs from NVD..."):
            payload = get_nvd(start_iso, end_iso, int(page) - 1, keyword)
        total = payload.get("totalResults", 0)
        max_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        if page > max_pages:
            st.warning(f"Page {page} is beyond the {max_pages} available pages. Choose a lower page.")
        rows = to_rows(payload.get("vulnerabilities", []), kev_ids)
        shown = [r for r in rows if (severity_choice == "ALL" or r["Severity"] == severity_choice)
                 and (not only_kev or r["In CISA KEV"])]
        a, b, c = st.columns(3)
        a.metric("NVD matching CVEs", f"{total:,}")
        b.metric("Loaded page", f"{page:,} / {max_pages:,}")
        c.metric("Visible after filters", len(shown))
        st.caption("Showing a maximum of 100 CVEs per page. NVD's total is not a count of the locally filtered results.")
        if shown:
            df = pd.DataFrame(shown)
            st.dataframe(df[["CVE", "Severity", "Score", "Published", "In CISA KEV", "Description"]],
                         width="stretch", hide_index=True)
            st.download_button("⬇ Download visible CSV", df.to_csv(index=False).encode("utf-8"),
                               file_name="sentryalert_cves.csv", mime="text/csv")
            chosen = st.selectbox("Inspect a CVE", [r["CVE"] for r in shown])
            item = next(r for r in shown if r["CVE"] == chosen)
            with st.container(border=True):
                st.subheader(item["CVE"])
                st.write(f"**Severity:** {item['Severity']} | **Score:** {item['Score'] if item['Score'] is not None else 'N/A'} | **CVSS:** {item['CVSS']}")
                st.write(f"**Published:** {item['Published']} | **In CISA KEV:** {'Yes' if item['In CISA KEV'] else 'No'}")
                st.write(item["Description"])
                st.link_button("Official NVD details", f"https://nvd.nist.gov/vuln/detail/{chosen}")
        else:
            st.info("No CVEs match the selected filters on this page.")
    except (requests.RequestException, ValueError, KeyError) as exc:
        st.error("NVD request failed: " + error_message(exc))

with tab_overview:
    st.subheader("Threat intelligence snapshot")
    if kev_error:
        st.warning("CISA KEV feed unavailable: " + kev_error)
    try:
        with st.spinner("Loading overview..."):
            overview = get_nvd(start_iso, end_iso, 0, "")
        rows = to_rows(overview.get("vulnerabilities", []), kev_ids)
        df = pd.DataFrame(rows)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("New CVEs in window", f"{overview.get('totalResults', 0):,}")
        c2.metric("Sample critical", sum(r["Severity"] == "CRITICAL" for r in rows))
        c3.metric("Sample high", sum(r["Severity"] == "HIGH" for r in rows))
        c4.metric("CISA KEV catalog", f"{len(kev_records):,}" if kev_data else "Unavailable")
        st.caption("Sample metrics reflect the first 100 recent NVD results, not the complete publication window.")
        if not df.empty:
            left, right = st.columns(2)
            with left:
                st.markdown("**Severity breakdown (first page)**")
                st.bar_chart(df["Severity"].value_counts())
            with right:
                st.markdown("**Daily publications (first page)**")
                st.line_chart(df.groupby("Published").size())
        st.info("SentryAlert currently tracks public disclosures and dependency advisories. It does not perform network exploitation or zero-day discovery.")
    except (requests.RequestException, ValueError, KeyError) as exc:
        st.error("Unable to load overview: " + error_message(exc))

with tab_kev:
    st.subheader("CISA Known Exploited Vulnerabilities")
    st.caption("CISA's KEV catalog contains vulnerabilities with evidence of exploitation in the wild.")
    if kev_error:
        st.error("CISA feed unavailable: " + kev_error)
    else:
        kev_search = st.text_input("Filter KEV catalog", placeholder="Vendor, product, CVE ID...")
        kev_limit = st.slider("Maximum results to show", 10, 500, 50, 10)
        matches = [x for x in kev_records if kev_search.lower().strip() in
                   (x.get("cveID", "") + " " + x.get("vendorProject", "") + " " +
                    x.get("product", "") + " " + x.get("vulnerabilityName", "")).lower()]
        matches.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        st.metric("Matching exploited CVEs", len(matches))
        kev_rows = [{"CVE": x.get("cveID"), "Vendor": x.get("vendorProject"),
                     "Product": x.get("product"), "Added": x.get("dateAdded"),
                     "Due date": x.get("dueDate"), "Description": x.get("shortDescription")}
                    for x in matches[:kev_limit]]
        if kev_rows:
            st.dataframe(pd.DataFrame(kev_rows), width="stretch", hide_index=True)
            st.download_button("⬇ Download shown KEV records", pd.DataFrame(kev_rows).to_csv(index=False),
                               file_name="sentryalert_kev.csv", mime="text/csv")
        else:
            st.info("No matching KEV records.")
        st.link_button("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

with tab_packages:
    st.subheader("Open-source dependency advisory checker")
    st.write("Check whether a **specific package version** is listed in the OSV vulnerability database. This is not a live scan of your computer.")
    with st.form("dependency_form"):
        ecosystem = st.selectbox("Ecosystem", ["PyPI", "npm", "Maven", "Go", "crates.io", "NuGet", "Packagist", "RubyGems"])
        package = st.text_input("Exact package name", placeholder="requests")
        version = st.text_input("Installed version", placeholder="2.31.0")
        submitted = st.form_submit_button("Check advisories", type="primary")
    if submitted:
        package = package.strip()
        version = version.strip()
        if not package or not version:
            st.warning("Enter both the package name and version.")
        else:
            try:
                with st.spinner("Checking OSV advisories..."):
                    result = query_osv(ecosystem, package, version)
                vulns = result.get("vulns", [])
                with db_connection() as conn:
                    conn.execute("INSERT INTO lookups (checked_at, ecosystem, package, version, findings, result_json) VALUES (?, ?, ?, ?, ?, ?)",
                                 (datetime.now(timezone.utc).isoformat(), ecosystem, package, version,
                                  len(vulns), json.dumps(result)))
                    conn.commit()
                st.metric("Matching advisories", len(vulns))
                if not vulns:
                    st.success("No matching OSV advisories returned. This does NOT prove the package is secure.")
                for vuln in vulns:
                    with st.expander(vuln.get("id", "Unknown advisory"), expanded=True):
                        st.write(vuln.get("summary") or vuln.get("details", "No summary available"))
                        aliases = vuln.get("aliases", [])
                        if aliases:
                            st.caption("Aliases: " + ", ".join(aliases))
                        st.link_button("View OSV advisory", f"https://osv.dev/vulnerability/{vuln.get('id', '')}")
                st.download_button("⬇ Download OSV JSON", json.dumps(result, indent=2),
                                   file_name="sentryalert_osv.json", mime="application/json")
            except (requests.RequestException, ValueError, sqlite3.Error) as exc:
                st.error("Lookup failed: " + error_message(exc))

with tab_scan:
    st.subheader("Project dependency vulnerability scanner")
    st.write("Upload a lockfile or pinned requirements file from a project you own or are authorized to assess. SentryAlert checks the declared versions against the OSV advisory database; it does **not** execute the uploaded file or probe your servers.")
    upload = st.file_uploader("Upload manifest (max 5 MB)", type=["txt", "json", "lock"], key="manifest_upload")
    st.caption("Supported filenames: requirements.txt, package-lock.json, npm-shrinkwrap.json, composer.lock. Python version ranges such as >= are skipped because an exact installed version is unknown.")
    if upload is not None and st.button("Scan project dependencies", type="primary"):
        try:
            if upload.size > 5 * 1024 * 1024:
                raise ValueError("File exceeds the 5 MB limit")
            content = upload.getvalue().decode("utf-8-sig")
            packages, skipped = parse_manifest(upload.name, content)
            if skipped:
                st.warning(f"Skipped {len(skipped)} unpinned or unsupported requirement lines. They were NOT checked.")
                with st.expander("Show skipped lines"):
                    st.code("\n".join(skipped[:100]))
            if not packages:
                st.warning("No exact-version dependencies found to check.")
            else:
                with st.spinner(f"Checking {len(packages)} dependencies against OSV..."):
                    results = scan_packages(packages)
                findings = flatten_findings(results)
                a, b, c = st.columns(3)
                a.metric("Dependencies checked", len(results))
                b.metric("Packages with advisories", sum(r["count"] > 0 for r in results))
                c.metric("Advisory matches", len(findings))
                if findings:
                    frame = pd.DataFrame(findings)
                    st.dataframe(frame, width="stretch", hide_index=True)
                    st.download_button("⬇ Export scan CSV", frame.to_csv(index=False), "sentryalert_scan.csv", "text/csv")
                    st.download_button("⬇ Export scan JSON", json.dumps(results, indent=2), "sentryalert_scan.json", "application/json")
                else:
                    st.success("OSV returned no matches for the checked package versions. This does not guarantee security.")
                st.caption("Advisories may be incomplete, delayed, or include disputed matches. Review affected ranges and vendor guidance before remediation.")
        except (UnicodeDecodeError, ValueError, KeyError, TypeError, requests.RequestException) as exc:
            st.error("Scan could not complete: " + error_message(exc))

with tab_history:
    st.subheader("Local dependency lookup history")
    st.caption("History is stored in a local SQLite database beside app.py. It is not shared across devices.")
    try:
        with db_connection() as conn:
            history = pd.read_sql_query("SELECT checked_at, ecosystem, package, version, findings FROM lookups ORDER BY id DESC LIMIT 500", conn)
        if history.empty:
            st.info("No dependency checks yet. Run one in the Dependency Checker tab.")
        else:
            st.dataframe(history, width="stretch", hide_index=True)
            st.download_button("⬇ Export history", history.to_csv(index=False),
                               file_name="sentryalert_history.csv", mime="text/csv")
    except sqlite3.Error as exc:
        st.error("Database error: " + str(exc))

with tab_about:
    st.subheader("About SentryAlert")
    st.write("**Sources:** NIST NVD CVE API, CISA Known Exploited Vulnerabilities, OSV.dev advisory API.")
    st.write("**Limitations:** NVD may publish or update records after disclosure. Severity is not a measure of actual exposure. KEV membership indicates known exploitation, not that your systems are affected. OSV matches advisories for supplied package/version coordinates; package naming must be exact.")
    st.write("**Safety:** No active scanning, exploit execution, or credential collection is performed. Only assess systems you own or are authorized to test.")
    st.write("**Automated alerts:** GitHub Actions can create GitHub issues for newly added CISA KEV entries. Enable Actions and Issues in your repository. See README for setup.")
    st.write("**Hosting:** Deploy app.py through Streamlit Community Cloud; scheduled alerts run separately in GitHub Actions.")
