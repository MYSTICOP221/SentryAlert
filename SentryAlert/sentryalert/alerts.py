"""Scheduled alerts: report newly added CISA KEV entries as GitHub issues."""
import os
import sys
from datetime import datetime, timedelta, timezone
import requests

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
API = 'https://api.github.com'


def new_kev_entries(feed, days=1, now=None):
    today = (now or datetime.now(timezone.utc)).date()
    cutoff = today - timedelta(days=days)
    return [v for v in feed.get('vulnerabilities', [])
            if cutoff <= datetime.strptime(v['dateAdded'], '%Y-%m-%d').date() <= today]


def run():
    token = os.getenv('GH_TOKEN') or os.getenv('GITHUB_TOKEN')
    repo = os.getenv('GITHUB_REPOSITORY')
    if not token or not repo:
        raise RuntimeError('Set GITHUB_TOKEN (or GH_TOKEN) and GITHUB_REPOSITORY=owner/repo')
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
               'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'SentryAlert/2.0'}
    feed_resp = requests.get(KEV_URL, timeout=45)
    feed_resp.raise_for_status()
    entries = new_kev_entries(feed_resp.json(), days=2)
    issues_url = f'{API}/repos/{repo}/issues'
    existing_resp = requests.get(issues_url, params={'state': 'all', 'per_page': 100}, headers=headers, timeout=30)
    existing_resp.raise_for_status()
    existing_titles = {issue.get('title') for issue in existing_resp.json()}
    created = 0
    for item in entries:
        title = f"[SentryAlert KEV] {item['cveID']}"
        if title in existing_titles:
            continue
        body = (f"**Known exploited vulnerability added by CISA** on {item['dateAdded']}\n\n"
                f"**Vendor:** {item.get('vendorProject', 'Unknown')}\n\n"
                f"**Product:** {item.get('product', 'Unknown')}\n\n"
                f"**Details:** {item.get('shortDescription', 'Not provided')}\n\n"
                f"**Recommended action:** {item.get('requiredAction', 'Review vendor guidance')}\n\n"
                f"**CISA due date:** {item.get('dueDate', 'Not provided')}\n\n"
                f"[NVD](https://nvd.nist.gov/vuln/detail/{item['cveID']}) | "
                f"[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n\n"
                "This advisory is not evidence that your own system is affected.")
        resp = requests.post(issues_url, json={'title': title, 'body': body}, headers=headers, timeout=30)
        resp.raise_for_status()
        existing_titles.add(title)
        created += 1
    print(f'Checked {len(entries)} recent KEV entries; created {created} GitHub issues.')


if __name__ == '__main__':
    try:
        run()
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f'Alert job failed: {exc}', file=sys.stderr)
        sys.exit(1)
