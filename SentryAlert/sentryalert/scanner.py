"""Passive software composition analysis using OSV's public advisory database."""
import json
import re
from pathlib import Path

import requests

OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
SUPPORTED = {'PyPI', 'npm', 'Packagist'}
MAX_PACKAGES = 250


def parse_requirements(text):
    """Only exact pins (==) can be checked reliably; skip ranges and editable/VCS refs."""
    packages, skipped = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(('-r', '--', '-e')):
            continue
        m = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+!-]+)(?:\s*(?:#.*)?)?$', line)
        if m:
            packages.append({'ecosystem': 'PyPI', 'name': m.group(1), 'version': m.group(2)})
        else:
            skipped.append(line)
    return packages, skipped


def parse_package_lock(text):
    data = json.loads(text)
    packages = []
    if isinstance(data.get('packages'), dict):
        for key, value in data['packages'].items():
            if not key.startswith('node_modules/') or not isinstance(value, dict):
                continue
            name = key.rsplit('node_modules/', 1)[-1]
            version = value.get('version')
            if name and isinstance(version, str):
                packages.append({'ecosystem': 'npm', 'name': name, 'version': version})
    elif isinstance(data.get('dependencies'), dict):
        def walk(deps):
            for name, value in deps.items():
                if not isinstance(value, dict):
                    continue
                if isinstance(value.get('version'), str):
                    packages.append({'ecosystem': 'npm', 'name': name, 'version': value['version']})
                walk(value.get('dependencies', {}))
        walk(data['dependencies'])
    return packages, []


def parse_composer_lock(text):
    data = json.loads(text)
    packages = []
    for item in data.get('packages', []) + data.get('packages-dev', []):
        name, version = item.get('name'), item.get('version')
        if name and version and re.match(r'^v?\d', version):
            packages.append({'ecosystem': 'Packagist', 'name': name, 'version': version.lstrip('v')})
    return packages, []


def parse_manifest(filename, text):
    name = Path(filename).name.lower()
    if name == 'requirements.txt':
        packages, skipped = parse_requirements(text)
    elif name in ('package-lock.json', 'npm-shrinkwrap.json'):
        packages, skipped = parse_package_lock(text)
    elif name == 'composer.lock':
        packages, skipped = parse_composer_lock(text)
    else:
        raise ValueError('Supported files: requirements.txt, package-lock.json, npm-shrinkwrap.json, composer.lock')
    seen, unique = set(), []
    for pkg in packages:
        key = (pkg['ecosystem'], pkg['name'].lower(), pkg['version'])
        if key not in seen:
            seen.add(key)
            unique.append(pkg)
    if len(unique) > MAX_PACKAGES:
        raise ValueError(f'Manifest has {len(unique)} packages; maximum per scan is {MAX_PACKAGES}.')
    return unique, skipped


def scan_packages(packages, session=None):
    if not packages:
        return []
    if len(packages) > MAX_PACKAGES:
        raise ValueError('Too many packages for one scan')
    http = session or requests
    queries = [{'package': {'name': p['name'], 'ecosystem': p['ecosystem']}, 'version': p['version']} for p in packages]
    response = http.post(OSV_BATCH, json={'queries': queries}, timeout=45,
                         headers={'User-Agent': 'SentryAlert/2.0'})
    response.raise_for_status()
    results = response.json().get('results', [])
    if len(results) != len(packages):
        raise ValueError('OSV returned an incomplete result set')
    return [{**p, 'vulnerabilities': r.get('vulns', []), 'count': len(r.get('vulns', []))}
            for p, r in zip(packages, results)]


def flatten_findings(results):
    return [{'Ecosystem': r['ecosystem'], 'Package': r['name'], 'Version': r['version'],
             'Advisory': v.get('id', 'Unknown'), 'Aliases': ', '.join(v.get('aliases', [])),
             'OSV URL': 'https://osv.dev/vulnerability/' + v.get('id', '')}
            for r in results for v in r['vulnerabilities']]
