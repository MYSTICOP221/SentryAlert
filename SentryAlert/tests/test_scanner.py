import json
import pytest
from sentryalert.scanner import parse_manifest, scan_packages, flatten_findings
from sentryalert.alerts import new_kev_entries
from datetime import datetime, timezone


def test_pinned_requirements():
    pkgs, skipped = parse_manifest('requirements.txt', 'requests==2.31.0\nflask>=2\n#comment\n')
    assert pkgs == [{'ecosystem': 'PyPI', 'name': 'requests', 'version': '2.31.0'}]
    assert skipped == ['flask>=2']


def test_npm_lock():
    lock = {'packages': {'': {'version': '1.0.0'}, 'node_modules/lodash': {'version': '4.17.20'}}}
    pkgs, _ = parse_manifest('package-lock.json', json.dumps(lock))
    assert pkgs[0]['name'] == 'lodash'


def test_composer_lock():
    pkgs, _ = parse_manifest('composer.lock', json.dumps({'packages': [{'name': 'vendor/a', 'version': 'v1.2.3'}]}))
    assert pkgs[0]['version'] == '1.2.3'


def test_unsupported():
    with pytest.raises(ValueError):
        parse_manifest('setup.py', 'x')


def test_osv_batch_mock():
    class Response:
        def raise_for_status(self): pass
        def json(self): return {'results': [{'vulns': [{'id': 'GHSA-test'}]}]}
    class Session:
        def post(self, *args, **kwargs): return Response()
    res = scan_packages([{'ecosystem': 'PyPI', 'name': 'requests', 'version': '2.31.0'}], Session())
    assert res[0]['count'] == 1
    assert flatten_findings(res)[0]['Advisory'] == 'GHSA-test'


def test_recent_kev():
    feed = {'vulnerabilities': [{'dateAdded': '2026-10-21'}, {'dateAdded': '2026-09-01'}]}
    result = new_kev_entries(feed, 2, datetime(2026, 10, 22, tzinfo=timezone.utc))
    assert len(result) == 1
