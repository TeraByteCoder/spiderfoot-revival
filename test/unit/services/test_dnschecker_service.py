# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from spiderfoot.services.dnschecker_service import (
    collect_scan_domains,
    load_dnschecker_results,
    run_scan_dnschecker,
)
from spiderfoot.services.email_security_audit import (
    DMARCResult,
    DomainAuditResult,
    MXResult,
    RISK_CRITICAL,
    SPFResult,
)


def _make_row(data, event_type, false_positive=0):
    row = [0] * 14
    row[1] = data
    row[4] = event_type
    row[13] = false_positive
    return tuple(row)


class TestDnscheckerService(unittest.TestCase):
    def test_collect_scan_domains_maps_subdomains_to_root(self):
        dbh = MagicMock()
        dbh.scanInstanceGet.return_value = ('Test Scan', 'example.com')
        dbh.scanResultEvent.return_value = [
            _make_row('example.com', 'DOMAIN_NAME'),
            _make_row('mail.example.com', 'INTERNET_NAME'),
            _make_row('sub.other.org', 'INTERNET_NAME'),
            _make_row('fp.example.com', 'INTERNET_NAME', false_positive=1),
        ]
        roots, mapping = collect_scan_domains(dbh, 'scan1')
        self.assertEqual(roots, ['example.com', 'sub.other.org'])
        self.assertEqual(mapping['example.com'], 'example.com')
        self.assertEqual(mapping['mail.example.com'], 'example.com')
        self.assertEqual(mapping['sub.other.org'], 'sub.other.org')

    @patch('spiderfoot.services.dnschecker_service.audit_single_domain')
    def test_run_and_load_scan_dnschecker(self, mock_audit):
        def _fake_audit(domain, root_domain, is_root, **kwargs):
            return DomainAuditResult(
                domain=domain,
                root_domain=root_domain,
                is_root=is_root,
                checked_at='2026-11-27T00:00:00+00:00',
                dns_exists=True,
                mx=MXResult(status='ok', has_mx=True),
                spf=SPFResult(status='no_answer', present=False),
                dmarc=DMARCResult(status='no_answer', present=False),
                dkim_selectors=[],
                dkim_found_count=0,
                risk_level=RISK_CRITICAL,
                risk_score=95,
                risk_reasons=['Kein SPF'],
                recommendations=['SPF setzen'],
            )

        mock_audit.side_effect = _fake_audit

        dbh = MagicMock()
        dbh.scanInstanceGet.return_value = ('Test Scan', 'example.com')
        dbh.scanResultEvent.return_value = [
            _make_row('example.com', 'DOMAIN_NAME'),
            _make_row('api.example.com', 'INTERNET_NAME'),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            payload = run_scan_dnschecker(dbh, 'scan123', data_dir=tmpdir, skip_dkim=True)
            self.assertEqual(payload['summary']['total_targets'], 2)
            self.assertEqual(payload['summary']['risk_counts'][RISK_CRITICAL], 2)

            loaded = load_dnschecker_results('scan123', data_dir=tmpdir)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded['metadata']['scan_id'], 'scan123')
            self.assertTrue((Path(tmpdir) / 'dnschecker' / 'scan123.html').exists())


if __name__ == '__main__':
    unittest.main()
