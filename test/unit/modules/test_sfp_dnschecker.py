# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from modules.sfp_dnschecker import sfp_dnschecker
from spiderfoot import SpiderFootEvent
from spiderfoot.services.email_security_audit import (
    DMARCResult,
    DomainAuditResult,
    MXResult,
    RISK_CRITICAL,
    SPFResult,
)


class TestModuleDnschecker(unittest.TestCase):
    def test_opts_and_events(self):
        module = sfp_dnschecker()
        self.assertEqual(len(module.opts), len(module.optdescs))
        self.assertIn('DOMAIN_NAME', module.watchedEvents())
        self.assertIn('INTERNET_NAME', module.watchedEvents())
        self.assertIn('VULNERABILITY_GENERAL', module.producedEvents())
        self.assertIn('DNS_SPF', module.producedEvents())

    @patch('modules.sfp_dnschecker.audit_single_domain')
    def test_handle_event_emits_events_and_persists(self, mock_audit):
        mock_audit.return_value = DomainAuditResult(
            domain='example.com',
            root_domain='example.com',
            is_root=True,
            checked_at='2026-11-27T00:00:00+00:00',
            dns_exists=True,
            mx=MXResult(status='ok', has_mx=True),
            spf=SPFResult(status='ok', present=True, primary_record='v=spf1 ~all', qualifier='~all'),
            dmarc=DMARCResult(status='no_answer', present=False),
            dkim_selectors=[],
            dkim_found_count=0,
            risk_level=RISK_CRITICAL,
            risk_score=95,
            risk_reasons=['Kein DMARC-Record'],
            recommendations=['DMARC setzen'],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            sf = MagicMock()
            sf.opts = {'_datadir': tmpdir}
            module = sfp_dnschecker()
            module.setup(sf, {'skip_dkim': True})
            module.__name__ = 'sfp_dnschecker'
            module.getScanId = MagicMock(return_value='scan_mod_1')
            module.checkForStop = MagicMock(return_value=False)

            emitted = []
            module.notifyListeners = lambda evt: emitted.append(evt)

            root_evt = SpiderFootEvent('ROOT', 'example.com', '', '')
            evt = SpiderFootEvent('DOMAIN_NAME', 'example.com', 'sfp_dns', root_evt)
            module.handleEvent(evt)

            types = [e.eventType for e in emitted]
            self.assertIn('DNS_SPF', types)
            self.assertIn('RAW_DNS_RECORDS', types)
            self.assertIn('VULNERABILITY_GENERAL', types)
            self.assertTrue((Path(tmpdir) / 'dnschecker' / 'scan_mod_1.json').exists())
            self.assertTrue((Path(tmpdir) / 'dnschecker' / 'scan_mod_1.html').exists())


if __name__ == '__main__':
    unittest.main()
