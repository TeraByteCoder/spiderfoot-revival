# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnschecker
# Purpose:      Passive Email Security & Spoofing Risk Auditor (MX, SPF, DMARC,
#               DKIM) for discovered domains and subdomains.
#
# Author:       SpiderFoot Revival
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from spiderfoot.services.dnschecker_service import (
    _resolve_root_domain,
    get_dnschecker_paths,
)
from spiderfoot.services.domain_export_service import _clean_domain
from spiderfoot.services.email_security_audit import (
    DEFAULT_DKIM_SELECTORS,
    RISK_HIGH,
    RISK_CRITICAL,
    RateLimiter,
    TOOL_VERSION,
    _build_resolver,
    audit_single_domain,
    build_summary,
    generate_html_report,
)


class sfp_dnschecker(SpiderFootPlugin):

    meta = {
        'name': "DNS & Email Security Auditor (dnschecker)",
        'summary': "Audits MX, SPF, DMARC, and DKIM records for discovered domains and subdomains to assess email spoofing risk.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["DNS"],
        'dataSource': {
            'website': "https://tools.ietf.org/html/rfc7489",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Passive DNS queries for MX, SPF, DMARC, and DKIM records.",
        }
    }

    opts = {
        'dns_timeout': 4.0,
        'dns_lifetime': 8.0,
        'rate_limit': 0.02,
        'skip_dkim': False,
    }

    optdescs = {
        'dns_timeout': "Per-query DNS timeout in seconds.",
        'dns_lifetime': "Total DNS resolution lifetime in seconds.",
        'rate_limit': "Minimum interval in seconds between DNS queries.",
        'skip_dkim': "Skip DKIM selector probing for faster scans.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "DNS"
        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self._rate_limiter = RateLimiter(float(self.opts.get('rate_limit', 0.02)))
        self._audit_map = {}
        self._start_ts = time.monotonic()

        self._mergeOpts(userOpts)
        self._rate_limiter = RateLimiter(float(self.opts.get('rate_limit', 0.02)))

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "DOMAIN_NAME_PARENT",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
        ]

    def producedEvents(self):
        return [
            "DNS_SPF",
            "DNS_TEXT",
            "RAW_DNS_RECORDS",
            "VULNERABILITY_GENERAL",
        ]

    def _get_resolver(self):
        res = getattr(self._thread_local, 'resolver', None)
        if res is None:
            res = _build_resolver(
                float(self.opts.get('dns_timeout', 4.0)),
                float(self.opts.get('dns_lifetime', 8.0)),
                None,
            )
            self._thread_local.resolver = res
        return res

    def _persist_report(self):
        scan_id = self.getScanId()
        if not scan_id:
            return
        data_dir = self.sf.opts.get('_datadir') or os.environ.get('SPIDERFOOT_DATA', '/var/lib/spiderfoot')
        with self._lock:
            results_list = list(self._audit_map.values())
        if not results_list:
            return

        domain_set = {r.domain for r in results_list}
        roots = sorted({_resolve_root_domain(r.domain, domain_set) for r in results_list})
        for r in results_list:
            root = _resolve_root_domain(r.domain, domain_set)
            r.root_domain = root
            r.is_root = (r.domain == root)

        results_list.sort(key=lambda r: (r.root_domain, not r.is_root, -r.risk_score, r.domain))
        duration = time.monotonic() - self._start_ts
        summary = build_summary(results_list, roots)

        json_path, html_path = get_dnschecker_paths(str(scan_id), data_dir=data_dir)
        payload = {
            'metadata': {
                'tool': 'email_security_audit',
                'version': TOOL_VERSION,
                'scan_id': str(scan_id),
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': round(duration, 2),
            },
            'summary': summary,
            'results': [asdict(item) for item in results_list],
        }
        try:
            json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
            generate_html_report(html_path, results_list, summary, duration)
        except Exception as exc:
            self.debug(f"Could not persist dnschecker report for {scan_id}: {exc}")

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState or self.checkForStop():
            return

        host = _clean_domain(eventData)
        if not host:
            return

        with self._lock:
            if host in self.results:
                return
            self.results[host] = True

        self.debug(f"Auditing DNS/Email security for {host} (from {srcModuleName}: {eventName})")

        root_guess = host
        is_root = (eventName in ("DOMAIN_NAME", "DOMAIN_NAME_PARENT"))
        if not is_root and '.' in host:
            parts = host.split('.')
            if len(parts) >= 2:
                root_guess = '.'.join(parts[-2:])

        root_dmarc = None
        with self._lock:
            if root_guess in self._audit_map:
                root_dmarc = self._audit_map[root_guess].dmarc

        res = audit_single_domain(
            domain=host,
            root_domain=root_guess,
            is_root=is_root,
            resolver=self._get_resolver(),
            rate_limiter=self._rate_limiter,
            dkim_selectors=DEFAULT_DKIM_SELECTORS,
            root_dmarc=root_dmarc,
            skip_dkim=bool(self.opts.get('skip_dkim', False)),
        )

        with self._lock:
            self._audit_map[host] = res

        if res.spf.primary_record:
            self.notifyListeners(SpiderFootEvent("DNS_SPF", res.spf.primary_record, self.__name__, event))

        if res.dmarc.primary_record:
            self.notifyListeners(SpiderFootEvent("DNS_TEXT", f"_dmarc.{host}: {res.dmarc.primary_record}", self.__name__, event))

        summary_line = (
            f"dnschecker [{host}] Risk={res.risk_level} ({res.risk_score}/100) | "
            f"MX={'Null-MX' if res.mx.is_null_mx else ('Yes' if res.mx.has_mx else 'No')} | "
            f"SPF={res.spf.qualifier or 'missing'} | "
            f"DMARC={res.dmarc.effective_policy or 'missing'} | "
            f"DKIM={res.dkim_found_count}"
        )
        self.notifyListeners(SpiderFootEvent("RAW_DNS_RECORDS", summary_line, self.__name__, event))

        if res.risk_level in (RISK_CRITICAL, RISK_HIGH):
            reasons_str = "; ".join(res.risk_reasons[:3])
            vuln_msg = f"Email Spoofing Risk [{res.risk_level}] on {host}: {reasons_str}"
            self.notifyListeners(SpiderFootEvent("VULNERABILITY_GENERAL", vuln_msg, self.__name__, event))

        self._persist_report()

# End of sfp_dnschecker class
