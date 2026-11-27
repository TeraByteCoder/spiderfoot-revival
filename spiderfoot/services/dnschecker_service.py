# -*- coding: utf-8 -*-
"""Service integrating email_security_audit (dnschecker) with SpiderFoot scans."""

import concurrent.futures
import json
import os
import re
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver

from spiderfoot.services.domain_export_service import (
    _clean_domain,
    extract_domains_from_events,
)
from spiderfoot.services.email_security_audit import (
    DEFAULT_DKIM_SELECTORS,
    DMARCResult,
    DomainAuditResult,
    RateLimiter,
    TOOL_VERSION,
    _build_resolver,
    audit_single_domain,
    build_summary,
    generate_html_report,
)


def _safe_scan_id(scan_id: str) -> str:
    """Sanitize scan_id for filesystem storage."""
    return re.sub(r'[^a-zA-Z0-9_-]', '', scan_id or '')


def get_dnschecker_dir(data_dir: Optional[str] = None) -> Path:
    """Return the directory where dnschecker JSON/HTML reports are persisted."""
    base = data_dir or os.environ.get('SPIDERFOOT_DATA', '/var/lib/spiderfoot')
    out_dir = Path(base) / 'dnschecker'
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def get_dnschecker_paths(scan_id: str, data_dir: Optional[str] = None) -> Tuple[Path, Path]:
    """Return (json_path, html_path) for a scan's dnschecker report."""
    safe_id = _safe_scan_id(scan_id)
    base_dir = get_dnschecker_dir(data_dir)
    return base_dir / f'{safe_id}.json', base_dir / f'{safe_id}.html'


def _resolve_root_domain(domain: str, domain_set: set[str], scan_target: Optional[str] = None) -> str:
    """Find the shortest existing ancestor in domain_set, or fall back to domain itself."""
    parts = domain.split('.')
    # Walk from shortest plausible domain (2 labels) up to full domain
    for i in range(len(parts) - 2, -1, -1):
        candidate = '.'.join(parts[i:])
        if candidate in domain_set:
            return candidate
    if scan_target and (domain == scan_target or domain.endswith('.' + scan_target)):
        return scan_target
    return domain


def collect_scan_domains(dbh: Any, scan_id: str) -> Tuple[List[str], Dict[str, str]]:
    """Collect unique domains/subdomains from a scan and map each to its root domain.

    Returns (sorted_root_domains, {domain: root_domain}).
    """
    scan = dbh.scanInstanceGet(scan_id)
    scan_target = _clean_domain(scan[1]) if scan and len(scan) > 1 else None
    rows = dbh.scanResultEvent(scan_id) or []
    domain_set = extract_domains_from_events(rows)
    if scan_target and not scan_target.replace('.', '').isdigit():
        domain_set.add(scan_target)

    domain_to_root: Dict[str, str] = {}
    roots: set[str] = set()
    for dom in sorted(domain_set):
        root = _resolve_root_domain(dom, domain_set, scan_target=scan_target)
        domain_to_root[dom] = root
        roots.add(root)

    return sorted(roots), domain_to_root


def run_scan_dnschecker(
    dbh: Any,
    scan_id: str,
    data_dir: Optional[str] = None,
    workers: int = 10,
    dns_timeout: float = 4.0,
    dns_lifetime: float = 8.0,
    rate_limit: float = 0.02,
    skip_dkim: bool = False,
) -> Dict[str, Any]:
    """Run MX/SPF/DMARC/DKIM audit on all domains discovered in a scan and persist results."""
    start_ts = time.monotonic()
    root_domains, domain_to_root = collect_scan_domains(dbh, scan_id)
    if not domain_to_root:
        raise ValueError('Keine Domains oder Subdomains in diesem Scan gefunden.')

    thread_local = threading.local()

    def _get_resolver() -> dns.resolver.Resolver:
        res = getattr(thread_local, 'resolver', None)
        if res is None:
            res = _build_resolver(dns_timeout, dns_lifetime, None)
            thread_local.resolver = res
        return res

    limiter = RateLimiter(rate_limit)
    selectors = DEFAULT_DKIM_SELECTORS

    def _audit(dom: str, root: str, is_root: bool, root_dmarc: Optional[DMARCResult]) -> DomainAuditResult:
        return audit_single_domain(
            domain=dom,
            root_domain=root,
            is_root=is_root,
            resolver=_get_resolver(),
            rate_limiter=limiter,
            dkim_selectors=selectors,
            root_dmarc=root_dmarc,
            skip_dkim=skip_dkim,
        )

    # 1. Audit root domains first so subdomains can inherit DMARC policies
    root_results: Dict[str, DomainAuditResult] = {}
    root_workers = max(1, min(workers, len(root_domains)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=root_workers) as executor:
        futures = {
            executor.submit(_audit, root, root, True, None): root
            for root in root_domains
        }
        for future in concurrent.futures.as_completed(futures):
            root = futures[future]
            root_results[root] = future.result()

    # 2. Audit subdomains in parallel
    subdomains = [(dom, root) for dom, root in domain_to_root.items() if dom != root]
    all_results: List[DomainAuditResult] = list(root_results.values())
    if subdomains:
        sub_workers = max(1, min(workers, len(subdomains)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=sub_workers) as executor:
            futures = {
                executor.submit(_audit, sub, root, False, root_results[root].dmarc): sub
                for sub, root in subdomains
            }
            for future in concurrent.futures.as_completed(futures):
                all_results.append(future.result())

    all_results.sort(key=lambda r: (r.root_domain, not r.is_root, -r.risk_score, r.domain))
    duration = time.monotonic() - start_ts
    summary = build_summary(all_results, root_domains)

    json_path, html_path = get_dnschecker_paths(scan_id, data_dir=data_dir)
    payload: Dict[str, Any] = {
        'metadata': {
            'tool': 'email_security_audit',
            'version': TOOL_VERSION,
            'scan_id': scan_id,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'duration_seconds': round(duration, 2),
        },
        'summary': summary,
        'results': [asdict(item) for item in all_results],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    generate_html_report(html_path, all_results, summary, duration)
    return payload


def load_dnschecker_results(scan_id: str, data_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load persisted dnschecker JSON results for a scan, or None if not yet run."""
    json_path, _ = get_dnschecker_paths(scan_id, data_dir=data_dir)
    if not json_path.exists():
        return None
    try:
        return json.loads(json_path.read_text(encoding='utf-8'))
    except Exception:
        return None
