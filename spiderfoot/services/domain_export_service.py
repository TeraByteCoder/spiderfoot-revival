# -*- coding: utf-8 -*-
"""Service for exporting discovered domains and subdomains as an alphabetical list."""

import re
from typing import Any, Iterable, Optional, Set, Tuple

DOMAIN_EVENT_TYPES = frozenset({
    'DOMAIN_NAME',
    'DOMAIN_NAME_PARENT',
    'INTERNET_NAME',
    'INTERNET_NAME_UNRESOLVED',
})


def _safe_filename(name: str) -> str:
    """Sanitize a scan name for use in a Content-Disposition filename."""
    cleaned = re.sub(r'[^a-zA-Z0-9._-]+', '_', (name or '').strip())
    return cleaned.strip('_') or 'SpiderFoot'


def _clean_domain(raw: Any) -> Optional[str]:
    """Normalize a raw event value to a lowercase domain/hostname, or None if invalid."""
    if raw is None:
        return None
    val = str(raw).replace('<SFURL>', '').replace('</SFURL>', '').strip().lower().rstrip('.')
    if not val or '.' not in val or any(c.isspace() for c in val):
        return None
    return val


def extract_domains_from_events(rows: Iterable[Any]) -> Set[str]:
    """Extract unique, non-false-positive domain and subdomain names from scan event rows."""
    domains: Set[str] = set()
    for row in rows:
        if len(row) < 5:
            continue
        event_type = row[4]
        if event_type not in DOMAIN_EVENT_TYPES:
            continue
        false_positive = row[13] if len(row) > 13 else 0
        if false_positive == 1:
            continue
        cleaned = _clean_domain(row[1])
        if cleaned:
            domains.add(cleaned)
    return domains


def format_domain_list(domains: Iterable[str]) -> str:
    """Format unique domains and subdomains as an alphabetically sorted, newline-separated list."""
    cleaned = sorted({d for d in (_clean_domain(x) for x in domains) if d})
    if not cleaned:
        return ''
    return '\n'.join(cleaned) + '\n'


def generate_domain_list_export(dbh: Any, scan_id: str) -> Tuple[str, str]:
    """Generate the domain list text export and filename for a scan."""
    scan = dbh.scanInstanceGet(scan_id)
    scan_name = scan[0] if scan else 'SpiderFoot'
    rows = dbh.scanResultEvent(scan_id) or []
    domains = extract_domains_from_events(rows)
    list_text = format_domain_list(domains)
    fname = f'{_safe_filename(scan_name)}-domains.txt'
    return list_text, fname
