# -*- coding: utf-8 -*-
"""Service for exporting discovered domains and subdomains as an alphabetical tree."""

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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


def _find_parent_domain(domain: str, domain_set: Set[str]) -> Optional[str]:
    """Find the longest existing ancestor domain in domain_set, or None if root."""
    parts = domain.split('.')
    for i in range(1, len(parts) - 1):
        candidate = '.'.join(parts[i:])
        if candidate in domain_set:
            return candidate
    return None


def build_domain_tree(domains: Iterable[str]) -> Tuple[List[str], Dict[str, List[str]]]:
    """Build an alphabetically sorted adjacency list (roots, children_map) for domains."""
    domain_set = {d for d in (_clean_domain(x) for x in domains) if d}
    children_map: Dict[str, List[str]] = {d: [] for d in domain_set}
    roots: List[str] = []

    for domain in sorted(domain_set):
        parent = _find_parent_domain(domain, domain_set)
        if parent is not None:
            children_map[parent].append(domain)
        else:
            roots.append(domain)

    roots.sort()
    for parent in children_map:
        children_map[parent].sort()

    return roots, children_map


def format_domain_tree(domains: Iterable[str]) -> str:
    """Format domains and subdomains as an alphabetically sorted, newline-separated tree."""
    roots, children_map = build_domain_tree(domains)
    if not roots:
        return ''

    lines: List[str] = []

    def _walk(node: str, prefix: str) -> None:
        children = children_map.get(node, [])
        for idx, child in enumerate(children):
            is_last = idx == len(children) - 1
            connector = '└── ' if is_last else '├── '
            lines.append(f'{prefix}{connector}{child}')
            next_prefix = f'{prefix}{"    " if is_last else "│   "}'
            _walk(child, next_prefix)

    for root in roots:
        lines.append(root)
        _walk(root, '')

    return '\n'.join(lines) + '\n'


def generate_domain_tree_export(dbh: Any, scan_id: str) -> Tuple[str, str]:
    """Generate the domain tree text export and filename for a scan."""
    scan = dbh.scanInstanceGet(scan_id)
    scan_name = scan[0] if scan else 'SpiderFoot'
    rows = dbh.scanResultEvent(scan_id) or []
    domains = extract_domains_from_events(rows)
    tree_text = format_domain_tree(domains)
    fname = f'{_safe_filename(scan_name)}-domains-tree.txt'
    return tree_text, fname
