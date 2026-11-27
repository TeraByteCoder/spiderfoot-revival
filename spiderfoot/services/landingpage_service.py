# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         landingpage_service
# Purpose:      Service for managing, capturing, grouping, and
#               rendering landing page snapshots for SpiderFoot scans.
# -----------------------------------------------------------------

import hashlib
import json
import logging
import os
import re
import urllib.parse
from html import unescape
from typing import Any, Dict, List, Optional, Tuple

from spiderfoot.helpers import SpiderFootHelpers

log = logging.getLogger(f"spiderfoot.{__name__}")

_SKIP_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
    '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot',
    '.pdf', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.webmanifest', '.vcf', '.xml', '.json', '.txt', '.rss',
)


def _get_snapshots_dir(scan_id: str) -> str:
    data_dir = os.environ.get('SPIDERFOOT_DATA', '/var/lib/spiderfoot')
    return os.path.join(data_dir, 'snapshots', str(scan_id))


def _extract_apex_domain(hostname: str) -> str:
    if not hostname:
        return "other"
    host = hostname.strip().lower().split(':')[0]
    parts = host.split('.')
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def _extract_title(html_str: str) -> str:
    if not html_str:
        return ""
    m = re.search(r'<title[^>]*>(.*?)</title>', html_str, re.IGNORECASE | re.DOTALL)
    if m:
        clean = re.sub(r'\s+', ' ', m.group(1)).strip()
        return unescape(clean)[:150]
    return ""


def _score_page(p: Dict[str, Any], seed_domain: str = "") -> int:
    score = 0
    code = int(p.get('status_code') or 0)
    title = (p.get('title') or '').strip().lower()
    url = (p.get('real_url') or p.get('url') or '').lower()
    host = (p.get('host') or '').lower()
    dom = (p.get('domain') or '').lower()

    # Status code priority
    if code == 200:
        score += 60
    elif 200 <= code < 400:
        score += 30
    else:
        score -= 60

    # Seed domain bonus
    if seed_domain and (seed_domain in dom or seed_domain in host):
        score += 50

    # Meaningful title
    if title:
        if "default page" in title or "plesk obsidian" in title or "test page" in title or "apache2" in title:
            score -= 50
        elif title == host:
            score -= 10
        else:
            score += 35

    # Penalize non-HTML or JSON / manifest / api
    if url.endswith('.webmanifest') or url.endswith('.vcf') or '/wp-json/' in url or url.endswith('.xml') or url.endswith('.json'):
        score -= 120

    # Penalize staging/autodiscover subdomains vs www / root
    if 'staging.' in host or 'autodiscover.' in host:
        score -= 20

    # Home/root landing page bonus
    try:
        path = urllib.parse.urlparse(url).path
        if path in ('', '/', '/index.html', '/index.php'):
            score += 25
    except Exception:
        pass

    return score


def get_scan_landing_pages(dbh: Any, scan_id: str) -> Dict[str, Any]:
    """Retrieve and group all captured landing pages for a scan."""
    # Determine seed target domain for prioritizing findings
    seed_domain = ""
    try:
        scan_info = dbh.scanInstanceGet(scan_id)
        if scan_info and len(scan_info) > 1 and scan_info[1]:
            seed_target = str(scan_info[1])
            seed_host = urllib.parse.urlparse(seed_target).netloc or seed_target
            seed_domain = _extract_apex_domain(seed_host)
    except Exception:
        seed_domain = ""

    try:
        rows = dbh.scanResultEvent(scan_id, 'WEB_LANDING_PAGE') or []
    except Exception as e:
        log.warning(f"Error fetching WEB_LANDING_PAGE for {scan_id}: {e}")
        rows = []

    pages = []
    seen_urls = set()

    for r in rows:
        # r[1] is data
        raw_data = r[1]
        if not raw_data:
            continue
        try:
            p = json.loads(raw_data)
        except Exception:
            continue

        url = p.get('real_url') or p.get('url') or ''
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Status formatting
        code = int(p.get('status_code') or 200)
        status_label = f"{code} OK" if code == 200 else str(code)
        if code in (301, 302, 303, 307, 308):
            status_label = f"{code} Redirect"
            status_badge = "bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300 border-sky-300"
        elif 200 <= code < 300:
            status_badge = "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300 border-emerald-300"
        elif 400 <= code < 500:
            status_label = f"{code} Client Error"
            status_badge = "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300 border-amber-300"
        else:
            status_label = f"{code} Server Error"
            status_badge = "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 border-red-300"

        size_bytes = int(p.get('size') or 0)
        size_str = f"{size_bytes / 1024:.1f} KB" if size_bytes > 1024 else f"{size_bytes} B"

        h = p.get('hash') or hashlib.sha256(url.encode()).hexdigest()[:16]

        domain = p.get('domain') or _extract_apex_domain(p.get('host') or urllib.parse.urlparse(url).netloc)

        pages.append({
            'hash': h,
            'url': p.get('url') or url,
            'real_url': url,
            'host': p.get('host') or urllib.parse.urlparse(url).netloc,
            'domain': domain,
            'status_code': code,
            'status_label': status_label,
            'status_badge': status_badge,
            'title': p.get('title') or p.get('host') or url,
            'server': p.get('server') or 'Unknown',
            'content_type': p.get('content_type') or 'text/html',
            'size': size_str,
            'view_url': f"/api/landingpage/view?id={scan_id}&hash={h}",
        })

    # Group by Oberdomain
    domain_groups = {}
    for p in pages:
        d = p['domain']
        if d not in domain_groups:
            domain_groups[d] = {
                'domain': d,
                'pages': [],
                'count': 0,
            }
        domain_groups[d]['pages'].append(p)
        domain_groups[d]['count'] += 1

    # Sort pages within each group by quality score (best landing page first)
    for g in domain_groups.values():
        g['pages'].sort(key=lambda x: -_score_page(x, seed_domain))

    # Sort domain groups:
    # 1. Groups matching seed_domain first
    # 2. Then by count and top page quality
    def _group_sort_key(g):
        is_seed = 1 if seed_domain and seed_domain in g['domain'] else 0
        top_score = _score_page(g['pages'][0], seed_domain) if g['pages'] else 0
        return (is_seed, top_score, g['count'])

    groups_list = sorted(domain_groups.values(), key=_group_sort_key, reverse=True)

    # Sort all_pages globally so top showcase shows richest content
    sorted_all_pages = sorted(pages, key=lambda x: -_score_page(x, seed_domain))

    success_count = sum(1 for p in pages if 200 <= p['status_code'] < 400)
    error_count = sum(1 for p in pages if p['status_code'] >= 400 or p['status_code'] == 0)

    return {
        'total_pages': len(pages),
        'domains_count': len(domain_groups),
        'success_count': success_count,
        'error_count': error_count,
        'groups': groups_list,
        'all_pages': sorted_all_pages,
    }


def get_snapshot_html(scan_id: str, url_hash: str) -> Optional[str]:
    """Retrieve raw HTML of saved snapshot file."""
    snapshots_dir = _get_snapshots_dir(scan_id)
    safe_hash = re.sub(r'[^a-zA-Z0-9_\-]', '', url_hash)
    file_path = os.path.join(snapshots_dir, f"{safe_hash}.html")

    if os.path.isfile(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            log.error(f"Error reading snapshot {file_path}: {e}")
    return None


def capture_scan_landing_pages(dbh: Any, scan_id: str, max_urls: int = 150, timeout: int = 5) -> Dict[str, Any]:
    """Inspect discovered targets in a scan and capture landing pages concurrently."""
    import concurrent.futures
    import ssl
    import threading
    import urllib.request

    scan_info = dbh.scanInstanceGet(scan_id)
    if not scan_info:
        return {'status': 'error', 'message': f'Scan {scan_id} not found'}

    # Collect already captured URLs to prevent duplicate scraping and DB records
    already_seen_urls = set()
    already_seen_hashes = set()
    try:
        cur_events = dbh.scanResultEvent(scan_id, 'WEB_LANDING_PAGE') or []
        for ce in cur_events:
            try:
                pj = json.loads(ce[1])
                for k in ('real_url', 'url'):
                    u = pj.get(k)
                    if u:
                        already_seen_urls.add(u.rstrip('/'))
                if pj.get('hash'):
                    already_seen_hashes.add(pj['hash'])
            except Exception:
                pass
    except Exception:
        pass

    # Collect candidate targets from scan results
    candidate_types = [
        'LINKED_URL_INTERNAL',
        'LINKED_URL_EXTERNAL',
        'INTERNET_NAME',
        'AFFILIATE_INTERNET_NAME',
        'CO_HOSTED_SITE',
        'DOMAIN_NAME'
    ]

    found_targets = set()
    for ctype in candidate_types:
        try:
            events = dbh.scanResultEvent(scan_id, ctype) or []
            for e in events:
                data = str(e[1] or '').strip()
                if data:
                    found_targets.add(data)
        except Exception:
            continue

    # Filter, clean, and normalize candidate URLs
    urls_to_test = []
    seen_normalized = set()
    host_page_counts = {}

    for raw_item in found_targets:
        clean_item = raw_item.strip().strip('\"\'').replace('\\/', '/').replace('\\"', '')
        if not clean_item:
            continue

        if clean_item.startswith(('http://', 'https://')):
            # Filter out non-pages, feeds, tel links, APIs, and static files
            if ('/tel:' in clean_item or '/mailto:' in clean_item or clean_item.endswith('/feed/')
                    or '/comments/feed' in clean_item or '/wp-json/' in clean_item or '/xmlrpc.php' in clean_item):
                continue
            try:
                parsed = urllib.parse.urlparse(clean_item)
            except Exception:
                continue

            p_lower = parsed.path.lower()
            if any(p_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
                continue

            host = parsed.netloc.split(':')[0].lower()
            if not host:
                continue

            # Limit pages per host to avoid single host saturation (e.g. max 20)
            host_count = host_page_counts.get(host, 0)
            if host_count >= 25:
                continue

            norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
            if parsed.query:
                norm_url += f"?{parsed.query}"

            if norm_url not in seen_normalized and norm_url not in already_seen_urls:
                seen_normalized.add(norm_url)
                host_page_counts[host] = host_count + 1
                urls_to_test.append(clean_item)
        else:
            host = clean_item.lower().split('/')[0].split(':')[0]
            if re.match(r'^[a-z0-9\.\-]+$', host):
                host_count = host_page_counts.get(host, 0)
                if host_count >= 25:
                    continue

                norm_https = f"https://{host}"
                if norm_https not in seen_normalized and norm_https not in already_seen_urls:
                    seen_normalized.add(norm_https)
                    host_page_counts[host] = host_count + 1
                    urls_to_test.append(norm_https)

    snapshots_dir = _get_snapshots_dir(scan_id)
    os.makedirs(snapshots_dir, exist_ok=True)

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    urls_to_test = urls_to_test[:max_urls]

    def _process_target(target_url: str):
        try:
            parsed = urllib.parse.urlparse(target_url)
            host = parsed.netloc.split(':')[0]
            apex_domain = _extract_apex_domain(host)

            if target_url.startswith(('http://', 'https://')):
                attempts = [target_url]
                if target_url.startswith('https://'):
                    attempts.append(target_url.replace('https://', 'http://', 1))
            else:
                attempts = [f"https://{host}", f"http://{host}"]

            for u in attempts:
                req = urllib.request.Request(
                    u,
                    headers={
                        'User-Agent': user_agent,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                )

                try:
                    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:
                        status_code = response.getcode() or 200
                        headers = dict(response.info())
                        final_url = response.geturl() or u
                        url_hash = hashlib.sha256(final_url.encode()).hexdigest()[:16]

                        content_bytes = response.read(600 * 1024)
                        try:
                            content_str = content_bytes.decode('utf-8', errors='ignore')
                        except Exception:
                            content_str = ""

                        is_html = (
                            '<html' in content_str.lower() or
                            '<body' in content_str.lower() or
                            '<title' in content_str.lower() or
                            '<!doctype' in content_str.lower() or
                            'text/html' in headers.get('content-type', '').lower()
                        )

                        if not is_html and status_code not in (200, 301, 302, 303, 307, 308):
                            continue

                        title = _extract_title(content_str) or host
                        server = headers.get('server', '')
                        content_type = headers.get('content-type', 'text/html')

                        # Save snapshot HTML file
                        snapshot_path = os.path.join(snapshots_dir, f"{url_hash}.html")
                        with open(snapshot_path, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(content_str)

                        page_payload = {
                            'url': u,
                            'real_url': final_url,
                            'hash': url_hash,
                            'host': host,
                            'domain': apex_domain,
                            'status_code': status_code,
                            'title': title,
                            'server': server,
                            'content_type': content_type,
                            'size': len(content_bytes),
                            'snapshot_file': f"snapshots/{scan_id}/{url_hash}.html",
                        }

                        evt_hash = hashlib.sha256(f"{scan_id}:WEB_LANDING_PAGE:{final_url}".encode()).hexdigest()
                        return (final_url, evt_hash, page_payload)

                except Exception:
                    continue

        except Exception as e:
            log.debug(f"Error handling target {target_url}: {e}")

        return None

    captured_count = 0

    # Concurrently scrape targets in thread pool, then save to DB in main thread
    if urls_to_test:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(_process_target, urls_to_test))

        for res in results:
            if not res:
                continue
            final_url, evt_hash, page_payload = res
            try:
                with dbh.dbhLock:
                    dbh.dbh.execute(
                        "INSERT INTO tbl_scan_results (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash) "
                        "VALUES (?, ?, 'WEB_LANDING_PAGE', strftime('%s','now'), 100, 100, 0, 'sfp_landingpage', ?, 0, 'ROOT')",
                        (scan_id, evt_hash, json.dumps(page_payload))
                    )
                captured_count += 1
                log.info(f"Saved landing page: {final_url}")
            except Exception as ex:
                log.debug(f"DB insert failed for {final_url}: {ex}")

        try:
            with dbh.dbhLock:
                dbh.conn.commit()
        except Exception:
            pass

    return {
        'status': 'success',
        'captured_count': captured_count,
        'tested_count': len(urls_to_test),
    }
