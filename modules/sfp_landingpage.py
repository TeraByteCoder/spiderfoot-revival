# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_landingpage
# Purpose:      SpiderFoot plug-in to fetch and render landing pages for all
#               discovered URLs, hostnames, and domains, saving full HTML
#               snapshots grouped by apex domain.
#
# Author:       Steve Micallef / SpiderFoot Revival
# Licence:      MIT
# -------------------------------------------------------------------------------

import hashlib
import json
import os
import re
import urllib.parse
from html import unescape

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_landingpage(SpiderFootPlugin):

    meta = {
        'name': "Landing Page Renderer",
        'summary': "Fetches and stores rendered HTML landing pages for discovered web targets, hostnames, and links.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Crawling and Scanning"]
    }

    opts = {
        'timeout': 6,
        'max_pages': 150,
        'useragent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        'fetch_ssl': True,
        'fetch_plain': True,
        'max_content_kb': 500,
    }

    optdescs = {
        'timeout': "HTTP request timeout in seconds.",
        'max_pages': "Maximum number of landing pages to capture and render per scan.",
        'useragent': "User-Agent string to send with HTTP requests.",
        'fetch_ssl': "Attempt HTTPS connections for discovered hostnames/domains?",
        'fetch_plain': "Attempt HTTP fallback if HTTPS fails or is unavailable?",
        'max_content_kb': "Maximum HTML size in KB to capture per page.",
    }

    results = None
    pageCount = 0
    errorState = False

    # Static file extensions to skip
    _SKIP_EXTENSIONS = (
        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
        '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot',
        '.pdf', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    )

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.pageCount = 0
        self.errorState = False
        self.__dataSource__ = "Target Website"

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return [
            "LINKED_URL_INTERNAL",
            "LINKED_URL_EXTERNAL",
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE",
            "DOMAIN_NAME",
        ]

    def producedEvents(self):
        return [
            "WEB_LANDING_PAGE",
            "TARGET_WEB_CONTENT",
        ]

    def _get_apex_domain(self, hostname: str) -> str:
        """Derive apex domain from hostname."""
        if not hostname:
            return ""
        host = hostname.strip().lower().split(':')[0]
        tld_list = self.sf.opts.get('_tldcache', [])
        if tld_list:
            try:
                dom = self.sf.hostDomain(host, tld_list)
                if dom:
                    return dom
            except Exception:
                pass
        # Fallback heuristic: take last 2 parts unless ccTLD style (e.g. co.uk, or.at)
        parts = host.split('.')
        if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
            return '.'.join(parts[-3:])
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host

    def _extract_title(self, html_str: str) -> str:
        """Extract clean page title from HTML."""
        if not html_str:
            return ""
        m = re.search(r'<title[^>]*>(.*?)</title>', html_str, re.IGNORECASE | re.DOTALL)
        if m:
            clean = re.sub(r'\s+', ' ', m.group(1)).strip()
            return unescape(clean)[:150]
        return ""

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = str(event.data or '').strip()

        if self.checkForStop():
            return

        if self.errorState:
            return

        if self.pageCount >= self.opts['max_pages']:
            return

        if not eventData:
            return

        urls_to_try = []

        if eventData.startswith(('http://', 'https://')):
            # Direct URL
            parsed = urllib.parse.urlparse(eventData)
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in self._SKIP_EXTENSIONS):
                return
            urls_to_try.append(eventData)
            host = parsed.netloc.split(':')[0]
        else:
            host = eventData.lower().split('/')[0].split(':')[0]
            # Validate host
            if not re.match(r'^[a-z0-9\.\-]+$', host):
                return

            if self.opts['fetch_ssl']:
                urls_to_try.append(f"https://{host}")
            if self.opts['fetch_plain']:
                urls_to_try.append(f"http://{host}")

        apex_domain = self._get_apex_domain(host)

        for target_url in urls_to_try:
            if target_url in self.results:
                continue

            self.results[target_url] = True

            self.debug(f"Attempting to fetch landing page for: {target_url}")

            try:
                res = self.sf.fetchUrl(
                    target_url,
                    timeout=self.opts['timeout'],
                    useragent=self.opts['useragent'],
                    verify=False,
                    sizeLimit=self.opts['max_content_kb'] * 1024
                )
            except Exception as e:
                self.debug(f"Exception fetching {target_url}: {e}")
                continue

            if not res or not res.get('code'):
                continue

            status_code = str(res.get('code', ''))
            content = res.get('content') or ''
            headers = res.get('headers') or {}
            real_url = res.get('realurl') or target_url

            # Verify it's a web response
            is_html = (
                isinstance(content, str) and (
                    '<html' in content.lower() or
                    '<body' in content.lower() or
                    '<title' in content.lower() or
                    '<!doctype' in content.lower() or
                    'text/html' in headers.get('content-type', '').lower()
                )
            )

            if not is_html and status_code not in ('200', '301', '302', '303', '307', '308'):
                continue

            title = self._extract_title(content) if isinstance(content, str) else ""
            server = headers.get('server', '')
            content_type = headers.get('content-type', '')
            content_size = len(content.encode('utf-8') if isinstance(content, str) else content)

            url_hash = hashlib.sha256(real_url.encode('utf-8')).hexdigest()[:16]

            # Save snapshot to disk if SPIDERFOOT_DATA is available
            data_dir = self.sf.opts.get('_datadir') or os.environ.get('SPIDERFOOT_DATA', '/var/lib/spiderfoot')
            snapshots_dir = os.path.join(data_dir, 'snapshots', str(self.getScanId()))
            snapshot_path = os.path.join(snapshots_dir, f"{url_hash}.html")

            try:
                os.makedirs(snapshots_dir, exist_ok=True)
                with open(snapshot_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(content if isinstance(content, str) else content.decode('utf-8', errors='ignore'))
            except Exception as e:
                self.debug(f"Could not save snapshot file {snapshot_path}: {e}")

            page_data = {
                'url': target_url,
                'real_url': real_url,
                'hash': url_hash,
                'host': host,
                'domain': apex_domain,
                'status_code': int(status_code) if status_code.isdigit() else 200,
                'title': title or host,
                'server': server,
                'content_type': content_type,
                'size': content_size,
                'snapshot_file': f"snapshots/{self.getScanId()}/{url_hash}.html",
                'html_preview': content[:2000] if isinstance(content, str) else ""
            }

            self.info(f"Captured landing page [{status_code}]: {real_url} ('{title}')")

            # Emit WEB_LANDING_PAGE event
            evt = SpiderFootEvent("WEB_LANDING_PAGE", json.dumps(page_data), self.__name__, event)
            self.notifyListeners(evt)

            self.pageCount += 1

            # If HTTPS succeeded with 200, don't bother trying plain HTTP for this host
            if target_url.startswith("https://") and status_code == '200':
                break

# End of sfp_landingpage class
