# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         html_export_service
# Purpose:      Generates complete, self-contained standalone HTML
#               reports for SpiderFoot scans in a modern White Mode design.
# -----------------------------------------------------------------

import html
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from spiderfoot.helpers import SpiderFootHelpers
from spiderfoot.services.event_service import (
    EVENT_CATEGORIES,
    categorize_event_summary,
)

log = logging.getLogger(f"spiderfoot.{__name__}")

# Category colors for light mode
CATEGORY_CONFIG = {
    'attack_surface': {
        'label': 'Attack Surface',
        'color': '#2563eb',  # blue-600
        'bg': '#eff6ff',     # blue-50
        'border': '#bfdbfe', # blue-200
        'text': '#1d4ed8',   # blue-700
        'types': ['INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED', 'IP_ADDRESS', 'TCP_PORT_OPEN',
                  'TCP_PORT_OPEN_BANNER', 'UDP_PORT_OPEN', 'DOMAIN_NAME'],
    },
    'identities': {
        'label': 'Identities & Exposure',
        'color': '#7c3aed',  # violet-600
        'bg': '#f5f3ff',     # violet-50
        'border': '#ddd6fe', # violet-200
        'text': '#6d28d9',   # violet-700
        'types': ['EMAILADDR', 'EMAILADDR_GENERIC', 'EMAILADDR_COMPROMISED', 'USERNAME',
                  'PHONE_NUMBER', 'HUMAN_NAME', 'ACCOUNT_EXTERNAL_OWNED', 'SOCIAL_MEDIA',
                  'LEAKSITE_CONTENT', 'LEAKSITE_URL', 'DARKNET_MENTION_CONTENT', 'PHONE_NUMBER_COMPROMISED'],
    },
    'infrastructure': {
        'label': 'Infrastructure',
        'color': '#0d9488',  # teal-600
        'bg': '#f0fdfa',     # teal-50
        'border': '#99f6e4', # teal-200
        'text': '#0f766e',   # teal-700
        'types': ['WEBSERVER_TECHNOLOGY', 'WEBSERVER_BANNER', 'WEBSERVER_HTTPHEADERS', 'OPERATING_SYSTEM',
                  'DEVICE_TYPE', 'SOFTWARE_USED', 'RAW_RIR_DATA', 'SSL_CERTIFICATE_ISSUED', 'SSL_CERTIFICATE_ISSUER',
                  'BGP_AS_MEMBER', 'COMPANY_NAME', 'PROVIDER_HOSTING', 'GEOINFO', 'DOMAIN_WHOIS', 'DOMAIN_REGISTRAR',
                  'CO_HOSTED_SITE', 'CO_HOSTED_SITE_DOMAIN', 'CO_HOSTED_SITE_DOMAIN_WHOIS', 'AFFILIATE_INTERNET_NAME',
                  'AFFILIATE_DOMAIN_NAME', 'NETBLOCK_OWNER', 'NETBLOCK_MEMBER', 'PROVIDER_DNS', 'PROVIDER_MAIL'],
    },
    'reputation': {
        'label': 'Reputation',
        'color': '#d97706',  # amber-600
        'bg': '#fffbeb',     # amber-50
        'border': '#fde68a', # amber-200
        'text': '#b45309',   # amber-700
        'types': ['MALICIOUS_IPADDR', 'MALICIOUS_INTERNET_NAME', 'MALICIOUS_AFFILIATE_IPADDR',
                  'MALICIOUS_NETBLOCK', 'MALICIOUS_SUBNET', 'BLACKLISTED_IPADDR', 'BLACKLISTED_INTERNET_NAME',
                  'BLACKLISTED_AFFILIATE_IPADDR', 'RANSOMWARE_VICTIM'],
    },
    'vulnerabilities': {
        'label': 'Vulnerabilities',
        'color': '#dc2626',  # red-600
        'bg': '#fef2f2',     # red-50
        'border': '#fecaca', # red-200
        'text': '#b91c1c',   # red-700
        'types': ['VULNERABILITY_CVE_CRITICAL', 'VULNERABILITY_CVE_HIGH', 'VULNERABILITY_CVE_MEDIUM',
                  'VULNERABILITY_CVE_LOW', 'VULNERABILITY_GENERAL'],
    },
    'other': {
        'label': 'Other',
        'color': '#64748b',  # slate-500
        'bg': '#f8fafc',     # slate-50
        'border': '#e2e8f0', # slate-200
        'text': '#475569',   # slate-600
        'types': [],
    },
    'root': {
        'label': 'Target Seed',
        'color': '#eab308',  # yellow-500
        'bg': '#fefce8',     # yellow-50
        'border': '#fef08a', # yellow-200
        'text': '#a16207',   # yellow-700
        'types': ['ROOT'],
    },
}


def _get_type_category(event_type: str) -> str:
    for cat_key, cat_val in CATEGORY_CONFIG.items():
        if event_type in cat_val['types']:
            return cat_key
    return 'other'


def _format_timestamp(ts: Optional[float]) -> str:
    if not ts:
        return '—'
    try:
        val = float(ts)
        if val > 1e11:
            val = val / 1000.0
        return datetime.fromtimestamp(val).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def _format_duration(started: Optional[float], ended: Optional[float]) -> str:
    if not started:
        return '—'
    try:
        s = float(started)
        if s > 1e11:
            s = s / 1000.0
        e = float(ended) if ended else time.time()
        if e > 1e11:
            e = e / 1000.0
        duration_secs = int(max(0, e - s))
        hours = duration_secs // 3600
        mins = (duration_secs % 3600) // 60
        secs = duration_secs % 60
        if hours > 0:
            return f"{hours}h {mins}m {secs}s"
        if mins > 0:
            return f"{mins}m {secs}s"
        return f"{secs}s"
    except Exception:
        return '—'


def _safe_filename(name: str) -> str:
    if not name:
        return "SpiderFoot"
    return re.sub(r'[^\w\-.]', '_', name)[:100]


def _read_vendor_file(filename: str) -> str:
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static', 'vendor', filename)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'spiderfoot', 'static', 'vendor', filename)),
        os.path.join('/home/spiderfoot/spiderfoot/static/vendor', filename),
        os.path.join('/home/spiderfoot/static/vendor', filename),
    ]
    for c in candidates:
        if os.path.isfile(c):
            try:
                with open(c, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                log.warning(f"Error reading {c}: {e}")
    return ""


def generate_scan_html_report(dbh: Any, scan_id: str, export_dir: Optional[str] = None) -> Tuple[str, str]:
    """Generate a self-contained, high quality White Mode HTML report for a scan.

    Returns:
        (html_content, filename)
    """
    row = dbh.scanInstanceGet(scan_id)
    if not row:
        raise ValueError(f"Scan {scan_id} not found in database.")

    # row: (name, seed_target, created, started, ended, status)
    scan_name = row[0]
    seed_target = row[1]
    created = row[2]
    started = row[3]
    ended = row[4]
    status = (row[5] or 'UNKNOWN').upper()

    started_str = _format_timestamp(started)
    ended_str = _format_timestamp(ended)
    duration_str = _format_duration(started, ended)

    # 1. Event summary
    try:
        event_summary = dbh.scanResultSummary(scan_id, 'type') or []
    except Exception:
        event_summary = []

    # 2. Module summary
    try:
        module_summary = dbh.scanResultSummary(scan_id, 'module') or []
    except Exception:
        module_summary = []

    # 3. Correlations
    try:
        correlations_raw = dbh.scanCorrelationList(scan_id) or []
    except Exception:
        correlations_raw = []

    findings = []
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    for c in correlations_raw:
        # (id, title, rule_id, rule_risk, rule_name, rule_descr, rule_logic, event_count)
        cid = c[0]
        title = c[1]
        rule_id = c[2]
        risk = (c[3] or 'INFO').upper()
        rule_name = c[4]
        rule_descr = c[5] or ''
        event_cnt = c[7] if len(c) > 7 else 0

        if risk == 'HIGH':
            high_count += 1
        elif risk == 'MEDIUM':
            medium_count += 1
        elif risk == 'LOW':
            low_count += 1
        else:
            info_count += 1

        findings.append({
            'id': cid,
            'title': title,
            'rule_id': rule_id,
            'risk': risk,
            'rule_name': rule_name,
            'description': rule_descr,
            'event_count': event_cnt,
        })

    # Sort findings by risk
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    findings.sort(key=lambda x: (risk_order.get(x['risk'], 99), -x['event_count']))

    # 4. Categories breakdown
    categories = categorize_event_summary(event_summary)

    # Total counts
    total_events = sum(int(r[3] or 0) for r in event_summary)
    unique_events = sum(int(r[4] or 0) for r in event_summary)
    module_count = len(module_summary)

    # 5. Raw events
    try:
        raw_events = dbh.scanResultEvent(scan_id) or []
    except Exception:
        raw_events = []

    # 6. Graph visualization data
    try:
        graph_json_str = SpiderFootHelpers.buildGraphJson([seed_target], raw_events)
    except Exception as e:
        log.warning(f"Failed to generate graph JSON for scan {scan_id}: {e}")
        graph_json_str = '{"nodes":[],"edges":[]}'

    # 7. Timeline data
    try:
        timeline_raw = dbh.scanResultHistory(scan_id) or []
    except Exception:
        timeline_raw = []

    timeline = []
    for t in timeline_raw:
        # (hourmin, type, count)
        timeline.append({
            'time': str(t[0]),
            'type': str(t[1]),
            'count': int(t[2] or 0),
        })

    # 8. Logs
    try:
        # Load up to 2000 non-debug or latest logs
        logs_raw = dbh.scanLogs(scan_id, limit=2000, reverse=True) or []
    except Exception:
        logs_raw = []

    logs = []
    for l in logs_raw:
        raw_ts = l[0] / 1000.0 if l and l[0] and l[0] > 1e11 else (l[0] if l and l[0] else 0)
        logs.append({
            'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(raw_ts)) if raw_ts else '',
            'component': l[1] if len(l) > 1 else '',
            'type': l[2] if len(l) > 2 else 'INFO',
            'message': l[3] if len(l) > 3 else '',
        })

    # Format events for client-side search/table
    events_list = []
    for idx, e in enumerate(raw_events):
        # e: (generated, data, source_data, module, type, confidence, visibility, risk, hash, source_event_hash, type_desc, data_type, scan_id, fp, dupe_count)
        raw_ts = e[0] / 1000.0 if e[0] and e[0] > 1e11 else (e[0] or 0)
        etype = e[4]
        cat = _get_type_category(etype)
        events_list.append({
            'id': idx + 1,
            'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(raw_ts)) if raw_ts else '',
            'data': str(e[1] or ''),
            'source': str(e[2] or ''),
            'module': str(e[3] or ''),
            'type_code': etype,
            'type': str(e[10] or etype),
            'category': cat,
            'confidence': int(e[5] or 100),
            'fp': bool(e[13]),
        })

    # Load Cytoscape libraries from disk
    cy_js = _read_vendor_file('cytoscape.umd.js')
    layout_base_js = _read_vendor_file('layout-base.js')
    cose_base_js = _read_vendor_file('cose-base.js')
    fcose_js = _read_vendor_file('cytoscape-fcose.js')

    # Filename
    safe_target = _safe_filename(seed_target or scan_name)
    fname = f"SpiderFoot_{safe_target}_{scan_id}_Report.html"

    # Landing pages data
    try:
        from spiderfoot.services.landingpage_service import get_scan_landing_pages, get_snapshot_html
        landing_pages_data = get_scan_landing_pages(dbh, scan_id)
        for p in landing_pages_data.get('all_pages', []):
            h_content = get_snapshot_html(scan_id, p['hash'])
            if h_content:
                base_u = p.get('real_url') or p.get('url') or ''
                inj = f'<base href="{html.escape(base_u, quote=True)}" target="_blank">\n<style>html, body {{ overflow: auto !important; }}</style>'
                if "<head>" in h_content:
                    h_content = h_content.replace("<head>", f"<head>\n{inj}", 1)
                elif "<HEAD>" in h_content:
                    h_content = h_content.replace("<HEAD>", f"<HEAD>\n{inj}", 1)
                else:
                    h_content = f"<head>{inj}</head>\n{h_content}"
            p['html_srcdoc'] = h_content or p.get('html_preview') or ''
    except Exception as e:
        log.warning(f"Could not load landing pages for export: {e}")
        landing_pages_data = {'total_pages': 0, 'domains_count': 0, 'success_count': 0, 'groups': [], 'all_pages': []}

    # Escape '<' and '>' in JSON to prevent closing </script> tags or HTML injection
    safe_events_json = json.dumps(events_list).replace('<', '\\u003c').replace('>', '\\u003e')
    safe_graph_json = graph_json_str.replace('<', '\\u003c').replace('>', '\\u003e')

    # Build the HTML document
    html_content = _render_white_mode_html(
        scan_id=scan_id,
        scan_name=scan_name,
        seed_target=seed_target,
        safe_target=safe_target,
        status=status,
        started_str=started_str,
        ended_str=ended_str,
        duration_str=duration_str,
        total_events=total_events,
        unique_events=unique_events,
        module_count=module_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        findings=findings,
        categories=categories,
        event_summary=event_summary,
        events_json=safe_events_json,
        graph_json=safe_graph_json,
        timeline=timeline,
        logs=logs,
        landing_pages_data=landing_pages_data,
        cy_js=cy_js,
        layout_base_js=layout_base_js,
        cose_base_js=cose_base_js,
        fcose_js=fcose_js,
    )

    if export_dir:
        try:
            os.makedirs(export_dir, exist_ok=True)
            out_path = os.path.join(export_dir, fname)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            log.info(f"Saved HTML export report to {out_path}")
        except Exception as e:
            log.error(f"Could not save report to {export_dir}: {e}")

    return html_content, fname


def _render_landing_pages_section(landing_pages_data: Dict[str, Any]) -> str:
    groups = landing_pages_data.get('groups', [])
    if not groups:
        return '<div class="p-8 text-center text-slate-400 bg-white rounded-xl border border-slate-200">No landing pages captured for this scan.</div>'

    html_out = []
    for g in groups:
        dom = html.escape(g['domain'])
        count = g['count']
        cards_html = []
        for p in g['pages']:
            u = html.escape(p['url'])
            real_u = html.escape(p['real_url'])
            title = html.escape(p['title'])
            server = html.escape(p.get('server') or 'Unknown')
            status_code = p['status_code']
            status_badge = p['status_badge']
            size = html.escape(p['size'])
            h = html.escape(p['hash'])
            srcdoc_content = html.escape(p.get('html_srcdoc') or '').replace('\n', ' ')
            search_str = html.escape(f"{p['title']} {real_u} {p['host']} {server}".lower())

            cards_html.append(f"""
            <div class="landing-page-card group relative bg-white border border-slate-200 rounded-xl shadow-2xs hover:shadow-md hover:border-cyan-500/50 transition-all cursor-pointer flex flex-col overflow-hidden"
                 data-search="{search_str}"
                 onclick="openPageModal('{h}')">
              
              <div class="flex items-center justify-between px-3 py-2 bg-slate-100 border-b border-slate-200 text-xs">
                <div class="flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full bg-red-400"></span>
                  <span class="w-2 h-2 rounded-full bg-amber-400"></span>
                  <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                </div>
                <span class="font-mono text-[10px] text-slate-500 truncate max-w-[140px]">{html.escape(p['host'])}</span>
                <span class="text-[10px] font-semibold px-1.5 py-0.2 rounded border {status_badge}">{status_code}</span>
              </div>

              <div class="relative w-full h-44 bg-slate-50 overflow-hidden border-b border-slate-100 flex items-center justify-center">
                <iframe srcdoc="{srcdoc_content}"
                        style="position: absolute; top: 0; left: 0; width: 400%; height: 400%; transform: scale(0.25); transform-origin: 0 0; -webkit-transform-origin: 0 0; border: 0; pointer-events: none; background: #ffffff;">
                </iframe>
                <div class="absolute inset-0 bg-cyan-900/10 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                  <span class="text-xs font-semibold px-3 py-1.5 rounded-lg bg-white/95 text-cyan-600 shadow-md">
                    Inspect Full Size
                  </span>
                </div>
              </div>

              <div class="p-3 flex-1 flex flex-col justify-between">
                <div>
                  <p class="text-xs font-bold text-slate-800 truncate mb-1" title="{title}">{title}</p>
                  <p class="text-[11px] font-mono text-slate-400 truncate mb-2" title="{real_u}">{real_u}</p>
                </div>
                <div class="flex items-center justify-between text-[10px] text-slate-500 pt-2 border-t border-slate-100">
                  <span class="truncate max-w-[120px]">{server}</span>
                  <span class="font-mono">{size}</span>
                </div>
              </div>
            </div>
            """)

        html_out.append(f"""
        <div class="landing-group-wrapper space-y-3" data-domain="{dom}">
          <div class="flex items-center gap-2 pb-2 border-b border-slate-200">
            <span class="w-6 h-6 rounded-md bg-cyan-100 text-cyan-600 flex items-center justify-center text-xs font-bold font-mono">🌐</span>
            <h3 class="text-base font-bold text-slate-800 font-mono tracking-tight">{dom}</h3>
            <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 font-mono">{count} {'page' if count == 1 else 'pages'}</span>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {''.join(cards_html)}
          </div>
        </div>
        """)

    return '\n'.join(html_out)


def _render_white_mode_html(
    scan_id: str,
    scan_name: str,
    seed_target: str,
    safe_target: str,
    status: str,
    started_str: str,
    ended_str: str,
    duration_str: str,
    total_events: int,
    unique_events: int,
    module_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    info_count: int,
    findings: List[Dict[str, Any]],
    categories: List[Dict[str, Any]],
    event_summary: List[Any],
    events_json: str,
    graph_json: str,
    timeline: List[Dict[str, Any]],
    logs: List[Dict[str, Any]],
    landing_pages_data: Dict[str, Any],
    cy_js: str,
    layout_base_js: str,
    cose_base_js: str,
    fcose_js: str,
) -> str:
    """Compose the complete standalone White Mode HTML document."""

    # Risk badge for status
    status_badge_classes = "bg-emerald-50 text-emerald-700 border-emerald-200"
    if status in ['RUNNING', 'STARTING']:
        status_badge_classes = "bg-sky-50 text-sky-700 border-sky-200"
    elif status in ['ERROR-FAILED', 'FAILED']:
        status_badge_classes = "bg-red-50 text-red-700 border-red-200"
    elif status in ['ABORTED', 'ABORT-REQUESTED']:
        status_badge_classes = "bg-amber-50 text-amber-700 border-amber-200"

    correlations_count = high_count + medium_count + low_count + info_count

    # Pre-render blocks for clean f-string interpolation
    if findings:
        findings_cards_html = "".join(_render_finding_card(f) for f in findings[:25])
        all_findings_html = "".join(_render_full_correlation_card(f) for f in findings)
    else:
        findings_cards_html = '<div class="p-8 text-center text-slate-400 bg-slate-50 rounded-xl border border-slate-200">No correlation findings detected.</div>'
        all_findings_html = '<div class="p-8 text-center text-slate-400 bg-white rounded-xl border border-slate-200">No correlation rules triggered for this scan.</div>'

    more_findings_btn = ""
    if len(findings) > 25:
        more_findings_btn = f'<div class="text-center pt-2"><button onclick="switchTab(\'correlations\')" class="text-xs font-semibold text-cyan-600 hover:text-cyan-700">View all {len(findings)} correlations &rarr;</button></div>'

    category_blocks_html = "".join(_render_category_block(cat) for cat in categories)
    summary_rows_html = "".join(_render_event_summary_row(row) for row in event_summary)
    timeline_rows_html = "".join(_render_timeline_row(t) for t in timeline) if timeline else '<div class="text-center text-slate-400 py-6">No timeline events recorded.</div>'
    log_rows_html = "".join(_render_log_entry(l) for l in logs) if logs else '<div class="text-center text-slate-500 py-6">No log entries available.</div>'
    event_options_html = "".join(f'<option value="{html.escape(r[0])}">{html.escape(r[1] or r[0])} ({r[3]})</option>' for r in event_summary)

    pages_groups_html = _render_landing_pages_section(landing_pages_data)
    landing_pages_count = landing_pages_data.get('total_pages', 0)
    landing_pages_json = json.dumps(landing_pages_data.get('all_pages', [])).replace('<', '\\u003c').replace('>', '\\u003e')

    chips_html = [f'<button onclick="filterPagesByDomain(\'\', this)" class="page-dom-chip active text-xs px-2.5 py-1 rounded-full border border-cyan-500 bg-cyan-600 text-white font-semibold shadow-2xs">All ({landing_pages_count})</button>']
    for g in landing_pages_data.get('groups', []):
        d = html.escape(g['domain'])
        c = g['count']
        chips_html.append(f'<button onclick="filterPagesByDomain(\'{d}\', this)" class="page-dom-chip text-xs px-2.5 py-1 rounded-full border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 font-mono shadow-2xs">{d} <span class="opacity-75">({c})</span></button>')
    pages_domain_chips_html = "".join(chips_html)

    # Vendor JS embedding logic
    vendor_scripts = ""
    if cy_js and fcose_js:
        vendor_scripts = f"""
        <script>{cy_js}</script>
        <script>{layout_base_js}</script>
        <script>{cose_base_js}</script>
        <script>{fcose_js}</script>
        """
    else:
        # Fallback to CDN
        vendor_scripts = """
        <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/layout-base@2.0.1/layout-base.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/cose-base@2.2.0/cose-base.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/cytoscape-fcose@2.2.0/cytoscape-fcose.js"></script>
        """

    # Category config JSON for JS
    category_config_json = json.dumps(CATEGORY_CONFIG)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SpiderFoot Report - {html.escape(seed_target)} ({scan_id})</title>

  <!-- Google Fonts: Inter & JetBrains Mono -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

  <!-- Tailwind CSS CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {{
      theme: {{
        extend: {{
          fontFamily: {{
            sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
          }},
          colors: {{
            sf: {{
              accent: '#0891b2',
              accentLight: '#06b6d4',
              surface: '#ffffff',
              border: '#e2e8f0',
              bg: '#f8fafc',
            }}
          }}
        }}
      }}
    }}
  </script>

  <style>
    body {{
      background-color: #f8fafc;
      color: #1e293b;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    /* Custom scrollbars */
    ::-webkit-scrollbar {{
      width: 8px;
      height: 8px;
    }}
    ::-webkit-scrollbar-track {{
      background: #f1f5f9;
    }}
    ::-webkit-scrollbar-thumb {{
      background: #cbd5e1;
      border-radius: 4px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
      background: #94a3b8;
    }}
    @media print {{
      .no-print {{ display: none !important; }}
      body {{ background: #fff !important; }}
      .card {{ box-shadow: none !important; border: 1px solid #cbd5e1 !important; }}
    }}
    .tab-btn.active {{
      border-bottom: 2px solid #0891b2;
      color: #0891b2;
      font-weight: 600;
      background-color: #f0fdfa;
    }}
    .badge-chip {{
      transition: all 0.15s ease-in-out;
    }}
    .badge-chip:hover {{
      transform: translateY(-1px);
    }}
  </style>

  {vendor_scripts}
</head>
<body class="min-h-screen antialiased flex flex-col">

  <!-- Top Navigation & Brand Header -->
  <header class="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="flex items-center justify-between h-16">
        
        <!-- Left: Logo & Target Title -->
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-lg bg-cyan-600 flex items-center justify-center text-white font-bold text-lg shadow-sm">
            🕷️
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="font-bold text-slate-900 text-lg tracking-tight">SpiderFoot</span>
              <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono font-medium">OSINT Report</span>
              <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border {status_badge_classes}">
                {html.escape(status)}
              </span>
            </div>
            <p class="text-xs text-slate-500 font-mono">Target: <strong class="text-slate-800">{html.escape(seed_target)}</strong> &middot; ID: {scan_id}</p>
          </div>
        </div>

        <!-- Right: Actions & Print -->
        <div class="flex items-center gap-2 no-print">
          <button onclick="window.print()" class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 transition-colors shadow-2xs">
            <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/></svg>
            Print / PDF
          </button>
          <button onclick="downloadJsonExport()" class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-cyan-50 border border-cyan-200 text-cyan-700 hover:bg-cyan-100 transition-colors shadow-2xs">
            <svg class="w-4 h-4 text-cyan-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Raw JSON
          </button>
          <button onclick="downloadXmlExport()" class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-cyan-50 border border-cyan-200 text-cyan-700 hover:bg-cyan-100 transition-colors shadow-2xs">
            <svg class="w-4 h-4 text-cyan-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Raw XML
          </button>
        </div>

      </div>
    </div>
  </header>

  <!-- Main Content Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">

    <!-- Top Key Metrics Cards -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
      
      <!-- Total Events -->
      <div class="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
        <p class="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Total Events</p>
        <p class="text-3xl font-mono font-bold text-slate-900">{total_events:,}</p>
        <p class="text-xs text-slate-500 mt-1">{unique_events:,} unique entities</p>
      </div>

      <!-- Correlations / Findings -->
      <div class="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
        <p class="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Correlations</p>
        <p class="text-3xl font-mono font-bold text-cyan-600">{correlations_count}</p>
        <p class="text-xs text-slate-500 mt-1">
          <span class="text-red-600 font-semibold">{high_count} High</span> &middot; 
          <span class="text-amber-600 font-semibold">{medium_count} Med</span> &middot; 
          <span class="text-sky-600 font-semibold">{low_count} Low</span>
        </p>
      </div>

      <!-- Modules Queried -->
      <div class="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
        <p class="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Data Sources</p>
        <p class="text-3xl font-mono font-bold text-slate-900">{module_count}</p>
        <p class="text-xs text-slate-500 mt-1">OSINT modules active</p>
      </div>

      <!-- Duration -->
      <div class="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
        <p class="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">Scan Duration</p>
        <p class="text-3xl font-mono font-bold text-slate-900">{html.escape(duration_str)}</p>
        <p class="text-xs text-slate-500 mt-1">{html.escape(started_str)}</p>
      </div>

    </div>

    <!-- Tabbed Navigation Bar -->
    <div class="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden mb-6">
      
      <div class="flex border-b border-slate-200 overflow-x-auto no-print">
        
        <button onclick="switchTab('summary')" id="tab-btn-summary" class="tab-btn active inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
          Overview & Summary
        </button>

        <button onclick="switchTab('data')" id="tab-btn-data" class="tab-btn inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
          Data & Events
          <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono">{total_events:,}</span>
        </button>

        <button onclick="switchTab('pages')" id="tab-btn-pages" class="tab-btn inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>
          Landing Pages
          <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono">{landing_pages_count}</span>
        </button>

        <button onclick="switchTab('graph')" id="tab-btn-graph" class="tab-btn inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"/></svg>
          Interactive Graph
          <span class="text-xs px-2 py-0.5 rounded-full bg-cyan-100 text-cyan-800 font-mono font-medium">Cytoscape</span>
        </button>

        <button onclick="switchTab('timeline')" id="tab-btn-timeline" class="tab-btn inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          Timeline
          <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono">{len(timeline)}</span>
        </button>

        <button onclick="switchTab('correlations')" id="tab-btn-correlations" class="tab-btn inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          Correlations
          <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono">{correlations_count}</span>
        </button>

        <button onclick="switchTab('logs')" id="tab-btn-logs" class="tab-btn inline-flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap text-slate-600 hover:text-cyan-600 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
          Scan Logs
          <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono">{len(logs)}</span>
        </button>

      </div>

      <!-- Tab Content Area -->
      <div class="p-6">

        <!-- ========================================================= -->
        <!-- TAB 1: SUMMARY / OVERVIEW                                 -->
        <!-- ========================================================= -->
        <div id="tab-content-summary" class="tab-pane space-y-8">
          
          <!-- Key Correlation Findings -->
          <div>
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-base font-bold text-slate-900 tracking-tight uppercase tracking-wider text-xs text-slate-500">Key Correlation Findings</h2>
              <span class="text-xs text-slate-500 font-medium">{len(findings)} rules matched</span>
            </div>

            <div class="space-y-3">
              {findings_cards_html}
              {more_findings_btn}
            </div>
          </div>

          <!-- Categorized Entities Breakdown -->
          <div>
            <h2 class="text-base font-bold text-slate-900 tracking-tight uppercase tracking-wider text-xs text-slate-500 mb-4">Discovered Entities by Category</h2>
            <div class="space-y-6">
              {category_blocks_html}
            </div>
          </div>

          <!-- All Event Types Summary Table -->
          <div>
            <h2 class="text-base font-bold text-slate-900 tracking-tight uppercase tracking-wider text-xs text-slate-500 mb-4">Event Types Breakdown</h2>
            <div class="overflow-x-auto border border-slate-200 rounded-xl">
              <table class="min-w-full divide-y divide-slate-200 text-left text-sm">
                <thead class="bg-slate-50 text-slate-600 text-xs uppercase font-semibold">
                  <tr>
                    <th class="px-4 py-3">Category</th>
                    <th class="px-4 py-3">Event Type</th>
                    <th class="px-4 py-3 text-right">Unique</th>
                    <th class="px-4 py-3 text-right">Total</th>
                    <th class="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 bg-white">
                  {summary_rows_html}
                </tbody>
              </table>
            </div>
          </div>

        </div>

        <!-- ========================================================= -->
        <!-- TAB 2: DATA & EVENTS (Interactive Table)                  -->
        <!-- ========================================================= -->
        <div id="tab-content-data" class="tab-pane hidden space-y-4">
          
          <!-- Search & Controls Bar -->
          <div class="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-3">
            
            <div class="flex flex-col sm:flex-row gap-3">
              <div class="flex-1 relative">
                <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                <input type="text" id="event-search" oninput="debounceEventFilter()" placeholder="Search events (data, module, type, source)..." class="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-slate-300 bg-white text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 shadow-2xs">
              </div>

              <select id="event-type-filter" onchange="filterEvents()" class="px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white text-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 shadow-2xs">
                <option value="">All Event Types</option>
                {event_options_html}
              </select>

              <select id="event-sort" onchange="filterEvents()" class="px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white text-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 shadow-2xs">
                <option value="data_asc">Sort: Data (A-Z)</option>
                <option value="time_desc">Sort: Newest First</option>
                <option value="time_asc">Sort: Oldest First</option>
                <option value="type_asc">Sort: Type</option>
                <option value="module_asc">Sort: Module</option>
                <option value="conf_desc">Sort: Confidence (High-Low)</option>
              </select>
            </div>

            <!-- Category Chips & Toggles -->
            <div class="flex items-center justify-between flex-wrap gap-2 pt-1 border-t border-slate-200">
              <div class="flex flex-wrap gap-1.5" id="category-filter-chips">
                <button onclick="setCategoryFilter('')" class="cat-chip active text-xs px-3 py-1 rounded-full border border-cyan-600 bg-cyan-50 text-cyan-700 font-medium">All</button>
                <button onclick="setCategoryFilter('attack_surface')" class="cat-chip text-xs px-3 py-1 rounded-full border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 font-medium">Attack Surface</button>
                <button onclick="setCategoryFilter('identities')" class="cat-chip text-xs px-3 py-1 rounded-full border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 font-medium">Identities</button>
                <button onclick="setCategoryFilter('infrastructure')" class="cat-chip text-xs px-3 py-1 rounded-full border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 font-medium">Infrastructure</button>
                <button onclick="setCategoryFilter('reputation')" class="cat-chip text-xs px-3 py-1 rounded-full border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 font-medium">Reputation</button>
                <button onclick="setCategoryFilter('vulnerabilities')" class="cat-chip text-xs px-3 py-1 rounded-full border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 font-medium">Vulnerabilities</button>
              </div>

              <div class="text-xs text-slate-500 font-mono">
                Showing <span id="event-visible-count" class="font-bold text-slate-800">0</span> of <span id="event-total-count" class="font-bold text-slate-800">0</span> events
              </div>
            </div>

          </div>

          <!-- Events List Container -->
          <div id="events-container" class="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs divide-y divide-slate-100">
            <!-- Rendered by client JavaScript -->
          </div>

          <!-- Pagination Bar -->
          <div class="flex items-center justify-between px-4 py-3 bg-white border border-slate-200 rounded-xl">
            <div class="text-xs text-slate-500">
              Page <span id="current-page-num" class="font-bold text-slate-800">1</span> of <span id="total-page-num" class="font-bold text-slate-800">1</span>
            </div>
            <div class="flex items-center gap-1">
              <button onclick="prevPage()" id="btn-prev-page" class="px-3 py-1 text-xs rounded border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed">Previous</button>
              <div id="pagination-pages" class="flex gap-1"></div>
              <button onclick="nextPage()" id="btn-next-page" class="px-3 py-1 text-xs rounded border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed">Next</button>
            </div>
          </div>

        </div>

        <!-- ========================================================= -->
        <!-- TAB 2.5: LANDING PAGES                                    -->
        <!-- ========================================================= -->
        <div id="tab-content-pages" class="tab-pane hidden space-y-6">
          
          <!-- Top Controls & Metrics -->
          <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 bg-white border border-slate-200 p-4 rounded-xl shadow-xs">
            <div class="flex items-center gap-4 flex-wrap">
              <div>
                <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Captured Pages</p>
                <p class="text-2xl font-mono font-bold text-slate-800">{landing_pages_count}</p>
              </div>
              <div class="h-8 w-px bg-slate-200"></div>
              <div>
                <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Domains</p>
                <p class="text-2xl font-mono font-bold text-cyan-600">{landing_pages_data.get('domains_count', 0)}</p>
              </div>
              <div class="h-8 w-px bg-slate-200"></div>
              <div>
                <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Status 200 OK</p>
                <p class="text-2xl font-mono font-bold text-emerald-600">{landing_pages_data.get('success_count', 0)}</p>
              </div>
            </div>

            <div class="flex items-center gap-2">
              <input type="text" id="pages-search" oninput="filterPages()" placeholder="Search pages, URLs, servers..." class="w-full sm:w-64 text-xs rounded-lg px-3 py-1.5 border border-slate-300 bg-white text-slate-800 focus:outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
          </div>

          <!-- Domain Filter Chips -->
          <div class="flex items-center gap-1.5 flex-wrap">
            <span class="text-xs text-slate-400 mr-1">Filter by Domain:</span>
            {pages_domain_chips_html}
          </div>

          <!-- Main Content: Groups by Oberdomain -->
          <div id="pages-groups-container" class="space-y-8">
            {pages_groups_html}
          </div>

        </div>

        <!-- ========================================================= -->
        <!-- TAB 3: INTERACTIVE GRAPH (Cytoscape.js)                    -->
        <!-- ========================================================= -->
        <div id="tab-content-graph" class="tab-pane hidden flex flex-col" style="height: calc(100vh - 240px); min-height: 650px;">
          
          <!-- Graph Toolbar -->
          <div class="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border border-slate-200 rounded-t-xl bg-white shadow-2xs">
            
            <div class="flex items-center gap-2 flex-wrap">
              <input type="text" id="graph-search" oninput="searchGraphNodes()" placeholder="Search nodes..." class="w-48 text-xs rounded-md px-3 py-1.5 border border-slate-300 bg-white text-slate-800 focus:outline-none focus:ring-2 focus:ring-cyan-500">

              <select id="graph-layout" onchange="runGraphLayout()" class="text-xs rounded-md px-2.5 py-1.5 border border-slate-300 bg-white text-slate-700">
                <option value="fcose">Layout: Organic (fcose)</option>
                <option value="breadthfirst">Layout: Hierarchy</option>
                <option value="concentric">Layout: Concentric</option>
                <option value="circle">Layout: Circle</option>
                <option value="grid">Layout: Grid</option>
              </select>

              <button onclick="fitGraph()" type="button" class="text-xs px-2.5 py-1.5 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300">
                Fit View
              </button>

              <button onclick="toggleCollapseLeaves()" id="btn-collapse-leaves" type="button" class="text-xs px-2.5 py-1.5 rounded-md bg-cyan-50 hover:bg-cyan-100 text-cyan-800 border border-cyan-300 font-medium">
                Leaves: Collapsed
              </button>

              <div class="flex items-center gap-1.5 text-xs text-slate-600 pl-2">
                <span>Min Deg:</span>
                <input type="range" id="min-degree-slider" min="0" max="15" value="0" oninput="applyDegreeFilter()" class="w-20 accent-cyan-600">
                <span id="min-degree-val" class="font-mono w-4">0</span>
              </div>
            </div>

            <div class="text-xs text-slate-500 font-mono">
              <span id="graph-visible-count">0</span> / <span id="graph-total-count">0</span> nodes
            </div>

          </div>

          <!-- Category Toggle Filter Chips -->
          <div class="flex flex-wrap gap-1 px-4 py-2 border-x border-b border-slate-200 bg-slate-50 text-xs">
            <span class="text-slate-400 py-1 mr-1">Categories:</span>
            <button onclick="toggleGraphCategory('attack_surface', this)" class="px-2 py-0.5 rounded-full border border-blue-200 bg-blue-50 text-blue-700 font-medium">Attack Surface</button>
            <button onclick="toggleGraphCategory('identities', this)" class="px-2 py-0.5 rounded-full border border-violet-200 bg-violet-50 text-violet-700 font-medium">Identities</button>
            <button onclick="toggleGraphCategory('infrastructure', this)" class="px-2 py-0.5 rounded-full border border-teal-200 bg-teal-50 text-teal-700 font-medium">Infrastructure</button>
            <button onclick="toggleGraphCategory('reputation', this)" class="px-2 py-0.5 rounded-full border border-amber-200 bg-amber-50 text-amber-700 font-medium">Reputation</button>
            <button onclick="toggleGraphCategory('vulnerabilities', this)" class="px-2 py-0.5 rounded-full border border-red-200 bg-red-50 text-red-700 font-medium">Vulnerabilities</button>
            <button onclick="toggleGraphCategory('root', this)" class="px-2 py-0.5 rounded-full border border-yellow-300 bg-yellow-50 text-yellow-800 font-medium">Target Root</button>
          </div>

          <!-- Main Graph Canvas & Node Inspector Panel -->
          <div class="flex-1 flex border-x border-b border-slate-200 rounded-b-xl overflow-hidden relative bg-white">
            
            <div id="cy-canvas" class="flex-1 bg-slate-50/50" style="min-width: 0;"></div>

            <!-- Side Node Inspector Panel -->
            <aside id="graph-side-panel" class="w-80 border-l border-slate-200 bg-white p-4 overflow-y-auto flex flex-col shadow-xs">
              <div id="graph-node-details">
                <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-2">Node Inspector</p>
                <p class="text-sm text-slate-600">Click any node in the graph to inspect its details, category, degree, and connected neighbors.</p>
                <div class="mt-4 p-3 bg-slate-50 rounded-lg border border-slate-200 text-xs text-slate-500 space-y-1">
                  <p>💡 <strong>Scroll:</strong> Zoom in/out</p>
                  <p>💡 <strong>Drag:</strong> Pan around graph</p>
                  <p>💡 <strong>Click:</strong> Inspect entity</p>
                </div>
              </div>
            </aside>

          </div>

        </div>

        <!-- ========================================================= -->
        <!-- TAB 4: TIMELINE                                           -->
        <!-- ========================================================= -->
        <div id="tab-content-timeline" class="tab-pane hidden space-y-4">
          <div class="border border-slate-200 rounded-xl bg-white p-6">
            <h2 class="text-base font-bold text-slate-900 tracking-tight mb-4">Event Discovery Timeline</h2>
            
            <div class="space-y-0 divide-y divide-slate-100">
              {timeline_rows_html}
            </div>
          </div>
        </div>

        <!-- ========================================================= -->
        <!-- TAB 5: CORRELATIONS                                       -->
        <!-- ========================================================= -->
        <div id="tab-content-correlations" class="tab-pane hidden space-y-4">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-base font-bold text-slate-900 tracking-tight">Correlation Rule Matches ({len(findings)})</h2>
            <div class="flex gap-2">
              <span class="text-xs px-2.5 py-1 rounded bg-red-50 text-red-700 border border-red-200 font-medium">{high_count} Critical</span>
              <span class="text-xs px-2.5 py-1 rounded bg-amber-50 text-amber-700 border border-amber-200 font-medium">{medium_count} Warning</span>
              <span class="text-xs px-2.5 py-1 rounded bg-sky-50 text-sky-700 border border-sky-200 font-medium">{low_count} Low</span>
              <span class="text-xs px-2.5 py-1 rounded bg-slate-100 text-slate-700 border border-slate-200 font-medium">{info_count} Info</span>
            </div>
          </div>

          <div class="space-y-3">
            {all_findings_html}
          </div>
        </div>

        <!-- ========================================================= -->
        <!-- TAB 6: SCAN LOG                                           -->
        <!-- ========================================================= -->
        <div id="tab-content-logs" class="tab-pane hidden space-y-4">
          
          <div class="bg-slate-50 p-4 rounded-xl border border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div class="flex items-center gap-2 w-full sm:w-auto">
              <input type="text" id="log-search" oninput="filterLogs()" placeholder="Search log messages..." class="text-xs rounded-lg px-3 py-2 border border-slate-300 bg-white text-slate-800 w-full sm:w-64 focus:outline-none focus:ring-2 focus:ring-cyan-500">
              <select id="log-level-filter" onchange="filterLogs()" class="text-xs rounded-lg px-3 py-2 border border-slate-300 bg-white text-slate-700">
                <option value="">All Log Levels</option>
                <option value="ERROR">ERROR</option>
                <option value="STATUS">STATUS / INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="DEBUG">DEBUG</option>
              </select>
            </div>
            <div class="text-xs text-slate-500 font-mono">
              Showing <span id="log-count">{len(logs)}</span> log entries
            </div>
          </div>

          <div class="border border-slate-200 rounded-xl overflow-hidden bg-slate-900 text-slate-200 font-mono text-xs max-h-[600px] overflow-y-auto p-4 space-y-1" id="log-container">
            {log_rows_html}
          </div>

        </div>

      </div>
    </div>

  </main>

  <!-- Landing Page Full-Size Inspector Modal ("raufdrücken für gross") -->
  <div id="page-preview-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6" onclick="if(event.target===this) closePageModal()">
    <div class="fixed inset-0 bg-slate-900/70 backdrop-blur-xs transition-opacity" onclick="closePageModal()"></div>
    <div class="relative bg-white border border-slate-200 rounded-2xl shadow-2xl w-full max-w-6xl h-[90vh] flex flex-col overflow-hidden z-10" onclick="event.stopPropagation()">
      <div class="flex items-center justify-between px-5 py-3.5 border-b border-slate-200 bg-slate-50">
        <div class="flex items-center gap-3 min-w-0 flex-1 mr-4">
          <span class="text-lg">🌐</span>
          <div class="min-w-0">
            <h4 id="modal-page-title" class="text-sm font-bold text-slate-900 truncate">Title</h4>
            <div class="flex items-center gap-2 mt-0.5">
              <span id="modal-page-url" class="text-[11px] font-mono text-cyan-600 truncate">URL</span>
              <span id="modal-page-status" class="text-[10px] font-bold px-1.5 py-0.2 rounded border">200</span>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <a id="modal-page-link" href="#" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg border border-slate-300 bg-white text-slate-700 hover:bg-slate-100 transition-colors">
            <span>Open Link</span>
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
          </a>
          <button onclick="closePageModal()" type="button" class="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors text-lg font-bold">
            &times;
          </button>
        </div>
      </div>
      <div class="flex-1 bg-white relative overflow-hidden">
        <iframe id="modal-page-iframe" class="w-full h-full border-0" sandbox="allow-same-origin allow-scripts"></iframe>
      </div>
      <div class="px-5 py-2.5 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500 font-mono">
        <div>
          <span>Server: <strong id="modal-page-server" class="text-slate-700"></strong></span>
          <span class="mx-2">&middot;</span>
          <span>Domain: <strong id="modal-page-domain" class="text-slate-700"></strong></span>
        </div>
        <div id="modal-page-size"></div>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <footer class="bg-white border-t border-slate-200 py-4 mt-auto">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
      <p>SpiderFoot Revival &middot; Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
      <p class="font-mono text-[11px]">Scan Target: {html.escape(seed_target)}</p>
    </div>
  </footer>

  <!-- Embedded Data Payload -->
  <script>
    const RAW_EVENTS = {events_json};
    const GRAPH_DATA = {graph_json};
    const CATEGORY_MAP = {category_config_json};
    const LANDING_PAGES = {landing_pages_json};
  </script>

  <!-- Interactive Client-side Script -->
  <script>
    // Tab Management
    function switchTab(tabId) {{
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.add('hidden'));

      const activeBtn = document.getElementById('tab-btn-' + tabId);
      const activePane = document.getElementById('tab-content-' + tabId);

      if (activeBtn) activeBtn.classList.add('active');
      if (activePane) activePane.classList.remove('hidden');

      if (tabId === 'graph') {{
        initCytoscapeGraph();
      }}
    }}

    // Export JSON
    function downloadJsonExport() {{
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(RAW_EVENTS, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", "SpiderFoot_{safe_target}_events.json");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }}

    function escapeXml(unsafe) {{
      return String(unsafe || '').replace(/[<>&'"]/g, function (c) {{
        switch (c) {{
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '&': return '&amp;';
          case '\'': return '&apos;';
          case '"': return '&quot;';
        }}
      }});
    }}

    // Export XML
    function downloadXmlExport() {{
      let xml = '<?xml version="1.0" encoding="UTF-8"?>\\n<spiderfoot version="4.0">\\n';
      xml += '  <scan target="{safe_target}">\\n';
      xml += '    <events>\\n';
      for (const ev of RAW_EVENTS) {{
        xml += '      <event>\\n';
        xml += '        <data>' + escapeXml(ev.data) + '</data>\\n';
        xml += '        <type>' + escapeXml(ev.type) + '</type>\\n';
        xml += '        <module>' + escapeXml(ev.module) + '</module>\\n';
        xml += '        <source>' + escapeXml(ev.source) + '</source>\\n';
        xml += '        <time>' + escapeXml(ev.time) + '</time>\\n';
        xml += '      </event>\\n';
      }}
      xml += '    </events>\\n';
      xml += '  </scan>\\n</spiderfoot>';
      const blob = new Blob([xml], {{ type: 'application/xml;charset=utf-8' }});
      const url = URL.createObjectURL(blob);
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", url);
      downloadAnchor.setAttribute("download", "SpiderFoot_{safe_target}_events.xml");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      URL.revokeObjectURL(url);
    }}

    // ==========================================
    // DATA / EVENTS TAB LOGIC (Client-side)
    // ==========================================
    let currentFilteredEvents = RAW_EVENTS;
    let currentPage = 1;
    const PAGE_SIZE = 50;
    let activeCategory = '';

    function setCategoryFilter(cat) {{
      activeCategory = cat;
      document.querySelectorAll('.cat-chip').forEach(btn => {{
        btn.classList.remove('active', 'border-cyan-600', 'bg-cyan-50', 'text-cyan-700');
        btn.classList.add('border-slate-200', 'bg-white', 'text-slate-600');
      }});
      event.target.classList.add('active', 'border-cyan-600', 'bg-cyan-50', 'text-cyan-700');
      event.target.classList.remove('border-slate-200', 'bg-white', 'text-slate-600');
      filterEvents();
    }}

    let debounceTimer = null;
    function debounceEventFilter() {{
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(filterEvents, 200);
    }}

    function filterEvents() {{
      const query = (document.getElementById('event-search').value || '').toLowerCase().trim();
      const typeFilter = document.getElementById('event-type-filter').value;
      const sort = document.getElementById('event-sort').value;

      currentFilteredEvents = RAW_EVENTS.filter(ev => {{
        if (activeCategory && ev.category !== activeCategory) return false;
        if (typeFilter && ev.type_code !== typeFilter) return false;
        if (query) {{
          const match = ev.data.toLowerCase().includes(query) ||
                        ev.type.toLowerCase().includes(query) ||
                        ev.module.toLowerCase().includes(query) ||
                        ev.source.toLowerCase().includes(query);
          if (!match) return false;
        }}
        return true;
      }});

      // Sorting
      if (sort === 'data_asc') {{
        currentFilteredEvents.sort((a, b) => a.data.localeCompare(b.data));
      }} else if (sort === 'time_desc') {{
        currentFilteredEvents.sort((a, b) => b.time.localeCompare(a.time));
      }} else if (sort === 'time_asc') {{
        currentFilteredEvents.sort((a, b) => a.time.localeCompare(b.time));
      }} else if (sort === 'type_asc') {{
        currentFilteredEvents.sort((a, b) => a.type.localeCompare(b.type));
      }} else if (sort === 'module_asc') {{
        currentFilteredEvents.sort((a, b) => a.module.localeCompare(b.module));
      }} else if (sort === 'conf_desc') {{
        currentFilteredEvents.sort((a, b) => b.confidence - a.confidence);
      }}

      currentPage = 1;
      renderEventsPage();
    }}

    function renderEventsPage() {{
      const container = document.getElementById('events-container');
      const totalCount = currentFilteredEvents.length;
      document.getElementById('event-visible-count').textContent = totalCount.toLocaleString();
      document.getElementById('event-total-count').textContent = RAW_EVENTS.length.toLocaleString();

      const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
      if (currentPage > totalPages) currentPage = totalPages;

      document.getElementById('current-page-num').textContent = currentPage;
      document.getElementById('total-page-num').textContent = totalPages;
      document.getElementById('btn-prev-page').disabled = (currentPage <= 1);
      document.getElementById('btn-next-page').disabled = (currentPage >= totalPages);

      const start = (currentPage - 1) * PAGE_SIZE;
      const pageEvents = currentFilteredEvents.slice(start, start + PAGE_SIZE);

      if (pageEvents.length === 0) {{
        container.innerHTML = '<div class="p-8 text-center text-slate-400 text-sm">No matching events found.</div>';
        return;
      }}

      let html = '';
      for (const ev of pageEvents) {{
        const catInfo = CATEGORY_MAP[ev.category] || CATEGORY_MAP['other'];
        const badgeStyle = `background-color: ${{catInfo.bg}}; color: ${{catInfo.text}}; border-color: ${{catInfo.border}};`;
        
        html += `
        <div class="event-item hover:bg-slate-50 transition-colors">
          <div class="flex items-center gap-3 px-4 py-3 cursor-pointer select-none" onclick="toggleEventDetail(${{ev.id}})">
            <span class="text-slate-400 text-xs w-4 font-bold" id="arr-${{ev.id}}">&rsaquo;</span>
            <span class="text-xs font-semibold px-2 py-0.5 rounded-full border shrink-0 font-mono" style="${{badgeStyle}}">
              ${{escapeHtml(ev.type)}}
            </span>
            <span class="flex-1 font-mono text-xs text-slate-800 truncate" title="${{escapeHtml(ev.data)}}">
              ${{escapeHtml(ev.data.substring(0, 180))}}
            </span>
            ${{ev.source ? `<span class="hidden md:inline font-mono text-[11px] text-slate-400 max-w-[200px] truncate" title="${{escapeHtml(ev.source)}}">&larr; ${{escapeHtml(ev.source.substring(0, 60))}}</span>` : ''}}
            <span class="text-[11px] font-mono text-slate-500 shrink-0">${{escapeHtml(ev.module)}}</span>
          </div>

          <div id="detail-${{ev.id}}" class="hidden px-4 pb-3 pt-1 border-t border-slate-100 bg-slate-50/70 ml-7 mr-4 mb-2 rounded-lg text-xs space-y-2">
            <div class="flex items-center justify-between text-slate-500 font-mono pt-1 text-[11px]">
              <div>
                <span class="font-semibold text-slate-700">${{escapeHtml(ev.type_code)}}</span> &middot; 
                <span>${{escapeHtml(ev.module)}}</span> &middot; 
                <span>${{ev.confidence}}% confidence</span> &middot; 
                <span>${{escapeHtml(ev.time)}}</span>
              </div>
              <button onclick="copyToClipboard('${{encodeURIComponent(ev.data)}}', this)" class="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-700 hover:bg-slate-100 font-sans">
                Copy Data
              </button>
            </div>
            ${{ev.source ? `<div class="text-slate-600 font-mono text-[11px] break-all"><strong class="text-slate-500">Source:</strong> ${{escapeHtml(ev.source)}}</div>` : ''}}
            <div class="bg-white p-3 rounded border border-slate-200 font-mono text-xs text-slate-900 break-all whitespace-pre-wrap max-h-48 overflow-y-auto select-all">
              ${{escapeHtml(ev.data)}}
            </div>
          </div>
        </div>`;
      }}

      container.innerHTML = html;
    }}

    function toggleEventDetail(id) {{
      const detail = document.getElementById('detail-' + id);
      const arr = document.getElementById('arr-' + id);
      if (!detail) return;
      if (detail.classList.contains('hidden')) {{
        detail.classList.remove('hidden');
        if (arr) {{ arr.innerHTML = '&dsaquo;'; arr.style.transform = 'rotate(90deg)'; }}
      }} else {{
        detail.classList.add('hidden');
        if (arr) {{ arr.innerHTML = '&rsaquo;'; arr.style.transform = 'none'; }}
      }}
    }}

    function prevPage() {{
      if (currentPage > 1) {{
        currentPage--;
        renderEventsPage();
      }}
    }}

    function nextPage() {{
      const totalPages = Math.ceil(currentFilteredEvents.length / PAGE_SIZE);
      if (currentPage < totalPages) {{
        currentPage++;
        renderEventsPage();
      }}
    }}

    function copyToClipboard(encodedStr, btn) {{
      const text = decodeURIComponent(encodedStr);
      navigator.clipboard.writeText(text).then(() => {{
        const oldText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = oldText, 1500);
      }});
    }}

    function escapeHtml(str) {{
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }}

    // ==========================================
    // GRAPH TAB LOGIC (Cytoscape.js)
    // ==========================================
    let cyInstance = null;
    let cyInitialized = false;
    let collapsedLeavesActive = true;
    let hiddenGraphCategories = new Set();
    const LEAF_THRESHOLD = 8;

    function initCytoscapeGraph() {{
      if (cyInitialized && cyInstance) {{
        cyInstance.resize();
        return;
      }}

      const container = document.getElementById('cy-canvas');
      if (!container || !window.cytoscape) return;

      if (window.cytoscapeFcose && !window.__fcoseRegistered) {{
        window.cytoscape.use(window.cytoscapeFcose);
        window.__fcoseRegistered = true;
      }}

      const nodes = GRAPH_DATA.nodes || [];
      const edges = GRAPH_DATA.edges || [];
      document.getElementById('graph-total-count').textContent = nodes.length;
      document.getElementById('graph-visible-count').textContent = nodes.length;

      // Degree calculation
      const degree = {{}};
      nodes.forEach(n => degree[n.id] = 0);
      edges.forEach(e => {{
        degree[e.source] = (degree[e.source] || 0) + 1;
        degree[e.target] = (degree[e.target] || 0) + 1;
      }});

      // Adjacency for leaf collapse
      const adj = {{}};
      nodes.forEach(n => adj[n.id] = []);
      edges.forEach(e => {{
        adj[e.source].push(e.target);
        adj[e.target].push(e.source);
      }});

      const leafParent = {{}};
      const hubLeafCount = {{}};
      nodes.forEach(n => {{
        if (n.is_root) return;
        if ((degree[n.id] || 0) === 1 && adj[n.id].length === 1) {{
          const p = adj[n.id][0];
          leafParent[n.id] = p;
          hubLeafCount[p] = (hubLeafCount[p] || 0) + 1;
        }}
      }});

      const collapsibleHubs = new Set();
      Object.entries(hubLeafCount).forEach(([hubId, count]) => {{
        if (count >= LEAF_THRESHOLD) collapsibleHubs.add(hubId);
      }});

      const elements = [];
      nodes.forEach(n => {{
        let cat = 'other';
        if (n.is_root) cat = 'root';
        else {{
          for (const [k, v] of Object.entries(CATEGORY_MAP)) {{
            if (v.types && v.types.includes(n.type)) {{ cat = k; break; }}
          }}
        }}

        const catInfo = CATEGORY_MAP[cat] || CATEGORY_MAP['other'];
        const isLeaf = (degree[n.id] === 1 && collapsibleHubs.has(leafParent[n.id]));
        const hubCount = collapsibleHubs.has(n.id) ? hubLeafCount[n.id] : 0;
        const size = n.is_root ? 32 : Math.min(36, 12 + Math.sqrt(degree[n.id] || 0) * 4);

        elements.push({{
          data: {{
            id: n.id,
            label: hubCount ? `${{n.label}} (+${{hubCount}})` : n.label,
            baseLabel: n.label,
            type: n.type,
            category: cat,
            color: catInfo.color,
            isRoot: !!n.is_root,
            degree: degree[n.id] || 0,
            size: size,
            isLeaf: isLeaf,
            collapsedBy: isLeaf ? leafParent[n.id] : null
          }}
        }});
      }});

      edges.forEach(e => {{
        elements.push({{
          data: {{ id: 'e' + e.id, source: e.source, target: e.target }}
        }});
      }});

      cyInstance = window.cytoscape({{
        container: container,
        elements: elements,
        minZoom: 0.05,
        maxZoom: 4,
        wheelSensitivity: 0.25,
        style: [
          {{
            selector: 'node',
            style: {{
              'background-color': 'data(color)',
              'width': 'data(size)',
              'height': 'data(size)',
              'label': 'data(label)',
              'color': '#0f172a',
              'font-size': 10,
              'font-family': 'JetBrains Mono, monospace',
              'text-wrap': 'ellipsis',
              'text-max-width': 120,
              'text-margin-y': -4,
              'text-valign': 'bottom',
              'text-halign': 'center',
              'text-outline-color': '#ffffff',
              'text-outline-width': 2,
              'border-width': 1.5,
              'border-color': '#ffffff',
              'min-zoomed-font-size': 6,
            }}
          }},
          {{
            selector: 'node[?isRoot]',
            style: {{
              'border-width': 3,
              'border-color': '#eab308',
              'font-size': 12,
              'font-weight': 'bold',
              'z-index': 10,
              'min-zoomed-font-size': 4,
            }}
          }},
          {{
            selector: 'node.highlight',
            style: {{
              'border-width': 3,
              'border-color': '#0891b2',
              'z-index': 99
            }}
          }},
          {{
            selector: 'node.dimmed',
            style: {{ 'opacity': 0.15 }}
          }},
          {{
            selector: 'node.hidden',
            style: {{ 'display': 'none' }}
          }},
          {{
            selector: 'edge',
            style: {{
              'width': 1,
              'line-color': '#cbd5e1',
              'target-arrow-color': '#cbd5e1',
              'target-arrow-shape': 'triangle',
              'arrow-scale': 0.8,
              'curve-style': 'bezier',
              'opacity': 0.6
            }}
          }},
          {{
            selector: 'edge.highlight',
            style: {{
              'line-color': '#0891b2',
              'target-arrow-color': '#0891b2',
              'opacity': 1,
              'width': 2
            }}
          }},
          {{
            selector: 'edge.dimmed',
            style: {{ 'opacity': 0.05 }}
          }}
        ]
      }});

      // Node Selection click
      cyInstance.on('tap', 'node', function(evt) {{
        const node = evt.target;
        showNodeInspector(node);
      }});

      cyInstance.on('tap', function(evt) {{
        if (evt.target === cyInstance) {{
          clearNodeHighlight();
        }}
      }});

      cyInitialized = true;
      applyGraphVisibility();
      runGraphLayout();
    }}

    function showNodeInspector(node) {{
      const d = node.data();
      const neighbors = node.neighborhood().nodes();

      cyInstance.elements().removeClass('highlight dimmed');
      node.addClass('highlight');
      node.neighborhood().addClass('highlight');
      cyInstance.elements().difference(node.neighborhood().union(node)).addClass('dimmed');

      let neighborsHtml = '';
      neighbors.forEach(n => {{
        const nd = n.data();
        neighborsHtml += `
        <li class="py-1">
          <button onclick="focusNode('${{nd.id}}')" class="w-full text-left truncate hover:text-cyan-600 font-mono text-[11px] flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full shrink-0" style="background-color: ${{nd.color}}"></span>
            <span class="truncate">${{escapeHtml(nd.baseLabel)}}</span>
          </button>
        </li>`;
      }});

      const panel = document.getElementById('graph-node-details');
      panel.innerHTML = `
        <div class="flex items-center justify-between pb-2 border-b border-slate-200 mb-3">
          <p class="text-xs uppercase tracking-wider text-slate-500 font-bold">Selected Node</p>
          <button onclick="clearNodeHighlight()" class="text-slate-400 hover:text-slate-700 text-xs font-bold">&times;</button>
        </div>
        <div class="space-y-3 text-xs">
          <div>
            <span class="text-slate-400 text-[11px]">Type</span>
            <p class="font-mono text-slate-800 font-semibold break-all">${{escapeHtml(d.type)}}</p>
          </div>
          <div>
            <span class="text-slate-400 text-[11px]">Value</span>
            <p class="font-mono text-slate-900 bg-slate-50 p-2 rounded border border-slate-200 break-all select-all">${{escapeHtml(d.baseLabel)}}</p>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-slate-400 text-[11px]">Connections:</span>
            <span class="font-mono font-bold text-slate-800">${{d.degree}}</span>
          </div>
          <div>
            <span class="text-slate-400 text-[11px] mb-1 block">Connected Neighbors (${{neighbors.length}})</span>
            <ul class="divide-y divide-slate-100 max-h-48 overflow-y-auto">
              ${{neighborsHtml || '<li class="text-slate-400 italic">No neighbors</li>'}}
            </ul>
          </div>
        </div>
      `;
    }}

    function focusNode(nodeId) {{
      if (!cyInstance) return;
      const target = cyInstance.getElementById(nodeId);
      if (target.length > 0) {{
        cyInstance.animate({{ center: {{ eles: target }}, zoom: 1.5 }}, {{ duration: 300 }});
        showNodeInspector(target);
      }}
    }}

    function clearNodeHighlight() {{
      if (!cyInstance) return;
      cyInstance.elements().removeClass('highlight dimmed');
      const panel = document.getElementById('graph-node-details');
      panel.innerHTML = `
        <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-2">Node Inspector</p>
        <p class="text-sm text-slate-600">Click any node in the graph to inspect its details, category, degree, and connected neighbors.</p>
      `;
    }}

    function fitGraph() {{
      if (cyInstance) cyInstance.fit(null, 30);
    }}

    function runGraphLayout() {{
      if (!cyInstance) return;
      const layoutName = document.getElementById('graph-layout').value || 'fcose';
      const opts = {{ name: layoutName, animate: true, animationDuration: 400 }};
      if (layoutName === 'fcose') {{
        opts.quality = 'default';
        opts.randomize = false;
        opts.nodeDimensionsIncludeLabels = true;
      }}
      cyInstance.layout(opts).run();
    }}

    function toggleCollapseLeaves() {{
      collapsedLeavesActive = !collapsedLeavesActive;
      const btn = document.getElementById('btn-collapse-leaves');
      if (collapsedLeavesActive) {{
        btn.textContent = 'Leaves: Collapsed';
        btn.className = 'text-xs px-2.5 py-1.5 rounded-md bg-cyan-50 hover:bg-cyan-100 text-cyan-800 border border-cyan-300 font-medium';
      }} else {{
        btn.textContent = 'Leaves: Expanded';
        btn.className = 'text-xs px-2.5 py-1.5 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 font-medium';
      }}
      applyGraphVisibility();
      runGraphLayout();
    }}

    function toggleGraphCategory(cat, btn) {{
      if (hiddenGraphCategories.has(cat)) {{
        hiddenGraphCategories.delete(cat);
        btn.classList.remove('opacity-40', 'line-through');
      }} else {{
        hiddenGraphCategories.add(cat);
        btn.classList.add('opacity-40', 'line-through');
      }}
      applyGraphVisibility();
    }}

    function applyDegreeFilter() {{
      const val = parseInt(document.getElementById('min-degree-slider').value, 10);
      document.getElementById('min-degree-val').textContent = val;
      applyGraphVisibility();
    }}

    function applyGraphVisibility() {{
      if (!cyInstance) return;
      const minDeg = parseInt(document.getElementById('min-degree-slider').value, 10) || 0;

      cyInstance.batch(() => {{
        cyInstance.nodes().forEach(node => {{
          const d = node.data();
          let hide = false;

          // Leaf collapse
          if (collapsedLeavesActive && d.isLeaf) hide = true;

          // Category filter
          if (hiddenGraphCategories.has(d.category)) hide = true;

          // Min degree filter
          if (!d.isRoot && d.degree < minDeg) hide = true;

          if (hide) node.addClass('hidden');
          else node.removeClass('hidden');
        }});
      }});

      const visible = cyInstance.nodes(':visible').length;
      document.getElementById('graph-visible-count').textContent = visible;
    }}

    function searchGraphNodes() {{
      if (!cyInstance) return;
      const q = (document.getElementById('graph-search').value || '').toLowerCase().trim();
      if (!q) {{
        cyInstance.elements().removeClass('highlight dimmed');
        return;
      }}
      cyInstance.batch(() => {{
        cyInstance.nodes().forEach(n => {{
          const label = (n.data('baseLabel') || '').toLowerCase();
          const type = (n.data('type') || '').toLowerCase();
          if (label.includes(q) || type.includes(q)) {{
            n.addClass('highlight').removeClass('dimmed');
          }} else {{
            n.addClass('dimmed').removeClass('highlight');
          }}
        }});
      }});
    }}

    // ==========================================
    // LOGS TAB FILTERING
    // ==========================================
    function filterLogs() {{
      const q = (document.getElementById('log-search').value || '').toLowerCase().trim();
      const level = document.getElementById('log-level-filter').value;
      const rows = document.querySelectorAll('.log-row');
      let visible = 0;

      rows.forEach(r => {{
        const text = r.textContent.toLowerCase();
        const rLevel = r.getAttribute('data-level') || '';
        let show = true;

        if (level && rLevel !== level) show = false;
        if (q && !text.includes(q)) show = false;

        if (show) {{
          r.style.display = 'flex';
          visible++;
        }} else {{
          r.style.display = 'none';
        }}
      }});

      document.getElementById('log-count').textContent = visible;
    }}

    // ==========================================
    // LANDING PAGES TAB LOGIC (Client-side)
    // ==========================================
    let selectedLandingDomain = '';
    let landingSearchQuery = '';

    function filterPages() {{
      const q = (document.getElementById('pages-search')?.value || '').toLowerCase();
      landingSearchQuery = q;
      applyPagesFilter();
    }}

    function filterPagesByDomain(domain, btn) {{
      selectedLandingDomain = domain;
      document.querySelectorAll('.page-dom-chip').forEach(c => {{
        c.classList.remove('active', 'bg-cyan-600', 'text-white', 'border-cyan-500');
        c.classList.add('bg-white', 'text-slate-600', 'border-slate-200');
      }});
      if (btn) {{
        btn.classList.add('active', 'bg-cyan-600', 'text-white', 'border-cyan-500');
        btn.classList.remove('bg-white', 'text-slate-600', 'border-slate-200');
      }}
      applyPagesFilter();
    }}

    function applyPagesFilter() {{
      document.querySelectorAll('.landing-group-wrapper').forEach(grp => {{
        const grpDomain = grp.getAttribute('data-domain');
        const domainMatch = !selectedLandingDomain || grpDomain === selectedLandingDomain;
        let visibleCardsInGroup = 0;
        
        grp.querySelectorAll('.landing-page-card').forEach(card => {{
          const text = (card.getAttribute('data-search') || '').toLowerCase();
          const textMatch = !landingSearchQuery || text.includes(landingSearchQuery);
          if (domainMatch && textMatch) {{
            card.style.display = '';
            visibleCardsInGroup++;
          }} else {{
            card.style.display = 'none';
          }}
        }});

        grp.style.display = (domainMatch && visibleCardsInGroup > 0) ? '' : 'none';
      }});
    }}

    function openPageModal(hash) {{
      const page = (LANDING_PAGES || []).find(p => p.hash === hash);
      if (!page) return;
      document.getElementById('modal-page-title').innerText = page.title || 'Untitled';
      document.getElementById('modal-page-url').innerText = page.real_url || page.url;
      document.getElementById('modal-page-link').href = page.real_url || page.url;
      
      const statusEl = document.getElementById('modal-page-status');
      statusEl.innerText = page.status_label || (page.status_code ? page.status_code + ' OK' : 'Unknown');
      statusEl.className = 'text-[10px] font-bold px-1.5 py-0.2 rounded border ' + (page.status_badge || 'bg-slate-100 text-slate-700 border-slate-300');
      
      document.getElementById('modal-page-server').innerText = page.server || 'Unknown';
      document.getElementById('modal-page-domain').innerText = page.domain || '';
      document.getElementById('modal-page-size').innerText = page.size || '';
      
      const iframe = document.getElementById('modal-page-iframe');
      iframe.srcdoc = page.html_srcdoc || page.html_preview || '<div style="font-family:sans-serif;padding:2rem;color:#666;">No snapshot content available</div>';
      
      document.getElementById('page-preview-modal').classList.remove('hidden');
    }}

    function closePageModal() {{
      const modal = document.getElementById('page-preview-modal');
      if (modal) modal.classList.add('hidden');
      const iframe = document.getElementById('modal-page-iframe');
      if (iframe) iframe.srcdoc = '';
    }}

    window.addEventListener('keydown', (e) => {{
      if (e.key === 'Escape') closePageModal();
    }});

    // Initial load
    window.addEventListener('DOMContentLoaded', () => {{
      filterEvents();
      if (window.location.hash) {{
        const tab = window.location.hash.replace('#', '');
        switchTab(tab);
      }}
    }});
  </script>

</body>
</html>
"""


def _render_finding_card(f: Dict[str, Any]) -> str:
    risk = f['risk']
    badge_bg = "bg-slate-100 text-slate-700 border-slate-200"
    border_l = "border-l-4 border-l-slate-400"
    if risk == 'HIGH':
        badge_bg = "bg-red-50 text-red-700 border-red-200"
        border_l = "border-l-4 border-l-red-500"
    elif risk == 'MEDIUM':
        badge_bg = "bg-amber-50 text-amber-700 border-amber-200"
        border_l = "border-l-4 border-l-amber-500"
    elif risk == 'LOW':
        badge_bg = "bg-sky-50 text-sky-700 border-sky-200"
        border_l = "border-l-4 border-l-sky-500"

    return f"""
    <div class="bg-white border border-slate-200 rounded-lg p-3.5 shadow-2xs {border_l} hover:shadow-xs transition-shadow">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2 mb-1">
            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border {badge_bg}">{html.escape(risk)}</span>
            <span class="text-sm font-semibold text-slate-900 truncate">{html.escape(f['title'])}</span>
          </div>
          <p class="text-xs text-slate-600 line-clamp-2">{html.escape(f['description'])}</p>
          <p class="text-[11px] text-slate-400 mt-1 font-mono">Rule: {html.escape(f['rule_name'])}</p>
        </div>
        <div class="text-right shrink-0">
          <span class="text-base font-bold font-mono text-slate-800">{f['event_count']}</span>
          <span class="text-[10px] text-slate-400 block uppercase">events</span>
        </div>
      </div>
    </div>
    """


def _render_full_correlation_card(f: Dict[str, Any]) -> str:
    risk = f['risk']
    badge_bg = "bg-slate-100 text-slate-700 border-slate-200"
    border_l = "border-l-4 border-l-slate-400"
    if risk == 'HIGH':
        badge_bg = "bg-red-50 text-red-700 border-red-200"
        border_l = "border-l-4 border-l-red-500"
    elif risk == 'MEDIUM':
        badge_bg = "bg-amber-50 text-amber-700 border-amber-200"
        border_l = "border-l-4 border-l-amber-500"
    elif risk == 'LOW':
        badge_bg = "bg-sky-50 text-sky-700 border-sky-200"
        border_l = "border-l-4 border-l-sky-500"

    return f"""
    <div class="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs {border_l}">
      <div class="flex items-start justify-between gap-3 mb-2">
        <div>
          <div class="flex items-center gap-2 mb-1">
            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border {badge_bg}">{html.escape(risk)}</span>
            <span class="text-sm font-bold text-slate-900">{html.escape(f['title'])}</span>
          </div>
          <p class="text-xs text-slate-400 font-mono">Rule: {html.escape(f['rule_name'])} ({html.escape(f['rule_id'])})</p>
        </div>
        <div class="text-right shrink-0">
          <span class="text-lg font-bold font-mono text-slate-800">{f['event_count']}</span>
          <span class="text-xs text-slate-400 block">supporting events</span>
        </div>
      </div>
      <p class="text-xs text-slate-600 bg-slate-50 p-3 rounded-lg border border-slate-100 leading-relaxed">{html.escape(f['description'])}</p>
    </div>
    """


def _render_category_block(cat: Dict[str, Any]) -> str:
    entries_html = ""
    for item in cat.get('entries', []):
        entries_html += f"""
        <div class="bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2.5 text-center min-w-[100px] shadow-2xs badge-chip">
          <p class="text-lg font-mono font-bold text-slate-800">{item['count']:,}</p>
          <p class="text-xs text-slate-500 font-medium">{html.escape(item['label'])}</p>
        </div>
        """

    return f"""
    <div>
      <h3 class="text-xs font-bold text-slate-700 uppercase tracking-wider mb-2.5 flex items-center gap-2">
        <span>{html.escape(cat['label'])}</span>
      </h3>
      <div class="flex flex-wrap gap-2.5">
        {entries_html}
      </div>
    </div>
    """


def _render_event_summary_row(row: Any) -> str:
    # row: (type, event_descr, last_in, total, utotal)
    etype = row[0]
    descr = row[1] or etype
    total = int(row[3] or 0)
    utotal = int(row[4] or 0)
    cat = _get_type_category(etype)
    cat_label = CATEGORY_CONFIG.get(cat, {}).get('label', 'Other')

    return f"""
    <tr class="hover:bg-slate-50/80 transition-colors">
      <td class="px-4 py-2.5 text-xs text-slate-500 font-medium">{html.escape(cat_label)}</td>
      <td class="px-4 py-2.5">
        <span class="font-mono text-xs font-semibold text-slate-800">{html.escape(etype)}</span>
        <span class="text-xs text-slate-500 ml-1.5 hidden sm:inline">&middot; {html.escape(descr)}</span>
      </td>
      <td class="px-4 py-2.5 text-right font-mono text-xs text-slate-600">{utotal:,}</td>
      <td class="px-4 py-2.5 text-right font-mono text-xs font-bold text-slate-900">{total:,}</td>
      <td class="px-4 py-2.5 text-right">
        <button onclick="document.getElementById('event-type-filter').value='{html.escape(etype)}'; switchTab('data'); filterEvents();" class="text-xs font-semibold text-cyan-600 hover:text-cyan-700">Filter &rarr;</button>
      </td>
    </tr>
    """


def _render_timeline_row(t: Dict[str, Any]) -> str:
    return f"""
    <div class="flex items-center gap-4 py-2.5">
      <span class="font-mono text-xs text-slate-400 w-16 shrink-0">{html.escape(t['time'])}</span>
      <div class="w-2 h-2 rounded-full bg-cyan-600 shrink-0"></div>
      <div class="flex-1 min-w-0 flex items-center justify-between">
        <span class="font-mono text-xs font-medium text-slate-800 truncate">{html.escape(t['type'])}</span>
        <span class="text-xs text-slate-500 font-mono">({t['count']} event{'s' if t['count'] != 1 else ''})</span>
      </div>
    </div>
    """


def _render_log_entry(l: Dict[str, Any]) -> str:
    lvl = (l['type'] or 'INFO').upper()
    color_class = "text-slate-300"
    if 'ERROR' in lvl:
        color_class = "text-red-400 font-bold"
    elif 'WARN' in lvl:
        color_class = "text-amber-400"
    elif 'STATUS' in lvl:
        color_class = "text-emerald-400"
    elif 'DEBUG' in lvl:
        color_class = "text-slate-500"

    return f"""
    <div class="flex gap-3 py-0.5 hover:bg-slate-800/50 log-row" data-level="{html.escape(lvl)}">
      <span class="text-slate-500 shrink-0 w-36">{html.escape(l['time'])}</span>
      <span class="text-cyan-400 shrink-0 w-36 truncate" title="{html.escape(l['component'])}">[{html.escape(l['component'])}]</span>
      <span class="{color_class} break-all">{html.escape(l['message'])}</span>
    </div>
    """
