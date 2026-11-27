#!/usr/bin/env python3
"""Passive Email Security & Spoofing Risk Auditor (SPF, DMARC, MX, DKIM).

Reads root domains from a text file, discovers subdomains passively via crt.sh
Certificate Transparency logs, inspects DNS email-authentication records,
evaluates spoofing risk, and exports structured JSON and an interactive HTML
dashboard.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import ipaddress
import json
import logging
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import requests

TOOL_VERSION = "1.0.0"

DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mail",
    "dkim",
    "s1",
    "s2",
    "smtp",
    "mandrill",
    "sendgrid",
    "amazonses",
)

RISK_CRITICAL = "Kritisch"
RISK_HIGH = "Hoch"
RISK_MEDIUM = "Mittel"
RISK_SECURE = "Sicher / Gehärtet"

RISK_SCORE_MAP: dict[str, int] = {
    RISK_CRITICAL: 95,
    RISK_HIGH: 75,
    RISK_MEDIUM: 45,
    RISK_SECURE: 10,
}

HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
SPF_ALL_RE = re.compile(r"(?:^|\s)([+\-~?]?all)(?:\s|$)", re.IGNORECASE)
SPF_REDIRECT_RE = re.compile(r"(?:^|\s)redirect=([^\s]+)", re.IGNORECASE)
DMARC_TAG_RE = re.compile(r"\b([a-zA-Z]+)\s*=\s*([^;\s]+)")

logger = logging.getLogger("email_security_audit")


class RateLimiter:
    """Thread-safe minimum-interval rate limiter."""

    def __init__(self, min_interval_seconds: float) -> None:
        self._min_interval = max(0.0, min_interval_seconds)
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


@dataclass
class MXResult:
    status: str  # ok, no_answer, nxdomain, timeout, error
    records: list[dict[str, Any]] = field(default_factory=list)
    has_mx: bool = False
    is_null_mx: bool = False
    error: str | None = None


@dataclass
class SPFResult:
    status: str
    raw_records: list[str] = field(default_factory=list)
    primary_record: str | None = None
    present: bool = False
    multiple_records: bool = False
    qualifier: str | None = None  # -all, ~all, ?all, +all, missing, redirect
    redirect_target: str | None = None
    error: str | None = None


@dataclass
class DMARCResult:
    status: str
    record_domain: str | None = None
    raw_records: list[str] = field(default_factory=list)
    primary_record: str | None = None
    present: bool = False
    multiple_records: bool = False
    policy: str | None = None  # none, quarantine, reject
    subdomain_policy: str | None = None  # none, quarantine, reject
    pct: int | None = None
    rua: str | None = None
    ruf: str | None = None
    adkim: str | None = None
    aspf: str | None = None
    inherited_from: str | None = None
    effective_policy: str | None = None
    error: str | None = None


@dataclass
class DKIMSelectorResult:
    selector: str
    fqdn: str
    found: bool
    record_type: str | None = None  # TXT or CNAME
    value: str | None = None
    status: str = "no_answer"


@dataclass
class DomainAuditResult:
    domain: str
    root_domain: str
    is_root: bool
    checked_at: str
    dns_exists: bool
    mx: MXResult
    spf: SPFResult
    dmarc: DMARCResult
    dkim_selectors: list[DKIMSelectorResult] = field(default_factory=list)
    dkim_found_count: int = 0
    risk_level: str = RISK_MEDIUM
    risk_score: int = 45
    risk_reasons: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


def normalize_hostname(raw: str) -> str:
    """Normalize a hostname by trimming whitespace, wildcards, and trailing dots."""
    host = raw.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    return host


def is_valid_hostname(hostname: str) -> bool:
    """Validate an RFC-compliant hostname and reject IP addresses or wildcards."""
    if not hostname or len(hostname) > 253:
        return False
    if "*" in hostname or "@" in hostname or "/" in hostname or " " in hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    return all(HOSTNAME_LABEL_RE.match(label) for label in labels)


def load_domains(path: Path) -> list[str]:
    """Load, validate, and deduplicate root domains from a text file."""
    if not path.is_file():
        raise FileNotFoundError(f"Eingabedatei nicht gefunden: {path}")

    seen: set[str] = set()
    domains: list[str] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        cleaned = raw_line.split("#", 1)[0].strip()
        if not cleaned:
            continue
        domain = normalize_hostname(cleaned)
        if not is_valid_hostname(domain):
            logger.warning("Überspringe ungültige Domain in Zeile %d: %r", line_no, raw_line.strip())
            continue
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def fetch_certspotter_subdomains(
    root_domain: str,
    session: requests.Session | None = None,
    timeout: float = 15.0,
) -> list[str]:
    """Fallback passive CT discovery via SSLMate CertSpotter public API."""
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={root_domain}&include_subdomains=true&expand=dns_names"
    )
    own_session = session is None
    client = session or requests.Session()
    headers = {"User-Agent": f"EmailSecurityAudit/{TOOL_VERSION} (+defensive-audit)"}
    subdomains: set[str] = set()
    suffix = f".{root_domain}"

    try:
        resp = client.get(url, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            logger.warning("CertSpotter HTTP %d für %s", resp.status_code, root_domain)
            return []
        data = resp.json()
        if not isinstance(data, list):
            return []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for candidate in entry.get("dns_names") or []:
                if not isinstance(candidate, str):
                    continue
                host = normalize_hostname(candidate)
                if is_valid_hostname(host) and host != root_domain and host.endswith(suffix):
                    subdomains.add(host)
    except (requests.RequestException, ValueError) as exc:
        logger.warning("CertSpotter Fehler für %s: %s", root_domain, exc)
    finally:
        if own_session:
            client.close()

    return sorted(subdomains)


def fetch_crtsh_subdomains(
    root_domain: str,
    session: requests.Session | None = None,
    timeout: float = 15.0,
    max_retries: int = 2,
) -> list[str]:
    """Passively discover subdomains for a root domain using crt.sh JSON API."""
    url = f"https://crt.sh/?q=%.{root_domain}&output=json"
    own_session = session is None
    client = session or requests.Session()
    headers = {"User-Agent": f"EmailSecurityAudit/{TOOL_VERSION} (+defensive-audit)"}

    payload: list[dict[str, Any]] = []
    last_error: Exception | None = None
    fallback_needed = False

    try:
        for attempt in range(1, max_retries + 1):
            try:
                resp = client.get(url, headers=headers, timeout=timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        payload = data
                    break
                if resp.status_code in (429, 500, 502, 503, 504):
                    retry_after = resp.headers.get("Retry-After")
                    wait_s = int(retry_after) if (retry_after and retry_after.isdigit()) else min(2 ** attempt, 8)
                    wait_s = min(wait_s, 15)
                    logger.warning(
                        "crt.sh HTTP %d für %s (Versuch %d/%d) – warte %ds",
                        resp.status_code,
                        root_domain,
                        attempt,
                        max_retries,
                        wait_s,
                    )
                    if attempt < max_retries:
                        time.sleep(wait_s)
                    else:
                        fallback_needed = True
                    continue
                logger.warning("crt.sh lieferte HTTP %d für %s", resp.status_code, root_domain)
                break
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt < max_retries:
                    wait_s = min(2 ** attempt, 6)
                    logger.warning(
                        "crt.sh Fehler für %s (Versuch %d/%d): %s – warte %ds",
                        root_domain,
                        attempt,
                        max_retries,
                        exc,
                        wait_s,
                    )
                    time.sleep(wait_s)
                else:
                    fallback_needed = True
        else:
            if last_error:
                logger.error("crt.sh Abfrage für %s fehlgeschlagen: %s", root_domain, last_error)
    finally:
        if own_session:
            client.close()

    if fallback_needed:
        logger.info("Wechsle für %s auf CertSpotter-Fallback...", root_domain)
        return fetch_certspotter_subdomains(root_domain, session=session, timeout=timeout)

    subdomains: set[str] = set()
    suffix = f".{root_domain}"
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        candidates: list[str] = []
        name_value = entry.get("name_value")
        if isinstance(name_value, str):
            candidates.extend(name_value.splitlines())
        common_name = entry.get("common_name")
        if isinstance(common_name, str):
            candidates.append(common_name)

        for candidate in candidates:
            host = normalize_hostname(candidate)
            if not is_valid_hostname(host):
                continue
            if host != root_domain and host.endswith(suffix):
                subdomains.add(host)

    return sorted(subdomains)


def _build_resolver(
    timeout: float,
    lifetime: float,
    nameservers: list[str] | None = None,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def _decode_txt_rdata(rdata: Any) -> str:
    """Concatenate multi-string TXT rdata cleanly into a single string."""
    strings = getattr(rdata, "strings", None)
    if strings:
        parts = [
            part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
            for part in strings
        ]
        return "".join(parts)
    return str(rdata).strip('"')


def _safe_resolve(
    resolver: dns.resolver.Resolver,
    qname: str,
    rdtype: str,
    rate_limiter: RateLimiter,
) -> tuple[str, list[Any], str | None]:
    """Execute a DNS query with rate limiting and normalized error statuses."""
    rate_limiter.wait()
    try:
        answer = resolver.resolve(qname, rdtype)
        return "ok", list(answer), None
    except dns.resolver.NXDOMAIN:
        return "nxdomain", [], None
    except dns.resolver.NoAnswer:
        return "no_answer", [], None
    except dns.resolver.NoNameservers as exc:
        return "error", [], f"NoNameservers: {exc}"
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        return "timeout", [], f"DNS-Timeout: {exc}"
    except dns.exception.DNSException as exc:
        return "error", [], f"DNS-Fehler: {exc}"


def check_mx(
    domain: str,
    resolver: dns.resolver.Resolver,
    rate_limiter: RateLimiter,
) -> MXResult:
    status, rdatas, error = _safe_resolve(resolver, domain, "MX", rate_limiter)
    if status != "ok":
        return MXResult(status=status, error=error)

    records: list[dict[str, Any]] = []
    for rdata in rdatas:
        exchange = str(rdata.exchange).rstrip(".").lower()
        records.append({"preference": int(rdata.preference), "exchange": exchange})
    records.sort(key=lambda r: (r["preference"], r["exchange"]))

    is_null_mx = len(records) == 1 and records[0]["preference"] == 0 and records[0]["exchange"] == ""
    has_mx = len(records) > 0 and not is_null_mx
    return MXResult(
        status="ok",
        records=records,
        has_mx=has_mx,
        is_null_mx=is_null_mx,
    )


def parse_spf_record(record: str) -> tuple[str, str | None]:
    """Extract the `all` qualifier (or `redirect`) from an SPF TXT record."""
    match = SPF_ALL_RE.search(record)
    if match:
        token = match.group(1).lower()
        if token == "all":
            return "+all", None
        return token, None

    redirect_match = SPF_REDIRECT_RE.search(record)
    if redirect_match:
        return "redirect", redirect_match.group(1).lower().rstrip(".")

    return "missing", None


def check_spf(
    domain: str,
    resolver: dns.resolver.Resolver,
    rate_limiter: RateLimiter,
) -> SPFResult:
    status, rdatas, error = _safe_resolve(resolver, domain, "TXT", rate_limiter)
    if status != "ok":
        return SPFResult(status=status, error=error)

    spf_records: list[str] = []
    for rdata in rdatas:
        txt = _decode_txt_rdata(rdata).strip()
        lower_txt = txt.lower()
        if lower_txt == "v=spf1" or lower_txt.startswith("v=spf1 "):
            spf_records.append(txt)

    if not spf_records:
        return SPFResult(status="no_answer", present=False)

    primary = spf_records[0]
    qualifier, redirect_target = parse_spf_record(primary)
    return SPFResult(
        status="ok",
        raw_records=spf_records,
        primary_record=primary,
        present=True,
        multiple_records=len(spf_records) > 1,
        qualifier=qualifier,
        redirect_target=redirect_target,
    )


def parse_dmarc_record(record: str) -> dict[str, Any]:
    """Parse DMARC tags from a v=DMARC1 TXT record."""
    tags: dict[str, str] = {}
    for key, val in DMARC_TAG_RE.findall(record):
        tags[key.lower()] = val.strip()

    pct_val: int | None = None
    if "pct" in tags and tags["pct"].isdigit():
        pct_val = int(tags["pct"])

    def _norm_policy(raw: str | None) -> str | None:
        if not raw:
            return None
        val = raw.lower()
        return val if val in {"none", "quarantine", "reject"} else val

    return {
        "policy": _norm_policy(tags.get("p")),
        "subdomain_policy": _norm_policy(tags.get("sp")),
        "pct": pct_val,
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "adkim": tags.get("adkim", "").lower() or None,
        "aspf": tags.get("aspf", "").lower() or None,
    }


def check_dmarc(
    domain: str,
    resolver: dns.resolver.Resolver,
    rate_limiter: RateLimiter,
) -> DMARCResult:
    dmarc_domain = f"_dmarc.{domain}"
    status, rdatas, error = _safe_resolve(resolver, dmarc_domain, "TXT", rate_limiter)
    if status != "ok":
        return DMARCResult(status=status, record_domain=dmarc_domain, error=error)

    dmarc_records: list[str] = []
    for rdata in rdatas:
        txt = _decode_txt_rdata(rdata).strip()
        if txt.lower().startswith("v=dmarc1"):
            dmarc_records.append(txt)

    if not dmarc_records:
        return DMARCResult(status="no_answer", record_domain=dmarc_domain, present=False)

    primary = dmarc_records[0]
    parsed = parse_dmarc_record(primary)
    return DMARCResult(
        status="ok",
        record_domain=dmarc_domain,
        raw_records=dmarc_records,
        primary_record=primary,
        present=True,
        multiple_records=len(dmarc_records) > 1,
        policy=parsed["policy"],
        subdomain_policy=parsed["subdomain_policy"],
        pct=parsed["pct"],
        rua=parsed["rua"],
        ruf=parsed["ruf"],
        adkim=parsed["adkim"],
        aspf=parsed["aspf"],
        effective_policy=parsed["policy"],
    )


def apply_effective_dmarc(dmarc: DMARCResult, root_dmarc: DMARCResult | None, root_domain: str) -> None:
    """Resolve effective DMARC policy for a subdomain from its root domain if missing."""
    if dmarc.present:
        dmarc.effective_policy = dmarc.policy
        return
    if root_dmarc and root_dmarc.present:
        inherited_policy = root_dmarc.subdomain_policy or root_dmarc.policy
        dmarc.inherited_from = root_domain
        dmarc.effective_policy = inherited_policy


def check_dkim_selectors(
    domain: str,
    selectors: tuple[str, ...],
    resolver: dns.resolver.Resolver,
    rate_limiter: RateLimiter,
) -> list[DKIMSelectorResult]:
    """Best-effort check of common DKIM selector TXT and CNAME records."""
    results: list[DKIMSelectorResult] = []
    for selector in selectors:
        fqdn = f"{selector}._domainkey.{domain}"
        status, rdatas, _ = _safe_resolve(resolver, fqdn, "TXT", rate_limiter)
        if status == "ok" and rdatas:
            txt_values = [_decode_txt_rdata(r).strip() for r in rdatas]
            dkim_txt = next(
                (v for v in txt_values if "p=" in v.lower() or "v=dkim1" in v.lower()),
                None,
            )
            if dkim_txt is not None:
                results.append(
                    DKIMSelectorResult(
                        selector=selector,
                        fqdn=fqdn,
                        found=True,
                        record_type="TXT",
                        value=dkim_txt,
                        status="ok",
                    )
                )
                continue

        if status == "no_answer":
            c_status, c_rdatas, _ = _safe_resolve(resolver, fqdn, "CNAME", rate_limiter)
            if c_status == "ok" and c_rdatas:
                target = str(c_rdatas[0].target).rstrip(".").lower()
                results.append(
                    DKIMSelectorResult(
                        selector=selector,
                        fqdn=fqdn,
                        found=True,
                        record_type="CNAME",
                        value=target,
                        status="ok",
                    )
                )
                continue

        results.append(
            DKIMSelectorResult(
                selector=selector,
                fqdn=fqdn,
                found=False,
                status=status,
            )
        )
    return results


def evaluate_risk(
    domain: str,
    root_domain: str,
    is_root: bool,
    mx: MXResult,
    spf: SPFResult,
    dmarc: DMARCResult,
    dkim_found_count: int,
) -> tuple[str, int, list[str], list[str]]:
    """Evaluate spoofing risk level, numeric score, reasons, and remediation steps."""
    reasons: list[str] = []
    recommendations: list[str] = []

    enforcing_dmarc = dmarc.effective_policy in {"reject", "quarantine"}
    spf_strict = spf.present and not spf.multiple_records and spf.qualifier == "-all"
    spf_softfail = spf.present and not spf.multiple_records and spf.qualifier == "~all"
    spf_weak_or_missing = (
        not spf.present
        or spf.multiple_records
        or spf.qualifier in {"+all", "?all", "missing", None}
    )

    if spf.multiple_records:
        reasons.append("Mehrere SPF-Records vorhanden (RFC 7208 PermError – SPF wirkungslos).")
        recommendations.append(
            f"Führe alle SPF-Einträge für {domain} zu genau einem `v=spf1 ... -all`-TXT-Record zusammen."
        )

    if dmarc.multiple_records:
        reasons.append("Mehrere DMARC-Records vorhanden (RFC 7489 – Policy ungültig).")
        recommendations.append(
            f"Konsolidiere `_dmarc.{domain}` auf einen einzigen gültigen `v=DMARC1`-Record."
        )

    # Inactive subdomain explicitly hardened with `v=spf1 -all` (and no active MX)
    if not is_root and not mx.has_mx and spf_strict:
        reasons.append("Inaktive Subdomain ohne MX-Record ist explizit mit `v=spf1 -all` gehärtet.")
        if not enforcing_dmarc:
            recommendations.append(
                f"Optional: Setze auf {root_domain} `sp=reject` im DMARC-Record, um alle Subdomains zusätzlich abzusichern."
            )
        else:
            recommendations.append("Keine akute Maßnahme nötig; Konfiguration regelmäßig prüfen.")
        return RISK_SECURE, RISK_SCORE_MAP[RISK_SECURE], reasons, recommendations

    # Critical / High: No SPF (or +all / ?all / permerror) AND no enforcing DMARC
    if spf_weak_or_missing and not enforcing_dmarc:
        if spf.qualifier == "+all":
            reasons.append("SPF erlaubt mit `+all` jedem Server weltweit den Versand im Namen der Domain.")
            recommendations.append(f"Ersetze `+all` im SPF-Record von {domain} umgehend durch `-all`.")
            level = RISK_CRITICAL
        elif not spf.present:
            reasons.append("Kein SPF-Record vorhanden.")
            if not mx.has_mx:
                recommendations.append(
                    f"Setze `v=spf1 -all` für die ungenutzte {'Domain' if is_root else 'Subdomain'} {domain}."
                )
            else:
                recommendations.append(
                    f"Veröffentliche einen restriktiven SPF-Record (z. B. `v=spf1 include:<mailprovider> -all`) für {domain}."
                )
            level = RISK_CRITICAL if (mx.has_mx or is_root) else RISK_HIGH
        elif spf.qualifier == "?all":
            reasons.append("SPF nutzt neutrales `?all`, was keinen Schutz vor Spoofing bietet.")
            recommendations.append(f"Ändere `?all` im SPF-Record von {domain} auf `-all`.")
            level = RISK_HIGH
        else:
            reasons.append("SPF-Record ist unvollständig oder fehlerhaft (kein gültiges `-all`/`~all`).")
            recommendations.append(f"Korrigiere den SPF-Record von {domain} mit abschließendem `-all`.")
            level = RISK_HIGH

        if dmarc.effective_policy == "none":
            reasons.append("DMARC steht nur auf `p=none` (reiner Monitoring-Modus, keine Blockierung).")
            recommendations.append(
                f"Hebe DMARC nach Auswertung der RUA-Berichte auf `p=quarantine` oder `p=reject` an."
            )
        else:
            reasons.append("Keine durchsetzende DMARC-Policy (`p=reject` oder `p=quarantine`) aktiv.")
            target = f"_dmarc.{domain}" if is_root else f"_dmarc.{root_domain}"
            recommendations.append(
                f"Konfiguriere unter `{target}` eine DMARC-Policy (`v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@{root_domain}`)."
            )

        return level, RISK_SCORE_MAP[level], reasons, recommendations

    # Secure / Hardened: Strict SPF (-all) AND enforcing DMARC
    if spf_strict and enforcing_dmarc:
        reasons.append(f"Strenges SPF (`-all`) und durchsetzende DMARC-Policy (`{dmarc.effective_policy}`) aktiv.")
        if mx.has_mx and dkim_found_count == 0:
            reasons.append("Hinweis: Kein Standard-DKIM-Selektor gefunden (möglicherweise benutzerdefinierter Selektor).")
            recommendations.append("Prüfe, ob ein aktiver DKIM-Selektor für ausgehende Mails konfiguriert ist.")
        else:
            recommendations.append("Konfiguration ist gehärtet; DMARC-RUA-Berichte weiterhin überwachen.")
        return RISK_SECURE, RISK_SCORE_MAP[RISK_SECURE], reasons, recommendations

    # Medium: SPF ~all with p=none/missing, OR strict SPF without enforcing DMARC,
    # OR weak/missing SPF mitigated by enforcing DMARC
    if spf_softfail and not enforcing_dmarc:
        reasons.append("SPF nutzt Softfail (`~all`), aber DMARC steht auf `p=none` oder fehlt.")
        recommendations.append(f"Härte SPF auf `-all` und aktiviere DMARC `p=quarantine` oder `p=reject`.")
    elif spf_softfail and enforcing_dmarc:
        reasons.append(
            f"DMARC (`{dmarc.effective_policy}`) schützt, aber SPF nutzt noch Softfail (`~all`) statt `-all`."
        )
        recommendations.append(f"Stelle SPF für {domain} von `~all` auf `-all` um.")
    elif spf_strict and not enforcing_dmarc:
        reasons.append("Strenges SPF (`-all`) vorhanden, aber DMARC ist nicht auf `quarantine`/`reject` gesetzt.")
        recommendations.append(
            f"Aktiviere DMARC `p=quarantine` oder `p=reject` (für Subdomains zusätzlich `sp=reject` auf {root_domain})."
        )
    else:
        reasons.append(
            f"DMARC (`{dmarc.effective_policy}`) greift, jedoch fehlt ein strenger SPF-Record (`-all`)."
        )
        if not mx.has_mx:
            recommendations.append(f"Setze `v=spf1 -all` für die inaktive Subdomain {domain}.")
        else:
            recommendations.append(f"Hinterlege einen gültigen SPF-Record mit `-all` für {domain}.")

    if mx.has_mx and dkim_found_count == 0:
        recommendations.append("Stelle sicher, dass ausgehende E-Mails mit DKIM signiert werden.")

    return RISK_MEDIUM, RISK_SCORE_MAP[RISK_MEDIUM], reasons, recommendations


def audit_single_domain(
    domain: str,
    root_domain: str,
    is_root: bool,
    resolver: dns.resolver.Resolver,
    rate_limiter: RateLimiter,
    dkim_selectors: tuple[str, ...],
    root_dmarc: DMARCResult | None = None,
    skip_dkim: bool = False,
) -> DomainAuditResult:
    """Run MX, SPF, DMARC, and DKIM checks and score spoofing risk for one host."""
    mx = check_mx(domain, resolver, rate_limiter)
    spf = check_spf(domain, resolver, rate_limiter)
    dmarc = check_dmarc(domain, resolver, rate_limiter)
    if not is_root:
        apply_effective_dmarc(dmarc, root_dmarc, root_domain)

    # Skip DKIM probing if disabled or if the domain is NXDOMAIN/timing out
    if skip_dkim or (mx.status == "nxdomain" and spf.status == "nxdomain") or (
        mx.status == "timeout" and spf.status == "timeout"
    ):
        dkim_results: list[DKIMSelectorResult] = []
        dns_exists = not (mx.status == "nxdomain" and spf.status == "nxdomain")
    else:
        dns_exists = True
        dkim_results = check_dkim_selectors(domain, dkim_selectors, resolver, rate_limiter)

    dkim_found_count = sum(1 for item in dkim_results if item.found)
    risk_level, risk_score, reasons, recommendations = evaluate_risk(
        domain=domain,
        root_domain=root_domain,
        is_root=is_root,
        mx=mx,
        spf=spf,
        dmarc=dmarc,
        dkim_found_count=dkim_found_count,
    )

    return DomainAuditResult(
        domain=domain,
        root_domain=root_domain,
        is_root=is_root,
        checked_at=datetime.now(timezone.utc).isoformat(),
        dns_exists=dns_exists,
        mx=mx,
        spf=spf,
        dmarc=dmarc,
        dkim_selectors=dkim_results,
        dkim_found_count=dkim_found_count,
        risk_level=risk_level,
        risk_score=risk_score,
        risk_reasons=reasons,
        recommendations=recommendations,
    )


def build_summary(results: list[DomainAuditResult], root_domains: list[str]) -> dict[str, Any]:
    """Compute aggregate audit statistics across all audited domains."""
    risk_counts = {
        RISK_CRITICAL: 0,
        RISK_HIGH: 0,
        RISK_MEDIUM: 0,
        RISK_SECURE: 0,
    }
    spf_stats = {"strict_-all": 0, "softfail_~all": 0, "weak_or_missing": 0}
    dmarc_stats = {"reject": 0, "quarantine": 0, "none": 0, "missing": 0}
    mx_present = 0
    dkim_present = 0
    per_root: dict[str, dict[str, int]] = {
        r: {"total": 0, RISK_CRITICAL: 0, RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_SECURE: 0}
        for r in root_domains
    }

    for res in results:
        risk_counts[res.risk_level] = risk_counts.get(res.risk_level, 0) + 1
        if res.root_domain in per_root:
            per_root[res.root_domain]["total"] += 1
            per_root[res.root_domain][res.risk_level] += 1

        if res.mx.has_mx:
            mx_present += 1
        if res.dkim_found_count > 0:
            dkim_present += 1

        if res.spf.present and not res.spf.multiple_records and res.spf.qualifier == "-all":
            spf_stats["strict_-all"] += 1
        elif res.spf.present and not res.spf.multiple_records and res.spf.qualifier == "~all":
            spf_stats["softfail_~all"] += 1
        else:
            spf_stats["weak_or_missing"] += 1

        eff = res.dmarc.effective_policy
        if eff in {"reject", "quarantine", "none"}:
            dmarc_stats[eff] += 1
        else:
            dmarc_stats["missing"] += 1

    return {
        "total_targets": len(results),
        "root_domains_count": len(root_domains),
        "subdomains_count": sum(1 for r in results if not r.is_root),
        "risk_counts": risk_counts,
        "spf_stats": spf_stats,
        "dmarc_stats": dmarc_stats,
        "mx_present_count": mx_present,
        "dkim_found_domains_count": dkim_present,
        "per_root": per_root,
    }


def export_json_report(
    output_path: Path,
    results: list[DomainAuditResult],
    summary: dict[str, Any],
    duration_seconds: float,
    input_file: str,
) -> None:
    """Write the complete audit report as formatted UTF-8 JSON."""
    payload = {
        "metadata": {
            "tool": "email_security_audit",
            "version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": input_file,
            "duration_seconds": round(duration_seconds, 2),
        },
        "summary": summary,
        "results": [asdict(item) for item in results],
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_html_report(
    output_path: Path,
    results: list[DomainAuditResult],
    summary: dict[str, Any],
    duration_seconds: float,
) -> None:
    """Generate a standalone, interactive, offline-capable HTML dashboard."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Serialize minimal safe JSON for client-side filtering & charts
    client_rows = []
    for r in results:
        dkim_hits = [
            f"{d.selector} ({d.record_type}: {d.value})"
            for d in r.dkim_selectors
            if d.found
        ]
        mx_list = [f"{m['preference']} {m['exchange'] or '.'}" for m in r.mx.records]
        client_rows.append(
            {
                "domain": r.domain,
                "root": r.root_domain,
                "is_root": r.is_root,
                "dns_exists": r.dns_exists,
                "risk": r.risk_level,
                "score": r.risk_score,
                "has_mx": r.mx.has_mx,
                "is_null_mx": r.mx.is_null_mx,
                "mx_records": mx_list,
                "spf_present": r.spf.present,
                "spf_qualifier": r.spf.qualifier or "fehlend",
                "spf_record": r.spf.primary_record or "",
                "spf_multiple": r.spf.multiple_records,
                "dmarc_present": r.dmarc.present,
                "dmarc_policy": r.dmarc.policy or "fehlend",
                "dmarc_sp": r.dmarc.subdomain_policy or "",
                "dmarc_effective": r.dmarc.effective_policy or "fehlend",
                "dmarc_inherited_from": r.dmarc.inherited_from or "",
                "dmarc_record": r.dmarc.primary_record or "",
                "dkim_count": r.dkim_found_count,
                "dkim_hits": dkim_hits,
                "reasons": r.risk_reasons,
                "recommendations": r.recommendations,
            }
        )

    # Escape </script> sequences safely inside embedded JSON
    embedded_data = json.dumps(
        {"summary": summary, "rows": client_rows},
        ensure_ascii=False,
    ).replace("</", "<\\/")

    risk_counts = summary["risk_counts"]
    critical_high = risk_counts[RISK_CRITICAL] + risk_counts[RISK_HIGH]
    total = max(summary["total_targets"], 1)
    dmarc_enforced = summary["dmarc_stats"]["reject"] + summary["dmarc_stats"]["quarantine"]
    spf_strict = summary["spf_stats"]["strict_-all"]

    html_doc = f"""<!DOCTYPE html>
<html lang="de" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Email Security Audit Dashboard</title>
  <style>
    :root {{
      --bg: #0b1120;
      --surface: #111827;
      --surface-alt: #1e293b;
      --border: #334155;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --secure: #22c55e;
      --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.45);
    }}
    [data-theme="light"] {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-alt: #f1f5f9;
      --border: #cbd5e1;
      --text: #0f172a;
      --text-muted: #475569;
      --accent: #0284c7;
      --critical: #dc2626;
      --high: #ea580c;
      --medium: #ca8a04;
      --secure: #16a34a;
      --shadow: 0 4px 14px rgba(15, 23, 42, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{ max-width: 1380px; margin: 0 auto; padding: 24px; }}
    header {{
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      gap: 16px; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border);
    }}
    h1 {{ margin: 0; font-size: 1.65rem; letter-spacing: -0.02em; }}
    .subtitle {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 4px; }}
    .btn {{
      background: var(--surface-alt); color: var(--text); border: 1px solid var(--border);
      padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 0.88rem; font-weight: 500;
    }}
    .btn:hover {{ border-color: var(--accent); }}
    .kpi-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px; margin-bottom: 24px;
    }}
    .card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 18px; box-shadow: var(--shadow);
    }}
    .kpi-label {{ color: var(--text-muted); font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .kpi-value {{ font-size: 2rem; font-weight: 700; margin: 6px 0 2px; }}
    .kpi-sub {{ font-size: 0.82rem; color: var(--text-muted); }}
    .charts-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 16px; margin-bottom: 24px;
    }}
    .chart-title {{ font-size: 1rem; font-weight: 600; margin: 0 0 14px; }}
    .controls {{
      display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; align-items: center;
    }}
    input[type="search"], select {{
      background: var(--surface); color: var(--text); border: 1px solid var(--border);
      padding: 9px 12px; border-radius: 8px; font-size: 0.9rem;
    }}
    input[type="search"] {{ flex: 1 1 260px; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th, td {{ padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{
      color: var(--text-muted); font-weight: 600; font-size: 0.8rem;
      text-transform: uppercase; letter-spacing: 0.04em; cursor: pointer; user-select: none;
    }}
    tr.data-row {{ cursor: pointer; transition: background 0.15s; }}
    tr.data-row:hover {{ background: var(--surface-alt); }}
    tr.detail-row {{ display: none; background: var(--surface-alt); }}
    tr.detail-row.open {{ display: table-row; }}
    .badge {{
      display: inline-block; padding: 3px 9px; border-radius: 999px;
      font-size: 0.78rem; font-weight: 600; white-space: nowrap;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.16); color: var(--critical); border: 1px solid rgba(239,68,68,0.4); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.16); color: var(--high); border: 1px solid rgba(249,115,22,0.4); }}
    .badge-medium {{ background: rgba(234, 179, 8, 0.16); color: var(--medium); border: 1px solid rgba(234,179,8,0.4); }}
    .badge-secure {{ background: rgba(34, 197, 94, 0.16); color: var(--secure); border: 1px solid rgba(34,197,94,0.4); }}
    .badge-muted {{ background: var(--surface-alt); color: var(--text-muted); border: 1px solid var(--border); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; word-break: break-all; }}
    .detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; padding: 6px 4px; }}
    .detail-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }}
    .detail-box h4 {{ margin: 0 0 8px; font-size: 0.85rem; color: var(--accent); text-transform: uppercase; }}
    ul.clean {{ margin: 0; padding-left: 18px; }}
    ul.clean li {{ margin-bottom: 4px; }}
    .legend {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 10px; font-size: 0.82rem; color: var(--text-muted); }}
    .legend-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }}
    .bar-row {{ margin-bottom: 10px; }}
    .bar-label {{ display: flex; justify-content: space-between; font-size: 0.84rem; margin-bottom: 4px; }}
    .bar-track {{ height: 10px; background: var(--surface-alt); border-radius: 999px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 999px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Email Security Audit Dashboard</h1>
        <div class="subtitle">Erstellt: {html.escape(generated_at)} &bull; Laufzeit: {duration_seconds:.2f}s &bull; Passive CT-Discovery + DNS-Audit</div>
      </div>
      <button id="themeToggle" class="btn" type="button">Light Mode</button>
    </header>

    <section class="kpi-grid">
      <div class="card">
        <div class="kpi-label">Geprüfte Ziele</div>
        <div class="kpi-value">{summary['total_targets']}</div>
        <div class="kpi-sub">{summary['root_domains_count']} Hauptdomains &bull; {summary['subdomains_count']} Subdomains</div>
      </div>
      <div class="card">
        <div class="kpi-label">Kritisch / Hoch</div>
        <div class="kpi-value" style="color: var(--critical);">{critical_high}</div>
        <div class="kpi-sub">{(critical_high / total * 100):.1f}% Spoofing-anfällig</div>
      </div>
      <div class="card">
        <div class="kpi-label">Strenges SPF (-all)</div>
        <div class="kpi-value" style="color: var(--accent);">{spf_strict}</div>
        <div class="kpi-sub">{(spf_strict / total * 100):.1f}% Abdeckung</div>
      </div>
      <div class="card">
        <div class="kpi-label">DMARC Durchgesetzt</div>
        <div class="kpi-value" style="color: var(--secure);">{dmarc_enforced}</div>
        <div class="kpi-sub">quarantine oder reject aktiv</div>
      </div>
      <div class="card">
        <div class="kpi-label">Aktive Mailserver (MX)</div>
        <div class="kpi-value">{summary['mx_present_count']}</div>
        <div class="kpi-sub">{summary['dkim_found_domains_count']} mit gefundenem DKIM</div>
      </div>
    </section>

    <section class="charts-grid">
      <div class="card">
        <h2 class="chart-title">Risikoverteilung (Spoofing-Anfälligkeit)</h2>
        <div id="riskChartWrap" style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;"></div>
      </div>
      <div class="card">
        <h2 class="chart-title">Protokoll-Abdeckung (SPF &amp; DMARC)</h2>
        <div id="protocolChartWrap"></div>
      </div>
      <div class="card">
        <h2 class="chart-title">Risiko nach Hauptdomain</h2>
        <div id="rootChartWrap"></div>
      </div>
    </section>

    <section class="card">
      <div class="controls">
        <input id="searchInput" type="search" placeholder="Suche nach Domain, SPF/DMARC-String oder Empfehlung..." />
        <select id="riskFilter">
          <option value="ALL">Alle Risikostufen</option>
          <option value="Kritisch">Kritisch</option>
          <option value="Hoch">Hoch</option>
          <option value="Mittel">Mittel</option>
          <option value="Sicher / Gehärtet">Sicher / Gehärtet</option>
        </select>
        <select id="typeFilter">
          <option value="ALL">Haupt- &amp; Subdomains</option>
          <option value="ROOT">Nur Hauptdomains</option>
          <option value="SUB">Nur Subdomains</option>
        </select>
        <select id="rootFilter">
          <option value="ALL">Alle Hauptdomains</option>
        </select>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th data-sort="domain">Domain &#8597;</th>
              <th data-sort="risk">Risiko &#8597;</th>
              <th>MX</th>
              <th>SPF</th>
              <th>DMARC (Effektiv)</th>
              <th>DKIM</th>
              <th>Top-Empfehlung</th>
            </tr>
          </thead>
          <tbody id="auditBody"></tbody>
        </table>
      </div>
      <div id="emptyState" style="display:none;padding:24px;text-align:center;color:var(--text-muted);">
        Keine Einträge für die aktuellen Filter gefunden.
      </div>
    </section>
  </div>

  <script id="audit-data" type="application/json">{embedded_data}</script>
  <script>
    (function () {{
      const payload = JSON.parse(document.getElementById("audit-data").textContent);
      const rows = payload.rows || [];
      const summary = payload.summary || {{}};
      let sortKey = "score";
      let sortDesc = true;

      const rootEl = document.documentElement;
      const themeBtn = document.getElementById("themeToggle");
      const savedTheme = localStorage.getItem("esa_theme") || "dark";
      rootEl.setAttribute("data-theme", savedTheme);
      themeBtn.textContent = savedTheme === "dark" ? "Light Mode" : "Dark Mode";
      themeBtn.addEventListener("click", () => {{
        const next = rootEl.getAttribute("data-theme") === "dark" ? "light" : "dark";
        rootEl.setAttribute("data-theme", next);
        localStorage.setItem("esa_theme", next);
        themeBtn.textContent = next === "dark" ? "Light Mode" : "Dark Mode";
      }});

      function esc(str) {{
        return String(str ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      }}

      function riskBadgeClass(level) {{
        if (level === "Kritisch") return "badge-critical";
        if (level === "Hoch") return "badge-high";
        if (level === "Mittel") return "badge-medium";
        return "badge-secure";
      }}

      // Populate root filter
      const rootFilter = document.getElementById("rootFilter");
      const roots = Array.from(new Set(rows.map(r => r.root))).sort();
      roots.forEach(r => {{
        const opt = document.createElement("option");
        opt.value = r;
        opt.textContent = r;
        rootFilter.appendChild(opt);
      }});

      // Render Donut Chart (SVG)
      function renderRiskChart() {{
        const rc = summary.risk_counts || {{}};
        const items = [
          {{ label: "Kritisch", val: rc["Kritisch"] || 0, color: "var(--critical)" }},
          {{ label: "Hoch", val: rc["Hoch"] || 0, color: "var(--high)" }},
          {{ label: "Mittel", val: rc["Mittel"] || 0, color: "var(--medium)" }},
          {{ label: "Sicher / Gehärtet", val: rc["Sicher / Gehärtet"] || 0, color: "var(--secure)" }}
        ];
        const total = items.reduce((a, b) => a + b.val, 0) || 1;
        const r = 56, c = 2 * Math.PI * r;
        let offset = 0;
        const circles = items.map(it => {{
          const len = (it.val / total) * c;
          const seg = `<circle cx="70" cy="70" r="${{r}}" fill="none" stroke="${{it.color}}" stroke-width="20" stroke-dasharray="${{len}} ${{c - len}}" stroke-dashoffset="${{-offset}}"></circle>`;
          offset += len;
          return seg;
        }}).join("");

        const legend = items.map(it =>
          `<div><span class="legend-dot" style="background:${{it.color}}"></span>${{esc(it.label)}}: <strong>${{it.val}}</strong></div>`
        ).join("");

        document.getElementById("riskChartWrap").innerHTML = `
          <svg width="140" height="140" viewBox="0 0 140 140" style="transform:rotate(-90deg);">
            <circle cx="70" cy="70" r="${{r}}" fill="none" stroke="var(--surface-alt)" stroke-width="20"></circle>
            ${{circles}}
          </svg>
          <div style="display:flex;flex-direction:column;gap:6px;font-size:0.88rem;">${{legend}}</div>
        `;
      }}

      function renderBar(label, count, total, color) {{
        const pct = total ? Math.round((count / total) * 100) : 0;
        return `
          <div class="bar-row">
            <div class="bar-label"><span>${{esc(label)}}</span><span>${{count}} (${{pct}}%)</span></div>
            <div class="bar-track"><div class="bar-fill" style="width:${{pct}}%;background:${{color}};"></div></div>
          </div>
        `;
      }}

      function renderProtocolChart() {{
        const total = summary.total_targets || 0;
        const spf = summary.spf_stats || {{}};
        const dm = summary.dmarc_stats || {{}};
        document.getElementById("protocolChartWrap").innerHTML =
          renderBar("SPF streng (-all)", spf["strict_-all"] || 0, total, "var(--secure)") +
          renderBar("SPF Softfail (~all)", spf["softfail_~all"] || 0, total, "var(--medium)") +
          renderBar("SPF fehlend / unsicher", spf["weak_or_missing"] || 0, total, "var(--critical)") +
          renderBar("DMARC reject / quarantine", (dm.reject || 0) + (dm.quarantine || 0), total, "var(--accent)") +
          renderBar("DMARC p=none / fehlend", (dm.none || 0) + (dm.missing || 0), total, "var(--high)");
      }}

      function renderRootChart() {{
        const perRoot = summary.per_root || {{}};
        const entries = Object.entries(perRoot).slice(0, 6);
        if (!entries.length) {{
          document.getElementById("rootChartWrap").innerHTML = "<div class='subtitle'>Keine Daten</div>";
          return;
        }}
        document.getElementById("rootChartWrap").innerHTML = entries.map(([domain, st]) => {{
          const bad = (st["Kritisch"] || 0) + (st["Hoch"] || 0);
          return renderBar(`${{domain}} (${{bad}} Krit./Hoch)`, bad, st.total || 1, bad > 0 ? "var(--high)" : "var(--secure)");
        }}).join("");
      }}

      function renderTable() {{
        const q = document.getElementById("searchInput").value.trim().toLowerCase();
        const rf = document.getElementById("riskFilter").value;
        const tf = document.getElementById("typeFilter").value;
        const rof = rootFilter.value;

        let filtered = rows.filter(r => {{
          if (rf !== "ALL" && r.risk !== rf) return false;
          if (tf === "ROOT" && !r.is_root) return false;
          if (tf === "SUB" && r.is_root) return false;
          if (rof !== "ALL" && r.root !== rof) return false;
          if (q) {{
            const hay = `${{r.domain}} ${{r.spf_record}} ${{r.dmarc_record}} ${{r.recommendations.join(" ")}}`.toLowerCase();
            if (!hay.includes(q)) return false;
          }}
          return true;
        }});

        filtered.sort((a, b) => {{
          let cmp = 0;
          if (sortKey === "domain") cmp = a.domain.localeCompare(b.domain);
          else cmp = a.score - b.score;
          return sortDesc ? -cmp : cmp;
        }});

        const tbody = document.getElementById("auditBody");
        const empty = document.getElementById("emptyState");
        if (!filtered.length) {{
          tbody.innerHTML = "";
          empty.style.display = "block";
          return;
        }}
        empty.style.display = "none";

        tbody.innerHTML = filtered.map((r, idx) => {{
          const typeTag = r.is_root ? '<span class="badge badge-muted">Root</span>' : '<span class="badge badge-muted">Sub</span>';
          const mxTag = r.has_mx ? "Ja" : (r.is_null_mx ? "Null-MX" : "Nein");
          const dmarcLabel = r.dmarc_inherited_from ? `${{r.dmarc_effective}} (von ${{r.dmarc_inherited_from}})` : r.dmarc_effective;
          const topRec = r.recommendations[0] || "—";
          return `
            <tr class="data-row" data-idx="${{idx}}">
              <td><strong>${{esc(r.domain)}}</strong> ${{typeTag}}</td>
              <td><span class="badge ${{riskBadgeClass(r.risk)}}">${{esc(r.risk)}}</span></td>
              <td>${{esc(mxTag)}}</td>
              <td class="mono">${{esc(r.spf_qualifier)}}</td>
              <td class="mono">${{esc(dmarcLabel)}}</td>
              <td>${{r.dkim_count > 0 ? r.dkim_count + " gefunden" : "—"}}</td>
              <td>${{esc(topRec)}}</td>
            </tr>
            <tr class="detail-row" id="detail-${{idx}}">
              <td colspan="7">
                <div class="detail-grid">
                  <div class="detail-box">
                    <h4>DNS-Rohdaten</h4>
                    <p><strong>MX:</strong> <span class="mono">${{r.mx_records.length ? esc(r.mx_records.join(", ")) : "Keine"}}</span></p>
                    <p><strong>SPF:</strong> <span class="mono">${{esc(r.spf_record || "Kein SPF-Record")}}</span></p>
                    <p><strong>DMARC:</strong> <span class="mono">${{esc(r.dmarc_record || (r.dmarc_inherited_from ? "Geerbt von " + r.dmarc_inherited_from : "Kein DMARC-Record"))}}</span></p>
                    <p><strong>DKIM:</strong> <span class="mono">${{r.dkim_hits.length ? esc(r.dkim_hits.join(" | ")) : "Keine Standard-Selektoren gefunden"}}</span></p>
                  </div>
                  <div class="detail-box">
                    <h4>Risikobewertung &amp; Empfehlungen</h4>
                    <p><strong>Gründe:</strong></p>
                    <ul class="clean">${{r.reasons.map(x => `<li>${{esc(x)}}</li>`).join("")}}</ul>
                    <p style="margin-top:8px;"><strong>Handlungsempfehlungen:</strong></p>
                    <ul class="clean">${{r.recommendations.map(x => `<li>${{esc(x)}}</li>`).join("")}}</ul>
                  </div>
                </div>
              </td>
            </tr>
          `;
        }}).join("");

        tbody.querySelectorAll("tr.data-row").forEach(tr => {{
          tr.addEventListener("click", () => {{
            const detail = document.getElementById("detail-" + tr.dataset.idx);
            if (detail) detail.classList.toggle("open");
          }});
        }});
      }}

      document.querySelectorAll("th[data-sort]").forEach(th => {{
        th.addEventListener("click", () => {{
          const key = th.dataset.sort === "risk" ? "score" : "domain";
          if (sortKey === key) sortDesc = !sortDesc;
          else {{ sortKey = key; sortDesc = key === "score"; }}
          renderTable();
        }});
      }});

      ["searchInput", "riskFilter", "typeFilter", "rootFilter"].forEach(id => {{
        document.getElementById(id).addEventListener("input", renderTable);
        document.getElementById(id).addEventListener("change", renderTable);
      }});

      renderRiskChart();
      renderProtocolChart();
      renderRootChart();
      renderTable();
    }})();
  </script>
</body>
</html>
"""
    output_path.write_text(html_doc, encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passives E-Mail-Sicherheitsaudit (CT-Subdomains, MX, SPF, DMARC, DKIM)."
    )
    parser.add_argument("-i", "--input", type=Path, default=Path("domains.txt"), help="Pfad zur domains.txt")
    parser.add_argument("--json-output", type=Path, default=Path("audit_report.json"), help="JSON-Ausgabedatei")
    parser.add_argument("--html-output", type=Path, default=Path("audit_report.html"), help="HTML-Dashboard-Ausgabedatei")
    parser.add_argument("--workers", type=int, default=30, help="Parallele DNS-Worker (Standard: 30)")
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="DNS-Timeout pro Versuch in Sekunden (Standard: 2.0)")
    parser.add_argument("--dns-lifetime", type=float, default=3.5, help="DNS-Gesamt-Lifetime in Sekunden (Standard: 3.5)")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Mindestabstand zwischen DNS-Queries in Sekunden (Standard: 0.0)")
    parser.add_argument("--nameservers", type=str, default="", help="Kommagetrennte DNS-Server (z. B. 1.1.1.1,8.8.8.8)")
    parser.add_argument("--dkim-selectors", type=str, default="", help="Zusätzliche kommagetrennte DKIM-Selektoren")
    parser.add_argument("--skip-subdomains", action="store_true", help="Nur Hauptdomains ohne crt.sh-Subdomains prüfen")
    parser.add_argument("--skip-dkim", action="store_true", help="DKIM-Selektor-Prüfung überspringen (deutlich schneller)")
    parser.add_argument(
        "--ct-delay",
        type=float,
        default=1.5,
        help="Pause in Sekunden zwischen crt.sh-Abfragen zur Vermeidung von HTTP 429 (Standard: 1.5)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Ausführliches Debug-Logging aktivieren")
    return parser.parse_args(argv)


def run_audit(args: argparse.Namespace) -> int:
    start_ts = time.monotonic()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    root_domains = load_domains(args.input)
    if not root_domains:
        logger.error("Keine gültigen Domains in %s gefunden.", args.input)
        return 1

    nameservers = [ns.strip() for ns in args.nameservers.split(",") if ns.strip()] or None
    extra_selectors = [s.strip().lower() for s in args.dkim_selectors.split(",") if s.strip()]
    selectors = tuple(dict.fromkeys([*DEFAULT_DKIM_SELECTORS, *extra_selectors]))

    thread_local = threading.local()

    def _get_thread_resolver() -> dns.resolver.Resolver:
        res = getattr(thread_local, "resolver", None)
        if res is None:
            res = _build_resolver(args.dns_timeout, args.dns_lifetime, nameservers)
            thread_local.resolver = res
        return res

    def _audit_in_worker(
        dom: str,
        root_dom: str,
        is_root_flag: bool,
        root_dmarc_res: DMARCResult | None = None,
    ) -> DomainAuditResult:
        return audit_single_domain(
            domain=dom,
            root_domain=root_dom,
            is_root=is_root_flag,
            resolver=_get_thread_resolver(),
            rate_limiter=rate_limiter,
            dkim_selectors=selectors,
            root_dmarc=root_dmarc_res,
            skip_dkim=args.skip_dkim,
        )

    rate_limiter = RateLimiter(args.rate_limit)

    logger.info("Starte Audit für %d Hauptdomain(s)...", len(root_domains))

    # 1. Audit root domains in parallel so subdomains can inherit DMARC policies accurately
    root_results: dict[str, DomainAuditResult] = {}
    root_workers = max(1, min(args.workers, len(root_domains)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=root_workers) as executor:
        root_futures = {
            executor.submit(_audit_in_worker, root, root, True, None): root
            for root in root_domains
        }
        for future in concurrent.futures.as_completed(root_futures):
            root = root_futures[future]
            root_results[root] = future.result()

    # 2. Passive subdomain discovery via crt.sh (sequential + polite delay to prevent HTTP 429/502)
    subdomain_tasks: list[tuple[str, str]] = []
    if not args.skip_subdomains:
        seen_subs: set[str] = set(root_domains)
        with requests.Session() as session:
            for idx, root in enumerate(root_domains):
                if idx > 0 and args.ct_delay > 0:
                    time.sleep(args.ct_delay)
                subs = fetch_crtsh_subdomains(root, session=session)
                logger.info("  -> %d eindeutige Subdomain(s) für %s gefunden.", len(subs), root)
                for sub in subs:
                    if sub not in seen_subs:
                        seen_subs.add(sub)
                        subdomain_tasks.append((sub, root))

    # 3. Audit subdomains concurrently with thread-local resolvers
    all_results: list[DomainAuditResult] = list(root_results.values())
    if subdomain_tasks:
        max_workers = max(1, min(args.workers, len(subdomain_tasks)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _audit_in_worker,
                    sub,
                    root,
                    False,
                    root_results[root].dmarc,
                ): sub
                for sub, root in subdomain_tasks
            }
            for future in concurrent.futures.as_completed(futures):
                sub = futures[future]
                try:
                    all_results.append(future.result())
                except Exception as exc:
                    logger.error("Fehler bei Prüfung von %s: %s", sub, exc)

    all_results.sort(key=lambda r: (r.root_domain, not r.is_root, -r.risk_score, r.domain))
    duration = time.monotonic() - start_ts
    summary = build_summary(all_results, root_domains)

    export_json_report(args.json_output, all_results, summary, duration, str(args.input))
    generate_html_report(args.html_output, all_results, summary, duration)

    logger.info(
        "Audit abgeschlossen in %.2fs (%d Ziele). Reports: %s, %s",
        duration,
        len(all_results),
        args.json_output,
        args.html_output,
    )
    return 0


def main() -> int:
    try:
        return run_audit(parse_args())
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        logger.warning("Audit durch Benutzer abgebrochen.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
