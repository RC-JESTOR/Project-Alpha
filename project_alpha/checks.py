"""Modular passive OWASP defensive security checks for Project Alpha."""

import re
from typing import List

from .models import Finding, PageSnapshot

REQUIRED_SECURITY_HEADERS = [
    (
        "content-security-policy",
        "MEDIUM",
        "Missing Content-Security-Policy (CSP) Header",
        "Define a strict Content-Security-Policy header restricting script-src and object-src.",
    ),
    (
        "x-frame-options",
        "LOW",
        "Missing X-Frame-Options Clickjacking Protection",
        "Set X-Frame-Options: DENY (or SAMEORIGIN) alongside CSP frame-ancestors.",
    ),
    (
        "x-content-type-options",
        "LOW",
        "Missing X-Content-Type-Options Header",
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    ),
    (
        "referrer-policy",
        "INFO",
        "Missing Referrer-Policy Header",
        "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    ),
    (
        "permissions-policy",
        "INFO",
        "Missing Permissions-Policy Header",
        "Restrict unused browser features via Permissions-Policy.",
    ),
]

DANGEROUS_DOM_SINKS = [
    (r"document\.write\s*\(", "document.write() DOM sink"),
    (r"\.innerHTML\s*=", "Direct innerHTML assignment"),
    (r"\beval\s*\(", "Dynamic eval() execution"),
    (r"new\s+Function\s*\(", "Dynamic Function constructor"),
]

CSRF_NAME_HINTS = ("csrf", "xsrf", "token", "nonce", "authenticity")


def check_security_headers(page: PageSnapshot) -> List[Finding]:
    """Audit HTTP response headers against OWASP Secure Headers best practices."""
    findings: List[Finding] = []
    headers = page.headers

    for header_key, severity, title, remediation in REQUIRED_SECURITY_HEADERS:
        if header_key not in headers:
            findings.append(
                Finding(
                    id=f"HDR-{header_key.upper()}",
                    title=title,
                    severity=severity,
                    category="HTTP Security Headers",
                    url=page.url,
                    evidence=f"Header '{header_key}' absent in HTTP {page.status_code} response.",
                    remediation=remediation,
                )
            )

    if page.url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="HDR-HSTS",
                title="Missing Strict-Transport-Security (HSTS) on HTTPS Endpoint",
                severity="MEDIUM",
                category="Transport Security",
                url=page.url,
                evidence="HTTPS response omitted Strict-Transport-Security header.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )

    for leak_hdr in ("server", "x-powered-by", "x-aspnet-version"):
        if leak_hdr in headers and headers[leak_hdr].strip():
            findings.append(
                Finding(
                    id=f"INFO-{leak_hdr.upper()}",
                    title=f"Technology Banner Disclosure ({leak_hdr})",
                    severity="INFO",
                    category="Information Disclosure",
                    url=page.url,
                    evidence=f"{leak_hdr}: {headers[leak_hdr]}",
                    remediation=f"Suppress or genericize the '{leak_hdr}' response header.",
                )
            )

    return findings


def check_cookies(page: PageSnapshot) -> List[Finding]:
    """Verify Set-Cookie headers enforce HttpOnly, Secure (HTTPS), and SameSite."""
    findings: List[Finding] = []
    for raw_cookie in page.cookies:
        lower = raw_cookie.lower()
        cookie_name = raw_cookie.split("=", 1)[0].strip()
        missing_flags = []
        if "httponly" not in lower:
            missing_flags.append("HttpOnly")
        if page.url.startswith("https://") and "secure" not in lower:
            missing_flags.append("Secure")
        if "samesite" not in lower:
            missing_flags.append("SameSite")

        if missing_flags:
            findings.append(
                Finding(
                    id="COOKIE-FLAGS",
                    title=f"Insecure Cookie Flags on '{cookie_name}'",
                    severity="MEDIUM" if "HttpOnly" in missing_flags else "LOW",
                    category="Session Management",
                    url=page.url,
                    evidence=f"Missing flags: {', '.join(missing_flags)} (Set-Cookie: {cookie_name}=...)",
                    remediation="Set HttpOnly, Secure (on HTTPS), and SameSite=Lax/Strict on session cookies.",
                )
            )
    return findings


def check_dom_and_forms(page: PageSnapshot) -> List[Finding]:
    """Passively inspect rendered DOM for form hardening, unsafe sinks, and asset hygiene."""
    findings: List[Finding] = []

    for form in page.forms:
        if form.method == "POST":
            has_csrf = any(
                any(hint in (inp.get("name", "").lower()) for hint in CSRF_NAME_HINTS)
                for inp in form.inputs
            )
            if not has_csrf:
                findings.append(
                    Finding(
                        id="FORM-CSRF",
                        title="POST Form Missing Anti-CSRF Token Heuristic",
                        severity="MEDIUM",
                        category="Cross-Site Request Forgery",
                        url=page.url,
                        evidence=f"POST form targeting '{form.action}' has no recognizable CSRF token field.",
                        remediation="Include a per-session cryptographically random anti-CSRF token and validate SameSite cookies.",
                    )
                )

        if page.url.startswith("https://") and form.action.startswith("http://"):
            findings.append(
                Finding(
                    id="FORM-MIXED",
                    title="HTTPS Form Submits Over Cleartext HTTP",
                    severity="HIGH",
                    category="Transport Security",
                    url=page.url,
                    evidence=f"Form action '{form.action}' downgrades submission to HTTP.",
                    remediation="Serve and submit all form endpoints exclusively over HTTPS.",
                )
            )

    for pattern, label in DANGEROUS_DOM_SINKS:
        if re.search(pattern, page.html, flags=re.IGNORECASE):
            findings.append(
                Finding(
                    id="DOM-SINK",
                    title=f"Potential DOM-XSS Sink Detected ({label})",
                    severity="LOW",
                    category="Client-Side Security",
                    url=page.url,
                    evidence=f"Matched pattern '{label}' in rendered page source.",
                    remediation="Prefer textContent / createElement over unsafe HTML sinks, and enforce strict CSP.",
                )
            )

    blank_links = re.findall(r"""<a\b[^>]*target\s*=\s*['"]_blank['"][^>]*>""", page.html, flags=re.IGNORECASE)
    unsafe_blanks = [a for a in blank_links if "noopener" not in a.lower()]
    if unsafe_blanks:
        findings.append(
            Finding(
                id="DOM-TABNABBING",
                title="External target='_blank' Links Missing rel='noopener'",
                severity="LOW",
                category="Client-Side Security",
                url=page.url,
                evidence=f"Detected {len(unsafe_blanks)} anchor tag(s) with target='_blank' lacking rel='noopener'.",
                remediation="Add rel='noopener noreferrer' to all target='_blank' links.",
            )
        )

    if page.url.startswith("https://"):
        mixed_assets = re.findall(r"""(?:src|href)\s*=\s*['"]http://[^'"]+['"]""", page.html, flags=re.IGNORECASE)
        if mixed_assets:
            findings.append(
                Finding(
                    id="TLS-MIXED-CONTENT",
                    title="Mixed-Content Subresources Loaded Over HTTP",
                    severity="MEDIUM",
                    category="Transport Security",
                    url=page.url,
                    evidence=f"Found {len(mixed_assets)} cleartext http:// asset reference(s) on an HTTPS page.",
                    remediation="Upgrade all scripts, stylesheets, and media URLs to HTTPS.",
                )
            )

    sensitive_comments = re.findall(
        r"<!--[^>]*(?:TODO|FIXME|password|secret|apikey|api_key|debug)[^>]*-->",
        page.html,
        flags=re.IGNORECASE,
    )
    if sensitive_comments:
        findings.append(
            Finding(
                id="INFO-COMMENT",
                title="Sensitive Developer Comment in HTML Source",
                severity="LOW",
                category="Information Disclosure",
                url=page.url,
                evidence=f"Found {len(sensitive_comments)} comment(s) containing debug/secret keywords.",
                remediation="Strip internal developer notes and credentials from production templates.",
            )
        )

    return findings


def run_all_checks(pages: List[PageSnapshot]) -> List[Finding]:
    """Run all passive defensive checks across crawled page snapshots."""
    all_findings: List[Finding] = []
    seen_keys = set()

    for page in pages:
        batch = []
        batch.extend(check_security_headers(page))
        batch.extend(check_cookies(page))
        batch.extend(check_dom_and_forms(page))

        for f in batch:
            dedup = (f.id, f.url, f.title)
            if dedup not in seen_keys:
                seen_keys.add(dedup)
                all_findings.append(f)

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda item: severity_rank.get(item.severity.upper(), 9))
    return all_findings
