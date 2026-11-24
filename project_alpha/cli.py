"""Command-line interface for Project Alpha."""

import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse

from .checks import run_all_checks
from .crawler import SurfaceCrawler
from .models import ScanReport
from .reporter import export_html, export_json, print_cli_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="project-alpha",
        description="Project Alpha — Automated Passive Web Security & OWASP Header/DOM Auditor (Authorized Testing Only)",
    )
    parser.add_argument("--url", required=True, help="Target URL to audit (e.g. http://127.0.0.1:8000)")
    parser.add_argument(
        "--mode",
        choices=["auto", "selenium", "http"],
        default="auto",
        help="Render engine: 'selenium' (headless Chrome for SPAs), 'http' (lightweight), or 'auto' (default).",
    )
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum same-origin pages to inspect (default: 10)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--output-json", help="Export structured JSON report to path")
    parser.add_argument("--output-html", help="Export dark-mode HTML audit report to path")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you have explicit authorization to audit the target.",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        parser.error("Invalid --url. Provide a full http:// or https:// URL.")

    is_local = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if not args.authorized and not is_local:
        print("[!] Refusing to audit non-local target without --authorized flag.")
        print("    Only inspect web applications you own or have written permission to assess.")
        return 2

    crawler = SurfaceCrawler(
        target_url=args.url,
        mode=args.mode,
        max_pages=args.max_pages,
        timeout=args.timeout,
    )
    pages = crawler.crawl()

    report = ScanReport(
        target=args.url,
        mode=crawler.active_mode,
        pages_scanned=len(pages),
        forms_discovered=sum(len(p.forms) for p in pages),
        findings=run_all_checks(pages),
        finished_at=datetime.now(timezone.utc).isoformat(),
    )

    print_cli_summary(report)

    if args.output_json:
        p = export_json(report, args.output_json)
        print(f"[+] JSON report saved -> {p}")
    if args.output_html:
        p = export_html(report, args.output_html)
        print(f"[+] HTML report saved -> {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
