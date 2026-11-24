"""DOM & HTTP crawler supporting Headless Selenium WebDriver with pure-Python fallback."""

from collections import deque
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .models import FormInfo, PageSnapshot

USER_AGENT = "ProjectAlpha-SecAudit/1.0 (+https://github.com/RC-JESTOR/Project-Alpha)"


class _DOMSurfaceParser(HTMLParser):
    """Lightweight HTML parser to extract links and forms without external dependencies."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.forms: List[FormInfo] = []
        self._current_form: Optional[FormInfo] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "a" and "href" in attr_map:
            href = attr_map["href"].strip()
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                self.links.append(urljoin(self.base_url, href))
        elif tag == "form":
            action = urljoin(self.base_url, attr_map.get("action", ""))
            method = (attr_map.get("method", "GET") or "GET").upper()
            self._current_form = FormInfo(page_url=self.base_url, action=action, method=method)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            self._current_form.inputs.append({
                "tag": tag,
                "name": attr_map.get("name", ""),
                "type": attr_map.get("type", "text").lower(),
                "autocomplete": attr_map.get("autocomplete", "").lower(),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def fetch_http_metadata(url: str, timeout: int = 8) -> Tuple[int, Dict[str, str], List[str], str]:
    """Fetch HTTP status, headers, Set-Cookie headers, and raw response body."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = resp.headers.get_all("Set-Cookie") or []
            raw = resp.read().decode("utf-8", errors="replace")
            return status, headers, cookies, raw
    except HTTPError as err:
        headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        cookies = err.headers.get_all("Set-Cookie") if err.headers else []
        body = err.read().decode("utf-8", errors="replace") if err.fp else ""
        return err.code, headers, cookies or [], body
    except URLError:
        return 0, {}, [], ""


class SurfaceCrawler:
    """Crawls same-origin pages using Headless Selenium (SPA-ready) or HTTP fallback."""

    def __init__(self, target_url: str, mode: str = "auto", max_pages: int = 10, timeout: int = 8):
        self.target_url = target_url.rstrip("/")
        self.mode = mode
        self.max_pages = max(1, max_pages)
        self.timeout = timeout
        self.origin = urlparse(self.target_url).netloc
        self._driver = None
        self.active_mode = "http"

    def _init_selenium(self) -> bool:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            opts = Options()
            opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument(f"--user-agent={USER_AGENT}")
            self._driver = webdriver.Chrome(options=opts)
            self._driver.set_page_load_timeout(self.timeout)
            self.active_mode = "selenium"
            return True
        except Exception:
            self._driver = None
            self.active_mode = "http"
            return False

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    def crawl(self) -> List[PageSnapshot]:
        if self.mode in ("selenium", "auto"):
            ok = self._init_selenium()
            if not ok and self.mode == "selenium":
                raise RuntimeError(
                    "Selenium headless Chrome driver could not be initialized. "
                    "Install Chrome/ChromeDriver or re-run with --mode http."
                )

        visited: Set[str] = set()
        queue: deque = deque([self.target_url])
        snapshots: List[PageSnapshot] = []

        try:
            while queue and len(snapshots) < self.max_pages:
                current = queue.popleft()
                norm = current.split("#")[0]
                if norm in visited:
                    continue
                visited.add(norm)

                status, headers, cookies, raw_html = fetch_http_metadata(norm, timeout=self.timeout)
                if status == 0 and self._driver is None:
                    continue

                rendered_html = raw_html
                rendered_via = "http"

                if self._driver is not None:
                    try:
                        self._driver.get(norm)
                        rendered_html = self._driver.page_source or raw_html
                        rendered_via = "selenium"
                    except Exception:
                        rendered_via = "http"

                parser = _DOMSurfaceParser(norm)
                parser.feed(rendered_html)

                snap = PageSnapshot(
                    url=norm,
                    status_code=status,
                    headers=headers,
                    cookies=cookies,
                    html=rendered_html,
                    links=parser.links,
                    forms=parser.forms,
                    rendered_via=rendered_via,
                )
                snapshots.append(snap)

                for link in parser.links:
                    parsed = urlparse(link)
                    if parsed.scheme in ("http", "https") and parsed.netloc == self.origin:
                        clean_link = link.split("#")[0]
                        if clean_link not in visited:
                            queue.append(clean_link)
        finally:
            self.close()

        return snapshots
