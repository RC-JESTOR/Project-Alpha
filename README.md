# Project Alpha

![Python](https://img.shields.io/badge/Python-3.9%2B-00ff66?style=for-the-badge&logo=python&logoColor=white)
![Selenium](https://img.shields.io/badge/Selenium-Headless%20SPA-00d2ff?style=for-the-badge&logo=selenium&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-a855f7?style=for-the-badge)

Automated passive web application security posture & OWASP compliance auditor engineered in **Python** with **Selenium** to uncover missing security headers, insecure cookies, DOM sinks, and form misconfigurations across modern web stacks.

> **Authorized Use Only:** Project Alpha performs passive defensive configuration audits and is intended solely for web applications you own or have explicit permission to evaluate.

---

## Key Capabilities

- **Dual-Engine DOM Inspection:** Uses Headless Chrome via **Selenium** (`--mode selenium` / `--mode auto`) to inspect JavaScript-rendered Single Page Applications (SPAs), with an automatic zero-dependency pure-Python HTTP fallback (`--mode http`).
- **OWASP Security Header & Banner Auditing:** Audits `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and technology banner leaks (`Server`, `X-Powered-By`).
- **Session & DOM Hygiene Analysis:** Flags cookies missing `HttpOnly`/`Secure`/`SameSite`, POST forms missing CSRF token heuristics, mixed-content form downgrades or assets, `target="_blank"` links missing `rel="noopener"`, sensitive HTML comments, and client-side DOM sinks (`innerHTML`, `document.write`, `eval`).
- **Structured Audit Reporting:** Outputs clean CLI tables, machine-readable **JSON** (`--output-json`), and standalone dark-mode **HTML** audit reports (`--output-html`).

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/RC-JESTOR/Project-Alpha.git
cd Project-Alpha

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run an authorized audit (with JSON + HTML reports)
python main.py --url http://127.0.0.1:8000 --authorized --output-json reports/audit.json --output-html reports/audit.html
```

### Run the Built-in End-to-End Test Suite

```bash
python -m unittest discover -s tests -v
```

---

## Project Structure

```text
Project-Alpha/
├── main.py
├── requirements.txt
├── project_alpha/
│   ├── __init__.py
│   ├── cli.py          # CLI argument parsing & authorization guard
│   ├── crawler.py      # Headless Selenium + pure-Python HTTP crawler
│   ├── checks.py       # Modular passive OWASP security checks
│   ├── models.py       # Finding, FormInfo, PageSnapshot & ScanReport
│   └── reporter.py     # CLI summary, JSON & Dark-Cyber HTML reports
└── tests/
    └── test_scanner.py # Local sandbox HTTP server end-to-end test
```

---

## Author

**Navida Sathsindu Wijesooriya (RC-JESTOR)**  
Cyber Security & IT Graduate | National CTF Finalist & Top Performer  
[GitHub](https://github.com/RC-JESTOR) • [LinkedIn](https://www.linkedin.com/in/navida-wijesooriya)
