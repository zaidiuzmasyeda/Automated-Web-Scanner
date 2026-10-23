# Automated Web Security Header Checker

## Overview
A beginner-friendly Python utility that reviews selected HTTP security response headers and optionally displays selected CORS response headers. Use only on websites you own or have explicit permission to assess.

## Files
- `web_security_scanner.py` — Python source code
- `requirements.txt` — dependency list
- `Project_Report.pdf` — project documentation
- `README.md` — setup and usage

## Requirements
Python 3.9 or later.

## Setup
Run:
```bash
python -m pip install -r requirements.txt
```

## Usage
```bash
python web_security_scanner.py https://example.com
```
Optional CORS response-header observation:
```bash
python web_security_scanner.py https://your-authorized-site.example --origin https://your-app.example
```

## How it works
The script sends a normal HTTP GET request, follows redirects, and checks for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy. If an Origin is provided, it prints selected Access-Control response headers.

## Limitations and ethics
This is not a full vulnerability scanner or penetration test. It does not crawl pages, inspect application code, test authentication, or perform a complete CORS preflight assessment. A missing header is not automatically a vulnerability and a present header does not prove a site is secure. Test only systems you own or have explicit permission to assess.

## Suggested tests
1. Run against an authorized HTTPS website.
2. Try malformed input and check validation.
3. Try an HTTP URL and observe the reminder.
4. If authorized, provide an Origin and review the CORS headers.
5. Record real outputs and take your own screenshots before submitting.
