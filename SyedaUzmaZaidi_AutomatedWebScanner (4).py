#!/usr/bin/env python3
"""Basic security-header checker for sites you own or are authorized to assess."""
import argparse
from urllib.parse import urlparse
import requests

CHECKS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

def valid_url(value):
    p = urlparse(value)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Provide a complete http:// or https:// URL.")
    if p.username or p.password:
        raise ValueError("Do not put usernames or passwords in a URL.")
    return p

def scan(url, origin=None, timeout=8):
    parsed = valid_url(url)
    result = requests.get(url, timeout=timeout, allow_redirects=True,
                          stream=True, headers={"User-Agent":"Student-Security-Header-Checker/1.0"})
    headers = {k.lower(): v for k, v in result.headers.items()}
    print("Automated Web Security Header Checker")
    print("Requested URL:", url)
    print("Final URL:", result.url)
    print("HTTP status:", result.status_code)
    print("HTTPS input:", "Yes" if parsed.scheme == "https" else "No")
    print("\nSecurity header review:")
    for key, label in CHECKS.items():
        if key in headers:
            print(f"[PRESENT] {label}: {headers[key]}")
        else:
            print(f"[REVIEW] Missing {label} ({key})")
    if parsed.scheme != "https":
        print("[REVIEW] Submitted URL uses HTTP rather than HTTPS.")
    if origin:
        print("\nObserved CORS response headers for supplied Origin:", origin)
        for key in ("access-control-allow-origin", "access-control-allow-credentials",
                    "access-control-allow-methods"):
            print(f"{key}: {headers.get(key, '(not present)')}")
        allow_origin = headers.get("access-control-allow-origin")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower()
        if allow_origin == "*" and allow_credentials == "true":
            print("[REVIEW] Check CORS policy carefully; verify actual browser/preflight behaviour.")
    print("\nLimitations: This is a basic check, not a penetration test or a guarantee of safety.")
    print("Missing headers are not automatically vulnerabilities; manually validate findings.")
    result.close()

def main():
    parser = argparse.ArgumentParser(description="Review selected HTTP security headers.")
    parser.add_argument("url", help="Full URL of an authorized test website")
    parser.add_argument("--origin", help="Optional Origin for basic CORS header observation")
    parser.add_argument("--timeout", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be from 1 to 30 seconds")
    try:
        valid_url(args.url)
        if args.origin:
            p = urlparse(args.origin)
            if p.scheme not in ("http", "https") or not p.hostname:
                parser.error("--origin must be a complete HTTP(S) origin")
        scan(args.url, args.origin, args.timeout)
    except ValueError as e:
        parser.error(str(e))
    except requests.RequestException as e:
        print("Request failed:", e)

if __name__ == "__main__":
    main()
