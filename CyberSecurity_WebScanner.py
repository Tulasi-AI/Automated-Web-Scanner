#!/usr/bin/env python3
"""
Automated Web Security Header & CORS Auditor
-------------------------------------------
Audits a website you own or have permission to test for common security
headers and basic CORS misconfiguration indicators.

Usage:
    python web_scanner.py https://example.com
    python web_scanner.py https://example.com --json report.json

Notes:
- Only scan systems you own or are authorized to assess.
- This is a lightweight, non-invasive checker, not a full penetration test.
- CORS checks use a harmless Origin header and do not attempt exploitation.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency: requests\nInstall it with: python -m pip install requests", file=sys.stderr)
    raise SystemExit(2)


SECURITY_HEADERS = {
    "strict-transport-security": (
        "High",
        "Enforces HTTPS in supporting browsers. Usually appropriate for HTTPS sites."
    ),
    "content-security-policy": (
        "High",
        "Helps reduce the impact of cross-site scripting and content injection."
    ),
    "x-content-type-options": (
        "Medium",
        "Use 'nosniff' to prevent MIME-type sniffing."
    ),
    "referrer-policy": (
        "Low",
        "Controls how much referrer information browsers send."
    ),
    "permissions-policy": (
        "Low",
        "Restricts access to browser features such as camera and microphone."
    ),
    "x-frame-options": (
        "Medium",
        "Helps prevent clickjacking in older browsers; CSP frame-ancestors is a modern alternative."
    ),
}


def normalize_url(raw_url):
    """Require an explicit HTTP(S) URL and return a normalized URL."""
    raw_url = raw_url.strip()
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return raw_url


def audit(url, timeout=10):
    findings = []
    result = {
        "target": url,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "http_status": None,
        "final_url": None,
        "security_headers": {},
        "cors": {},
        "errors": [],
        "limitations": [
            "Results are indicators, not proof of exploitability.",
            "Only the initial response and one harmless CORS preflight-style request are checked.",
            "Review application behavior and browser-side access controls manually."
        ],
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Authorized-Web-Header-Auditor/1.0",
        "Accept": "*/*",
    })

    try:
        response = session.get(
            url, timeout=timeout, allow_redirects=True, stream=True
        )
        result["http_status"] = response.status_code
        result["final_url"] = response.url
        headers = {k.lower(): v.strip() for k, v in response.headers.items()}

        for name, (severity, purpose) in SECURITY_HEADERS.items():
            value = headers.get(name)
            result["security_headers"][name] = {
                "present": value is not None,
                "value": value,
                "severity_if_missing": severity,
                "purpose": purpose,
            }
            if value is None:
                findings.append({
                    "type": "missing_security_header",
                    "header": name,
                    "severity": severity,
                    "message": f"Missing {name}: {purpose}",
                })

        if urlparse(response.url).scheme == "https":
            hsts = headers.get("strict-transport-security")
            if hsts and "max-age=" not in hsts.lower():
                findings.append({
                    "type": "review_security_header",
                    "header": "strict-transport-security",
                    "severity": "Low",
                    "message": "HSTS is present but no max-age directive was detected; review its configuration.",
                })
        elif urlparse(url).scheme == "http":
            findings.append({
                "type": "target_uses_http",
                "severity": "High",
                "message": "The supplied URL uses HTTP. Test the HTTPS version if the site supports it.",
            })

        response.close()

    except requests.RequestException as exc:
        result["errors"].append(f"GET request failed: {exc}")
        result["findings"] = findings
        return result

    # Send a benign, deliberately untrusted origin to observe the server's response.
    test_origin = "https://cors-audit.invalid"
    try:
        cors_response = session.options(
            result["final_url"] or url,
            headers={
                "Origin": test_origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
            timeout=timeout,
            allow_redirects=False,
        )
        cors_headers = {k.lower(): v.strip() for k, v in cors_response.headers.items()}
        allow_origin = cors_headers.get("access-control-allow-origin")
        allow_credentials = cors_headers.get("access-control-allow-credentials", "").lower()
        allow_methods = cors_headers.get("access-control-allow-methods")
        allow_headers = cors_headers.get("access-control-allow-headers")

        wildcard = allow_origin == "*"
        reflects_test_origin = allow_origin == test_origin
        credentials_true = allow_credentials == "true"

        result["cors"] = {
            "test_origin": test_origin,
            "http_status": cors_response.status_code,
            "access_control_allow_origin": allow_origin,
            "access_control_allow_credentials": allow_credentials or None,
            "access_control_allow_methods": allow_methods,
            "access_control_allow_headers": allow_headers,
            "wildcard_origin": wildcard,
            "reflects_untrusted_test_origin": reflects_test_origin,
            "credentials_allowed": credentials_true,
        }

        if wildcard:
            findings.append({
                "type": "cors_wildcard_origin",
                "severity": "Info",
                "message": "CORS allows any origin ('*'). This is not automatically a vulnerability; review whether the exposed resources are intended to be public.",
            })
        if reflects_test_origin:
            severity = "High" if credentials_true else "Medium"
            findings.append({
                "type": "cors_origin_reflection",
                "severity": severity,
                "message": "The response echoed a deliberately untrusted Origin. Verify that the application uses a strict allowlist; risk is higher when credentials are allowed.",
            })
        if credentials_true and wildcard:
            findings.append({
                "type": "cors_wildcard_with_credentials_header",
                "severity": "Low",
                "message": "The response combines wildcard origin and credentials permission. Browsers generally reject credentialed CORS responses with ACAO '*', but review the policy and other routes.",
            })

        cors_response.close()
    except requests.RequestException as exc:
        result["errors"].append(f"CORS OPTIONS request failed: {exc}")

    result["findings"] = findings
    result["summary"] = {
        "security_headers_checked": len(SECURITY_HEADERS),
        "missing_security_headers": sum(
            1 for v in result["security_headers"].values() if not v["present"]
        ),
        "findings_count": len(findings),
    }
    return result


def print_report(report):
    print("\n=== Automated Web Security Audit ===")
    print(f"Target: {report['target']}")
    print(f"Final URL: {report.get('final_url') or 'N/A'}")
    print(f"HTTP status: {report.get('http_status') or 'N/A'}")

    print("\n-- Security headers --")
    if not report["security_headers"]:
        print("No header results available.")
    for name, item in report["security_headers"].items():
        status = "PRESENT" if item["present"] else "MISSING"
        value = f" | value: {item['value']}" if item["value"] else ""
        print(f"[{status}] {name} (severity if missing: {item['severity_if_missing']}){value}")

    print("\n-- CORS observations --")
    if report["cors"]:
        for key, value in report["cors"].items():
            print(f"{key}: {value}")
    else:
        print("No CORS results available.")

    print("\n-- Findings --")
    if report.get("findings"):
        for finding in report["findings"]:
            print(f"[{finding['severity']}] {finding['type']}: {finding['message']}")
    else:
        print("No findings recorded.")

    if report.get("errors"):
        print("\n-- Errors --")
        for error in report["errors"]:
            print(f"- {error}")

    if report.get("summary"):
        print("\n-- Summary --")
        print(json.dumps(report["summary"], indent=2))

    print("\nNote: Treat findings as leads for manual verification, not definitive proof of vulnerability.")


def main():
    parser = argparse.ArgumentParser(
        description="Audit a permitted website for common security headers and basic CORS indicators."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_path", help="Save the complete report as JSON")
    args = parser.parse_args()

    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    report = audit(url, timeout=args.timeout)
    print_report(report)

    if args.json_path:
        try:
            with open(args.json_path, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2, ensure_ascii=False)
            print(f"\nJSON report saved to: {args.json_path}")
        except OSError as exc:
            print(f"Could not save JSON report: {exc}", file=sys.stderr)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
