#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
track_version.py — HTTP Enum and Fingerprinting Script
Performs http-enum style path discovery, header analysis, and response body hashing
to fingerprint server technology, PHP version, and OS signatures.

Usage:
    python track_version.py --url http://127.0.0.1:8105
"""

import argparse
import sys
import os
import urllib.parse
import urllib.request
import ssl
import hashlib
import json

COMMON_PATHS = [
    "/",
    "/index.php",
    "/robots.txt",
    "/favicon.ico",
    "/server-status",
    "/.git/HEAD",
    "/phpinfo.php",
    "/test.php",
    "/readme.html",
    "/wp-login.php"
]

def fingerprint_path(base_url: str, path: str) -> dict:
    url = base_url.rstrip("/") + path
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    res = {
        "path": path,
        "url": url,
        "status": "unreachable",
        "server": None,
        "x_powered_by": None,
        "content_md5": None,
        "content_length": 0
    }

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HttpEnumScanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            res["status"] = resp.status
            res["server"] = resp.headers.get("Server")
            res["x_powered_by"] = resp.headers.get("X-Powered-By")
            body = resp.read()
            res["content_length"] = len(body)
            res["content_md5"] = hashlib.md5(body).hexdigest()
    except urllib.error.HTTPError as e:
        res["status"] = e.code
        res["server"] = e.headers.get("Server")
        res["x_powered_by"] = e.headers.get("X-Powered-By")
        try:
            body = e.read()
            res["content_length"] = len(body)
            res["content_md5"] = hashlib.md5(body).hexdigest()
        except Exception:
            pass
    except Exception as e:
        res["error"] = str(e)

    return res

def main():
    parser = argparse.ArgumentParser(description="HTTP Enum & Fingerprinting Tool")
    parser.add_argument("--url", default="http://127.0.0.1:8105", help="Target base URL (default: http://127.0.0.1:8105)")
    args = parser.parse_args()

    print(f"[*] Starting HTTP Enum fingerprinting against: {args.url}")
    report = {
        "target": args.url,
        "findings": []
    }

    for path in COMMON_PATHS:
        finding = fingerprint_path(args.url, path)
        print(json.dumps(finding, indent=2))
        report["findings"].append(finding)

    output_dir = "E:/Work/Wangdu/websec/track_version"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "fingerprint_report.json")

    print(f"\n[*] Writing fingerprint report to '{output_path}'...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("[+] Fingerprint scan complete.")

if __name__ == "__main__":
    main()
