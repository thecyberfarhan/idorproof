#!/usr/bin/env python3
"""Record a logged-in user's requests to a HAR file, stdlib only.

This is how you would normally produce idorproof's input (your browser DevTools or
Burp can "Save as HAR" too); here it doubles as the test fixture. It visits each
path as the given user and saves the request + response so idorproof can learn that
user's data fingerprint and the ids they legitimately own.

Usage: capture.py <base_url> <bearer_token> <out.har> <path> [<path> ...]
"""
import json
import sys
import urllib.request
import urllib.error


def record(base, token, paths):
    entries = []
    for path in paths:
        url = base.rstrip("/") + path
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                status, text = r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", "replace")
        entries.append({
            "request": {"method": "GET", "url": url,
                        "headers": [{"name": "Authorization", "value": f"Bearer {token}"}]},
            "response": {"status": status,
                         "content": {"mimeType": "application/json", "text": text}},
        })
    return {"log": {"version": "1.2", "creator": {"name": "idorproof-capture"}, "entries": entries}}


def main():
    base, token, out, paths = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    har = record(base, token, paths)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2)
    print(f"wrote {out} ({len(paths)} requests)")


if __name__ == "__main__":
    main()
