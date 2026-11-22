#!/usr/bin/env python3
"""A deliberately vulnerable test API for idorproof, with stdlib only.

It has three object-level endpoints that are BROKEN (any logged-in user can read
any object by changing the id in the URL) and two that are CORRECTLY scoped (they
check ownership and return 403 for someone else's object). idorproof should flag
exactly the broken ones as CONFIRMED and leave the scoped ones as BLOCKED, which is
how its false-positive rate gets tested, not just whether it runs.

Run:  python3 vulnerable_api.py [port]     (default 8099)
Auth: Authorization: Bearer <token>  ->  tok-alice (user 1) or tok-bob (user 2)
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS = {"tok-alice": 1, "tok-bob": 2}

USERS = {
    1: {"id": 1, "email": "alice@corp.test", "full_name": "Alice Anderson", "phone": "555-0101"},
    2: {"id": 2, "email": "bob@corp.test", "full_name": "Bob Brennan", "phone": "555-0202"},
}
# notes[id] = {owner, title, body}
NOTES = {
    11: {"id": 11, "owner": 1, "title": "Alice password reset", "body": "reset code 4471-ALICE"},
    22: {"id": 22, "owner": 2, "title": "Bob bank details", "body": "acct 99812-BOB"},
}
INVOICES = {
    101: {"id": 101, "owner": 1, "amount": 420, "card_last4": "1111"},
    202: {"id": 202, "owner": 2, "amount": 999, "card_last4": "2222"},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _auth(self):
        hdr = self.headers.get("Authorization", "")
        tok = hdr[7:] if hdr.startswith("Bearer ") else ""
        return TOKENS.get(tok)

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        uid = self._auth()
        if uid is None:
            return self._send(401, {"error": "unauthorized"})
        parts = [p for p in self.path.split("?")[0].split("/") if p]

        # GET /api/account  -> your own account (baseline, used for fingerprinting)
        if parts == ["api", "account"]:
            return self._send(200, USERS[uid])

        # GET /api/users/<id>/profile  -> BROKEN: no ownership check
        if len(parts) == 4 and parts[:2] == ["api", "users"] and parts[3] == "profile":
            tid = int(parts[2]) if parts[2].isdigit() else None
            if tid in USERS:
                return self._send(200, USERS[tid])          # <-- BOLA
            return self._send(404, {"error": "not found"})

        # GET /api/notes/<id>  -> BROKEN: no ownership check
        if len(parts) == 3 and parts[:2] == ["api", "notes"]:
            nid = int(parts[2]) if parts[2].isdigit() else None
            if nid in NOTES:
                return self._send(200, NOTES[nid])          # <-- BOLA
            return self._send(404, {"error": "not found"})

        # GET /api/invoices/<id>  -> BROKEN: no ownership check
        if len(parts) == 3 and parts[:2] == ["api", "invoices"]:
            iid = int(parts[2]) if parts[2].isdigit() else None
            if iid in INVOICES:
                return self._send(200, INVOICES[iid])       # <-- BOLA
            return self._send(404, {"error": "not found"})

        # GET /api/users/<id>/orders  -> CORRECT: ownership enforced
        if len(parts) == 4 and parts[:2] == ["api", "users"] and parts[3] == "orders":
            tid = int(parts[2]) if parts[2].isdigit() else None
            if tid != uid:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"owner": uid, "orders": [{"sku": f"SKU-{uid}", "qty": 1}]})

        # GET /api/settings/<id>  -> CORRECT: ownership enforced
        if len(parts) == 3 and parts[:2] == ["api", "settings"]:
            tid = int(parts[2]) if parts[2].isdigit() else None
            if tid != uid:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"owner": uid, "theme": "dark", "secret_pin": f"PIN-{uid}"})

        return self._send(404, {"error": "no such route"})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"vulnerable_api on http://127.0.0.1:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
