"""End-to-end tests: run idorproof against the bundled vulnerable API and assert
it confirms exactly the broken endpoints and blocks the correctly-scoped ones,
with zero false positives. Also unit-tests the templating and fingerprint logic."""
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from idorproof.core import (audit, parse_har, template, positions, id_like,
                            fingerprint, Req)
from testbed.vulnerable_api import Handler
from testbed import capture

ALICE = ("tok-alice", ["/api/account", "/api/users/1/profile", "/api/notes/11",
                       "/api/invoices/101", "/api/users/1/orders", "/api/settings/1"])
BOB = ("tok-bob", ["/api/account", "/api/users/2/profile", "/api/notes/22",
                   "/api/invoices/202", "/api/users/2/orders", "/api/settings/2"])


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _caps(server, tmp_path):
    out = {}
    for name, (tok, paths) in {"alice": ALICE, "bob": BOB}.items():
        har = capture.record(server, tok, paths)
        f = tmp_path / f"{name}.har"
        f.write_text(json.dumps(har))
        out[name] = parse_har(str(f))
    return out["alice"], out["bob"]


def test_confirms_broken_blocks_scoped(server, tmp_path):
    a, b = _caps(server, tmp_path)
    findings = audit(a, b, "alice", "bob", target=server)
    by_ep = {}
    for f in findings:
        by_ep.setdefault(f["endpoint"], set()).add(f["verdict"])

    # the three broken endpoints must be CONFIRMED
    for ep in ("/api/users/{id}/profile", "/api/notes/{id}", "/api/invoices/{id}"):
        assert "CONFIRMED" in by_ep[ep], f"{ep} should be confirmed, got {by_ep.get(ep)}"

    # the two correctly-scoped endpoints must NEVER be confirmed or suspected
    for ep in ("/api/users/{id}/orders", "/api/settings/{id}"):
        assert by_ep.get(ep, set()) <= {"BLOCKED"}, f"{ep} false positive: {by_ep.get(ep)}"


def test_confirmed_findings_carry_evidence(server, tmp_path):
    a, b = _caps(server, tmp_path)
    findings = audit(a, b, "alice", "bob", target=server)
    confirmed = [f for f in findings if f["verdict"] == "CONFIRMED"]
    assert confirmed, "expected at least one confirmed finding"
    for f in confirmed:
        assert f["evidence"], f"confirmed finding without evidence: {f['endpoint']}"


def test_both_directions_detected(server, tmp_path):
    a, b = _caps(server, tmp_path)
    findings = audit(a, b, "alice", "bob", target=server)
    profile = [f for f in findings if f["endpoint"] == "/api/users/{id}/profile"
               and f["verdict"] == "CONFIRMED"]
    attackers = {f["attacker"] for f in profile}
    assert attackers == {"alice", "bob"}, f"expected both directions, got {attackers}"


def test_no_leak_means_no_false_positive(server, tmp_path):
    # if both users are the SAME account, nothing is cross-account, so nothing confirms
    har = capture.record(server, "tok-alice", ALICE[1])
    f = tmp_path / "a.har"; f.write_text(json.dumps(har))
    same = parse_har(str(f))
    findings = audit(same, same, "a1", "a2", target=server)
    assert not [x for x in findings if x["verdict"] == "CONFIRMED"]


def test_template_and_id_helpers():
    assert id_like("123") and id_like("a1b2c3d4e5f6a1b2") and not id_like("profile")
    assert template("http://h/api/users/5/profile") == "/api/users/{id}/profile"
    assert template("http://h/api/notes/22") == "/api/notes/{id}"
    assert ("p", 3) in positions("http://h/api/users/5/profile")


def test_fingerprint_excludes_shared_and_ids():
    owner = [Req("GET", "http://h/x", {}, None, 200, '{"email":"bob@corp.test","id":2}')]
    other = [Req("GET", "http://h/x", {}, None, 200, '{"email":"alice@corp.test","id":1}')]
    fp = fingerprint(owner, other)
    assert "bob@corp.test" in fp
    assert "alice@corp.test" not in fp   # the other user's value
    assert "2" not in fp                 # a bare id
