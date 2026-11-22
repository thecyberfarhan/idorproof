"""Core engine for idorproof.

The idea, in one line: a request that returns another user's data to you is a
broken-object-level-authorization (BOLA / IDOR) bug. Everything here exists to
PROVE that, not guess it.

How it works:
  1. Read two captures (HAR), one per logged-in user (the "owner" of their data).
  2. Group requests into endpoint templates, e.g. GET /api/users/{id}/profile,
     by replacing id-like path segments and query values with {id}.
  3. Build a data fingerprint per user: the identifying leaf values from their own
     responses (their email, name, record contents), minus the other user's values
     and minus the id tokens themselves, so echoed ids never cause a false hit.
  4. Replay one user's request with the OTHER user's id, using the first user's
     own session. Then classify the response:
       CONFIRMED  the victim's fingerprint leaked into the attacker's response
                  (we print the exact field that leaked as evidence)
       SUSPECTED  access was granted (2xx) but no victim data was proven to leak
       BLOCKED    the server denied it (401/403/404) -> authorization worked
No status-code or response-length guessing: a finding is CONFIRMED only with the
leaked value in hand.
"""
import json
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
# headers we never replay verbatim (recomputed or connection-scoped)
SKIP_HEADERS = {"content-length", "host", "connection", "accept-encoding", "transfer-encoding"}


def id_like(value):
    """Is this path segment / query value an object id we might tamper with?"""
    if value is None:
        return False
    v = str(value)
    return bool(v.isdigit() or UUID_RE.match(v) or HEX_RE.match(v))


# ----- captures -------------------------------------------------------------
class Req:
    __slots__ = ("method", "url", "headers", "body", "status", "resp_text")

    def __init__(self, method, url, headers, body, status, resp_text):
        self.method = method.upper()
        self.url = url
        self.headers = headers        # dict, original-case keys
        self.body = body              # str or None
        self.status = status          # int or None (from capture)
        self.resp_text = resp_text    # str (captured response body)


def parse_har(path):
    """Read a HAR file into Req objects. Only GET/typical REST entries are used."""
    with open(path, encoding="utf-8") as f:
        har = json.load(f)
    reqs = []
    for entry in har.get("log", {}).get("entries", []):
        rq, rs = entry.get("request", {}), entry.get("response", {})
        url = rq.get("url")
        if not url:
            continue
        headers = {h["name"]: h["value"] for h in rq.get("headers", []) if h.get("name")}
        body = (rq.get("postData") or {}).get("text")
        resp_text = (rs.get("content") or {}).get("text") or ""
        reqs.append(Req(rq.get("method", "GET"), url, headers, body, rs.get("status"), resp_text))
    return reqs


# ----- templating + ids -----------------------------------------------------
def _parts(url):
    s = urlsplit(url)
    segs = s.path.split("/")                 # keeps leading '' so indexes are stable
    query = parse_qsl(s.query, keep_blank_values=True)
    return s, segs, query


def positions(url):
    """Return the id-bearing positions in a URL: ('p', i) path seg, ('q', j) query."""
    _, segs, query = _parts(url)
    pos = [("p", i) for i, seg in enumerate(segs) if id_like(seg)]
    pos += [("q", j) for j, (_, v) in enumerate(query) if id_like(v)]
    return pos


def template(url):
    """A stable key for the endpoint: method-agnostic path+query with ids blanked."""
    _, segs, query = _parts(url)
    tsegs = ["{id}" if id_like(s) else s for s in segs]
    tq = sorted(f"{k}={{id}}" if id_like(v) else f"{k}={v}" for k, v in query)
    return "/".join(tsegs) + ("?" + "&".join(tq) if tq else "")


def id_at(url, pos):
    _, segs, query = _parts(url)
    return segs[pos[1]] if pos[0] == "p" else query[pos[1]][1]


def with_id(url, pos, new_id):
    """Return url with the id at `pos` replaced by new_id."""
    s, segs, query = _parts(url)
    if pos[0] == "p":
        segs = list(segs); segs[pos[1]] = str(new_id)
        path, q = "/".join(segs), s.query
    else:
        query = list(query); k = query[pos[1]][0]; query[pos[1]] = (k, str(new_id))
        path, q = s.path, urlencode(query)
    return urlunsplit((s.scheme, s.netloc, path, q, s.fragment))


# ----- fingerprints ---------------------------------------------------------
def leaf_pairs(text):
    """(field_name, string_value) for every leaf in a JSON body. [] if not JSON."""
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []
    out = []

    def walk(node, key):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif isinstance(node, bool) or node is None:
            return
        else:
            out.append((key or "value", str(node)))
    walk(obj, None)
    return out


def _identifying(values):
    """Keep values distinctive enough to be real evidence (len>=4, not a bare id)."""
    return {v for v in values if len(v) >= 4 and not id_like(v)}


def fingerprint(owner_reqs, other_reqs):
    """Values that identify the owner's data and NOT the other user's."""
    own = _identifying(v for r in owner_reqs for _, v in leaf_pairs(r.resp_text))
    other = _identifying(v for r in other_reqs for _, v in leaf_pairs(r.resp_text))
    return own - other


def owned_ids(reqs):
    """{template: {pos: set(id values this user used there)}}."""
    table = {}
    for r in reqs:
        t = template(r.url)
        for pos in positions(r.url):
            table.setdefault(t, {}).setdefault(pos, set()).add(id_at(r.url, pos))
    return table


def object_index(reqs):
    """{(template, pos, id): response_text} — what each user saw for each object
    they legitimately accessed. Used to confirm a leak by matching the replayed
    response against the victim's own captured object, even when the distinguishing
    value is numeric (a card number, an amount) that the fingerprint would skip."""
    idx = {}
    for r in reqs:
        t = template(r.url)
        for pos in positions(r.url):
            idx[(t, pos, id_at(r.url, pos))] = r.resp_text
    return idx


# ----- sending --------------------------------------------------------------
def send(req, url, timeout, insecure):
    headers = {k: v for k, v in req.headers.items() if k.lower() not in SKIP_HEADERS}
    data = req.body.encode() if req.body else None
    r = urllib.request.Request(url, data=data, headers=headers, method=req.method)
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, f"__error__ {e}"


# ----- audit ----------------------------------------------------------------
def retarget(url, target):
    if not target:
        return url
    s, t = urlsplit(url), urlsplit(target)
    return urlunsplit((t.scheme or s.scheme, t.netloc or s.netloc, s.path, s.query, s.fragment))


def classify(status, resp_text, victim_fp, victim_obj=None, attacker_obj=None, vid=None, mine=None):
    """Return (verdict, evidence). Two independent ways to CONFIRM:
      1. fingerprint: a value that uniquely identifies the victim's data (their
         email, name, record text) shows up in the response;
      2. object match: the response carries values from the victim's OWN captured
         object that the attacker's own object does not have (catches numeric-only
         leaks like a card number), excluding the ids themselves."""
    if status is None or status < 200 or status >= 300:
        return "BLOCKED", []
    pairs = leaf_pairs(resp_text)
    resp_vals = {v for _, v in pairs}
    leaked = set(resp_vals & victim_fp)
    if victim_obj:
        vobj = {v for _, v in leaf_pairs(victim_obj)}
        aobj = {v for _, v in leaf_pairs(attacker_obj)} if attacker_obj else set()
        ids = {str(vid), str(mine)}
        distinguishing = {v for v in (vobj - aobj) if len(v) >= 3 and v not in ids}
        leaked |= (resp_vals & distinguishing)
    if not leaked:
        return "SUSPECTED", []
    seen, uniq = set(), []
    for k, v in pairs:
        if v in leaked and (k, v) not in seen:
            seen.add((k, v)); uniq.append((k, v))
    return "CONFIRMED", uniq[:4]


def audit(cap_a, cap_b, label_a="A", label_b="B", target=None, timeout=10, insecure=False):
    """Run both directions and return a list of finding dicts."""
    fp = {label_a: fingerprint(cap_a, cap_b), label_b: fingerprint(cap_b, cap_a)}
    owned = {label_a: owned_ids(cap_a), label_b: owned_ids(cap_b)}
    objs = {label_a: object_index(cap_a), label_b: object_index(cap_b)}
    caps = {label_a: cap_a, label_b: cap_b}
    findings, done = [], set()

    for attacker, victim in ((label_a, label_b), (label_b, label_a)):
        for r in caps[attacker]:
            t = template(r.url)
            vowned = owned[victim].get(t, {})
            for pos in positions(r.url):
                mine = id_at(r.url, pos)
                for vid in sorted(vowned.get(pos, set())):
                    if str(vid) == str(mine):
                        continue
                    url = retarget(with_id(r.url, pos, vid), target)
                    key = (attacker, r.method, t, pos, str(vid))
                    if key in done:
                        continue
                    done.add(key)
                    status, body = send(r, url, timeout, insecure)
                    verdict, evidence = classify(
                        status, body, fp[victim],
                        victim_obj=objs[victim].get((t, pos, vid)),
                        attacker_obj=objs[attacker].get((t, pos, mine)),
                        vid=vid, mine=mine)
                    findings.append({
                        "verdict": verdict, "attacker": attacker, "victim": victim,
                        "method": r.method, "endpoint": t, "url": url,
                        "tampered": {"where": pos[0], "to": str(vid), "from": str(mine)},
                        "status": status, "evidence": evidence,
                    })
    order = {"CONFIRMED": 0, "SUSPECTED": 1, "BLOCKED": 2}
    findings.sort(key=lambda f: (order[f["verdict"]], f["endpoint"]))
    return findings
