# idorproof

> Prove broken object-level authorization (BOLA / IDOR) by replaying one user's requests with another user's object ids, and confirm every finding with the exact data that leaked.

BOLA is the number one risk on the OWASP API Security Top 10, and it is still mostly found by hand in Burp. The tools that do automate it flag on status codes and response sizes, then leave you to decide whether each hit is real, which is why they are noisy. idorproof takes two logged-in users' captured traffic, replays each user's requests using the other user's object ids, and only reports a confirmed bug when it can show the victim's own data coming back in the attacker's response.

## At a glance

| | |
|---|---|
| Kind | Original |
| Status | Active |
| Language | Python |
| Requires | Python 3.9+, no dependencies |
| License | MIT |

## Why

Authorization bugs do not show up in a single request. A `GET /api/users/5/profile` looks completely normal on its own. It is only a vulnerability if user 5 is not you and the server hands you their data anyway. That is a two-session, two-identity problem, and a scanner that only ever sees one session cannot find it. idorproof is built around that fact: you give it two accounts, it does the swapping, and it decides each case by comparing what came back against what each account legitimately owns.

## What this shows

The thing that makes idorproof different from a basic IDOR script, and the part worth understanding:

- **Evidence, not guessing.** A finding is marked CONFIRMED only when the response actually contains the victim's data. It prints the leaked field, for example `email = bob@corp.test`, so there is nothing to eyeball and nothing to second-guess.
- **A three-rung confidence ladder.** CONFIRMED (the victim's data leaked), SUSPECTED (access got through with a 2xx but no victim data could be proven to leak, worth a manual look), and BLOCKED (the server denied it, so authorization worked). Most tools only give you "interesting / not interesting".
- **Two independent ways to confirm**, so numeric-only leaks are not missed: a per-user data fingerprint (the victim's email, name, record text that the other user does not have), and a direct comparison against the victim's own captured object (which catches a leaked card number or amount that a fingerprint would skip). Echoed ids are excluded from both, so the object id coming back in the response never causes a false positive.
- **Scriptable and CI-friendly.** It is a command-line tool with a JSON report and a configurable exit code, so it can run in a pipeline, not only in a GUI.

## Install

```bash
pipx install git+https://github.com/thecyberfarhan/idorproof
# or, from a clone:
pip install .
```

No third-party dependencies; the Python standard library is all it needs.

## Usage

1. Log in as user A and browse the app with your browser's DevTools (or Burp) recording, then **Save as HAR**. Do the same as user B. Each capture should include each user reading their own data.
2. Run idorproof with both captures:

```bash
idorproof --a alice.har --b bob.har --label-a alice --label-b bob
```

It replays the requests live, so point it at the same environment the captures came from (or use `--target http://localhost:8099` to send them somewhere else). `--json findings.json` writes the full report; `--fail-on confirmed` (the default) makes it exit non-zero when a real bug is found, for CI.

## How it works

1. Parse both HAR captures into requests.
2. Group requests into endpoint templates by blanking id-like path segments and query values, so `GET /api/users/1/profile` and `GET /api/users/2/profile` become one template.
3. Build each user's data fingerprint and the set of object ids they legitimately used.
4. For every template, replay one user's request with the other user's id, using the first user's session, in both directions.
5. Classify each response: CONFIRMED if the victim's data leaked (with the field as evidence), SUSPECTED if access was granted without a provable leak, BLOCKED if denied.

## Testing

A deliberately vulnerable API ships in `testbed/` with three broken endpoints and two correctly-scoped ones. The test suite stands it up, records two users, runs a full audit, and asserts that the broken endpoints are CONFIRMED, the scoped endpoints are never flagged, and every confirmation carries evidence. In other words it is tested for its false-positive rate, not just that it runs.

```bash
pip install pytest && python3 -m pytest
```

Try it by hand:

```bash
python3 testbed/vulnerable_api.py 8099 &
python3 testbed/capture.py http://127.0.0.1:8099 tok-alice alice.har /api/account /api/users/1/profile /api/notes/11 /api/invoices/101 /api/users/1/orders /api/settings/1
python3 testbed/capture.py http://127.0.0.1:8099 tok-bob   bob.har   /api/account /api/users/2/profile /api/notes/22 /api/invoices/202 /api/users/2/orders /api/settings/2
idorproof --a alice.har --b bob.har --label-a alice --label-b bob
```

## Scope and responsible use

idorproof only replays requests you supply, from accounts you control, against a target you choose. Run it only against systems you own or are explicitly authorized to test. It is a testing tool for finding your own authorization bugs before someone else does.

## License

MIT. See [LICENSE](LICENSE).
