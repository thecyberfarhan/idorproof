"""Command-line interface for idorproof."""
import argparse
import json
import sys

from . import __version__
from .core import parse_har, audit

C = {"CONFIRMED": "\033[1;31m", "SUSPECTED": "\033[1;33m", "BLOCKED": "\033[1;32m",
     "head": "\033[1;36m", "dim": "\033[2m", "0": "\033[0m"}


def _c(use, key, text):
    return f"{C[key]}{text}{C['0']}" if use else text


def report(findings, use_color):
    counts = {"CONFIRMED": 0, "SUSPECTED": 0, "BLOCKED": 0}
    for f in findings:
        counts[f["verdict"]] += 1

    print(_c(use_color, "head", "\nidorproof - object-level authorization audit"))
    print(f"  {len(findings)} cross-account checks: "
          f"{_c(use_color, 'CONFIRMED', str(counts['CONFIRMED']) + ' confirmed')}, "
          f"{_c(use_color, 'SUSPECTED', str(counts['SUSPECTED']) + ' suspected')}, "
          f"{_c(use_color, 'BLOCKED', str(counts['BLOCKED']) + ' blocked')}\n")

    for f in findings:
        if f["verdict"] == "BLOCKED":
            continue
        tag = _c(use_color, f["verdict"], f["verdict"])
        t = f["tampered"]
        print(f"  [{tag}] {f['method']} {f['endpoint']}")
        print(f"         {f['attacker']} read {f['victim']}'s object "
              f"(id {t['from']} -> {t['to']}), HTTP {f['status']}")
        for k, v in f["evidence"]:
            print(f"         {_c(use_color, 'dim', 'leaked')} {k} = {v}")
        print(f"         {_c(use_color, 'dim', f['url'])}")
    if counts["CONFIRMED"] == 0 and counts["SUSPECTED"] == 0:
        print("  No authorization bypasses found. Every cross-account read was denied.")
    print()


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="idorproof",
        description="Prove BOLA/IDOR by replaying one user's requests with another user's ids.")
    p.add_argument("--a", required=True, metavar="HAR", help="capture of user A (logged in as themselves)")
    p.add_argument("--b", required=True, metavar="HAR", help="capture of user B")
    p.add_argument("--label-a", default="A", help="name for user A in the report (default: A)")
    p.add_argument("--label-b", default="B", help="name for user B (default: B)")
    p.add_argument("--target", metavar="URL", help="override scheme+host of replayed requests (e.g. http://localhost:8099)")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds (default: 10)")
    p.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    p.add_argument("--json", metavar="FILE", help="write full findings as JSON to FILE")
    p.add_argument("--fail-on", choices=["confirmed", "suspected", "none"], default="confirmed",
                   help="exit non-zero when findings at this level or worse exist (default: confirmed)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--version", action="version", version=f"idorproof {__version__}")
    args = p.parse_args(argv)

    try:
        cap_a, cap_b = parse_har(args.a), parse_har(args.b)
    except (OSError, ValueError) as e:
        p.error(f"could not read capture: {e}")

    findings = audit(cap_a, cap_b, args.label_a, args.label_b,
                     target=args.target, timeout=args.timeout, insecure=args.insecure)

    use_color = sys.stdout.isatty() and not args.no_color
    report(findings, use_color)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        print(f"  Full findings written to {args.json}\n")

    confirmed = sum(1 for f in findings if f["verdict"] == "CONFIRMED")
    suspected = sum(1 for f in findings if f["verdict"] == "SUSPECTED")
    if args.fail_on == "confirmed" and confirmed:
        return 1
    if args.fail_on == "suspected" and (confirmed or suspected):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
