"""Command line interface: ``rangecert diff`` and ``rangecert explain``."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys

from .core import Policy, SpecError, fmt_interval


def _load(path: str) -> Policy:
    with open(path, encoding="utf-8") as handle:
        return Policy.parse(handle.read(), source=path)


def _point(text: str, family: int) -> int:
    try:
        if text.isdigit():
            return int(text)
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise SpecError(f"bad point {text!r}: {exc}") from exc
    if address.version != family:
        raise SpecError(f"point {text!r} is IPv{address.version}, policy is IPv{family}")
    return int(address)


def _render(diff, out) -> None:
    for change in diff.removed:
        out.write(
            f"removed  {fmt_interval(change.start, change.end, change.family)}"
            f"  labels={','.join(change.labels) or '-'}"
            f"  witness={ipaddress.ip_address(change.witness)}"
        )
        out.write("\n")
    for change in diff.added:
        out.write(
            f"added    {fmt_interval(change.start, change.end, change.family)}"
            f"  labels={','.join(change.labels) or '-'}"
            f"  witness={ipaddress.ip_address(change.witness)}"
        )
        out.write("\n")
    out.write(
        f"effective: added={len(diff.added)} removed={len(diff.removed)} "
        f"old_intervals={len(diff.old.intervals())} "
        f"new_intervals={len(diff.new.intervals())} certificate=verified\n"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rangecert",
        description="Exact interval-policy diff with a re-runnable certificate.",
    )
    parser.add_argument("--version", action="version", version="rangecert 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("diff", help="semantic diff between two policy files")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true", help="machine-readable output")

    e = sub.add_parser("explain", help="which rules cover a point")
    e.add_argument("policy")
    e.add_argument("point")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "diff":
            old, new = _load(args.old), _load(args.new)
            diff = old.diff(new)
            if args.json:
                payload = diff.as_dict()
                payload["old_source"] = args.old
                payload["new_source"] = args.new
                payload["certificate"] = "verified"
                json.dump(payload, sys.stdout, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                _render(diff, sys.stdout)
            return 0 if diff.empty else 1

        # explain
        policy = _load(args.policy)
        point = _point(args.point, policy.family)
        rules = policy.explain(point)
        if not rules:
            print(f"{args.point}: not covered")
            return 3
        for rule in rules:
            print(
                f"{args.point}: {rule.label}  "
                f"[{fmt_interval(rule.start, rule.end, rule.family)}]  "
                f"{args.policy}:{rule.line_no}  raw={rule.raw}"
            )
        return 0
    except SpecError as exc:
        print(f"rangecert: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"rangecert: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
