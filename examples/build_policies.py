"""Regenerate examples/policy-before.txt and policy-after.txt from real CIDRs.

The CIDR corpus is GitHub's public meta endpoint (api.github.com/meta), fetched
on 2026-11-21 and stored verbatim in examples/github-meta-trimmed.json.

The "after" revision deliberately contains:
  * prefix splits (text changes, same effective set),
  * one removal that is *not* covered by any other rule,
  * one addition that is not already covered.
This is what makes the example useful: textual review and semantic review tell
different stories, and rangecert shows the difference.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from rangecert import Policy  # noqa: E402

NEW_RULE = "198.51.100.0/24"


def load_entries():
    meta = json.loads((HERE / "github-meta-trimmed.json").read_text())
    seen, out = set(), []
    for key in ("hooks", "web", "git"):
        for cidr in meta[key]:
            if ":" in cidr or cidr in seen:
                continue
            seen.add(cidr)
            out.append((key, cidr))
    return out


def render(entries):
    return "".join(f"{cidr}  # {label}\n" for label, cidr in entries)


def split(cidr):
    net = ipaddress.ip_network(cidr)
    if net.version == 4 and net.prefixlen <= 31:
        return [str(sub) for sub in net.subnets(prefixlen_diff=1)]
    return [cidr]


def main():
    entries = load_entries()
    before = render(entries)
    old = Policy.parse(before)

    # pick the first rule whose removal actually changes the allowed set
    removed = None
    for label, cidr in reversed(entries):
        candidate = [(lb, c) for lb, c in entries if c != cidr]
        if old.diff(Policy.parse(render(candidate))).removed:
            removed = (label, cidr)
            break
    if removed is None:
        raise SystemExit("no effective removal candidate")

    after_entries = []
    for label, cidr in entries:
        if (label, cidr) == removed:
            continue
        for part in split(cidr):
            after_entries.append((label, part))
    if Policy.parse(render(after_entries + [("added-rule", NEW_RULE)])).diff(old).added:
        after_entries.append(("added-rule", NEW_RULE))

    after = render(after_entries)
    new = Policy.parse(after)
    diff = old.diff(new)

    (HERE / "policy-before.txt").write_text(before)
    (HERE / "policy-after.txt").write_text(after)
    print(
        json.dumps(
            {
                "before_lines": len(before.splitlines()),
                "after_lines": len(after.splitlines()),
                "removed_rule": {"label": removed[0], "cidr": removed[1]},
                "added_rule": NEW_RULE,
                "added_intervals": len(diff.added),
                "removed_intervals": len(diff.removed),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
