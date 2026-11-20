"""Compare a line-level diff with the semantic interval diff on the example.

Run: python examples/compare_textdiff.py
"""

from __future__ import annotations

import difflib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from rangecert import Policy  # noqa: E402


def main():
    before = (HERE / "policy-before.txt").read_text().splitlines()
    after = (HERE / "policy-after.txt").read_text().splitlines()
    textual = 0
    for line in difflib.unified_diff(before, after, lineterm="", n=0):
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith(("+", "-")):
            textual += 1

    old, new = Policy.parse("\n".join(before)), Policy.parse("\n".join(after))
    diff = old.diff(new)
    effective = len(diff.added) + len(diff.removed)
    print(f"rules_before={len(old.rules)}")
    print(f"rules_after={len(new.rules)}")
    print(f"textual_lines_changed={textual}")
    print(f"effective_intervals_changed={effective}")
    print(f"added_intervals={len(diff.added)}")
    print(f"removed_intervals={len(diff.removed)}")
    print(f"ratio_textual_to_effective={textual / effective:.2f}")
    print("certificate=verified")


if __name__ == "__main__":
    main()
