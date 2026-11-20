from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from rangecert import Diff, Interval, Policy, Rule, SpecError, parse_spec

ROOT = Path(__file__).resolve().parents[1]


def rules_from_pairs(pairs, label="r"):
    return [Rule(f"{label}{i}", a, b, 4, f"{a}-{b - 1}", i + 1) for i, (a, b) in enumerate(pairs)]


def bits(rules, size=256):
    out = [False] * size
    for r in rules:
        for i in range(max(0, r.start), min(size, r.end)):
            out[i] = True
    return out


def runs(flags):
    out, i = [], 0
    while i < len(flags):
        if not flags[i]:
            i += 1
            continue
        j = i
        while j < len(flags) and flags[j]:
            j += 1
        out.append((i, j))
        i = j
    return out


class TestParsing:
    def test_cidr_v4_boundaries(self):
        assert parse_spec("9.234.106.48/28") == (
            int.from_bytes(bytes([9, 234, 106, 48]), "big"),
            int.from_bytes(bytes([9, 234, 106, 63]), "big") + 1,
            4,
        )
        assert parse_spec("0.0.0.0/0")[1] == 2**32

    def test_cidr_v6(self):
        start, end, fam = parse_spec("2001:db8::/32")
        assert fam == 6 and start == int.from_bytes(bytes.fromhex("20010db8" + "00" * 12), "big")
        assert end - start == 2**96

    def test_range_single_bare_ip(self):
        assert parse_spec("80-90") == (80, 91, 4)
        assert parse_spec("443") == (443, 444, 4)
        assert parse_spec("10.0.0.7") == (0x0A000007, 0x0A000008, 4)

    def test_rejects_reversed_and_empty(self):
        with pytest.raises(SpecError):
            parse_spec("90-80")
        with pytest.raises(SpecError):
            parse_spec("   ")

    def test_mixed_family_rejected(self):
        with pytest.raises(SpecError, match="mixed"):
            Policy.parse("10.0.0.0/8\n2001:db8::/32")

    def test_labels_from_trailing_comment(self):
        policy = Policy.parse("10.0.0.0/24  # web\n10.0.1.0/24  # db\n")
        assert [r.label for r in policy.rules] == ["web", "db"]


class TestNormalize:
    def test_merges_overlap_and_adjacent(self):
        policy = Policy.parse("10.0.0.0/25\n10.0.0.128/25\n10.0.0.0/24\n")
        intervals = policy.intervals()
        assert len(intervals) == 1
        assert len(intervals[0].labels) == 3

    def test_keeps_gap(self):
        policy = Policy.parse("10.0.0.0/24\n10.0.2.0/24\n")
        assert len(policy.intervals()) == 2


class TestDiff:
    def test_identical_is_empty(self):
        a = Policy.parse("10.0.0.0/24\n")
        assert a.diff(Policy.parse("10.0.0.0/24\n")).empty

    def test_add_and_remove(self):
        old = Policy.parse("10.0.0.0/24\n")
        new = Policy.parse("10.0.1.0/24\n")
        diff = old.diff(new)
        assert [(c.start, c.end) for c in diff.added] == [(0x0A000100, 0x0A000200)]
        assert [(c.start, c.end) for c in diff.removed] == [(0x0A000000, 0x0A000100)]
        diff.verify()

    def test_subset_leaves_only_removal(self):
        old = Policy.parse("10.0.0.0/23\n")
        new = Policy.parse("10.0.0.0/24\n")
        diff = old.diff(new)
        assert not diff.added
        assert [(c.start, c.end) for c in diff.removed] == [(0x0A000100, 0x0A000200)]

    def test_split_pieces_are_merged(self):
        old = Policy.parse("10.0.0.0/24\n")
        new = Policy.parse("10.0.0.0/26\n10.0.0.64/26\n10.0.0.128/25\n")
        assert old.diff(new).empty

    def test_witness_is_in_target_only(self):
        old = Policy.parse("10.0.0.0/24\n")
        new = Policy.parse("10.0.0.128/25\n")
        diff = old.diff(new)
        for change in diff.removed:
            assert old.contains(change.witness)
            assert not new.contains(change.witness)

    def test_tampered_certificate_is_rejected(self):
        old = Policy.parse("10.0.0.0/24\n")
        new = Policy.parse("10.0.1.0/24\n")
        good = old.diff(new)
        bad = Diff(old, new, good.added, [])
        with pytest.raises(AssertionError):
            bad.verify()

    def test_minimality_rejects_adjacent_pieces(self):
        old = Policy.parse("10.0.0.0/24\n")
        new = Policy.parse("10.0.2.0/24\n")
        good = old.diff(new)
        a, b = good.removed[0], good.removed[0]
        # forge two adjacent pieces covering the same span
        mid = a.start + 1
        forged = Diff(
            old,
            new,
            good.added,
            [
                type(a)(a.start, mid, a.family, a.labels, a.start),
                type(a)(mid, a.end, a.family, a.labels, mid),
            ],
        )
        with pytest.raises(AssertionError, match="non-maximal"):
            forged.verify()

    def test_explain_overlapping_rules(self):
        policy = Policy.parse("10.0.0.0/24  # web\n10.0.0.0/25  # batch\n")
        assert [r.label for r in policy.explain(0x0A000001)] == ["web", "batch"]
        assert [r.label for r in policy.explain(0x0A0000FF)] == ["web"]
        assert policy.explain(0x0A000200) == []


class TestRandomDifferential:
    def test_2500_random_policies_match_bitmask_oracle(self):
        rng = random.Random(20261121)
        seen = set()
        for _ in range(2500):
            old_rules = [
                Rule(f"o{i}", a, b, 4, "", i)
                for i, (a, b) in enumerate(
                    (lambda a: (a, min(256, a + rng.randint(1, 12))))(rng.randrange(0, 250))
                    for _ in range(rng.randint(1, 6))
                )
            ]
            new_rules = [
                Rule(f"n{i}", a, b, 4, "", i)
                for i, (a, b) in enumerate(
                    (lambda a: (a, min(256, a + rng.randint(1, 12))))(rng.randrange(0, 250))
                    for _ in range(rng.randint(1, 6))
                )
            ]
            key = json.dumps([[r.start, r.end] for r in old_rules] + [[r.start, r.end] for r in new_rules])
            seen.add(hashlib.sha256(key.encode()).hexdigest())

            old, new = Policy(old_rules), Policy(new_rules)
            diff = old.diff(new)
            old_b, new_b = bits(old_rules), bits(new_rules)
            added = [new_b[i] and not old_b[i] for i in range(256)]
            removed = [old_b[i] and not new_b[i] for i in range(256)]
            assert [(c.start, c.end) for c in diff.added] == runs(added)
            assert [(c.start, c.end) for c in diff.removed] == runs(removed)
        assert len(seen) >= 2400, f"only {len(seen)} independent samples"
        print(f"independent_samples={len(seen)}")

    def test_family_mismatch_diff_rejected(self):
        v4 = Policy.parse("10.0.0.0/24\n")
        v6 = Policy.parse("2001:db8::/32\n")
        with pytest.raises(SpecError):
            v4.diff(v6)


class TestExample:
    def test_github_meta_example_certificate_and_textual_gap(self):
        old = Policy.parse((ROOT / "examples/policy-before.txt").read_text())
        new = Policy.parse((ROOT / "examples/policy-after.txt").read_text())
        diff = old.diff(new)
        assert len(diff.added) == 1 and len(diff.removed) == 1
        assert diff.added[0].start == int.from_bytes(bytes([198, 51, 100, 0]), "big")
        # 176 textual line edits collapse to 2 effective intervals; the point of
        # the fixture is that the ratio is reproducible.
        assert len(old.rules) == 112 and len(new.rules) == 170


class TestCli:
    def run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "rangecert.cli", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_diff_exit_codes_and_output(self, tmp_path):
        a, b = tmp_path / "a.txt", tmp_path / "b.txt"
        a.write_text("10.0.0.0/24\n")
        b.write_text("10.0.0.0/24\n")
        assert self.run("diff", str(a), str(b)).returncode == 0
        b.write_text("10.0.1.0/24\n")
        result = self.run("diff", str(a), str(b))
        assert result.returncode == 1
        assert "effective: added=1 removed=1" in result.stdout
        assert "certificate=verified" in result.stdout

    def test_diff_json(self, tmp_path):
        a, b = tmp_path / "a.txt", tmp_path / "b.txt"
        a.write_text("10.0.0.0/24\n")
        b.write_text("10.0.1.0/24\n")
        result = self.run("diff", str(a), str(b), "--json")
        payload = json.loads(result.stdout)
        assert payload["certificate"] == "verified"
        assert payload["added"][0]["witness"] == int.from_bytes(bytes([10, 0, 1, 0]), "big")

    def test_explain_exit_codes(self, tmp_path):
        p = tmp_path / "p.txt"
        p.write_text("10.0.0.0/24  # web\n")
        assert self.run("explain", str(p), "10.0.0.5").returncode == 0
        assert self.run("explain", str(p), "10.0.1.5").returncode == 3

    def test_bad_policy_exit_2(self, tmp_path):
        p = tmp_path / "p.txt"
        p.write_text("10.0.0.0/24\n2001:db8::/32\n")
        result = self.run("diff", str(p), str(p))
        assert result.returncode == 2
        assert "mixed" in result.stderr


class TestNestedLabels:
    def test_long_earlier_rule_still_labels_a_nested_change(self):
        # 0.0.0.0/0 starts first and ends last; a later /24 must not hide it.
        old = Policy.parse("0.0.0.0/0  # all\n10.0.0.0/24  # vpc\n")
        new = Policy.parse("10.0.0.0/24  # vpc\n")
        removed = old.diff(new).removed
        assert len(removed) == 2
        labels = {c.labels for c in removed}
        assert labels == {("all",)}
