"""Exact interval-policy algebra with a recomputable change certificate.

A policy is a set of integer intervals (IP prefixes, port ranges, VLAN ids...).
The interesting operation is not "is point X allowed" but "what actually changed
between two policy revisions", with each change carrying a witness and with a
global equation that a reviewer can re-run.

Every interval is half-open [start, end); the universe is a single address
family per policy (IPv4 or IPv6).
"""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Iterable, Sequence


class SpecError(ValueError):
    """Raised when a policy line cannot be parsed unambiguously."""


_RANGE_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")


@dataclass(frozen=True)
class Interval:
    start: int
    end: int
    family: int
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.family not in (4, 6):
            raise SpecError(f"unsupported address family: {self.family!r}")
        if not isinstance(self.start, int) or not isinstance(self.end, int):
            raise SpecError("interval bounds must be integers")
        if self.start < 0 or self.end <= self.start:
            raise SpecError(f"invalid half-open interval [{self.start}, {self.end})")


@dataclass(frozen=True)
class Rule:
    label: str
    start: int
    end: int
    family: int
    raw: str
    line_no: int


def parse_spec(text: str, family: int | None = None) -> tuple[int, int, int]:
    """Parse ``CIDR``, ``A-B`` (inclusive), a single integer, or a bare IP."""
    s = text.strip()
    if not s:
        raise SpecError("empty range specification")
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise SpecError(f"bad CIDR {s!r}: {exc}") from exc
        return int(net.network_address), int(net.broadcast_address) + 1, net.version
    m = _RANGE_RE.match(s)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if b < a:
            raise SpecError(f"reversed range {s!r}")
        return a, b + 1, family or 4
    if s.isdigit():
        n = int(s)
        return n, n + 1, family or 4
    try:
        ip = ipaddress.ip_address(s)
    except ValueError as exc:
        raise SpecError(f"bad range specification {s!r}") from exc
    return int(ip), int(ip) + 1, ip.version


def parse_policy(text: str, source: str = "<string>") -> tuple[list[Rule], int]:
    """Return rules in file order plus the single family they belong to."""
    rules: list[Rule] = []
    family: int | None = None
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        body, _, comment = stripped.partition("#")
        label = comment.strip() or body.strip()
        for piece in body.split(","):
            piece = piece.strip()
            if not piece:
                raise SpecError(f"{source}:{line_no}: empty entry in list")
            start, end, fam = parse_spec(piece, family)
            if family is None:
                family = fam
            elif fam != family:
                raise SpecError(
                    f"{source}:{line_no}: mixed IPv{family} and IPv{fam} "
                    "in one policy (split them into two policies)"
                )
            rules.append(Rule(label, start, end, fam, piece, line_no))
    if family is None:
        raise SpecError(f"{source}: policy has no rules")
    return rules, family


def _merge(intervals: Iterable[Interval]) -> list[Interval]:
    ordered = sorted(intervals, key=lambda i: (i.family, i.start, i.end))
    out: list[Interval] = []
    for item in ordered:
        if out and item.family == out[-1].family and item.start <= out[-1].end:
            prev = out[-1]
            merged_end = max(prev.end, item.end)
            labels = tuple(sorted(set(prev.labels) | set(item.labels)))
            out[-1] = Interval(prev.start, merged_end, prev.family, labels)
        else:
            out.append(item)
    return out


def _spans(intervals: Sequence[Interval]) -> list[tuple[int, int, int]]:
    return [(i.start, i.end, i.family) for i in intervals]


def _covered_idx(intervals: Sequence[Interval], starts: Sequence[int], start: int, end: int) -> bool:
    """True iff the normalized union covers every integer in [start, end)."""
    k = bisect_right(starts, start) - 1
    if k < 0:
        return False
    pos = start
    while k < len(intervals) and intervals[k].start <= pos:
        pos = max(pos, intervals[k].end)
        if pos >= end:
            return True
        k += 1
    return False


def _overlaps_idx(intervals: Sequence[Interval], starts: Sequence[int], start: int, end: int) -> bool:
    k = bisect_right(starts, start) - 1
    if k >= 0 and intervals[k].end > start:
        return True
    k += 1
    return k < len(intervals) and intervals[k].start < end


def _covered(intervals: Sequence[Interval], start: int, end: int) -> bool:
    return _covered_idx(intervals, [i.start for i in intervals], start, end)


def _overlaps(intervals: Sequence[Interval], start: int, end: int) -> bool:
    return _overlaps_idx(intervals, [i.start for i in intervals], start, end)


def _labels_at(rules: Sequence[Rule], starts: Sequence[int], point: int) -> tuple[str, ...]:
    """Labels of every rule covering ``point``, in file order."""
    k = bisect_right(starts, point) - 1
    found: list[tuple[int, str]] = []
    while k >= 0 and rules[k].end > point:
        if rules[k].start <= point:
            found.append((rules[k].line_no, rules[k].label))
        k -= 1
    found.sort()
    return tuple(dict.fromkeys(label for _, label in found))


def _difference(a: Sequence[Interval], b: Sequence[Interval]) -> list[Interval]:
    """a \\ b for two normalized, disjoint interval lists."""
    if not b:
        return list(a)
    ends = [i.end for i in b]
    out: list[Interval] = []
    for item in a:
        # first b whose end is strictly after this a's start
        k = bisect_right(ends, item.start)
        cursor = item.start
        while k < len(b) and b[k].start < item.end:
            if b[k].start > cursor:
                out.append(
                    Interval(cursor, min(b[k].start, item.end), item.family, item.labels)
                )
            cursor = max(cursor, b[k].end)
            if cursor >= item.end:
                break
            k += 1
        if cursor < item.end:
            out.append(Interval(cursor, item.end, item.family, item.labels))
    return _merge(out)


@dataclass(frozen=True)
class Change:
    start: int
    end: int
    family: int
    labels: tuple[str, ...]
    witness: int

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "family": self.family,
            "labels": list(self.labels),
            "witness": self.witness,
        }


@dataclass
class Diff:
    old: "Policy"
    new: "Policy"
    added: list[Change]
    removed: list[Change]

    @property
    def empty(self) -> bool:
        return not self.added and not self.removed

    def verify(self) -> None:
        """Raise AssertionError if the certificate does not reproduce the change."""
        old_i, new_i = self.old.intervals(), self.new.intervals()
        old_starts = [i.start for i in old_i]
        new_starts = [i.start for i in new_i]
        for kind, changes, src, src_starts, dst, dst_starts in (
            ("added", self.added, old_i, old_starts, new_i, new_starts),
            ("removed", self.removed, new_i, new_starts, old_i, old_starts),
        ):
            for ch in changes:
                assert ch.start < ch.end, f"{kind}: empty interval"
                assert _covered_idx(dst, dst_starts, ch.start, ch.end), (
                    f"{kind} [{ch.start},{ch.end}) is not fully present in target"
                )
                assert not _overlaps_idx(src, src_starts, ch.start, ch.end), (
                    f"{kind} [{ch.start},{ch.end}) overlaps the source policy"
                )
                assert _covered_idx(dst, dst_starts, ch.witness, ch.witness + 1), (
                    f"{kind}: witness {ch.witness} not in target"
                )
                assert not _covered_idx(src, src_starts, ch.witness, ch.witness + 1), (
                    f"{kind}: witness {ch.witness} already in source"
                )
        added_i = [Interval(c.start, c.end, c.family) for c in self.added]
        removed_i = [Interval(c.start, c.end, c.family) for c in self.removed]
        assert _spans(_merge([*old_i, *added_i])) == _spans(_merge([*new_i, *removed_i])), (
            "certificate equation failed: old + added != new + removed"
        )
        # old \ removed == new \ added == the unchanged intersection
        left = _spans(_difference(old_i, removed_i))
        right = _spans(_difference(new_i, added_i))
        assert left == right, (
            "certificate equation failed: old \\ removed != new \\ added"
        )
        # Minimality in interval count: the produced pieces are maximal, i.e. no
        # two consecutive pieces can be joined without crossing a real boundary.
        for pieces in (self.added, self.removed):
            ordered = sorted(pieces, key=lambda c: (c.family, c.start))
            for left, right in zip(ordered, ordered[1:]):
                assert left.family != right.family or left.end < right.start, (
                    "non-maximal change pieces (adjacent intervals should be merged)"
                )

    def as_dict(self) -> dict:
        return {
            "added": [c.as_dict() for c in self.added],
            "removed": [c.as_dict() for c in self.removed],
            "added_intervals": len(self.added),
            "removed_intervals": len(self.removed),
            "old_intervals": len(self.old.intervals()),
            "new_intervals": len(self.new.intervals()),
        }


class Policy:
    def __init__(self, rules: Sequence[Rule], source: str = "<memory>"):
        if not rules:
            raise SpecError(f"{source}: empty policy")
        families = {r.family for r in rules}
        if len(families) != 1:
            raise SpecError(f"{source}: mixed address families {sorted(families)}")
        self.rules = tuple(rules)
        self.family = rules[0].family
        self.source = source
        self._intervals: list[Interval] | None = None

    @classmethod
    def parse(cls, text: str, source: str = "<string>") -> "Policy":
        rules, _ = parse_policy(text, source)
        return cls(rules, source)

    def intervals(self) -> list[Interval]:
        if self._intervals is None:
            self._intervals = _merge(
                Interval(r.start, r.end, r.family, (r.label,)) for r in self.rules
            )
        return self._intervals

    def contains(self, point: int) -> bool:
        return any(r.start <= point < r.end for r in self.rules)

    def explain(self, point: int) -> list[Rule]:
        return [r for r in self.rules if r.start <= point < r.end]

    def diff(self, other: "Policy") -> Diff:
        if self.family != other.family:
            raise SpecError("cannot diff policies from different address families")
        old_i, new_i = self.intervals(), other.intervals()
        old_starts = [r.start for r in self.rules]
        new_starts = [r.start for r in other.rules]
        added = [
            Change(i.start, i.end, i.family, _labels_at(other.rules, new_starts, i.start), i.start)
            for i in _difference(new_i, old_i)
        ]
        removed = [
            Change(i.start, i.end, i.family, _labels_at(self.rules, old_starts, i.start), i.start)
            for i in _difference(old_i, new_i)
        ]
        result = Diff(self, other, added, removed)
        result.verify()
        return result


def fmt_interval(start: int, end: int, family: int) -> str:
    """Human-readable inclusive range; CIDR form is not used on purpose."""
    if family == 4:
        first, last = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end - 1)
    else:
        first, last = ipaddress.IPv6Address(start), ipaddress.IPv6Address(end - 1)
    return str(first) if first == last else f"{first} - {last}"
