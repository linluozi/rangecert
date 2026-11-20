# rangecert

**Semantic diff for interval policies (CIDRs, ports, VLANs): every change comes
with a witness point, and the patch is verified by an equation a reviewer can
re-run.**

`rangecert` answers "what actually changed between these two firewall / ACL /
VPC revisions?" instead of "which lines differ". It parses CIDRs, `A-B` ranges,
single integers and bare IPs into half-open integer intervals, diffs the
effective sets, and refuses to print a result it cannot prove.

Upstream: none

This is an original tool, not a patch to an upstream library. There is no
upstream test suite to run and no upstream speedup to claim; the evidence below
is the project's own test suite, fixture replay, and benchmark. See
[Limits](#limits) for the exact scope.

## Why a textual diff is not a policy diff

A rule can be re-spelled without changing the allowed set (prefix split, label
rename, reordering, duplicate rule). It can also change the effective set
without looking dramatic. On the included fixture, built from GitHub's public
`api.github.com/meta` CIDR list, **176 textual line edits collapse to 2 effective
interval changes (ratio 88:1)**. A reviewer reading the text diff spends time on
176 lines; `rangecert` shows the 2 real changes and a witness for each.

Re-run it:

```bash
python examples/compare_textdiff.py
```

```
rules_before=112
rules_after=170
textual_lines_changed=176
effective_intervals_changed=2
ratio_textual_to_effective=88.00
certificate=verified
```

The `after` fixture is derived on purpose: most prefixes are split into halves
(same set), one rule is removed, one `198.51.100.0/24` rule is added. The
generator is `examples/build_policies.py`; the source corpus is stored verbatim
in `examples/github-meta-trimmed.json` (5,047 bytes, fetched 2026-11-21).

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/rangecert --version
```

Tests only need `pytest`:

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest -q tests
```

## Use

```bash
# exit 0 = no effective change, 1 = change, 2 = parse error
rangecert diff examples/policy-before.txt examples/policy-after.txt

# machine-readable, includes witnesses
rangecert diff old.txt new.txt --json

# which rules cover this address? exit 0 = covered, 3 = not covered
rangecert explain examples/policy-before.txt 140.82.112.5
```

Policy format is one spec or comma-separated spec list per line; a trailing
`# comment` becomes the rule label. Empty lines and `#` lines are ignored.

```
140.82.112.0/20  # hooks
10.0.0.0-10.0.0.255  # legacy range
443  # port universe example (one family per policy)
```

## The certificate

For two normalized sets `old` and `new`, the diff produces maximal disjoint
intervals `added = new \ old` and `removed = old \ new`. Before returning,
`Policy.diff()` calls `Diff.verify()`, which checks:

1. every `added` interval is fully inside `new` and disjoint from `old`;
2. every `removed` interval is fully inside `old` and disjoint from `new`;
3. each change's witness point is in the destination set and not in the source;
4. `old ∪ added == new ∪ removed` (and `old \ removed == new \ added`);
5. change pieces are maximal, so the interval count is minimal for this diff.

If any check fails, the call raises instead of printing a diff. A deliberately
tampered certificate is rejected by the test suite, and a nested-rule test
proves that a later `/24` does not hide an earlier `0.0.0.0/0` rule.

## Benchmark

Both arms compute identical `(added, removed)` spans; the script asserts that
before timing. Baseline is the natural pairwise `O(n·m)` subtraction, the
optimized arm is `rangecert`'s bisect-based subtraction **including certificate
verification**. 3 warmups, 5 timed samples, median reported; raw samples are in
`bench/raw/`. Python 3.12.3, x86_64, seed 20261121.

| intervals per side | baseline median | rangecert median | speedup |
|---|---|---|---|
| 100 | 1.275 ms | 3.589 ms | 0.36x |
| 500 | 29.499 ms | 19.257 ms | 1.53x |
| 2000 | 474.107 ms | 82.469 ms | 5.75x |

Median speedup across the three scales: **1.53x**. The small case is honestly a
regression: certificate verification is `O(changes · log n)` and dominates at
n=100. The crossover is between 100 and 500 intervals. This is a design
trade-off, not a hidden cost.

```bash
python bench/bench.py
```

## Tests

```bash
.venv/bin/python -m pytest -q tests
# 24 passed in 0.75s
```

- 2,500 randomized old/new policy pairs are compared against an independent
  256-cell bitmask oracle, byte-for-byte on the resulting spans.
- The suite prints `independent_samples=2500`; samples are de-duplicated by
  SHA-256 of the canonical rule pairs (2,500 unique, no reseeded generator
  inside the loop).
- Parsing boundaries: `/0`, `/32`, IPv6 `/32`, reversed ranges, mixed families,
  overlapping and adjacent rules, trailing-comment labels.
- CLI exit codes 0/1/2/3, JSON output, and witness membership are covered by
  subprocess tests.

## 本轮创新

**B 档：把「策略差异」从文本 diff 改成可复算的最小编辑证书，并量化文本噪声。**
台账里的 `intervaltree-range-opt` 是区间查询加速，`csvresume` 是字节区间续读，
`topo-witness` 是图环见证；没有一条把「两个区间策略的语义差」做成带 witness、
带最小性检查、带全局守恒方程的补丁对象。新结论是可复现的：在真实 GitHub
meta CIDR 语料上，176 行文本变更只有 2 个有效区间变更（88:1），说明按行评审
会系统性高估策略变更面。

## Limits

- One address family per policy; IPv4 and IPv6 policies cannot be diffed.
- Intervals are integer half-open ranges. No allow/deny precedence, NAT, or
  rule-order semantics: this tool diffs the *effective allowed set*, which is
  the right object only after your ruleset has been flattened.
- `explain` reports source rules in file order; it does not model first-match
  wins.
- The fixture is derived from a real CIDR snapshot by splitting prefixes and
  editing two rules; it measures review noise, not production traffic.
- Benchmark numbers are from one machine and one run; raw samples are kept so
  the result can be recomputed, not treated as a universal constant.

## License

MIT, original work by `linluozi`. No upstream code is copied.
