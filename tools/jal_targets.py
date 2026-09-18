#!/usr/bin/env python3
"""Extract b.jal targets from an objdump listing, for seeding a census.

A raw firmware blob has no entry point, so call targets from a linear sweep are
the best available approximation of where functions start. Some are artefacts of
sweeping data, which is why the census reports how many of the seeds turn into
functions with returns.
"""
import re
import sys

listing, base, size = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
LINE = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\tb\.jal\s+(0x[0-9a-f]+)')
targets = set()
for ln in open(listing):
    m = LINE.match(ln)
    if m:
        t = int(m.group(2), 16) + base
        if base <= t < base + size:
            targets.add(t)
print('# b.jal targets from %s' % listing)
for t in sorted(targets):
    print(hex(t))
print('# %d targets' % len(targets), file=sys.stderr)
