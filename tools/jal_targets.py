#!/usr/bin/env python3
"""Extract b.jal targets from an objdump listing, for seeding a census.

A raw firmware blob has no entry point, so call targets are the best available
approximation of where functions start. A linear sweep also decodes data, and a
b.jal decoded inside data points anywhere, so the raw target list is noisy: in
stream 0, 2,959 of 7,268 targets do not even land on an instruction boundary.

    tools/jal_targets.py <listing> <base> <size> [filter]

filter is one of:
  all        every target in range (noisy; what a naive sweep gives)
  boundary   targets that land on an instruction the sweep decoded
  prologue   boundary targets whose first instruction adjusts or saves to r1
  strong     prologue targets, plus boundary targets called more than once
             (the default: the best clean/total ratio measured on stream 0)
"""
import collections
import re
import sys

listing, base, size = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
mode = sys.argv[4] if len(sys.argv) > 4 else 'strong'

CALL = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\tb\.jal\s+(0x[0-9a-f]+)')
INSN = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s*(.*)$')

decoded = {}
calls = collections.Counter()
for line in open(listing):
    m = INSN.match(line)
    if m:
        decoded[int(m.group(1), 16)] = (m.group(2), m.group(3).split(';;')[0].strip())
    m = CALL.match(line)
    if m:
        t = int(m.group(2), 16)
        if 0 <= t < size:
            calls[t] += 1


def is_prologue(t):
    mnem, ops = decoded.get(t, ('', ''))
    return (mnem == 'b.addi' and ops.startswith('r1,r1,-')) or \
           (mnem == 'b.sw' and '(r1)' in ops)


def keep(t):
    if mode == 'all':
        return True
    if t not in decoded:
        return False
    if mode == 'boundary':
        return True
    if mode == 'prologue':
        return is_prologue(t)
    return is_prologue(t) or calls[t] > 1


targets = sorted(t for t in calls if keep(t))
print(f'# b.jal targets from {listing} (filter: {mode})')
for t in targets:
    print(hex(t + base))
print(f'# {len(targets)} of {len(calls)} targets kept', file=sys.stderr)
