#!/usr/bin/env python3
"""Diff Ghidra's linear-sweep disassembly against the vendor objdump, address by address.

    tools/acceptance.py <objdump listing> <ghidra dump> [--show N]

The objdump listing comes from
    aeon-elf-objdump -D -b binary -m aeon:aeonR2 -EB <fixture>
and the Ghidra dump from ghidra_scripts/AeonDumpDisasm.java.

Addresses where objdump emits a one-byte `.word` are counted separately: those
bytes do not decode, so Ghidra having nothing there is expected.
"""
import re
import sys
from collections import Counter

LINE = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S+)\s*(.*)$')
NUM = re.compile(r'-?0x[0-9a-f]+')


def norm_num(tok):
    """0x007ad04a and 0x7ad04a are the same address; compare numerically."""
    neg = tok.startswith('-')
    v = int(tok.lstrip('-'), 16)
    return ('-' if neg else '') + hex(v)


def norm_ops(s):
    s = s.split(';;')[0].strip().replace(' ', '')
    return NUM.sub(lambda m: norm_num(m.group(0)), s)


def read_objdump(path):
    out = {}
    for ln in open(path):
        if 'is out of bounds' in ln:
            continue          # objdump's trailing message when the last
                              # instruction is truncated by the file end
        m = LINE.match(ln)
        if not m:
            continue
        addr, raw, mnem, ops = m.groups()
        out[int(addr, 16)] = (len(raw.split()), mnem, norm_ops(ops))
    return out


def read_ghidra(path):
    out = {}
    for ln in open(path):
        parts = ln.rstrip('\n').split('\t')
        if len(parts) < 3:
            continue
        addr, length, mnem = parts[0], int(parts[1]), parts[2]
        ops = parts[3] if len(parts) > 3 else ''
        out[int(addr, 16)] = (length, mnem, norm_ops(ops))
    return out


def main():
    obj = read_objdump(sys.argv[1])
    gh = read_ghidra(sys.argv[2])
    show = 20
    if '--show' in sys.argv:
        show = int(sys.argv[sys.argv.index('--show') + 1])

    counts = Counter()
    diffs = []
    for addr, (olen, omnem, oops) in sorted(obj.items()):
        g = gh.get(addr)
        if omnem == '.word':
            counts['objdump .word (undecodable byte)'] += 1
            if g and g[1] != '.bad':
                counts['ghidra decoded what objdump rejected'] += 1
                diffs.append((addr, (olen, omnem, oops), g, 'extra'))
            continue
        if g is None:
            counts['address not reached by ghidra sweep'] += 1
            diffs.append((addr, (olen, omnem, oops), None, 'missing'))
            continue
        if g[1] == '.bad':
            counts['ghidra failed to decode'] += 1
            diffs.append((addr, (olen, omnem, oops), g, 'nodecode'))
        elif g[0] != olen:
            counts['length differs'] += 1
            diffs.append((addr, (olen, omnem, oops), g, 'length'))
        elif g[1] != omnem:
            counts['mnemonic differs'] += 1
            diffs.append((addr, (olen, omnem, oops), g, 'mnemonic'))
        elif g[2] != oops:
            counts['operands differ'] += 1
            diffs.append((addr, (olen, omnem, oops), g, 'operands'))
        else:
            counts['match'] += 1

    total = sum(v for k, v in counts.items() if k != 'objdump .word (undecodable byte)')
    print(f'objdump instructions: {len(obj)}')
    for k, v in counts.most_common():
        print(f'  {k}: {v}')
    bad = sum(v for k, v in counts.items()
              if k not in ('match', 'objdump .word (undecodable byte)'))
    print(f'unexplained differences: {bad}')

    kinds = Counter(d[3] for d in diffs)
    for kind in kinds:
        sel = [d for d in diffs if d[3] == kind][:show]
        if not sel:
            continue
        print(f'\n-- {kind} ({kinds[kind]}) --')
        for addr, o, g, _ in sel:
            gs = f'{g[1]} {g[2]} (len {g[0]})' if g else '(absent)'
            print(f'  {addr:#08x}: objdump {o[1]} {o[2]} (len {o[0]})   ghidra {gs}')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
