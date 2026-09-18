#!/usr/bin/env python3
"""Check the operand model (from the ISA `letters` table) against every calibration probe.

Model under test, for a letter with len/shift/add/flags from the table:
    value  = (signed(field) if flags&2 else field) * (1<<shift) + add
    printed = value + insn_addr   if flags&8 (pc-relative), else value
    flags&1 -> register operand, printed as rN
Anything the model gets wrong is reported, so the SLEIGH generator only relies
on rules that hold for the whole table.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tosigned(v, w):
    return v - (1 << w) if v & (1 << (w - 1)) else v


def parse_num(tok):
    tok = tok.strip()
    m = re.fullmatch(r'[a-z]*(-?)0x([0-9a-f]+)', tok)
    if not m:
        return None
    v = int(m.group(2), 16)
    return -v if m.group(1) else v


def main():
    isa = json.load(open(os.path.join(HERE, 'isa/aeon_isa.json')))['aeon_aeonR2_isa']
    letters = {l['letter']: l for l in isa['letters'] if l['letter']}
    calib = json.load(open(os.path.join(HERE, 'isa/calibration.json')))

    bad = []
    checked = 0
    unknown_letters = set()
    for name, rec in calib.items():
        base = {}
        for p in rec['probes']:
            if p['ok'] and p['tag'][0] == 'base':
                base = p
        if not base:
            continue
        for p in rec['probes']:
            if not p['ok'] or p['tag'][0] != 'field':
                continue
            _, ch, raw, w = p['tag']
            raw &= (1 << w) - 1        # probe values are written into w bits
            L = letters.get(ch)
            if L is None:
                unknown_letters.add(ch)
                continue
            if L['flags'] & 1:            # register operand, checked separately
                continue
            # Which printed number changed vs the all-zero probe?
            now = [parse_num(t) for t in re.split(r'[,()]', p['ops'])]
            was = [parse_num(t) for t in re.split(r'[,()]', base['ops'])]
            if len(now) != len(was):
                bad.append((name, ch, raw, 'operand shape changed', p['ops'], base['ops']))
                continue
            val = tosigned(raw, w) if (L['flags'] & 2) else raw
            want = val * (1 << L['shift']) + L['add']
            if L['flags'] & 8:
                want += p['addr']
                want &= 0xffffffff
            hits = [(a, b) for a, b in zip(now, was) if a != b and a is not None]
            checked += 1
            if not hits:
                if want != (0 if not (L['flags'] & 8) else p['addr'] & 0xffffffff):
                    bad.append((name, ch, raw, 'no operand changed', p['ops'], want))
                continue
            got = hits[0][0]
            if got < 0:
                got &= 0xffffffff
                want &= 0xffffffff
            if got != want:
                bad.append((name, ch, raw, 'value', got, want))
    print('probes checked:', checked, 'mismatches:', len(bad))
    if unknown_letters:
        print('letters not in table:', sorted(unknown_letters))
    by_letter = {}
    for b in bad:
        by_letter.setdefault(b[1], []).append(b)
    for ch, items in sorted(by_letter.items(), key=lambda kv: -len(kv[1])):
        L = letters[ch]
        print(f"letter {ch!r} len={L['len']} shift={L['shift']} add={L['add']} "
              f"flags={L['flags']}: {len(items)} mismatches, e.g. {items[:2]}")
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
