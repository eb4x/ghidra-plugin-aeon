#!/usr/bin/env python3
"""Calibrate every aeonR2 operand against the vendor objdump.

For each decodable opcode, vary one operand field at a time and read the value
objdump prints, so the encoding->printed-value mapping (scale, bias, signedness,
pc-relativity) is measured rather than guessed. Also records the display
mnemonic objdump uses in default (b.) mode, and which encodings are shadowed by
an earlier table entry.

Writes isa/calibration.json.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OD = os.path.join(HERE, 'vendor/r2-elf-linux-1.3.5.14/bin/aeon-elf-objdump')
SCRATCH = os.environ.get('AEON_SCRATCH', '/tmp')

LINE = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S+)\s*(.*)$')


def runs(enc):
    """Split an encoding string into (char, [bit indices MSB-first]) runs."""
    out = []
    for i, c in enumerate(enc):
        if out and out[-1][0] == c and out[-1][1][-1] == i - 1:
            out[-1][1].append(i)
        else:
            out.append((c, [i]))
    return out


def letters_of(enc):
    """Operand letters in display order of first appearance, with their bit lists."""
    seen = {}
    order = []
    for c, bits in runs(enc):
        if c in '01-':
            continue
        if c not in seen:
            seen[c] = []
            order.append(c)
        seen[c].extend(bits)
    return order, seen


def encode(enc, values):
    """Build instruction bytes: fixed bits as written, '-' as 0, letters from values."""
    n = len(enc)
    bits = ['0'] * n
    for i, c in enumerate(enc):
        if c in '01':
            bits[i] = c
    for c, positions in values.items():
        pass
    return bits


def build(enc, assign):
    """assign maps letter -> integer; letter bits are filled MSB-first."""
    n = len(enc)
    bits = ['0'] * n
    for i, c in enumerate(enc):
        if c in '01':
            bits[i] = c
    _, pos = letters_of(enc)
    for c, v in assign.items():
        ps = pos[c]
        w = len(ps)
        b = format(v & ((1 << w) - 1), '0%db' % w)
        for p, ch in zip(ps, b):
            bits[p] = ch
    return int(''.join(bits), 2).to_bytes(n // 8, 'big')


def objdump(path, vma=0, prefix=False):
    cmd = [OD, '-D', '-b', 'binary', '-m', 'aeon:aeonR2', '-EB']
    if prefix:
        cmd += ['-M', 'prefix']
    if vma:
        cmd += ['--adjust-vma=0x%x' % vma]
    cmd.append(path)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    res = []
    for ln in out.splitlines():
        m = LINE.match(ln)
        if m:
            addr, raw, mnem, ops = m.groups()
            res.append((int(addr, 16), len(raw.split()), mnem, ops.split(';;')[0].strip()))
    return res


def main():
    isa = json.load(open(os.path.join(HERE, 'isa/aeon_isa.json')))['aeon_aeonR2_isa']
    ops = [o for o in isa['opcodes'] if not o['for_encode_only']]

    # One probe = one instruction in a batch file. Track what each was meant to be.
    probes = []           # (opcode index, tag, assign)
    for oi, op in enumerate(ops):
        enc = op['encoding'].replace(' ', '')
        order, pos = letters_of(enc)
        base = {c: 0 for c in order}
        probes.append((oi, ('base',), dict(base)))
        for c in order:
            w = len(pos[c])
            vals = sorted({1, 2, 3, (1 << (w - 1)) if w > 1 else 1,
                           ((1 << w) - 1)})
            for v in vals:
                a = dict(base)
                a[c] = v
                probes.append((oi, ('field', c, v, w), a))

    blob = bytearray()
    offsets = []
    for oi, tag, assign in probes:
        enc = ops[oi]['encoding'].replace(' ', '')
        b = build(enc, assign)
        offsets.append((len(blob), len(b)))
        blob += b

    path = os.path.join(SCRATCH, 'calib.bin')
    open(path, 'wb').write(bytes(blob))
    lo = {a: (n, m, o) for a, n, m, o in objdump(path, 0)}
    hi = {a: (n, m, o) for a, n, m, o in objdump(path, 0x100000)}
    lop = {a: (n, m, o) for a, n, m, o in objdump(path, 0, prefix=True)}

    out = {}
    for (oi, tag, assign), (off, ln) in zip(probes, offsets):
        op = ops[oi]
        rec = out.setdefault(op['name'], {
            'args': op['args'], 'encoding': op['encoding'],
            'func_unit': op['func_unit'], 'display': None, 'probes': [],
            'shadowed': False, 'length': ln,
        })
        got = lo.get(off)
        gotp = lop.get(off)
        if got is None or got[0] != ln or gotp is None or gotp[1] != op["name"]:
            rec['probes'].append({'tag': list(tag), 'ok': False})
            if tag == ('base',):
                rec['shadowed'] = True
            continue
        _, mnem, operands = got
        hirec = hi.get(off + 0x100000)
        if rec['display'] is None:
            rec['display'] = mnem
        rec['probes'].append({
            'tag': list(tag), 'ok': True, 'mnem': mnem, 'ops': operands,
            'addr': off, 'ops_vma': hirec[2] if hirec else None,
        })
    json.dump(out, open(os.path.join(HERE, 'isa/calibration.json'), 'w'), indent=1)
    nbad = sum(1 for v in out.values() if v['shadowed'])
    print('opcodes:', len(out), 'shadowed at all-zero fields:', nbad,
          'probes:', len(probes))


if __name__ == '__main__':
    main()
