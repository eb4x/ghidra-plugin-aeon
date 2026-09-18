#!/usr/bin/env python3
"""Test each don't-care ('-') bit of each opcode separately: is it ignored by
the decoder, or must it be zero? A run can be partly significant (bt.rfe), so
this probes one bit at a time. Writes isa/dontcare.json, mapping each opcode to
the list of its '-' bit positions (MSB-first index) the decoder ignores."""
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OD = os.path.join(HERE, 'vendor/r2-elf-linux-1.3.5.14/bin/aeon-elf-objdump')
S = os.environ.get('AEON_SCRATCH', '/tmp')
sys.path.insert(0, os.path.join(HERE, 'tools'))
from calibrate import runs, letters_of, build, objdump   # noqa: E402

isa = json.load(open(os.path.join(HERE, 'isa/aeon_isa.json')))['aeon_aeonR2_isa']
calib = json.load(open(os.path.join(HERE, 'isa/calibration.json')))
import tempfile
cells, meta = [], []
for op in isa['opcodes']:
    if op['for_encode_only']:
        continue
    enc = op['encoding'].replace(' ', '')
    order, pos = letters_of(enc)
    # give '?' (must-be-nonzero register) a legal value so the opcode decodes
    assign = {c: (1 if c in '?Z' else 0) for c in order}
    dash_bits = [i for i, c in enumerate(enc) if c == '-']
    for idx, bit in enumerate([None] + dash_bits):
        b = bytearray(build(enc, assign))
        if bit is not None:
            v = int.from_bytes(b, 'big') | (1 << (len(enc) - 1 - bit))
            b = bytearray(v.to_bytes(len(enc) // 8, 'big'))
        meta.append((op['name'], idx - 1, len(cells), len(b)))
        cells.append(bytes(b))
# one file per probe: an invalid probe must not desync the ones after it
tmp = tempfile.mkdtemp(dir=S)
paths = []
for i, cell in enumerate(cells):
    fp = os.path.join(tmp, f'{i}.bin')
    open(fp, 'wb').write(cell)
    paths.append(fp)
cmd = [OD, '-D', '-b', 'binary', '-m', 'aeon:aeonR2', '-EB', '-M', 'prefix'] + paths
out = subprocess.run(cmd, capture_output=True, text=True).stdout
seen, cur = {}, None
for ln in out.splitlines():
    if ln.endswith('file format binary'):
        cur = int(os.path.basename(ln.split(':')[0]).split('.')[0])
    elif cur is not None and '\t' in ln and ln.startswith('   '):
        parts = ln.split('\t')
        if len(parts) >= 3 and cur not in seen:
            seen[cur] = (len(parts[1].split()), parts[2].split()[0])
res = {}
for name, idx, off, ln in meta:
    got = seen.get(off)
    ok = bool(got and got[0] == ln and got[1] == name)
    if idx < 0:
        res[name] = {'baseline_ok': ok, 'ignored_bits': [], '_i': 0}
    else:
        enc = [o for o in isa['opcodes'] if o['name'] == name][0]['encoding'].replace(' ', '')
        dash_bits = [i for i, c in enumerate(enc) if c == '-']
        if ok:
            res[name]['ignored_bits'].append(dash_bits[idx])
json.dump(res, open(os.path.join(HERE, 'isa/dontcare.json'), 'w'), indent=1)
for v in res.values():
    v.pop('_i', None)
tot = sum(len([c for c in o['encoding'].replace(' ', '') if c == '-'])
          for o in isa['opcodes'] if not o['for_encode_only'])
ign = sum(len(v['ignored_bits']) for v in res.values() if v['baseline_ok'])
nob = sum(1 for v in res.values() if not v['baseline_ok'])
print(f'opcodes: {len(res)} (baseline failed for {nob}), dash bits: {tot}, ignored: {ign}')
