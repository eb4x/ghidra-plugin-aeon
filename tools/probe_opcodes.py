#!/usr/bin/env python3
"""Generate one instance per aeonR2 opcode (N random fills), run objdump with/without -M prefix, emit TSV oracle."""
import json, random, subprocess, sys, os, tempfile
OD = 'vendor/r2-elf-linux-1.3.5.14/bin/aeon-elf-objdump'
isa = json.load(open('isa/aeon_isa.json'))['aeon_aeonR2_isa']
N = int(sys.argv[1]) if len(sys.argv) > 1 else 4
random.seed(1)
items = []
for op in isa['opcodes']:
    if op['for_encode_only']: continue
    enc = op['encoding'].replace(' ', '')
    if len(enc) % 8: print('BADLEN', op['name'], len(enc), file=sys.stderr); continue
    for k in range(N):
        bits = ''.join(c if c in '01' else ('0' if c == '-' else ('0' if k == 0 else random.choice('01'))) for c in enc)
        items.append((op['name'], op['encoding'], int(bits, 2).to_bytes(len(enc)//8, 'big')))
def run(extra):
    res = {}
    with tempfile.TemporaryDirectory() as d:
        for i, (name, enc, b) in enumerate(items):
            p = os.path.join(d, f'{i}.bin'); open(p, 'wb').write(b)
        # batch: one file per insn keeps decoding independent
        files = [os.path.join(d, f'{i}.bin') for i in range(len(items))]
        out = subprocess.run([OD, '-D', '-b', 'binary', '-m', 'aeon:aeonR2', '-EB', *extra, *files], capture_output=True, text=True).stdout
        cur = None; lines = {}
        for ln in out.splitlines():
            if ln.endswith('file format binary'):
                cur = int(os.path.basename(ln.split(':')[0]).split('.')[0]); lines[cur] = []
            elif cur is not None and ln.startswith('   ') and ':\t' in ln:
                lines[cur].append(ln)
        return lines
plain, pref = run([]), run(['-M', 'prefix'])
def fmt(ls):
    return ' ;; '.join('\t'.join(x.strip() for x in l.split('\t')[1:]) for l in ls)
for i, (name, enc, b) in enumerate(items):
    print('\t'.join([name, b.hex(), fmt(pref.get(i, [])), fmt(plain.get(i, []))]))
