#!/usr/bin/env python3
"""Generate p-code test cases from the vendor simulator.

Each case is a short instruction sequence; the vendor simulator's final register
file is the expected result. ghidra_scripts/AeonEmuTest.java replays the same
bytes through Ghidra's p-code emulator and compares, so the semantics in the
SLEIGH spec are checked against the hardware model rather than against my
reading of it.

Writes tests/emu_cases.json.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, 'tools'))
from simprobe import probe, T, ENV     # noqa: E402

# Each case: (name, assembly). The sequences are self-contained: they set up
# their own inputs, so the emulator starts from an all-zero register file.
CASES = [
    ('add carries into CY',      'b.movi r3,-1\nb.movi r4,1\nb.add r6,r3,r4\nb.addc r20,r0,r0'),
    ('add does not carry',       'b.movi r3,1\nb.movi r4,1\nb.add r6,r3,r4\nb.addc r20,r0,r0'),
    ('addi carries',             'b.movi r3,-1\nb.addi r6,r3,1\nb.addc r20,r0,r0'),
    ('sub borrows',              'b.movi r4,1\nb.sub r6,r0,r4\nb.addc r20,r0,r0'),
    ('sub does not borrow',      'b.movi r4,1\nb.sub r6,r4,r0\nb.addc r20,r0,r0'),
    ('addc chains a carry',      'b.movi r3,-1\nb.movi r4,1\nb.add r5,r3,r4\nb.addc r6,r3,r0\nb.addc r20,r0,r0'),
    ('subb takes the borrow',    'b.movi r3,-1\nb.movi r4,1\nb.add r5,r3,r4\nb.movi r7,0\nb.subb r6,r7,r0'),
    ('64-bit add, low carries',  'b.movi r3,-1\nb.movi r4,-1\nb.movi r5,1\nb.movi r6,0\n'
                                 'b.add r7,r3,r5\nb.addc r8,r4,r6'),
    ('movhi + addi address',     'b.movhi r3,0x15\nb.addi r6,r3,0x10'),
    ('movhi + ori address',      'b.movhi r3,0x15\nb.ori r6,r3,0x25d0'),
    ('movhi + negative addi',    'b.movhi r3,0x1234\nb.addi r6,r3,-0x5678'),
    ('shifts',                   'b.movi r3,-16\nb.slli r6,r3,2\nb.srli r7,r3,4\nb.srai r8,r3,4'),
    ('rotate',                   'b.movi r3,-16\nb.movi r4,8\nb.ror r6,r3,r4'),
    ('logic',                    'b.movi r3,-1\nb.movi r4,0x5\nb.and r6,r3,r4\nb.or r7,r0,r4\n'
                                 'b.xor r8,r3,r4\nb.nand r9,r3,r4'),
    ('logic immediates',         'b.movi r3,-1\nb.andi r6,r3,0x0f\nb.ori r7,r0,0x0f\nb.xori r8,r3,0x0f'),
    ('sign and zero extension',  'b.movhi r3,0x1234\nb.ori r3,r3,0x80ff\n'
                                 'b.extbz r6,r3\nb.extbs r7,r3\nb.exthz r8,r3\nb.exths r9,r3'),
    ('multiply, low word',       'b.movhi r3,1\nb.mul r6,r3,r3\nb.movi r4,-3\nb.movi r5,5\nb.mul r7,r4,r5'),
    ('divide',                   'b.addi r3,r0,-20\nb.movi r4,5\nb.div r6,r3,r4\n'
                                 'b.addi r5,r0,20\nb.divu r7,r5,r4'),
    ('compare sets the flag',    'b.movi r3,5\nb.movi r4,7\nb.sfleu r3,r4\nb.cmov r6,r3,r4'),
    ('compare, false case',      'b.movi r3,9\nb.movi r4,7\nb.sfleu r3,r4\nb.cmov r6,r3,r4'),
    ('find first/last one',      'b.movhi r3,0x8000\nb.ori r3,r3,0x10\nb.ff1 r6,r3\nb.fl1 r7,r3'),
    ('store then load word',     'b.movhi r1,0x10\nb.addi r5,r0,0x7b\nb.sw 0x10(r1),r5\nb.lwz r6,0x10(r1)'),
    ('store then load byte',     'b.movhi r1,0x10\nb.movi r5,-1\nb.sb 0x14(r1),r5\n'
                                 'b.lbz r6,0x14(r1)\nb.lbs r7,0x14(r1)'),
    ('store then load half',     'b.movhi r1,0x10\nb.movi r5,-2\nb.sh 0x18(r1),r5\n'
                                 'b.lhz r6,0x18(r1)\nb.lhs r7,0x18(r1)'),
    ('push and pop move r1',     'b.movhi r1,0x10\nb.addi r5,r0,0x2a\nb.push r5\nb.pop r6'),
    ('conditional move, taken',  'b.movi r3,1\nb.movi r4,2\nb.sfeq r3,r3\nb.cmov r6,r3,r4'),
    # multi-word transfers: c selects 2/3/4/8 registers, offset scales by 4
    ('msw stores 2 registers',   'b.movhi r1,0x10\nb.addi r3,r0,0x33\nb.addi r4,r0,0x44\n'
                                 'b.msw 0x0(r1),r3,0x0\nb.lwz r6,0x0(r1)\nb.lwz r7,0x4(r1)'),
    ('msw stores 4 registers',   'b.movhi r1,0x10\nb.addi r3,r0,0x33\nb.addi r4,r0,0x44\n'
                                 'b.addi r5,r0,0x55\nb.addi r6,r0,0x66\n'
                                 'b.msw 0x0(r1),r3,0x2\nb.lwz r7,0x8(r1)\nb.lwz r8,0xc(r1)'),
    ('mlwz loads 3 registers',   'b.movhi r1,0x10\nb.addi r3,r0,0x33\nb.addi r4,r0,0x44\n'
                                 'b.addi r5,r0,0x55\nb.msw 0x0(r1),r3,0x1\n'
                                 'b.mlwz r6,0x0(r1),0x1'),
    ('divl shifts then divides', 'b.addi r3,r0,100\nb.addi r4,r0,8\n'
                                 '.byte 0xa0\n.byte 0xc3\n.byte 0x20\n.byte 0x40'),
    ('divl rounds half up',      'b.addi r3,r0,7\nb.addi r4,r0,2\n'
                                 '.byte 0xa0\n.byte 0xc3\n.byte 0x20\n.byte 0x01'),
    ('divl rounds negatives',    'b.addi r3,r0,-7\nb.addi r4,r0,2\n'
                                 '.byte 0xa0\n.byte 0xc3\n.byte 0x20\n.byte 0x01'),
    ('mlwz offset scales by 4',  'b.movhi r1,0x10\nb.addi r3,r0,0x33\nb.addi r4,r0,0x44\n'
                                 'b.msw 0x4(r1),r3,0x0\nb.mlwz r6,0x4(r1),0x0'),
]

# registers worth comparing: the ones the cases write
WATCH = [f'r{i}' for i in (1, 3, 4, 5, 6, 7, 8, 9, 20)] + ['flag']


def assemble(body):
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, 'c.s')
        with open(src, 'w') as fh:
            fh.write('\t.text\n\t.global _start\n_start:\n')
            for line in body.strip().splitlines():
                fh.write('\t' + line.strip() + '\n')
        obj, binf = os.path.join(d, 'c.o'), os.path.join(d, 'c.bin')
        r = subprocess.run([f'{T}/bin/aeon-elf-as', '-maeonR2', '-EB', '-munknown', '-mmulti',
                            src, '-o', obj], env=ENV, capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f'assembling failed:\n{body}\n{r.stderr}')
        subprocess.run([f'{T}/bin/aeon-elf-objcopy', '-O', 'binary', '-j', '.text', obj, binf],
                       check=True, env=ENV, capture_output=True)
        return open(binf, 'rb').read()


def main():
    out = []
    for name, body in CASES:
        code = assemble(body)
        regs = probe(body)
        expected = {k: regs[k] for k in WATCH if k in regs}
        out.append({'name': name, 'asm': body, 'bytes': code.hex(),
                    'expected': expected})
        print(f'{name:28s} {len(code):2d} bytes  ' +
              ' '.join(f'{k}={v:#x}' for k, v in expected.items() if v))
    path = os.path.join(HERE, 'tests/emu_cases.json')
    json.dump(out, open(path, 'w'), indent=1)
    print(f'\nwrote {path}: {len(out)} cases')


if __name__ == '__main__':
    main()
