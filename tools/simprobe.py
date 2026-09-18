#!/usr/bin/env python3
"""Ask the vendor simulator what an instruction actually does.

Each probe is assembled, linked at the simulator's reset vector and single-stepped
in aeon-elf-sim; the final register dump is returned. Used to settle semantics the
disassembler cannot show: which instructions write the carry flag, the borrow
polarity of b.subb, whether b.mul returns the high or low word, and so on.

    probe(body, setup=...)  -> {'r5': 0xffffffff, ..., 'flag': 1}

CY is not in the register dump, so it is read back with `b.addc rN,r0,r0`, which
leaves CY in rN.
"""
import os
import re
import subprocess
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = os.path.join(HERE, 'vendor/r2-elf-linux-1.3.5.14')
ENV = dict(os.environ, LC_ALL='C')

# Both setups initialise the operand registers identically, so the only
# difference between them is the state of CY.
INIT = 'b.movi r3,-1\nb.movi r4,1'                  # r3 = 0xffffffff, r4 = 1
SET_CY = f'{INIT}\nb.add r5,r3,r4'                   # 0xffffffff + 1 carries
CLEAR_CY = f'{INIT}\nb.add r5,r0,r0'                 # 0 + 0 does not
PROBE_CY = 'b.addc r20,r0,r0'                              # r20 = CY


def probe(body, steps=40):
    """Assemble and run one snippet; return the register file as a dict."""
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, 'p.s')
        with open(src, 'w') as fh:
            fh.write('\t.text\n\t.global _start\n_start:\n')
            for line in body.strip().splitlines():
                fh.write('\t' + line.strip() + '\n')
            fh.write('\tb.trap 0\n')
        obj, elf = os.path.join(d, 'p.o'), os.path.join(d, 'p.elf')
        subprocess.run([f'{T}/bin/aeon-elf-as', '-maeonR2', '-EB', '-munknown', '-mmulti', src, '-o', obj],
                       check=True, env=ENV, capture_output=True)
        subprocess.run([f'{T}/bin/aeon-elf-ld', '-maeonR2_elf', f'-L{T}/aeon-elf/lib',
                        '-Ttext', '0x700', '-e', '_start', obj, '-o', elf],
                       check=True, env=ENV, capture_output=True)
        out = subprocess.run([f'{T}/bin/aeon-elf-sim', '-q', '-i', '-f',
                              f'{T}/config_file/sim.cfg', elf],
                             input=f'run {steps}\nr\nq\n', capture_output=True,
                             text=True, env=ENV, timeout=120).stdout
    regs = {}
    for m in re.finditer(r'GPR(\d+): ([0-9a-f]{8})', out):
        regs['r%d' % int(m.group(1))] = int(m.group(2), 16)
    flags = re.findall(r'flag: (\d)', out)
    if flags:
        regs['flag'] = int(flags[-1])
    return regs


def writes_cy(insn):
    """True if `insn` sets the carry flag rather than leaving it alone."""
    with_cy = probe(f'{SET_CY}\n{insn}\n{PROBE_CY}')
    without = probe(f'{CLEAR_CY}\n{insn}\n{PROBE_CY}')
    # preserved: the probe sees what we put there; written: it sees the same thing
    # both times (whatever the instruction computed)
    return not (with_cy.get('r20') == 1 and without.get('r20') == 0)


if __name__ == '__main__':
    CASES = [
        ('b.add    r6,r3,r4', 'add, carrying'),
        ('b.add    r6,r0,r0', 'add, not carrying'),
        ('b.sub    r6,r0,r4', 'sub, borrowing'),
        ('b.sub    r6,r4,r0', 'sub, not borrowing'),
        ('b.addi   r6,r3,1', 'addi, carrying'),
        ('b.mul    r6,r3,r3', 'mul'),
        ('b.mulu   r6,r3,r3', 'mulu'),
        ('b.slli   r6,r3,1', 'slli out of the top bit'),
        ('b.srli   r6,r3,1', 'srli out of the bottom bit'),
        ('b.srai   r6,r3,1', 'srai'),
        ('b.ror    r6,r3,r4', 'ror'),
        ('b.sll    r6,r3,r4', 'sll'),
        ('b.and    r6,r3,r3', 'and'),
        ('b.or     r6,r3,r3', 'or'),
        ('b.xor    r6,r3,r3', 'xor'),
        ('b.ori    r6,r3,1', 'ori'),
        ('b.andi   r6,r3,1', 'andi'),
        ('b.xori   r6,r3,1', 'xori'),
        ('b.sfeq   r3,r3', 'sfeq'),
        ('b.sfleu  r3,r4', 'sfleu'),
        ('b.sfgtu  r3,r4', 'sfgtu'),
        ('b.sfeqi  r3,1', 'sfeqi'),
        ('b.movhi  r6,0x15', 'movhi'),
        ('b.movi   r6,1', 'movi'),
        ('b.mov    r6,r3', 'mov'),
        ('b.extbz  r6,r3', 'extbz'),
        ('b.cmov   r6,r3,r4', 'cmov'),
        ('b.ff1    r6,r3', 'ff1'),
        ('b.div    r6,r3,r4', 'div'),
        ('b.divu   r6,r3,r4', 'divu'),
    ]
    print('instructions that write CY:')
    for insn, label in CASES:
        print(f'  {"WRITES " if writes_cy(insn) else "preserves"}  {label:32s} {insn}')
