#!/usr/bin/env python3
"""Regenerate the smoke sample from smoke.s with the vendor toolchain.

Run through `./gradlew generateSmokeSample`. Writes, beside this file:
  smoke.bin      the raw image, loaded at 0x200000 (text, then data at 0x200080)
  smoke.objdump  the vendor objdump's decoding of the text, in the -D -b binary
                 form tools/acceptance.py reads; AeonSmoke.java compares Ghidra's
                 decoding with it

Built -EL -EBinst, as MStar firmware is: big-endian instructions, little-endian
data. The toolchain is vendor/ (gitignored, 32-bit, local only); CI checks the
committed outputs and never runs this.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
T = os.path.join(REPO, 'vendor/r2-elf-linux-1.3.5.14')
ENV = dict(os.environ, LC_ALL='C')   # the tools abort in loadlocale.c otherwise
BASE = 0x200000
DATA = 0x200080


def tool(name, *args):
    return subprocess.run([f'{T}/bin/aeon-elf-{name}', *args], env=ENV, check=True,
                          capture_output=True, text=True).stdout


def main():
    if not os.path.isdir(T):
        sys.exit(f'vendor toolchain not found: {T}')
    # a temporary directory under /tmp: the 32-bit tools fail on a 64-bit inode
    with tempfile.TemporaryDirectory() as d:
        obj, elf, image = (os.path.join(d, n) for n in ('smoke.o', 'smoke.elf', 'smoke.bin'))
        tool('as', '-maeonR2', '-EL', '-EBinst', '-munknown', '-mmulti',
             os.path.join(HERE, 'smoke.s'), '-o', obj)
        tool('ld', '-maeonR2_elf', '-EL', f'-L{T}/aeon-elf/lib/el', f'-L{T}/aeon-elf/lib',
             '-Ttext', hex(BASE), '-Tdata', hex(DATA), '-e', '_start', obj, '-o', elf)
        tool('objcopy', '-O', 'binary', elf, image)

        text = re.search(r'\.text\s+([0-9a-f]+)\s+([0-9a-f]+)', tool('objdump', '-h', elf))
        size, vma = int(text.group(1), 16), int(text.group(2), 16)
        if vma != BASE or size > DATA - BASE:
            sys.exit(f'.text is {size:#x} bytes at {vma:#x}; it must fit below {DATA:#x}')
        listing = tool('objdump', '-D', '-b', 'binary', '-m', 'aeon:aeonR2', '-EB',
                       f'--adjust-vma={BASE:#x}', f'--stop-address={BASE + size:#x}', image)

        with open(image, 'rb') as fh:
            data = fh.read()
    with open(os.path.join(HERE, 'smoke.bin'), 'wb') as fh:
        fh.write(data)
    lines = [ln for ln in listing.splitlines() if re.match(r'^\s*[0-9a-f]+:\t', ln)]
    with open(os.path.join(HERE, 'smoke.objdump'), 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    print(f'smoke.bin: {len(data)} bytes; smoke.objdump: {len(lines)} instructions')


if __name__ == '__main__':
    main()
