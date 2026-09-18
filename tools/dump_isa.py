#!/usr/bin/env python3
"""Static equivalent of smx-smx/aeon-isa extract.c: read ISA tables from aeon-elf-as (i386 ELF)."""
import struct, sys, json
path = sys.argv[1]
data = open(path, 'rb').read()
e_shoff, = struct.unpack_from('<I', data, 0x20)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x2e)
shdrs = [struct.unpack_from('<IIIIIIIIII', data, e_shoff + i*e_shentsize) for i in range(e_shnum)]
shstr = shdrs[e_shstrndx][4]
def cstr_at(off):
    return data[off:data.index(b'\0', off)].decode('latin1')
secs = {cstr_at(shstr + s[0]): s for s in shdrs}
def v2o(va):
    for s in shdrs:
        if s[1] != 8 and s[3] and s[3] <= va < s[3] + s[5]:
            return va - s[3] + s[4]
    raise ValueError(hex(va))
def u32(va): return struct.unpack_from('<I', data, v2o(va))[0]
def s(va): return cstr_at(v2o(va)) if va else None
sym = secs['.symtab']; strtab = shdrs[sym[6]]
syms = {}
for i in range(sym[5] // 16):
    n, val, sz, info, oth, shn = struct.unpack_from('<IIIBBH', data, sym[4] + i*16)
    if n: syms[cstr_at(strtab[4] + n)] = val
INSN_TYPES = "it_unknown it_exception it_arith it_shift it_compare it_cond_branch it_uncond_branch it_indirect_jump it_call it_return it_load it_store it_movimm it_move it_extend it_nop it_mac it_float it_simd it_asic it_cache it_bs it_subword it_sys it_hint it_loop".split()
def isa(name):
    b = syms[name]; a = u32(b)
    letters_p, _, opcodes_p, equiv_p = u32(a), u32(a+4), u32(a+8), u32(a+12)
    ops = []; p = opcodes_p
    while True:
        nm = s(u32(p))
        if not nm: break
        fu = u32(p+20)
        ops.append(dict(name=nm, args=s(u32(p+4)), encoding=s(u32(p+8)), flags=u32(p+16),
                        func_unit=INSN_TYPES[fu] if fu < len(INSN_TYPES) else fu,
                        for_encode_only=u32(p+24), version_control=u32(p+28)))
        p += 32
    letters = []; p = letters_p
    while data[v2o(p)]:
        c, fl, ln, sh, add, z, amb = struct.unpack_from('<B3xIIIiii', data, v2o(p))
        letters.append(dict(letter=chr(c), flags=fl, len=ln, shift=sh, add=add, zero_is_max_plus_1=z, ambigous_value=amb))
        p += 28
    equiv = []; p = equiv_p
    while equiv_p and u32(p):
        e = u32(p)
        equiv.append(dict(insn=s(u32(e)), flags=u32(e+4), args=s(u32(e+8)), args_map=s(u32(e+12)),
                          equiv_insns=[s(u32(e+16+4*i)) for i in range(6) if u32(e+16+4*i)]))
        p += 4
    return dict(letters=letters, opcodes=ops, equiv=equiv)
out = {n: isa(n) for n in ('aeon_aeon1_isa', 'aeon_aeon2_isa', 'aeon_aeonR2_isa')}
json.dump(out, sys.stdout, indent=1)
