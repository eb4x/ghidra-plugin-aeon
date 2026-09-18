#!/usr/bin/env python3
"""Generate the aeonR2 SLEIGH spec from the vendor ISA tables.

Reads isa/aeon_isa.json (dumped from aeon-elf-as) and isa/calibration.json
(measured against aeon-elf-objdump) and writes:

    data/languages/aeonR2.sinc   tokens, fields, attachments, constructors
    isa/priority.md              the decode-priority rules that were applied

Display names and operand formatting follow the vendor objdump's default (b.)
output, which is the acceptance oracle. Semantics come from SEMANTICS below;
anything not listed there gets a pseudo-op so it still decodes with the right
length and operands.
"""
import json
import os
import re
import sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Letters that are punctuation need an identifier to appear in templates.
LETTER_ID = {
    '%': 'PCT', '`': 'BTK', ':': 'COL', '_': 'UND', '~': 'TIL', ';': 'SEM',
    "'": 'QUO', '/': 'SLA', '!': 'BNG', '=': 'EQ', '&': 'AMP', '|': 'PIPE',
    '<': 'LT', '>': 'GT', '$': 'DOL', '@': 'AT', '#': 'HASH', '*': 'STAR',
    '^': 'CARET', '[': 'LBR', ']': 'RBR', '?': 'QM',
}


def lid(ch):
    return LETTER_ID.get(ch, ch)


def runs(enc):
    out = []
    for i, c in enumerate(enc):
        if out and out[-1][0] == c and out[-1][1][-1] == i - 1:
            out[-1][1].append(i)
        else:
            out.append((c, [i]))
    return out


def letter_runs(enc):
    """Ordered [(letter, [bit indices MSB-first])] runs, skipping fixed bits."""
    return [(c, bits) for c, bits in runs(enc) if c not in '01-']


def letters_of(enc):
    order, pos = [], {}
    for c, bits in letter_runs(enc):
        if c not in pos:
            pos[c] = []
            order.append(c)
        pos[c].extend(bits)
    return order, pos


def tok_of(enc):
    return {16: 'i16', 24: 'i24', 32: 'i32'}[len(enc)]


def tokpfx(enc):
    return {16: 't', 24: 'n', 32: 'g'}[len(enc)]


def field_name(enc, ch, bits):
    """Field name from token prefix, letter id and the token bit range."""
    n = len(enc)
    lo = n - 1 - bits[-1]
    hi = n - 1 - bits[0]
    return f'{tokpfx(enc)}_{lid(ch)}_{lo}_{hi}', lo, hi


# ---------------------------------------------------------------- semantics --
# Placeholders: {Xw} write form of register letter X, {X} read form (r0 reads
# as 0), immediates by letter id. {next} = inst_next, {this} = inst_start.
SEMANTICS = {
    # --- moves and arithmetic -------------------------------------------
    'bt.mov':    '{Dw} = {A};',
    'bt.add':    '{Dw} = {D} + {A};',
    'bt.addi':   '{Dw} = {D} + {I};',
    'bt.movi':   '{Dw} = {I};',
    'bt.movhi':  '{Dw} = {H} << 16;',
    'bt.add16':  '{Dw} = {D} + 16;',
    'bt.mov16':  '{Dw} = 16;',
    'bn.add':    '{Dw} = {A} + {B};',
    'bn.sub':    '{Dw} = {A} - {B};',
    'bn.addc':   'local c = zext(CY); {Dw} = {A} + {B} + c; CY = carry({A}, {B});',
    'bn.subb':   'local c = zext(CY); {Dw} = {A} - {B} - c; CY = {A} < {B};',
    'bn.mul':    '{Dw} = {A} * {B};',
    'bn.mulu':   '{Dw} = {A} * {B};',
    'bn.div':    '{Dw} = {A} s/ {B};',
    'bn.divu':   '{Dw} = {A} / {B};',
    'bn.and':    '{Dw} = {A} & {B};',
    'bn.or':     '{Dw} = {A} | {B};',
    'bn.xor':    '{Dw} = {A} ^ {B};',
    'bn.nand':   '{Dw} = ~({A} & {B});',
    'bn.andn':   '{Dw} = {A} & ~{B};',
    'bn.addi':   '{Dw} = {A} + {O};',
    'bn.andi':   '{Dw} = {A} & {N};',
    'bn.ori':    '{Dw} = {A} | {N};',
    'bn.xori':   '{Dw} = {A} ^ {O};',
    'bn.movhi':  '{Dw} = {DOL} << 16;',
    'bg.addi':   '{Dw} = {A} + {Y};',
    'bg.addic':  'local c = zext(CY); {Dw} = {A} + {Y} + c; CY = carry({A}, {Y}:4);',
    'bg.andi':   '{Dw} = {A} & {t};',
    'bg.ori':    '{Dw} = {A} | {t};',
    'bg.xori':   '{Dw} = {A} ^ {Y};',
    'bg.muli':   '{Dw} = {A} * {Y};',
    'bg.movhi':  '{Dw} = {U} << 16;',
    'bg.abs':    'local m:4 = -zext({A} s< 0); {Dw} = (-{A} & m) | ({A} & ~m);',
    'bg.min':    'local m:4 = -zext({A} s< {B}); {Dw} = ({A} & m) | ({B} & ~m);',
    'bg.max':    'local m:4 = -zext({A} s> {B}); {Dw} = ({A} & m) | ({B} & ~m);',
    'bg.minu':   'local m:4 = -zext({A} < {B}); {Dw} = ({A} & m) | ({B} & ~m);',
    'bg.maxu':   'local m:4 = -zext({A} > {B}); {Dw} = ({A} & m) | ({B} & ~m);',
    'bg.mini':   'local v:4 = {O}; local m:4 = -zext({A} s< v); {Dw} = ({A} & m) | (v & ~m);',
    'bg.maxi':   'local v:4 = {O}; local m:4 = -zext({A} s> v); {Dw} = ({A} & m) | (v & ~m);',
    'bg.minui':  'local v:4 = {LT}; local m:4 = -zext({A} < v); {Dw} = ({A} & m) | (v & ~m);',
    'bg.maxui':  'local v:4 = {LT}; local m:4 = -zext({A} > v); {Dw} = ({A} & m) | (v & ~m);',
    # conditional moves: F is the condition flag set by the sf* compares
    'bn.cmov':   'local m:4 = -zext(F != 0); {Dw} = ({A} & m) | ({B} & ~m);',
    'bn.cmovir': 'local v:4 = {I}; local m:4 = -zext(F != 0); {Dw} = (v & m) | ({B} & ~m);',
    'bn.cmovri': 'local v:4 = {I}; local m:4 = -zext(F != 0); {Dw} = ({A} & m) | (v & ~m);',
    'bn.cmovii': 'local v:4 = {I}; local w:4 = {L}; local m:4 = -zext(F != 0); {Dw} = (v & m) | (w & ~m);',
    # --- bit and byte manipulation ---------------------------------------
    'bn.extbz':  '{Dw} = zext({A}:1);',
    'bn.extbs':  '{Dw} = sext({A}:1);',
    'bn.exthz':  '{Dw} = zext({A}:2);',
    'bn.exths':  '{Dw} = sext({A}:2);',
    'bn.ff1':    '{Dw} = aeon_find_first_one({A});',
    'bn.fl1':    '{Dw} = aeon_find_last_one({A});',
    'bn.clz':    '{Dw} = aeon_count_leading_zeros({A});',
    'bn.swab':   '{Dw} = aeon_swap_bytes({A});',
    'bn.bitrev': '{Dw} = aeon_bit_reverse({A});',
    'bn.count1': '{Dw} = popcount({A});',
    'bn.sll':    '{Dw} = {A} << ({B} & 0x1f);',
    'bn.srl':    '{Dw} = {A} >> ({B} & 0x1f);',
    'bn.sra':    '{Dw} = {A} s>> ({B} & 0x1f);',
    'bn.ror':    '{Dw} = ({A} >> ({B} & 0x1f)) | ({A} << (32 - ({B} & 0x1f)));',
    'bn.slli':   '{Dw} = {A} << {H};',
    'bn.srli':   '{Dw} = {A} >> {H};',
    'bn.srai':   '{Dw} = {A} s>> {H};',
    'bn.rori':   '{Dw} = ({A} >> {H}) | ({A} << (32 - {H}));',
    # --- compares: set the F flag ----------------------------------------
    'bn.sfeq':   'F = ({A} == {B});',
    'bn.sfne':   'F = ({A} != {B});',
    'bn.sfles':  'F = ({A} s<= {B});',
    'bn.sfgts':  'F = ({A} s> {B});',
    'bn.sfleu':  'F = ({A} <= {B});',
    'bn.sfgtu':  'F = ({A} > {B});',
    'bn.sfeqi':  'F = ({A} == {O});',
    'bn.sfnei':  'F = ({A} != {O});',
    'bn.sflesi': 'F = ({A} s<= {O});',
    'bn.sfgtsi': 'F = ({A} s> {O});',
    'bn.sfleui': 'F = ({A} <= {O});',
    'bn.sfgtui': 'F = ({A} > {O});',
    'bg.sfeqi':  'F = ({A} == {Y});',
    'bg.sfnei':  'F = ({A} != {Y});',
    'bg.sflesi': 'F = ({A} s<= {Y});',
    'bg.sfgtsi': 'F = ({A} s> {Y});',
    'bg.sfleui': 'F = ({A} <= {Y});',
    'bg.sfgtui': 'F = ({A} > {Y});',
    'bt.sfgtui_minus32769': 'F = ({A} > -32769:4);',
    'bt.sfleui_minus32769': 'F = ({A} <= -32769:4);',
    'bt.sfgtsi_minus32769': 'F = ({A} s> -32769:4);',
    'bt.sflesi_minus32769': 'F = ({A} s<= -32769:4);',
    # --- branches and jumps ----------------------------------------------
    'bn.bf':     'if (F) goto {TIL};',
    'bn.bnf':    'if (!F) goto {TIL};',
    'bg.bf':     'if (F) goto {QUO};',
    'bg.bnf':    'if (!F) goto {QUO};',
    'bn.beqi':   'if ({A} == {PCT}) goto {BTK};',
    'bn.bnei':   'if ({A} != {PCT}) goto {BTK};',
    'bn.blesi':  'if ({A} s<= {PCT}) goto {BTK};',
    'bn.bgtsi':  'if ({A} s> {PCT}) goto {BTK};',
    'bn.bleui':  'if ({A} <= {PCT}) goto {BTK};',
    'bn.bgtui':  'if ({A} > {PCT}) goto {BTK};',
    'bg.beqi':   'if ({A} == {I}) goto {SEM};',
    'bg.bnei':   'if ({A} != {I}) goto {SEM};',
    'bg.blesi':  'if ({A} s<= {I}) goto {SEM};',
    'bg.bgtsi':  'if ({A} s> {I}) goto {SEM};',
    'bg.bleui':  'if ({A} <= {I}) goto {SEM};',
    'bg.bgtui':  'if ({A} > {I}) goto {SEM};',
    'bg.beq':    'if ({A} == {B}) goto {SEM};',
    'bg.bne':    'if ({A} != {B}) goto {SEM};',
    'bg.bles':   'if ({A} s<= {B}) goto {SEM};',
    'bg.bgts':   'if ({A} s> {B}) goto {SEM};',
    'bg.bleu':   'if ({A} <= {B}) goto {SEM};',
    'bg.bgtu':   'if ({A} > {B}) goto {SEM};',
    'bt.j':      'goto {T};',
    'bn.j':      'goto {s};',
    'bg.j':      'goto {SLA};',
    'bn.jal':    'r9 = inst_next; call {s};',
    'bg.jal':    'r9 = inst_next; call {SLA};',
    'bt.jalr':   'r9 = inst_next; call [{A}];',
    # bt.jr is split by register below (return vs computed jump)
    'bt.return': 'return [r9];',
    # --- loads and stores -------------------------------------------------
    'bn.lwz':    '{Dw} = *:4 ({A} + {COL});',
    'bn.lbz':    '{QMw} = zext(*:1 ({A} + {z}));',
    'bn.lbs':    '{Dw} = sext(*:1 ({A} + {z}));',
    'bn.lhz':    '{Dw} = zext(*:2 ({A} + {UND}));',
    'bn.lhs':    '{Dw} = sext(*:2 ({A} + {UND}));',
    'bn.sw':     '*:4 ({A} + {COL}) = {B};',
    'bn.sb':     '*:1 ({A} + {z}) = {B}:1;',
    'bn.sh':     '*:2 ({A} + {UND}) = {B}:2;',
    'bg.lwz':    '{Dw} = *:4 ({A} + {W});',
    'bg.lbz':    '{QMw} = zext(*:1 ({A} + {BNG}));',
    'bg.lbs':    '{QMw} = sext(*:1 ({A} + {BNG}));',
    'bg.lhz':    '{Dw} = zext(*:2 ({A} + {X}));',
    'bg.lhs':    '{Dw} = sext(*:2 ({A} + {X}));',
    'bg.sw':     '*:4 ({A} + {W}) = {B};',
    'bg.sb':     '*:1 ({A} + {Y}) = {B}:1;',
    'bg.sh':     '*:2 ({A} + {X}) = {B}:2;',
    # bt.stack: f=0 store, f=1 load, offset = F*4 from the stack pointer r1
    # (split into two constructors below)
    'bt.push':   'r1 = r1 - 4; *:4 r1 = {A};',
    'bt.pop':    '{Dw} = *:4 r1; r1 = r1 + 4;',
    # --- system ------------------------------------------------------------
    'bt.nop':    '',
    'bn.nop':    '',
    'bt.trap':   'aeon_trap({G}:4);',
    'bt.sys':    'aeon_syscall();',
    'bt.rfe':    'aeon_return_from_exception(); return [pc];',
    'bt.ei':     'aeon_enable_interrupts();',
    'bt.di':     'aeon_disable_interrupts();',
    'bt.wait':   'aeon_wait();',
    'bt.synci':  'aeon_sync_icache();',
    'bt.syncd':  'aeon_sync_dcache();',
    'bt.syncp':  'aeon_sync_pipeline();',
    'bg.syncwritebuffer': 'aeon_sync_write_buffer();',
    'bg.mtspr':  'aeon_mtspr({A} + {PIPE}:4, {B});',
    'bg.mfspr':  '{Dw} = aeon_mfspr({A} + {PIPE}:4);',
    'bg.mtspr1': 'aeon_mtspr({U}:4, {B});',
    'bg.mfspr1': '{Dw} = aeon_mfspr({U}:4);',
}

# Opcodes whose display repeats the destination as a source (objdump prints the
# two-operand bt. forms in three-operand form).
DISPLAY_REPEAT_DEST = {'bt.add', 'bt.addi', 'bt.add16'}

# Decode priorities objdump applies that SLEIGH needs as explicit constraints.
PRIORITY = [
    ('bt.stack', 'QM', '!=0', 'bt.trap/bt.nop take the encoding when the register field is 0'),
    ('bn.lbz', 'QM', '!=0', 'bn.pclwz takes the encoding when rD is 0'),
    ('bg.lbz', 'QM', '!=0', 'bg.pclwz takes the encoding when rD is 0'),
    ('bg.lbs', 'QM', '!=0', 'objdump rejects bg.lbs with rD 0'),
]

# Split-out constructors: objdump prints one mnemonic, but the p-code differs.
# Each entry: opcode -> list of (extra pattern constraint on a letter, semantics)
SPLIT = {
    # r9 is the link register, so `b.jr r9` is a return and anything else is a
    # computed jump; `b.jalr` is an indirect call.
    'bt.jr': [('A', 9, 'return [r9];'), (None, None, 'goto [{A}];')],
    # bt.stack f=0 stores, f=1 loads, at r1 + F*4
    'bt.stack': [('f', 0, 'local off:4 = {F} * 4; *:4 (r1 + off) = {QM};'),
                 ('f', 1, 'local off:4 = {F} * 4; {QMw} = *:4 (r1 + off);')],
}

DEST_LETTERS = set('D?Z')


def sanitize(name):
    return 'aeon_' + re.sub(r'\W', '_', name.split('.', 1)[1])


class Gen:
    def __init__(self):
        self.isa = json.load(open(os.path.join(HERE, 'isa/aeon_isa.json')))['aeon_aeonR2_isa']
        self.calib = json.load(open(os.path.join(HERE, 'isa/calibration.json')))
        # measured per opcode: which '-' runs the decoder really ignores
        self.dontcare = json.load(open(os.path.join(HERE, 'isa/dontcare.json')))
        self.letters = {l['letter']: l for l in self.isa['letters'] if l['letter']}
        self.fields = {'i16': OrderedDict(), 'i24': OrderedDict(), 'i32': OrderedDict()}
        self.regfields = OrderedDict()      # field name -> 'r' or 'v'
        self.readsubs = OrderedDict()       # field name -> subtable name
        self.immsubs = OrderedDict()        # subtable name -> body lines
        self.pcodeops = set()
        self.used_subs = set()
        self.ctors = []
        self.priority_notes = []

    # -- field helpers ---------------------------------------------------
    def field(self, enc, ch, bits, signed=False, vector=False):
        name, lo, hi = field_name(enc, ch, bits)
        if vector:
            name = name.replace(f'_{lid(ch)}_', f'_v{lid(ch)}_', 1)
        tok = tok_of(enc)
        prev = self.fields[tok].get(name)
        if prev is None:
            self.fields[tok][name] = (lo, hi, signed)
        elif prev[2] != signed:
            # same bits, same letter: signedness must agree
            raise SystemExit(f'field {name} used both signed and unsigned')
        return name

    def dup_field(self, enc, ch, bits):
        """A second field over the same bits, for constraints on an operand."""
        name, lo, hi = field_name(enc, ch, bits)
        name = name.replace(f'_{lid(ch)}_', f'_{lid(ch)}c_', 1)
        self.fields[tok_of(enc)].setdefault(name, (lo, hi, False))
        return name

    def const_field(self, enc, lo, hi):
        name = f'{tokpfx(enc)}_c{lo}_{hi}'
        self.fields[tok_of(enc)].setdefault(name, (lo, hi, False))
        return name

    def read_sub(self, fname):
        """Subtable that reads a GPR field, yielding 0 for r0 (hardwired)."""
        if fname not in self.readsubs:
            sub = 'RD_' + fname
            self.readsubs[fname] = sub
        return self.readsubs[fname]

    # -- operand construction --------------------------------------------
    def operand(self, op, ch, enc, pos):
        """Return (display symbol, read expression, extra pattern symbols)."""
        L = self.letters[ch]
        bits = pos[ch]
        parts = [b for b in letter_runs(enc) if b[0] == ch]
        signed = bool(L['flags'] & 2)
        pcrel = bool(L['flags'] & 8)
        isreg = bool(L['flags'] & 1)
        scale = 1 << L['shift']
        add = L['add']

        if isreg:
            kind = 'v' if ('v' + ch) in op['args'] else 'r'
            fname = self.field(enc, ch, bits, vector=(kind == 'v'))
            self.regfields[fname] = kind
            if kind == 'v':
                return fname, fname, []
            return fname, self.read_sub(fname), [self.read_sub(fname)]

        if len(parts) == 1 and scale == 1 and add == 0 and not pcrel:
            fname = self.field(enc, ch, bits, signed)
            return fname, fname, []

        # computed: scaled, biased, pc-relative, or split across runs
        exprs = []
        width = 0
        for c, bs in reversed(parts):          # least significant run first
            f = self.field(enc, c, bs, False)
            exprs.append((f, len(bs)))
            width += len(bs)
        acc, shift = [], 0
        for f, w in exprs:
            acc.append(f if shift == 0 else f'({f} << {shift})')
            shift += w
        val = ' + '.join(reversed(acc)) if len(acc) > 1 else acc[0]
        sub = ('REL_' if pcrel else 'IMM_') + '_'.join(f for f, _ in exprs)
        if sub not in self.immsubs:
            lines = [f'{val}']
            expr = val
            if signed:
                sb = 1 << (width - 1)
                expr = f'((({expr}) ^ {hex(sb)}) - {hex(sb)})'
            if scale != 1:
                expr = f'(({expr}) * {scale})'
            if add:
                expr = f'(({expr}) + {add})'
            if pcrel:
                body = (f'{sub}: reloc is {" & ".join(f for f, _ in exprs)} '
                        f'[ reloc = inst_start + {expr}; ] {{ export *:4 reloc; }}')
            else:
                body = (f'{sub}: val is {" & ".join(f for f, _ in exprs)} '
                        f'[ val = {expr}; ] {{ export *[const]:4 val; }}')
            self.immsubs[sub] = body
        return sub, sub, [sub]

    # -- display ----------------------------------------------------------
    def display(self, name, op, symbols, enc):
        args = op['args']
        if not args:
            return ''
        out = []
        i = 0
        while i < len(args):
            c = args[i]
            if c in 'rvqa' and i + 1 < len(args) and args[i + 1] in symbols:
                letter = args[i + 1]
                if c in 'rv':
                    out.append(symbols[letter][0])
                else:                        # q0x1 / a0x0: literal prefix
                    out.append(f'"{c}"^{symbols[letter][0]}')
                i += 2
                continue
            if c in symbols:
                out.append(symbols[c][0])
                i += 1
                continue
            out.append(c)
            i += 1
        disp = ''.join(out)
        if name in DISPLAY_REPEAT_DEST:
            # objdump prints these two-operand forms as three operands, with the
            # destination repeated. An operand can appear only once in a display,
            # so the repeat uses the read form, which prints the same register.
            dest = [c for c in symbols if self.letters[c]['flags'] & 1][0]
            disp = symbols[dest][0] + ',' + symbols[dest][1] + disp[len(symbols[dest][0]):]
        return disp

    # -- constructors ------------------------------------------------------
    def build(self):
        for op in self.isa['opcodes']:
            if op['for_encode_only']:
                continue
            name = op['name']
            rec = self.calib.get(name)
            if rec is None or rec['display'] is None:
                continue
            enc = op['encoding'].replace(' ', '')
            order, pos = letters_of(enc)
            symbols = {}
            extra = []
            for ch in order:
                d, r, ex = self.operand(op, ch, enc, pos)
                symbols[ch] = (d, r)
                extra.extend(ex)

            # Fixed bits, plus the '-' runs the decoder does NOT ignore (dash
            # runs are measured one at a time by tools/dash_probe.py; an ignored
            # run stays unconstrained, a significant one must be zero).
            ignored = set(self.dontcare.get(name, {}).get('ignored_bits', []))
            # rewrite ignored '-' bits to '.', so they group as unconstrained
            marked = ''.join('.' if (c == '-' and i in ignored) else c
                             for i, c in enumerate(enc))
            constraints = []
            for c, bits in runs(marked):
                if c not in '01-':
                    continue
                val = int(''.join('0' if x == '-' else x for x in
                                  [marked[b] for b in bits]), 2)
                f = self.const_field(enc, len(enc) - 1 - bits[-1], len(enc) - 1 - bits[0])
                constraints.append(f'{f}={val}')

            disp = self.display(name, op, symbols, enc)
            mnem = rec['display']
            for pri_name, pri_letter, pri_op, note in PRIORITY:
                if pri_name == name:
                    ch = [c for c in order if lid(c) == pri_letter][0]
                    fname = self.dup_field(enc, ch, pos[ch])
                    constraints.append(f'{fname}{pri_op}')
                    self.priority_notes.append((name, f'{fname}{pri_op}', note))

            variants = SPLIT.get(name)
            if variants is None:
                variants = [(None, None, SEMANTICS.get(name))]
            for letter, value, sem in variants:
                cons = list(constraints)
                if letter is not None:
                    cons.append(f'{self.dup_field(enc, letter, pos[letter])}={value}')
                elif name in SPLIT:
                    # the general case must exclude the specific one
                    sl, sv, _ = SPLIT[name][0]
                    cons.append(f'{self.dup_field(enc, sl, pos[sl])}!={sv}')
                binds = [d for d, _ in symbols.values()]
                self.ctors.append(self.emit_ctor(name, mnem, disp, cons,
                                                 extra + binds, symbols, sem,
                                                 op, order))

    def emit_ctor(self, name, mnem, disp, constraints, extra, symbols, sem, op, order):
        if sem is None:
            sem = self.pseudo(name, op, symbols, order)
        else:
            sem = self.expand(sem, symbols)

        # bind what the display or the semantics actually name
        used = sorted({e for e in set(extra)
                       if re.search(rf'\b{re.escape(e)}\b', sem + ' ' + disp)})
        self.used_subs.update(used)
        pat = ' & '.join(constraints + used)
        head = f':{mnem} {disp}' if disp else f':{mnem}'
        return f'{head} is {pat} {{ {sem} }}'

    def expand(self, sem, symbols):
        def sub(m):
            key = m.group(1)
            write = key.endswith('w')
            base = key[:-1] if write else key
            for ch, (d, r) in symbols.items():
                if lid(ch) == base:
                    return d if write else r
            raise SystemExit(f'template refers to missing operand {key}')
        for op_name in re.findall(r'\b(aeon_\w+|popcount)\s*\(', sem):
            if op_name != 'popcount':
                self.pcodeops.add(op_name)
        return re.sub(r'\{(\w+)\}', sub, sem)

    def pseudo(self, name, op, symbols, order):
        """Fallback: a pseudo-op call that keeps operands and length honest."""
        fn = sanitize(name)
        self.pcodeops.add(fn)
        dest = None
        args = []
        for ch in order:
            L = self.letters[ch]
            d, r = symbols[ch]
            if dest is None and ch in DEST_LETTERS and (L['flags'] & 1):
                dest = d
                continue
            args.append(r if (L['flags'] & 1) else f'{r}:4')
        call = f'{fn}({", ".join(args)})' if args else f'{fn}()'
        return f'{dest} = {call};' if dest else f'{call};'

    # -- output ------------------------------------------------------------
    def write(self):
        L = []
        L.append('# Generated by tools/gen_sleigh.py from the vendor ISA tables.')
        L.append('# Do not edit by hand: edit the generator and regenerate.')
        L.append('')
        for tok, size in (('i16', 16), ('i24', 24), ('i32', 32)):
            L.append(f'define token {tok} ({size})')
            for fname, (lo, hi, signed) in self.fields[tok].items():
                L.append(f'  {fname}=({lo},{hi})' + (' signed' if signed else ''))
            L.append(';')
            L.append('')
        gpr = [f for f, k in self.regfields.items() if k == 'r']
        vec = [f for f, k in self.regfields.items() if k == 'v']
        rnames = ' '.join(f'r{i}' for i in range(32))
        vnames = ' '.join(f'v{i}' for i in range(32))
        for f in gpr:
            L.append(f'attach variables [ {f} ] [ {rnames} ];')
        for f in vec:
            L.append(f'attach variables [ {f} ] [ {vnames} ];')
        L.append('')
        for fname, sub in self.readsubs.items():
            if sub not in self.used_subs:
                continue          # nothing reads through this field
            L.append(f'{sub}: "r0" is {fname}=0 {{ export 0:4; }}')
            L.append(f'{sub}: {fname} is {fname} {{ export {fname}; }}')
        L.append('')
        for body in self.immsubs.values():
            L.append(body)
        L.append('')
        L.extend(self.ctors)
        L.append('')
        sinc = os.path.join(HERE, 'data/languages/aeonR2.sinc')
        os.makedirs(os.path.dirname(sinc), exist_ok=True)
        open(sinc, 'w').write('\n'.join(L) + '\n')

        ops = '\n'.join(f'define pcodeop {o};' for o in sorted(self.pcodeops))
        open(os.path.join(HERE, 'data/languages/aeonR2_pcodeops.sinc'), 'w').write(ops + '\n')

        with open(os.path.join(HERE, 'isa/priority.md'), 'w') as fh:
            fh.write('# Decode priority rules applied by the generator\n\n')
            fh.write('objdump takes the first matching table entry; SLEIGH takes the\n'
                     'most specific pattern. These constraints encode the difference.\n\n')
            for n, c, note in self.priority_notes:
                fh.write(f'- `{n}`: constraint `{c}` — {note}\n')
        print('constructors:', len(self.ctors), 'pcodeops:', len(self.pcodeops),
              'read subtables:', len(self.readsubs), 'imm subtables:', len(self.immsubs))


if __name__ == '__main__':
    g = Gen()
    g.build()
    g.write()
