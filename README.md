# ghidra-plugin-aeon — MStar AEON R2 processor module

A Ghidra processor module (SLEIGH) for the MStar **AEON R2** (`aeonR2`) core, packaged as a
standalone extension. The core is big-endian and OpenRISC-derived, with 32 general-purpose
registers and instructions of 2, 3 or 4 bytes.

## What the core looks like

| Property | Value | How it was established |
|---|---|---|
| Endianness | big | vendor objdump, `-EB` |
| Instruction length | top **three** bits of byte 0: `0xx`=3, `100`=2, `101`=4, `11x`=4 | vendor objdump; `101` is the 4-byte DSP/MAC/SIMD block |
| Alignment | 1 (instructions start at any byte) | fixtures |
| Delay slots | **none** | the vendor gcc driver rejects `-minsert-nop-before-branch` for `-march=aeonR2`, and aeonR2 output has no filled slots |
| `r0` | hardwired zero | wrote r0 in `aeon-elf-sim`, read back 0 |
| Flag | a single condition flag set by `sf*`, tested by `bf`/`bnf` | ISA tables, simulator register dump (`flag:`) |
| Stack pointer | `r1` | vendor gcc |
| Link register | `r9` (`b.jal` writes it, `b.jr r9` returns) | vendor gcc, fixtures |
| Arguments | `r3`..`r8`, then the stack at `0(r1)` | vendor gcc |
| Return value | `r3` (64-bit in `r3:r4`, high word in `r3`) | vendor gcc |
| Callee-saved | `r10`..`r22` | vendor gcc (`r23`..`r31` are used freely by leaf functions) |
| Address loads | `movhi rN,hi` then `addi/ori rN,rN,lo` (`addi` signed) | vendor gcc, fixtures |

## How the spec is produced

The spec is **generated from the vendor's own tables and measured against the vendor
disassembler**, not written by hand from observed encodings.

1. `tools/dump_isa.py` reads the ISA tables (opcodes, operand letters, equivalences) straight
   out of `aeon-elf-as`'s symbol table → `isa/aeon_isa.json`. This is the static equivalent of
   the `smx-smx/aeon-isa` `LD_PRELOAD` shim, which can't build here (no 32-bit glibc headers).
2. `tools/calibrate.py` encodes every opcode with varied field values, disassembles them with
   `aeon-elf-objdump`, and records how each operand prints → `isa/calibration.json`. This is
   what pins scale, bias, signedness and pc-relativity per operand, and the display mnemonic.
3. `tools/verify_letters.py` checks the operand model (from the ISA `letters` table) against
   every calibration probe. 2014 probes, mismatches only in `bg.loop`, `bg.btb`, `bg.dma_op`.
4. `tools/dash_probe.py` sets each don't-care (`-`) bit of each opcode one at a time to find
   which bits the decoder really ignores → `isa/dontcare.json`. Runs are often only *partly*
   ignored (`bt.rfe`), so this is per bit.
5. `tools/gen_sleigh.py` emits `data/languages/aeonR2.sinc` plus `isa/priority.md`, the list of
   decode-priority constraints it applied (objdump takes the first matching table entry; SLEIGH
   takes the most specific pattern, so the difference is written out explicitly).

Semantics live in `SEMANTICS` in the generator. The integer core, branches, loads/stores,
`movhi`, the `jr` split and the system instructions have real p-code; MAC/DSP/SIMD/float and
the cache/`entri`/`reti` family are pseudo-ops, so they still decode with the right length and
operands.

## Build

```
./gradlew buildExtension     # compiles the .slaspec first; a spec error fails the build
./gradlew installExtension   # extract into GHIDRA_USER_EXTENSIONS_DIR
./gradlew smokeTest          # decode tests/smoke.bin and compare with the vendor objdump
```

Every headless run goes through a Gradle task: each one wipes `build/smoke`, extracts the
freshly built zip into the settings dir it pins, and takes its verdict from a fixed line in
the script's output, since `analyzeHeadless` exits 0 even when a script throws.

`gradle.properties` (gitignored) points at the shared read-only SDK and the user extensions
directory. The sleigh step runs with `-l -c -n -u -t -f`, so pattern conflicts, colliding
operands, dead temporaries and unused fields fail the build.

## Acceptance

Ghidra's disassembly is diffed against the vendor objdump address by address, over a full
linear sweep of each fixture — mnemonic, operands and length:

```
./gradlew acceptanceTest -PaeonFixture=fixtures/sboot.bin -PaeonListing=fixtures-out/sboot.asm
```

which runs `ghidra_scripts/AeonDumpDisasm.java` (the linear-sweep dump) and
`tools/acceptance.py` (the diff), and fails on any unexplained difference.

| Fixture | instructions | unexplained differences |
|---|---|---|
| sBoot (0x0–0x20000) | 43,752 | 0 |
| HDCP module (base 0x157000) | 18,516 | 0 |
| stream 0 (main firmware, base ~0x300000) | 550,514 | 0 |

Bytes where objdump emits a one-byte `.word` are counted separately (578 / 353 / 55,682): they
do not decode, and Ghidra leaves them undefined.

Fixtures come from the `hp-z27k-g3` session and are not committed here.
