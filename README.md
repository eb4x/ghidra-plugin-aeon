# ghidra-plugin-aeon — MStar AEON R2 processor module

A Ghidra processor module (SLEIGH) for the MStar **AEON R2** (`aeonR2`) core, packaged as a
standalone extension. The core is OpenRISC-derived, with 32 general-purpose registers and
instructions of 2, 3 or 4 bytes, always big-endian. Data can be either byte order, so there
are two languages:

| language | data | use for |
|---|---|---|
| `AEON:LE:32:R2` | little-endian | MStar firmware (built `-EL`, which the vendor gcc turns into `-EL -EBinst`) |
| `AEON:LE:32:R2-harvard` | little-endian, in its own `data` space | MStar firmware whose data addresses reuse code addresses (the MST9U main firmware) |
| `AEON:BE:32:R2` | big-endian | code built `-EB`, the toolchain's default |

All three decode identically. They differ in every load and store (byte order, and in the
Harvard variant the address space), and in the order of 64-bit register pairs.

## What the core looks like

| Property | Value | How it was established |
|---|---|---|
| Endianness | instructions big; data big (`-EB`) or little (`-EL -EBinst`) | vendor gcc spec, assembler, `aeon-elf-sim -EL`; MStar images store packed `u16` fields low byte first and hold little-endian code-address records |
| Instruction length | top **three** bits of byte 0: `0xx`=3, `100`=2, `101`=4, `11x`=4 | vendor objdump; `101` is the 4-byte DSP/MAC/SIMD block |
| Alignment | 1 (instructions start at any byte) | fixtures |
| Delay slots | **none** | the vendor gcc driver rejects `-minsert-nop-before-branch` for `-march=aeonR2`, and aeonR2 output has no filled slots |
| `r0` | hardwired zero | wrote r0 in `aeon-elf-sim`, read back 0 |
| Flag | a single condition flag set by `sf*`, tested by `bf`/`bnf` | ISA tables, simulator register dump (`flag:`) |
| Carry | `add`/`addi`/`sub` write CY; `addc`/`subb`/`addic` take it in and write it out; everything else leaves it alone | `tools/simprobe.py`, measured instruction by instruction |
| `subb` polarity | borrow: `0 - 0` with CY set gives `0xffffffff` | simulator |
| Stack pointer | `r1` | vendor gcc |
| Link register | `r9` (`b.jal` writes it, `b.jr r9` returns) | vendor gcc, fixtures |
| Arguments | `r3`..`r8`, then the stack at `0(r1)` | vendor gcc |
| Return value | `r3`; 64-bit in `r3`+`r4`, high word in `r3` under `-EB` but **low** word in `r3` under `-EL` (arguments likewise) | vendor gcc `-mbe`/`-mle` |
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
| stream 0, EIM153 (main firmware, base ~0x300000) | 550,514 | 0 |
| stream 0, EIM162 (the same code, a later build) | 549,323 | 0 |
| TSUM_G slice (HP M24fd, a different MStar chip) | 58,987 | 0 |

Bytes where objdump emits a one-byte `.word` are counted separately: they do not decode, and
Ghidra leaves them undefined.

## P-code is tested against the vendor simulator, not just read off the tables

Decoding can be checked against objdump; semantics cannot. `tools/gen_emu_cases.py` runs short
sequences in MStar's `aeon-elf-sim` and records the resulting register file;
`ghidra_scripts/AeonEmuTest.java` replays the same bytes through Ghidra's p-code emulator and
compares. `./gradlew emuTest` runs the 35 committed cases: carry and borrow chains, 64-bit
addition, the address-load pair, shifts, logic, extension, multiply and divide, compares and
conditional moves, loads and stores of each width, push/pop and the multi-word transfers.
`emuTestLe` replays the same cases against the simulator run on an `-EL -EBinst` build, for
the little-endian language. Two cases store a word and read back bytes, which gives
different answers in the two byte orders, so each test catches the wrong endianness.

This is what caught the carry semantics. `b.add` sets CY in hardware, so modelling carry as
"only `addc` touches it" made every `addc` after an `add` read a stale flag — wrong in a way
that corrupts decompiled 64-bit arithmetic silently rather than failing. Deliberately
reverting that one line makes 4 of the cases fail, so the test has teeth.

Fixtures come from the `hp-z27k-g3` session and are not committed here, and neither are the
entry-point lists derived from them: generate one with
`tools/jal_targets.py <listing> <base> <size> strong` and pass it as `-PaeonSeeds`. The only
seed list in the repo is sBoot's, which is the architectural reset vector rather than anything
derived from a firmware image.

**The acceptance diff proves decoding, not code coverage.** Both tools sweep linearly, which
is what makes the comparison fair, but a linear sweep decodes .rodata as instructions too. No
instruction count from this table says anything about how much of a fixture is really code.

The TSUM_G slice also answered a question for `hp-z27k-g3`: that chip's core is aeonR2, not an
earlier AEON. Decoded as `aeon:aeonR2` 12.6% of the sweep fails to decode, against 67.2% as
`aeon1` and 52.6% as `aeon2`, and the `b.jr r9` return idiom appears 194 times under aeonR2 and
never under the other two.

## Verified against the decompiler, not just the listing

`./gradlew decompileCheck -PaeonFixture=… -PaeonSeeds=… -PaeonBase=…` decompiles every
function and reports failures, warnings by kind, and how many computed jumps recovered a jump
table. A clean listing and correct p-code say nothing about what a reader sees.

| fixture | functions | decompile failures | computed jumps | with a recovered table |
|---|---|---|---|---|
| HDCP module | 218 | 0 | 31 | 0 |
| stream 0 | 5,622 | 0 | 120 | 39 (78 targets) |

The `b.jr` split is doing its job: functions close at `b.jr r9` and the remaining computed
jumps are real switches. The compare-and-branch p-code helps here too: `b.bgtui` puts the
comparison directly in the `CBRANCH` condition, one step from the switch variable, which is
what lets Ghidra's guard analysis find the bound. That is a consequence of keeping `F` a
standalone register rather than a bit-field of `sr`.

Recovery needs the table bytes **in the same program**, in a block Ghidra treats as readable.
A table that lives in a separately imported image will not resolve however correct the spec
is, so an image whose tables sit outside it should be imported as one program at the right
base.

Where stream 0's unrecovered tables live is settled, and not where I guessed. I proposed they
were in another DEFLATE stream that had not been extracted; `hp-z27k-g3` refuted it by
checking: the payload has exactly five streams, and streams 1-4 all begin `42 4D` ("BM") —
they are OSD bitmaps, not code or data. The 0x2d0000 region is runtime RAM or something
stream 0's init copies there, the same situation as the HDCP module's 0xb000828. Those
dispatches need a live memory dump or the flash table that populates the region; no import
arrangement will recover them.

The AEON address map, from their pointer histogram, is useful context for anyone importing
one of these images:

| range | what |
|---|---|
| 0x300000 – ~0x3c0000 | main firmware (stream 0); base 0x300000 confirmed |
| 0x10xxxx – 0x16xxxx | the loadable modules, sharing one address space with the firmware, which calls into them (the HDCP module's 0x157000 sits here) |
| 0x2d0000 | data/table region, 551 references, populated at runtime |
| 0x1b06_0000 / 0x1b07_0000 | MMIO and buffers |

The HDCP module recovers none of its 31 because its dispatch tables
live in RAM — the pattern is `b.bgtui` bound check, `b.slli` index, `movhi`+`addi` table base
of 0xb000828, `b.lwz`, `b.jr` — and that RAM is not part of the module blob. Mapping the RAM
region (or importing the module alongside the firmware that fills it) is what would recover
them; nothing in the spec can.

## Read the disassembly, not the summary

Twice in building this, a script I wrote told me something the bytes contradicted, and both
times the summary was more convincing than it deserved to be.

- A carry-flag battery reported that `b.add` *preserves* CY. It didn't: the two runs it
  compared initialised the operand registers differently, so the "no carry" run was adding
  0+0. The real answer — `add`, `addi` and `sub` all write CY — changed four instructions'
  semantics.
- A jump-table analysis reported "bound check: NO" for all six sites I sampled. Every one of
  them has a `b.bgtui` immediately before the branch. The regex had a stray escape.

Neither error was in the module; both were in the tooling that measures it, and both would
have become findings if the next step had been to act on the summary. The habit that caught
them was opening the disassembly and reading it. A measurement that disagrees with the bytes
is a bug in the measurement until proven otherwise — and a peer's summary, including mine,
deserves the same treatment.

## What the module actually meets: the census

`./gradlew census -PaeonFixture=… -PaeonSeeds=… -PaeonBase=…` seeds entry points, lets
flow-based disassembly run, and counts only the instructions inside functions — the list that
says which pseudo-ops are worth replacing with real p-code. It marks an instruction as a
pseudo-op when its p-code contains a `CALLOTHER`, which is what the decompiler shows as an
opaque call, and reports the histogram twice: over all seeded functions, and over those that
reach a return, since a seed that was really data produces a function that runs off the end.

The census overturned my assumption about what to model next. In stream 0, pseudo-ops are
**183 of 195,110 instructions** in functions that return — under 0.1% — and the MAC/DSP/SIMD
breadth I had expected to matter is almost entirely in the non-returning functions, i.e. in
data swept as code. What did show up in real code was mundane: special-purpose register
access, `b.divl`, and `b.pclwz`. Those now have real p-code, which leaves sBoot with one
pseudo-op instruction reachable (`b.syncwritebuffer`, correctly opaque) and the HDCP module
with three.

| fixture | functions | reachable instructions | with a return | in-memory data refs |
|---|---|---|---|---|
| sBoot (seeded from the reset vector alone) | 102 | 3,957 | 96 | 169 |
| HDCP module (212 seeds from hp-z27k-g3) | 218 | 13,165 | 210 | 16 |
| stream 0 (2,516 filtered b.jal targets) | 3,143 | 216,210 | 3,074 | 13,757 |

**Seeding matters more than it looks.** Raw `b.jal` targets from a linear sweep include calls
decoded inside data, which point anywhere: of stream 0's 7,268 raw targets, 2,959 do not even
land on an instruction boundary. Seeding all of them produced 1,734 "functions" that ran off
the end and made the module look far worse than it is. `tools/jal_targets.py … strong` keeps
targets that start with a recognisable prologue or are called more than once, which drops the
run-off count from 1,734 to 31 — 97.8% of the seeded functions then reach a return or end in a
tail call. A function ending in a tail call is healthy too, and the census counts it as such.

In sBoot every function is accounted for: 96 return, 3 tail-call, and the remaining 3 are a
boot hand-off trampoline (`b.jr r3`, where the caller loads the address of the next image) and
two deliberate hang loops (`b.j` to themselves). No gaps in the spec.

## Analysis the extension adds

The same image that imported with 71 functions (stream 0, nothing seeded) now gets 3,437. Three
pieces make the difference, and they apply to both languages:

- **Function-start patterns** (`data/patterns/`). A non-leaf gcc function opens with
  `b.addi r1,r1,-N` and then `b.sw N-4(r1),r9`, in every encoding width the assembler picks.
  The stock Function Start Search finds those, and call following reaches the leaf functions
  from there. Of the functions no `b.jal` in the image reaches, a sample of six were all real
  starts, each directly after the previous function's `b.jr r9` or `b.j`. These are functions
  reached through pointer tables.
- **AEON Constant Reference Analyzer** (`src/main/java/aeon/AeonAddressAnalyzer.java`). This is
  the stock constant propagation, plus a DATA reference on each `b.addi`/`b.ori` that
  completes a `movhi` address. The stock analyzer already references a load or store through
  such a base. What it misses is the address itself when the code passes it on, e.g. a struct
  pointer or a string handed to a callee. On stream 0 that adds 6,560 references.
- **"Create Address Tables" is off by default** (a pspec property). With little-endian data it
  finds records of addresses that point just past call instructions. Ghidra's non-returning
  function heuristic reads a reference after a call as evidence that the callee never
  returns, so it marked nine busy helpers non-returning and cut off 270 functions.

`./gradlew decompileCheck` lists non-returning functions, so a regression like that shows. Its
`-PaeonDisable=<analyzer>,…` option switches analyzers off for an A/B comparison.

## Data addresses that coincide with code: the Harvard variant

In the MST9U main firmware, data addresses share their numbers with code, but not their bytes.
`0x3241e9` is used as a printf format string, but code sits at that address. `0x3c027c` is a
global next to a real function, and `0x3305da` is both a struct base and a function entry.
Ghidra's decompiler treats any address inside a function body as read-only
(`DecompileCallback.encodeFunction` gives the containing range a CONSTANT hole, whatever the
block permissions). So in one space, a load from such a global folded to the instruction
bytes that happened to be there. `FUN_0030e7f3` decompiled to `return 0`, with 13 blocks
removed as unreachable, in both plain languages.

`AEON:LE:32:R2-harvard` keeps instruction fetches and branch targets in `ram` and puts every
load and store, the stack included, in `data`:
- The generator names the space of every memory access and refuses to emit a code-space
  access that isn't a branch target.
- The cspec has `<global>` over both spaces and a stack pointer in `data`.
- The pspec creates `data_ram` at `data:0x200000`–`0x1affffff` (uninitialized, writable).
  The floor is 0x200000 because mapping from 0 turned every small constant and struct offset
  into a reference (over 20,000 of them). There is no MMIO block. Registers are written
  through helpers that take a register number (`0x121b00` is bank `0x121b`) and add it,
  scaled, to a base pointer the image reads but never sets. So the register addresses aren't
  visible statically, and mapping the numbers would make each one a false reference.

On a fresh import, `FUN_0030e7f3` decompiles all 162 instructions: four double-buffered queues
of ordinary `DAT_data_003c0xxx` globals. The "Read-only address is written" warnings are
gone, and so are 36 "jump tables" whose one non-fall-through target was garbage read from
instruction bytes.

What it cannot do yet is show data contents. sBoot places the image's rodata into data space
at runtime, scattered rather than at one offset, and until that placement is known the data
space is empty. Strings like the printf formats have no text, and a function pointer stored
in data gives its indirect call no target. Address data-space locations as `data:0x…`; a
bare number means code.
