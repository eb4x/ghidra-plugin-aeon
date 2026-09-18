# ghidra-plugin-aeon

The MStar AEON R2 (`aeonR2`) Ghidra processor module: a SLEIGH language plus processor and
compiler specs, generated from the vendor ISA tables and measured against the vendor objdump.

# Common to every ghidra-plugin-* repo

_Everything from here to "Repo-specific" is kept identical in every `ghidra-plugin-*`
CLAUDE.md. Change it in all of them together, after the other plugin sessions agree, then
compare this hash across the repos:_

```bash
awk '/^# Common to every ghidra-plugin-\* repo/{p=1} /^# Repo-specific/{p=0} p' CLAUDE.md | md5sum
```

## The team

The **core team** is permanent: `dailydriver` and the `ghidra-plugin-*` sessions (more
plugins may join over time), with `eclipse-plugin-mcp` for the IDE. **Project sessions**
(a reverse-engineering task on some target) come and go. All share four MCP servers:
`eclipse-workspace` + `eclipse-launch` on :8124, `ghidra-application-level` +
`ghidra-program` on :8765.

| session | cwd | owns | message it when |
| --- | --- | --- | --- |
| `dailydriver` | `~/src/ghidra/dailydriver` | Ghidra core: the fork, its dist builds, and the shared SDK it extracts | the decompiler, disassembler or Sleigh spec itself is wrong; anything needing a core patch; a Ghidra version bump; **deciding whether a fix belongs in core or in a plugin** |
| `ghidra-plugin-mcp` | `~/src/ghidra-plugin-mcp` | the MCP server inside Ghidra (:8765): tool set, ergonomics, friction log. The main component every project uses | you need a tool or `op` that doesn't exist, or one fights you. The first stop for any new RE project |
| `ghidra-plugin-rtlink` | `~/src/ghidra-plugin-rtlink` | RTLink/Plus overlays and DOS emulated-float (INT 34h–3Dh) code: overlay blocks, dispatch stubs, switch tables, DS xrefs, buried code | a late-DOS MZ target is mis-analysed: overlays, dispatch stubs, switch tables, DS xrefs, buried code, emulated x87. First stop for any coverage problem on DOS |
| `ghidra-plugin-keil8051` | `~/src/ghidra-plugin-keil8051` | Keil C51 / 8051: multi-module flash loader, vector seeding, `?C?xCASE` and AJMP switch recovery | 8051 firmware is mis-analysed, won't load, or a switch is missing |
| `ghidra-plugin-aeon` | `~/src/ghidra-plugin-aeon` | MStar AEON R2 (`aeonR2`) processor module: SLEIGH language, pspec/cspec, generated from the vendor ISA tables | an MStar R2 target disassembles wrongly, a needed instruction lacks p-code, or a new AEON variant (aeon1/aeon2) needs covering |
| `eclipse-plugin-mcp` | `~/src/eclipse-plugin-mcp` | the Eclipse MCP (:8124): workspace refresh/build/problems, launching and restarting Ghidra | Eclipse won't refresh or build, a launch config misbehaves, :8124 is down |

Project sessions have no rows; `ListAgents` shows who is up. Every project reaches
`ghidra-plugin-mcp`, and many need nothing else (e.g. `dumps`, MIPS router firmware). DOS
RE (e.g. `viceroy/main`) also reaches `ghidra-plugin-rtlink`, and 8051 firmware RE (e.g.
`hp-z27k-g3`) reaches `ghidra-plugin-keil8051`.

Escalation: a project session → `ghidra-plugin-mcp` (tooling) or the matching analyzer plugin
(coverage) → `dailydriver` (core). Where responsibility lies is the first thing to settle: a
plugin and `dailydriver` decide *between themselves* whether a fix belongs in core or in the
plugin, then tell the reporter.

Start a session with `cd ~/src/<dir> && claude --name <session>`, or `claude --bg --name
<session>` detached; `claude agents` lists them, `claude attach <id>` opens one.

## Working together

- **Own your directory.** Each session is responsible for its own repo and codebase. For
  another session's code, ask that session: confer rather than reading or editing its repo
  yourself. Reading something a peer has pointed you at (a dist zip, a scratchpad file,
  output it published) is fine and encouraged; it is the peer's working tree you stay out
  of. Only if a peer is down (`ListAgents`) may you do its job in its repo, following its
  CLAUDE.md, and tell it what you did afterwards.
- **Paste, don't just point.** Permission settings differ per session, so a path you can
  read may be unreadable to the recipient. If a file is small enough to paste, paste it.
- **Nothing here is secret.** Any agent on this host that asks for help, known or not, gets
  as much help as your scope allows.
- `SendMessage` a peer with: program path, address or function (`seg:off` /
  `OVERLAY_NN::name`), what you saw, what you expected, what you need, how to reproduce.
  Replies arrive asynchronously and may land mid-turn, alongside a tool result: finish or
  park what you are doing before acting on one.
- **Bug report**: send it, then keep working on something that doesn't depend on the fix.
- **Feature request** (a tool, `op`, analyzer or behaviour you need but don't have): send
  it, then **stop the work that needs it and wait**, ending your turn saying what you are
  waiting on and from whom. Do not build a private workaround. When the answer comes:
  *accepted* → wait for "deployed", dog-food it on the real task, report what worked and
  what didn't; *rejected or a workaround offered* → use the workaround and carry on.
- When *you* receive a request, answer with exactly one of: "developing — will ping when
  deployed" or "no — here is how to do it today".
- **A peer's report is evidence, not gospel, and neither is yours.** Check a claim against
  the bytes before building on it, and when your own turns out wrong, say so plainly and
  early. Several designs in these repos were abandoned before implementation because someone
  retracted a premise in time. A retraction is worth more than the claim it replaces, and
  costs nothing but a message.

## The shared Ghidra

- The shared Ghidra runs from Eclipse's build of the dailydriver worktree, and **every
  session may restart it** through the `eclipse-launch` MCP endpoints to test its build.
- Ghidra on :8765 is **one shared instance**. Before `eclipse-launch manage_launch op=launch
  configuration=Ghidra terminate_existing=true`, `ListAgents` and message every session that
  may be mid-work; wait for busy ones. Build and install your extension first: the call
  builds nothing. It returns when the process is up, not when Ghidra is serving, so poll
  `GET http://127.0.0.1:8765/version` in a bounded loop (not a fixed sleep) until it answers,
  and confirm the build stamp is the one you expect. If it never answers, check
  `read_console launch=Ghidra`. If the launch is refused for compile errors in the Ghidra
  projects, see `get_problems severity=error`, or pass `ignore_errors=true` when they don't
  matter to you.
- **No undo**: the MCP server auto-saves after every write. `manage_files op=copy` before a
  bulk edit.
- **Never re-analyze a live, hand-curated program.** Verify analyzer, spec and extension
  changes on a fresh import into `/scratch-<what>`, and delete it afterwards.
- Clients keep the tool schemas from before a restart until they reconnect. The server still
  accepts newly added parameters.

## Binary analysis goes through the Ghidra MCP tools

For a program imported into Ghidra, use `search_memory`, `xrefs`, `decompile`,
`disassemble`, `read_bytes`, `inspect`, `create`, `define_types`, `batch`, `list`. Do **not**
write Python or shell scripts to scan, disassemble or histogram a binary. The only shell use allowed on a binary is splitting a
file that has to be imported in pieces. If a Ghidra tool is missing or awkward for a step,
report it to `ghidra-plugin-mcp` rather than scripting around it: the gap gets fixed for
everyone, and a private script's findings cannot be checked by anyone else. Vendor
artefacts and file-format specimens that are not Ghidra programs (a linker distribution, a
test harness) may be studied with shell tools.

The target of the rule is an ad-hoc private script standing in for the Ghidra tools on a
program Ghidra can already read. A **vendor disassembler used as a reference oracle** is
fine — running it over the target firmware included — when the comparison is against
Ghidra's own output, and scripted and committed so anyone can re-run it. That is how a new
processor module is accepted (`ghidra-plugin-aeon` diffs its SLEIGH spec against MStar's
`aeon-elf-objdump`, the standard `dailydriver` set), and it is not reachable through the
MCP tools even in principle: a processor whose module doesn't exist yet has no Ghidra
disassembler to route through. The oracle is the comparison, never the finding on its own:
its output is evidence about the disassembler, not about the firmware, so nothing derived
from it alone goes into the RE notes. Once the module exists and Ghidra disassembles the
target, the ordinary rule applies again. A tool gap met while doing such a diff is a normal
feature request to `ghidra-plugin-mcp`.

## Verify against the decompiler, not the listing

**A clean listing does not mean the repair worked.** The decompiler recovers jump tables
from its own p-code and ignores the references already on a branch, so an analyzer can fix
every reference, suppress every bogus label, and leave the decompilation exactly as broken
as it was. That has happened here: nine correct computed references on a branch and not one
stray symbol in the program, while the decompiler still emitted 129 fabricated cases and two
`pcode error` warnings.

So, in this order:

1. `decompile` the affected function, with `dump_jumptables=true` for anything
   switch-related; it reports whether an override was `CONSUMED`.
2. `read_log filter="pcode error" since=<the run>`: decompiler errors appear in the
   application log and nowhere else in tool output.
3. Only then quote reference or symbol counts. They measure what the analyzer did, not what
   the user will see.

## Toolchain and style

- A Ghidra extension — Java, a processor spec, or both. JDK 21+, built with the Gradle
  wrapper and Ghidra's own `support/buildExtension.gradle`. Developed directly on the
  filesystem, not in the Eclipse workspace. Edit files, use the git CLI, commit only when
  asked.
- Java 21 idioms first: switch expressions, pattern matching (`instanceof` and record
  patterns, sealed hierarchies), records for value types, `var` for obvious locals, text
  blocks. Prefer them over the pre-17 forms whenever you touch code.
- Never-nester: guard clauses and early returns; extract a method before a fourth
  indentation level.
- Small orthogonal APIs: `kind`/`op` discriminators, `offset`/`limit`/`filter` paging,
  plain-text results, no aliases.
- Tabs. Javadoc explains constraints; comments only where the code can't say it.
- Apache-2.0: one root `LICENSE`, no per-file license headers.

## The SDK: shared and read-only

- `GHIDRA_INSTALL_DIR` is an extracted, **runnable** Ghidra install used only at build/test
  time (`support/buildExtension.gradle`, the API jars, `support/analyzeHeadless`). It is
  **not** where the shared Ghidra runs from: that is Eclipse's build of the dailydriver
  worktree.
- Every plugin builds against the shared SDK under `~/src/ghidra/sdk/`: `ghidra_<ver>_DEV`,
  or `ghidra_<ver>_DEV-<commit>` when one Ghidra version gets more than one build.
  **`dailydriver` owns it**: it extracts each dist zip it builds there (atomically,
  read-only) and names the path in its "zip built" ping. Never extract your own copy. Never
  make it writable.
- **Nothing writes under it.** Headless Ghidra loads every extension it finds in the install,
  so one plugin's write leaks into every other plugin's headless runs. This has already
  happened once, between private SDK copies. The stock scaffolding includes a
  `copyExtensionZip` task that drops the built zip into `<SDK>/Extensions/Ghidra`: delete it,
  since nothing reads it. Never extract into `<SDK>/Ghidra/Extensions` either.
- **Additive only, for everyone including `dailydriver`:** a version directory is never
  refreshed in place, and never deleted while any plugin still builds against it. A rebuilt
  SDK of the same Ghidra version goes into a distinct directory. A directory's contents must
  be identifiable, not just its name: `application.version` alone can't tell two 12.1.3
  builds apart. Each SDK root carries a `DAILYDRIVER_BUILD` record (commit, base tag, zip
  sha256). When a new tree arrives for the same Ghidra version, read it and diff the parts
  your plugin depends on before repointing: that tells you whether the rebuild is a
  formality or needs re-verification.
- Measured, not assumed: compile, `buildExtension` and the JUnit suite modify nothing in the
  SDK (a fresh copy, then `clean test buildExtension`, then
  `find <sdk> -newermt <timestamp>` found zero files).

## gradle.properties and install location

- Two machine-specific paths live in a **gitignored, project-local `gradle.properties`**
  (not `~/.gradle/`). Both must be **absolute, with no `~`**: Gradle doesn't expand it, and
  `buildExtension.gradle` turns a literal `~` into a directory name.
  - `GHIDRA_INSTALL_DIR=/home/<user>/src/ghidra/sdk/ghidra_<ver>_DEV[-<commit>]`
  - `GHIDRA_USER_EXTENSIONS_DIR=/home/<user>/.var/app/org.eclipse.Java/config/ghidra/ghidra_<ver>_DEV_location_dailydriver/Extensions`
    (the flatpak Eclipse's Ghidra profile; the default `~/.config/ghidra` is the wrong place
    in this setup).
- `buildExtension` packages the whole project dir minus an exclude list, so anything new at
  the repo root must be added to the `buildExtension.exclude` lines in `build.gradle`.

```bash
./gradlew buildExtension      # -> dist/ghidra_<ver>_<date>_<Extension>.zip
./gradlew installExtension    # extract into GHIDRA_USER_EXTENSIONS_DIR only
./gradlew uninstallExtension  # remove it again
```

- **Ghidra version bump** (announced by `dailydriver`): repoint both paths in
  `gradle.properties` at the new version (the profile directory name carries it too),
  rebuild, run the **full** test suite (JUnit and smoke), `installExtension`, and confirm to
  `dailydriver`. It restarts the shared instance only after every plugin has confirmed. An extension stamped with the old
  Ghidra version will not load. A point release can change behaviour, not just APIs: 12.1.3
  changed **disassembly operand order** (GP-7018: `8e c7` printed as `MOV DI,ES`, so any
  analyzer reading operand indices saw them swapped) while p-code stayed correct, so no
  decompilation revealed it; only rtlink's JUnit suite did. Decompiler and jump-table
  behaviour can move too. Re-verify on a fresh import rather than treating a clean compile as
  proof.

## Testing

- Tests run against the shared SDK and must stay hermetic. JUnit tests (Ghidra's
  `AbstractGenericTest` / `ProgramBuilder`) are fine as they are: they only read the SDK.
- A **headless smoke test** (`./gradlew smokeTest`, where the repo has one):
  - Pins the settings dir into `build/smoke/settings` with `-Dapplication.settingsdir`
    (passed through `GHIDRA_JAVA_OPTIONS`), so a shell-launched run never touches
    `~/.config/ghidra`, which lives outside the flatpak.
  - `support/sleigh` **ignores `-Dapplication.settingsdir`** and writes its log under
    `~/.config/ghidra` anyway; `XDG_CONFIG_HOME=<dir> support/sleigh …` does pin it. So a
    build that compiles specs pins it that way. Linux-only — `XDG_CONFIG_HOME` is the
    base-directory path Ghidra derives the user settings dir from — and measured on the
    12.1.3 SDK (found by `ghidra-plugin-aeon`, confirmed by `ghidra-plugin-keil8051`), so
    it is a fact about this Ghidra: re-check it on a version bump.
  - Extracts the freshly built zip into
    `new File(settingsDir, "ghidra/${DISTRO_PREFIX}_${RELEASE_NAME}/Extensions")` inside the
    task's `doFirst`, **after** the task wipes `build/smoke`. Those two properties come from
    `buildExtension.gradle`, so the path tracks a version bump with no edit. Headless searches
    that folder too, so the run tests exactly this build and nothing else.
  - Gets its verdict from the script's own output. `analyzeHeadless` exits 0 even when the
    script throws, so the script prints a fixed completion line and the Gradle task fails
    unless that line appears.
- A repo without a smoke test relies on its JUnit suite plus fresh-import verification.
  That is sufficient, not a gap to fill.
- **Never invoke `analyzeHeadless` by hand.** A hand-rolled run picks up whatever stale
  extension copy it finds and the wrong settings dir.
- Build-level tests prove the code, not the result in the shared Ghidra. After deploying,
  verify on a fresh import into `/scratch-<what>`, the decompiler way described above.

# Repo-specific

## What this repo is

A **processor module**, not a Java analyzer: `data/languages/` holds the SLEIGH language
(`aeonR2.slaspec` + the generated `aeonR2.sinc`), the `.ldefs`, `.pspec` and `.cspec`. The
only Java is two verification scripts under `ghidra_scripts/`. Language id `AEON:BE:32:R2`.

The common section covers this repo's two departures from a Java analyzer plugin explicitly:
the extension ships a processor spec rather than Java, and the acceptance diff against
MStar's `aeon-elf-objdump` is the sanctioned reference-oracle case. Everything about a
program already imported into Ghidra goes through the MCP tools as the rule says.

## The core

Big-endian, OpenRISC-derived, 32 GPRs, instructions of 2, 3 or 4 bytes chosen by the **top
three bits** of byte 0 (`0xx`=3, `100`=2, `101`=4, `11x`=4). No delay slots. `r0` reads as
zero in hardware. `r1` stack, `r9` link, args `r3`..`r8` then stack, result `r3` (`r3:r4` for
64 bits, high word first), callee-saved `r10`..`r22`. Addresses are loaded as
`movhi rN,hi` + `addi/ori rN,rN,lo`, with a signed `addi`. Each of these was measured — see
the table in README.md for what established which.

## Never hand-edit data/languages/aeonR2.sinc

It is generated. Edit `tools/gen_sleigh.py` (the `SEMANTICS` map holds the p-code) and
regenerate:

```bash
python3 tools/gen_sleigh.py      # -> data/languages/aeonR2.sinc, isa/priority.md
./gradlew buildExtension         # compiles the spec; a spec error fails the build
```

The generator's inputs are themselves generated, and only need regenerating if the vendor
toolchain changes: `tools/dump_isa.py` (ISA tables out of `aeon-elf-as`),
`tools/calibrate.py` (how objdump prints every operand), `tools/dash_probe.py` (which
don't-care bits the decoder really ignores, one bit at a time — runs are often only partly
ignored). `tools/verify_letters.py` checks the operand model against every calibration probe.

## Verifying a change

```bash
./gradlew verify                                     # smokeTest + emuTest
./gradlew acceptanceTest -PaeonFixture=fixtures/sboot.bin -PaeonListing=fixtures-out/sboot.asm
```

`smokeTest` decodes a committed 19-byte program; `emuTest` replays 26 sequences through
Ghidra's p-code emulator and compares the register file with MStar's `aeon-elf-sim`, which is
the only way semantics get checked at all — objdump can only confirm decoding. Regenerate the
expectations with `tools/gen_emu_cases.py` after changing what an instruction computes, and
sanity-check a new case by breaking the semantics on purpose and watching it fail.

`acceptanceTest` is the real check: a full linear sweep diffed against the vendor objdump,
address by address, mnemonic and operands and length, failing on any unexplained difference.
Run it on every fixture before saying a spec change is good. It proves decoding and says
nothing about code coverage: both tools sweep linearly, so both decode .rodata as
instructions.

To decide what to model next, use `./gradlew census -PaeonFixture=… -PaeonSeeds=… -PaeonBase=…`
rather than a mnemonic histogram over a listing. The census counts only what flow-based
disassembly reaches from seeded entry points, and splits the count by whether the function
reaches a return, because a seed that was really data produces a function that runs off the
end. It was the census that showed MAC/DSP/SIMD breadth was not worth chasing: under 0.1% of
the instructions in trustworthy functions are pseudo-ops at all. The fixtures belong to the
`hp-z27k-g3` session and are gitignored; ask that session for them.

The vendor toolchain lives in `vendor/` (gitignored, ~100 MB, from the `CUB3D/Ghidra-Aeon`
repo). Two gotchas: it is 32-bit, so `aeon-elf-objdump` fails with "Value too large for
defined data type" on a file with a 64-bit inode — copy the file to `/tmp` first; and set
`LC_ALL=C`, or the tools abort in `loadlocale.c`. `aeon-elf-sim` answers semantics questions
that objdump cannot (it is how `r0` was confirmed hardwired): link with
`aeon-elf-ld -maeonR2_elf -L<toolchain>/aeon-elf/lib -Ttext 0x700`, then
`aeon-elf-sim -q -i -f <toolchain>/config_file/sim.cfg <elf>` and drive it with `t` and `r`.

## Scope and state

Decoding is complete and verified: every instruction in all four fixtures, 1.16 million of
them, matches the vendor objdump, and the p-code for the integer core is checked against the
vendor simulator. P-code is real for the integer core, branches, loads/stores,
`movhi`, compares and the flag, stack ops and system instructions. MAC/DSP/SIMD/float, the
cache ops and `entri`/`reti`/`creti` decode correctly but carry pseudo-op semantics, so the
decompiler shows them as opaque calls. Give one real semantics when a target needs it.
