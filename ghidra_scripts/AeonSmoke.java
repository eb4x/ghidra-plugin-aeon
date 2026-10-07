/* Smoke test on the committed sample (src/test/smoke/smoke.s, loaded at 0x200000):
 *
 *  1. every instruction decodes as the vendor objdump decodes it (smoke.objdump,
 *     compared the way tools/acceptance.py compares: numbers by value, no spaces);
 *  2. after analysis, the b.jal callee is a function, AEON's address analyzer has
 *     referenced the struct base held in r11 (in the data space for the Harvard
 *     language), and the value completed from r0 has no reference;
 *  3. the decompiler produces the entry function without an error or a warning.
 *
 * Usage: -postScript AeonSmoke.java <smoke.objdump>
 * analyzeHeadless exits 0 even when a script throws, so the Gradle task passes only on
 * the "SMOKE OK" line this script prints when every check holds.
 */
//@category AEON

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AeonSmoke extends GhidraScript {

	private static final Pattern LINE =
		Pattern.compile("^\\s*([0-9a-f]+):\\t([0-9a-f ]+)\\t(\\S+)\\s*(.*)$");
	private static final Pattern NUM = Pattern.compile("-?0x[0-9a-f]+");

	/** The sample's layout, from smoke.s. */
	private static final long ENTRY = 0x200000;
	private static final long CALLEE = 0x200033;        // length
	private static final long BASE_COMPLETER = 0x200017; // b.addi r11,r11,lo(counters)
	private static final long R0_CONSTANT = 0x200023;    // b.addi r5,r0,0x7000
	private static final long COUNTERS = 0x200080;

	private final List<String> failures = new ArrayList<>();

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			printerr("usage: AeonSmoke.java <smoke.objdump>");
			return;
		}
		int decoded = checkDecoding(Path.of(args[0]));

		Address entry = toAddr(ENTRY);
		disassemble(entry);
		createFunction(entry, null);
		analyzeAll(currentProgram);
		checkAnalysis();
		checkDecompiler(entry);

		if (!failures.isEmpty()) {
			failures.forEach(f -> printerr("FAIL " + f));
			printerr("SMOKE FAILED: " + failures.size() + " checks");
			return;
		}
		println("SMOKE OK: " + decoded + " instructions match the vendor objdump; " +
			"analysis and decompiler checks pass");
	}

	private int checkDecoding(Path listing) throws Exception {
		PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);
		int n = 0;
		for (String line : Files.readAllLines(listing)) {
			Matcher m = LINE.matcher(line);
			if (!m.matches()) {
				continue;
			}
			n++;
			Address at = toAddr(Long.parseLong(m.group(1), 16));
			int wantLen = m.group(2).trim().split(" ").length;
			String want = m.group(3) + " " + normalise(m.group(4));
			PseudoInstruction insn = pdis.disassemble(at);
			if (insn == null) {
				failures.add(at + ": no instruction, objdump has " + line.trim());
				continue;
			}
			String got = insn.getMnemonicString() + " " +
				normalise(insn.toString().substring(insn.getMnemonicString().length()));
			if (insn.getLength() != wantLen || !got.equals(want)) {
				failures.add(at + ": Ghidra \"" + got + "\" (" + insn.getLength() +
					" bytes), objdump \"" + want + "\" (" + wantLen + " bytes)");
			}
		}
		if (n == 0) {
			failures.add("no instructions in " + listing);
		}
		return n;
	}

	/** As tools/acceptance.py: no spaces, and 0x00200033 equal to 0x200033. */
	private static String normalise(String operands) {
		String s = operands.replace(" ", "");
		Matcher m = NUM.matcher(s);
		StringBuilder out = new StringBuilder();
		while (m.find()) {
			String tok = m.group();
			boolean neg = tok.startsWith("-");
			long v = Long.parseUnsignedLong(tok.substring(neg ? 3 : 2), 16);
			m.appendReplacement(out, (neg ? "-" : "") + "0x" + Long.toHexString(v));
		}
		m.appendTail(out);
		return out.toString();
	}

	private void checkAnalysis() {
		if (getFunctionAt(toAddr(CALLEE)) == null) {
			failures.add("no function at the b.jal callee " + toAddr(CALLEE));
		}

		// counters lives in the data space in the Harvard language
		Address counters = currentProgram.getLanguage().getDefaultDataSpace().getAddress(COUNTERS);
		boolean found = false;
		for (Reference r : getReferencesFrom(toAddr(BASE_COMPLETER))) {
			found |= r.getReferenceType().isData() && r.getToAddress().equals(counters);
		}
		if (!found) {
			failures.add("no DATA reference from the struct-base b.addi at " +
				toAddr(BASE_COMPLETER) + " to " + counters);
		}

		for (Reference r : getReferencesFrom(toAddr(R0_CONSTANT))) {
			if (r.getReferenceType().isData()) {
				failures.add("the r0-completed constant at " + toAddr(R0_CONSTANT) +
					" got a reference to " + r.getToAddress());
			}
		}
	}

	private void checkDecompiler(Address entry) {
		Function f = getFunctionAt(entry);
		if (f == null) {
			failures.add("no function at the entry " + entry);
			return;
		}
		DecompInterface decomp = new DecompInterface();
		try {
			decomp.openProgram(currentProgram);
			DecompileResults res = decomp.decompileFunction(f, 60, monitor);
			if (!res.decompileCompleted() || res.getDecompiledFunction() == null) {
				failures.add("decompiling " + f.getName() + " failed: " + res.getErrorMessage());
				return;
			}
			String c = res.getDecompiledFunction().getC();
			println("decompiled " + f.getName() + ":\n" + c);
			if (c.contains("WARNING") || c.contains("pcode error")) {
				failures.add("the decompiler warned on " + f.getName());
			}
			// What the AEON p-code has to get right for this C to come out: the call through
			// b.jal, the struct load and store through the movhi base in r11 (in the data
			// space for the Harvard language), the string address passed in r3, and the
			// r0-completed value staying a plain number.
			String data = currentProgram.getLanguage().getDefaultDataSpace().getName();
			for (String want : List.of(
					"FUN_ram_00200033(",
					"DAT_" + data + "_00200088 = ",
					"DAT_" + data + "_00200084",
					data + "_0020008c)",
					"+ 0x7000;")) {
				if (!c.contains(want)) {
					failures.add("the decompiled " + f.getName() + " lacks \"" + want + "\"");
				}
			}
		}
		finally {
			decomp.dispose();
		}
	}
}
