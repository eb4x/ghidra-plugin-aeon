/* Census of the instructions that real control flow reaches, as opposed to what
 * a linear sweep decodes.
 *
 * A linear sweep decodes .rodata as instructions, so a mnemonic histogram over a
 * whole fixture says nothing about what a decompiler will meet. This seeds entry
 * points, lets flow-based disassembly run, and then counts only instructions
 * inside functions — which is the list that says whether a pseudo-op is worth
 * replacing with real p-code.
 *
 * An instruction counts as a pseudo-op when its p-code contains a CALLOTHER,
 * which is exactly what the decompiler shows as an opaque call.
 *
 * Usage: analyzeHeadless ... -postScript AeonCensus.java seed=<file> [seed=<file> ...]
 */
//@category AEON

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class AeonCensus extends GhidraScript {

	@Override
	public void run() throws Exception {
		for (String arg : getScriptArgs()) {
			if (arg.startsWith("seed=")) {
				seed(arg.substring(5));
			}
		}
		analyzeAll(currentProgram);

		// A seed that was really data produces a "function" that runs off the end,
		// so the histogram is also kept for functions that reach a return, which
		// are the ones a reader would trust.
		Map<String, int[]> counts = new HashMap<>();     // mnemonic -> {total, pseudo, clean}
		int reached = 0;
		int functions = 0;
		int endsWithReturn = 0;
		int fallsThrough = 0;

		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			functions++;
			boolean sawReturn = false;
			Instruction last = null;
			List<Instruction> body = new ArrayList<>();
			for (Instruction insn : currentProgram.getListing()
					.getInstructions(f.getBody(), true)) {
				reached++;
				last = insn;
				body.add(insn);
				String m = insn.getMnemonicString();
				int[] c = counts.computeIfAbsent(m, k -> new int[3]);
				c[0]++;
				if (isPseudo(insn)) {
					c[1]++;
				}
				if (insn.getFlowType().isTerminal()) {
					sawReturn = true;
				}
			}
			if (sawReturn) {
				for (Instruction insn : body) {
					counts.get(insn.getMnemonicString())[2]++;
				}
			}
			if (sawReturn) {
				endsWithReturn++;
			}
			else if (last != null && last.getFlowType().isFallthrough()) {
				fallsThrough++;
			}
		}

		int dataRefs = 0;
		int movhiPairs = 0;
		for (Instruction insn : currentProgram.getListing().getInstructions(true)) {
			if (getFunctionContaining(insn.getAddress()) == null) {
				continue;
			}
			if (insn.getMnemonicString().equals("b.movhi")) {
				movhiPairs++;
			}
			for (Reference r : insn.getReferencesFrom()) {
				if (r.getReferenceType().isData() &&
					currentProgram.getMemory().contains(r.getToAddress())) {
					dataRefs++;
				}
			}
		}

		List<Map.Entry<String, int[]>> rows = new ArrayList<>(counts.entrySet());
		rows.sort((a, b) -> b.getValue()[0] - a.getValue()[0]);

		println("AEON CENSUS");
		println("  functions:                  " + functions);
		println("  instructions in functions:  " + reached);
		println("  functions with a return:    " + endsWithReturn);
		println("  functions running off the end: " + fallsThrough);
		println("  b.movhi in functions:       " + movhiPairs);
		println("  in-memory data references:  " + dataRefs);
		println("  distinct mnemonics:         " + rows.size());
		println("  --- reached mnemonics, pseudo-ops marked ---");
		println("  mnemonic                  all  in returning functions");
		for (Map.Entry<String, int[]> e : rows) {
			int[] c = e.getValue();
			println(String.format("  %-24s %6d %6d%s", e.getKey(), c[0], c[2],
				c[1] > 0 ? "   PSEUDO-OP" : ""));
		}
		println("AEON CENSUS DONE");
	}

	private boolean isPseudo(Instruction insn) {
		for (PcodeOp op : insn.getPcode()) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				return true;
			}
		}
		return false;
	}

	private void seed(String path) throws Exception {
		int n = 0;
		for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of(path))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			Address a = currentProgram.getAddressFactory().getAddress(line);
			if (a == null) {
				continue;
			}
			disassemble(a);
			createFunction(a, null);
			n++;
		}
		println("seeded " + n + " entry points from " + path);
	}
}
