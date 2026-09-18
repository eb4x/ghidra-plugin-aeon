/* Report what analysis recovered: functions, references created by the
 * movhi+addi/lwz address-load pair, and strings that got referenced.
 *
 * Usage: analyzeHeadless ... -postScript AeonCheckRefs.java [seed=<file>] [address ...]
 * seed=<file> reads one hex address per line, disassembles and creates a
 * function at each, then re-runs analysis: a raw blob has no entry point, so
 * without seeds nothing is disassembled. Each remaining address is printed with
 * its instruction and references, to spot-check known cases.
 */
//@category AEON

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AeonCheckRefs extends GhidraScript {

	@Override
	public void run() throws Exception {
		for (String arg : getScriptArgs()) {
			if (arg.startsWith("seed=")) {
				seed(arg.substring(5));
			}
		}

		int functions = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			functions++;
		}

		int movhi = 0;
		int movhiWithRef = 0;
		int instructions = 0;
		for (Instruction insn : currentProgram.getListing().getInstructions(true)) {
			instructions++;
			if (!insn.getMnemonicString().equals("b.movhi")) {
				continue;
			}
			movhi++;
			// A resolved address load shows up as a reference from the movhi or
			// from the instruction that adds the low half.
			if (hasDataRef(insn) || hasDataRef(insn.getNext())) {
				movhiWithRef++;
			}
		}

		int strings = 0;
		int stringsReferenced = 0;
		for (Data d : currentProgram.getListing().getDefinedData(true)) {
			if (StringDataInstance.getStringDataInstance(d) == StringDataInstance.NULL_INSTANCE) {
				continue;
			}
			strings++;
			if (currentProgram.getReferenceManager()
					.getReferenceCountTo(d.getAddress()) > 0) {
				stringsReferenced++;
			}
		}

		println("AEON analysis summary");
		println("  instructions:          " + instructions);
		println("  functions:             " + functions);
		println("  b.movhi:               " + movhi);
		println("  b.movhi with data ref: " + movhiWithRef);
		println("  strings:               " + strings);
		println("  strings referenced:    " + stringsReferenced);

		// where do the resolved address loads actually point?
		int dataRefs = 0;
		int shown = 0;
		for (Instruction insn : currentProgram.getListing().getInstructions(true)) {
			for (Reference r : insn.getReferencesFrom()) {
				if (!r.getReferenceType().isData() ||
					!currentProgram.getMemory().contains(r.getToAddress())) {
					continue;
				}
				dataRefs++;
				if (shown < 10) {
					Data d = getDataAt(r.getToAddress());
					println("  ref " + insn.getAddress() + " -> " + r.getToAddress() +
						"  " + (d == null ? "(undefined)" : d.toString()));
					shown++;
				}
			}
		}
		println("  in-memory data refs:   " + dataRefs);

		for (String arg : getScriptArgs()) {
			if (arg.startsWith("seed=")) {
				continue;
			}
			Address a = currentProgram.getAddressFactory().getAddress(arg);
			if (a == null) {
				continue;
			}
			Instruction insn = getInstructionAt(a);
			println("  " + arg + ": " + (insn == null ? "(no instruction)" : insn.toString()));
			if (insn != null) {
				for (ghidra.program.model.pcode.PcodeOp p : insn.getPcode()) {
					println("      pcode: " + p.toString());
				}
				for (Reference r : insn.getReferencesFrom()) {
					println("      -> " + r.getToAddress() + " " + r.getReferenceType());
				}
			}
			Function f = getFunctionContaining(a);
			if (f != null) {
				println("      in function " + f.getName() + " @ " + f.getEntryPoint());
			}
		}
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
		analyzeAll(currentProgram);
	}

	private boolean hasDataRef(Instruction insn) {
		if (insn == null) {
			return false;
		}
		for (Reference r : insn.getReferencesFrom()) {
			if (r.getReferenceType().isData()) {
				return true;
			}
		}
		return false;
	}
}
