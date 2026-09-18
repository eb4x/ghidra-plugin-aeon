/* Decompile every function and report what the decompiler makes of them.
 *
 * Listings, p-code emulation and reference counts all measure what the spec
 * does; none of them shows what a reader will actually see. This runs the
 * decompiler over each function and reports failures, warnings, and the
 * functions whose output looks pathological, plus a sample decompilation.
 *
 * Usage: analyzeHeadless ... -postScript AeonDecompileCheck.java seed=<file> [show=<address>]
 *        [functions=<file>]   also write every function entry point, one per line
 */
//@category AEON

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class AeonDecompileCheck extends GhidraScript {

	private static final int TIMEOUT = 60;

	@Override
	public void run() throws Exception {
		String show = null;
		String functionsOut = null;
		for (String arg : getScriptArgs()) {
			if (arg.startsWith("seed=")) {
				seed(arg.substring(5));
			}
			else if (arg.startsWith("show=")) {
				show = arg.substring(5);
			}
			else if (arg.startsWith("functions=")) {
				functionsOut = arg.substring(10);
			}
		}
		analyzeAll(currentProgram);
		if (functionsOut != null) {
			var lines = new ArrayList<String>();
			currentProgram.getFunctionManager().getFunctions(true)
					.forEach(f -> lines.add("0x" + f.getEntryPoint().toString(false)));
			java.nio.file.Files.write(java.nio.file.Path.of(functionsOut), lines);
		}

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try {
			int ok = 0;
			int failed = 0;
			int empty = 0;
			Map<String, Integer> warnings = new HashMap<>();
			List<String> failures = new ArrayList<>();

			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (monitor.isCancelled()) {
					break;
				}
				DecompileResults res = decomp.decompileFunction(f, TIMEOUT, monitor);
				if (!res.decompileCompleted() || res.getDecompiledFunction() == null) {
					failed++;
					if (failures.size() < 10) {
						failures.add(f.getEntryPoint() + " " + res.getErrorMessage());
					}
					continue;
				}
				String c = res.getDecompiledFunction().getC();
				ok++;
				// Ghidra puts its complaints in /* WARNING: ... */ comments
				for (String line : c.split("\n")) {
					int i = line.indexOf("WARNING:");
					if (i >= 0) {
						String w = line.substring(i + 8).trim();
						warnings.merge(w.length() > 70 ? w.substring(0, 70) : w, 1, Integer::sum);
					}
				}
				if (c.lines().count() <= 3) {
					empty++;
				}
			}

			// Computed jumps are where a wrong jr split or an unresolvable table
			// shows up: a recovered switch has several targets on the branch.
			int computed = 0;
			int resolved = 0;
			int targets = 0;
			List<String> unresolvedList = new ArrayList<>();
			for (ghidra.program.model.listing.Instruction insn :
					currentProgram.getListing().getInstructions(true)) {
				if (!insn.getFlowType().isComputed() || !insn.getFlowType().isJump()) {
					continue;
				}
				if (getFunctionContaining(insn.getAddress()) == null) {
					continue;
				}
				computed++;
				int n = 0;
				for (ghidra.program.model.symbol.Reference r : insn.getReferencesFrom()) {
					if (r.getReferenceType().isJump() && r.getReferenceType().isComputed()) {
						n++;
					}
				}
				if (n > 1) {
					resolved++;
					targets += n;
				}
				else if (unresolvedList.size() < 40) {
					Function fn = getFunctionContaining(insn.getAddress());
					unresolvedList.add(insn.getAddress() + "  " + insn + "   in " +
						(fn == null ? "?" : fn.getEntryPoint().toString()));
				}
			}

			// A wrongly non-returning callee truncates every caller after the call,
			// so list which functions analysis marked that way.
			List<String> noReturn = new ArrayList<>();
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (f.hasNoReturn()) {
					noReturn.add(f.getEntryPoint() + " (" +
						f.getSymbol().getReferenceCount() + " refs)");
				}
			}

			println("AEON DECOMPILE CHECK");
			println("  non-returning functions: " + noReturn.size());
			noReturn.stream().limit(15).forEach(x -> println("    no return: " + x));
			println("  computed jumps:          " + computed);
			println("  with a recovered table:  " + resolved + " (" + targets + " targets)");
			println("  decompiled:     " + ok);
			println("  failed:         " + failed);
			println("  near-empty:     " + empty);
			for (String f : failures) {
				println("    failure: " + f);
			}
			println("  --- computed jumps with no recovered table ---");
			unresolvedList.forEach(x -> println("    " + x));
			println("  --- decompiler warnings by kind ---");
			warnings.entrySet().stream()
					.sorted((a, b) -> b.getValue() - a.getValue())
					.limit(20)
					.forEach(e -> println(String.format("  %6d  %s", e.getValue(), e.getKey())));

			if (show != null) {
				Address a = currentProgram.getAddressFactory().getAddress(show);
				Function f = a == null ? null : getFunctionContaining(a);
				if (f != null) {
					DecompileResults res = decomp.decompileFunction(f, TIMEOUT, monitor);
					println("  --- " + f.getName() + " @ " + f.getEntryPoint() + " ---");
					if (res.getDecompiledFunction() != null) {
						println(res.getDecompiledFunction().getC());
					}
				}
			}
			println("AEON DECOMPILE CHECK DONE");
		}
		finally {
			decomp.dispose();
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
	}
}
