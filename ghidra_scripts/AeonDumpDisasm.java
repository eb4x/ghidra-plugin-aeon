/* Dump a linear-sweep disassembly of the whole program, the same way the vendor
 * objdump sweeps a flat binary: decode one instruction at an address, advance by
 * its length, and on a failure emit one undecoded byte and resync.
 *
 * Output (one line per address): <hex addr> TAB <length> TAB <mnemonic> TAB <operands>
 * A failure prints length 1, mnemonic ".bad" and no operands.
 *
 * Usage: analyzeHeadless ... -postScript AeonDumpDisasm.java <output file>
 */
//@category AEON

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemoryBlock;

public class AeonDumpDisasm extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("usage: AeonDumpDisasm <output file>");
			return;
		}
		PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);
		try (PrintWriter out = new PrintWriter(args[0])) {
			for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
				if (!block.isInitialized()) {
					continue;
				}
				Address addr = block.getStart();
				Address end = block.getEnd();
				while (addr.compareTo(end) <= 0) {
					int length = 1;
					String mnemonic = ".bad";
					String operands = "";
					try {
						PseudoInstruction insn = pdis.disassemble(addr);
						if (insn != null) {
							length = insn.getLength();
							mnemonic = insn.getMnemonicString();
							// toString() keeps the display exactly as the listing
							// shows it, including separators like 0x10(r2).
							String text = insn.toString();
							int sp = text.indexOf(' ');
							operands = sp < 0 ? "" : text.substring(sp + 1).trim();
						}
					}
					catch (Exception e) {
						// leave it as .bad: objdump emits one byte and resyncs
					}
					out.println(Long.toHexString(addr.getOffset()) + "\t" + length + "\t" +
						mnemonic + "\t" + operands);
					if (monitor.isCancelled()) {
						return;
					}
					try {
						addr = addr.addNoWrap(length);
					}
					catch (Exception e) {
						break;
					}
				}
			}
		}
		println("AeonDumpDisasm: wrote " + args[0]);
	}
}
