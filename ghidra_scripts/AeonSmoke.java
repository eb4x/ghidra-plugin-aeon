/* Smoke test: load the AEON R2 language and check that tests/smoke.bin decodes
 * exactly as the vendor objdump decodes it — one instruction of each length, the
 * movhi+addi address-load pair, and the r9 return.
 *
 * analyzeHeadless exits 0 even when a script throws, so the Gradle task looks
 * for the completion line this script prints on success and nothing else.
 */
//@category AEON

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;

public class AeonSmoke extends GhidraScript {

	/**
	 * offset, expected length, expected listing text. The text is the vendor
	 * objdump's, except that Ghidra zero-pads an address operand (objdump prints
	 * 0x927, Ghidra 0x00000927); tools/acceptance.py normalises that difference.
	 */
	private static final Object[][] EXPECTED = {
		{ 0x00, 2, "b.add r2,r2,r2" },
		{ 0x02, 3, "b.sw 0x10(r2),r10" },
		{ 0x05, 4, "b.addi r3,r3,0x5678" },
		{ 0x09, 4, "b.movhi r3,0x0" },
		{ 0x0d, 4, "b.jal 0x00000927" },
		{ 0x11, 2, "b.jr r9" },
	};

	@Override
	public void run() throws Exception {
		Address base = currentProgram.getMinAddress();
		PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);
		int failures = 0;

		for (Object[] row : EXPECTED) {
			Address at = base.add((Integer) row[0]);
			int wantLen = (Integer) row[1];
			String want = (String) row[2];

			PseudoInstruction insn = pdis.disassemble(at);
			if (insn == null) {
				printerr("FAIL " + at + ": no instruction, expected " + want);
				failures++;
				continue;
			}
			String got = insn.toString().replaceAll("\\s+", " ").trim();
			if (insn.getLength() != wantLen || !got.equals(want)) {
				printerr("FAIL " + at + ": got \"" + got + "\" (len " + insn.getLength() +
					"), expected \"" + want + "\" (len " + wantLen + ")");
				failures++;
			}
		}

		if (failures > 0) {
			printerr("AEON SMOKE FAILED: " + failures + " of " + EXPECTED.length);
			return;
		}
		println("AEON SMOKE OK: " + EXPECTED.length + " instructions match the vendor objdump");
	}
}
