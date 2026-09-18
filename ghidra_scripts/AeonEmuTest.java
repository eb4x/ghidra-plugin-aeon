/* Differential p-code test: replay the cases in tests/emu_cases.json through
 * Ghidra's emulator and compare the register file with the vendor simulator's.
 *
 * The expected values come from aeon-elf-sim (tools/gen_emu_cases.py), so this
 * checks the SLEIGH semantics against MStar's own model of the hardware rather
 * than against anyone's reading of the ISA tables.
 *
 * Usage: analyzeHeadless ... -postScript AeonEmuTest.java <emu_cases.json>
 * Prints "AEON EMU OK: <n> cases" when every case matches; the Gradle task
 * fails unless that line appears.
 */
//@category AEON

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class AeonEmuTest extends GhidraScript {

	private static final long CODE = 0x1000;
	private static final long STOP = 0x2000;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("usage: AeonEmuTest <emu_cases.json>");
			return;
		}
		String json = java.nio.file.Files.readString(java.nio.file.Path.of(args[0]));
		List<Map<String, Object>> cases = parseCases(json);

		int failures = 0;
		for (Map<String, Object> c : cases) {
			if (!runCase(c)) {
				failures++;
			}
		}
		if (failures > 0) {
			printerr("AEON EMU FAILED: " + failures + " of " + cases.size() + " cases");
			return;
		}
		println("AEON EMU OK: " + cases.size() + " cases match the vendor simulator");
	}

	private boolean runCase(Map<String, Object> c) throws Exception {
		String name = (String) c.get("name");
		byte[] code = hexToBytes((String) c.get("bytes"));
		@SuppressWarnings("unchecked")
		Map<String, Long> expected = (Map<String, Long>) c.get("expected");

		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			Address start = toAddr(CODE);
			emu.writeMemory(start, code);
			// every register starts at zero, as the simulator's do
			for (int i = 0; i < 32; i++) {
				emu.writeRegister("r" + i, 0);
			}
			emu.writeRegister("F", 0);
			emu.writeRegister("CY", 0);
			emu.writeRegister("pc", CODE);
			emu.setBreakpoint(toAddr(STOP));

			int steps = 0;
			while (emu.getExecutionAddress().getOffset() < CODE + code.length) {
				if (!emu.step(monitor) || ++steps > 200) {
					printerr("FAIL " + name + ": emulation stopped at " +
						emu.getExecutionAddress() + " — " + emu.getLastError());
					return false;
				}
			}

			List<String> bad = new ArrayList<>();
			for (Map.Entry<String, Long> e : expected.entrySet()) {
				String reg = e.getKey().equals("flag") ? "F" : e.getKey();
				long got = emu.readRegister(reg).longValue() & 0xffffffffL;
				long want = e.getValue() & 0xffffffffL;
				if (got != want) {
					bad.add(String.format("%s: got %#x, vendor sim says %#x", reg, got, want));
				}
			}
			if (!bad.isEmpty()) {
				printerr("FAIL " + name + ": " + String.join("; ", bad));
				return false;
			}
			return true;
		}
		finally {
			emu.dispose();
		}
	}

	private static byte[] hexToBytes(String hex) {
		byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}

	/** Minimal reader for the flat shape gen_emu_cases.py writes. */
	private static List<Map<String, Object>> parseCases(String json) {
		List<Map<String, Object>> cases = new ArrayList<>();
		java.util.regex.Matcher m = java.util.regex.Pattern
				.compile("\\{\\s*\"name\":\\s*\"(.*?)\",.*?\"bytes\":\\s*\"([0-9a-f]*)\"," +
					"\\s*\"expected\":\\s*\\{(.*?)\\}\\s*\\}", java.util.regex.Pattern.DOTALL)
				.matcher(json);
		while (m.find()) {
			Map<String, Object> c = new java.util.LinkedHashMap<>();
			c.put("name", m.group(1));
			c.put("bytes", m.group(2));
			Map<String, Long> expected = new java.util.LinkedHashMap<>();
			java.util.regex.Matcher r = java.util.regex.Pattern
					.compile("\"(\\w+)\":\\s*(\\d+)").matcher(m.group(3));
			while (r.find()) {
				expected.put(r.group(1), Long.parseLong(r.group(2)));
			}
			c.put("expected", expected);
			cases.add(c);
		}
		return cases;
	}
}
