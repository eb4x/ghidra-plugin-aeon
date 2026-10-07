package aeon;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.GModule;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * AeonAddressAnalyzer on hand-built programs. The instruction bytes are the vendor
 * aeon-elf-as encodings of the assembly beside them; instructions are big-endian in
 * every AEON language, so the same bytes serve all three.
 */
public class AeonAddressAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LE = "AEON:LE:32:R2";
	private static final String BE = "AEON:BE:32:R2";
	private static final String HARVARD = "AEON:LE:32:R2-harvard";

	/** Code is placed here; the block spans 0x20000..0x2ffff. */
	private static final String CODE = "0x20000";

	private static final byte[] JR_R9 = bytes(0x85, 0x29);

	private ProgramBuilder builder;
	private Program program;

	/**
	 * The test layout only finds modules inside the Ghidra install, so the AEON languages
	 * would be missing. Add this repo as a module, from the ghidra.external.modules property
	 * the build sets, as Ghidra's non-test layout already does.
	 */
	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new GhidraTestApplicationLayout(new File(getTestDirectoryPath())) {
			@Override
			protected Map<String, GModule> findGhidraModules() throws IOException {
				var modules = new HashMap<>(super.findGhidraModules());
				var external = System.getProperty("ghidra.external.modules", "");
				for (var path : external.split(File.pathSeparator)) {
					var dir = new ResourceFile(path);
					if (!path.isBlank() && ModuleUtilities.isModuleDirectory(dir)) {
						modules.putAll(ModuleUtilities.findModules(applicationRootDirs, List.of(dir)));
					}
				}
				return modules;
			}
		};
	}

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	// The stock propagator references an address returned in r3, and a load or store through
	// one, but not the completed address itself. The positive cases complete it in r11 and up,
	// so only AEON can account for the reference.

	@Test
	public void movhiAddiGetsADataReference() throws Exception {
		build(LE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze();
		assertDataRef("0x20002", "0x20040");
	}

	/** The control for the positive cases: the stock propagator alone leaves this out. */
	@Test
	public void stockPropagationAloneMissesTheAddress() throws Exception {
		build(LE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze(new ConstantPropagationAnalyzer());
		assertNoDataRef("0x20002");
	}

	/** AEON replaces the stock analyzer for this processor, so it must keep what stock does. */
	@Test
	public void returnedAddressKeepsItsStockReference() throws Exception {
		build(LE,
			0x94, 0x62,             // 0x20000 b.movhi r3,0x2
			0x1c, 0x63, 0x40);      // 0x20002 b.addi  r3,r3,0x40
		analyze();
		assertDataRef("0x20002", "0x20040");
	}

	/** The common firmware shape: a struct base. Stock references the load, AEON the base. */
	@Test
	public void loadBaseGetsADataReferenceBesideTheLoads() throws Exception {
		build(LE,
			0x94, 0xe2,             // 0x20000 b.movhi r7,0x2
			0x1c, 0xe7, 0x40,       // 0x20002 b.addi  r7,r7,0x40
			0x0c, 0xc7, 0x26);      // 0x20005 b.lwz   r6,0x24(r7)
		analyze();
		assertDataRef("0x20002", "0x20040");
		Reference[] load = program.getReferenceManager().getReferencesFrom(addr("0x20005"));
		assertEquals(Arrays.toString(load), 1, load.length);
		assertEquals(addr("0x20064"), load[0].getToAddress());
	}

	@Test
	public void movhiOriGetsADataReference() throws Exception {
		build(LE,
			0x95, 0x82,             // 0x20000 b.movhi r12,0x2
			0x51, 0x8c, 0x80);      // 0x20002 b.ori   r12,r12,0x80
		analyze();
		assertDataRef("0x20002", "0x20080");
	}

	@Test
	public void negativeAddiBorrowsFromTheHighHalf() throws Exception {
		build(LE,
			0x95, 0xa3,             // 0x20000 b.movhi r13,0x3
			0x9d, 0xb0);            // 0x20002 b.addi  r13,r13,-0x10
		analyze();
		assertDataRef("0x20002", "0x2fff0");
	}

	@Test
	public void valueCompletedFromR0IsNotAnAddress() throws Exception {
		build(LE,
			0x1e, 0x00, 0xf0);      // 0x20000 b.addi r16,r0,-0x10   (0xfffffff0)
		builder.createMemory("high", "0xffffff00", 0x100);
		analyze();
		assertNoDataRef("0x20000");
	}

	@Test
	public void valueBelow64KiBIsNotAnAddress() throws Exception {
		build(LE,
			0x95, 0xc0,             // 0x20000 b.movhi r14,0x0
			0xfd, 0xce, 0x70, 0x00);// 0x20002 b.addi  r14,r14,0x7000
		builder.createMemory("low", "0x7000", 0x100);
		analyze();
		assertNoDataRef("0x20002");
	}

	@Test
	public void valueOutsideMemoryIsNotAnAddress() throws Exception {
		build(LE,
			0x95, 0xe5,             // 0x20000 b.movhi r15,0x5
			0x1d, 0xef, 0x10);      // 0x20002 b.addi  r15,r15,0x10   (0x50010, unmapped)
		analyze();
		assertNoDataRef("0x20002");
	}

	@Test
	public void existingReferenceIsNotDuplicated() throws Exception {
		build(LE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		tx(program, () -> program.getReferenceManager().addMemoryReference(addr("0x20002"),
			addr("0x20100"), RefType.DATA, SourceType.USER_DEFINED, 0));
		analyze();
		Reference[] refs = program.getReferenceManager().getReferencesFrom(addr("0x20002"), 0);
		assertEquals(Arrays.toString(refs), 1, refs.length);
		assertEquals(addr("0x20100"), refs[0].getToAddress());
	}

	@Test
	public void bigEndianDataLanguageMarksTheSameAddress() throws Exception {
		build(BE,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze();
		assertDataRef("0x20002", "0x20040");
	}

	@Test
	public void harvardReferenceLandsInTheDataSpace() throws Exception {
		build(HARVARD,
			0x95, 0x62,             // 0x20000 b.movhi r11,0x2
			0x1d, 0x6b, 0x40);      // 0x20002 b.addi  r11,r11,0x40
		analyze();
		Address to = program.getAddressFactory().getAddressSpace("data").getAddress(0x20040);
		Reference ref = dataRef("0x20002");
		assertNotNull("no DATA reference on the addi", ref);
		assertEquals(to, ref.getToAddress());
	}

	/**
	 * A one-function program: the given code at CODE, then b.jr r9. The Harvard language
	 * also gets data memory at the same addresses, as its pspec maps data_ram.
	 * <p>
	 * Disassembly goes through the bare Disassembler, not ProgramBuilder's: that one runs
	 * auto-analysis, AEON's analyzer included, so every reference would exist before the
	 * test's own analyzer ran and no test could tell one analyzer from another.
	 */
	private void build(String language, int... code) throws Exception {
		builder = new ProgramBuilder("aeon", language, this);
		builder.createMemory("ram", CODE, 0x10000);
		if (language.equals(HARVARD)) {
			builder.createMemory("data", "data:" + CODE, 0x10000);
		}
		byte[] body = bytes(code);
		byte[] all = Arrays.copyOf(body, body.length + JR_R9.length);
		System.arraycopy(JR_R9, 0, all, body.length, JR_R9.length);
		builder.setBytes(CODE, all);
		program = builder.getProgram();
		Address entry = addr(CODE);
		tx(program, () -> {
			AddressSetView body2 = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
					.disassemble(entry, null);
			program.getFunctionManager()
					.createFunction("f", entry, body2, SourceType.USER_DEFINED);
		});
		assertEquals("references before analysis", 0,
			program.getReferenceManager().getReferenceCountFrom(entry.add(2)));
	}

	private void analyze() throws Exception {
		analyze(new AeonAddressAnalyzer());
	}

	/**
	 * Runs an analyzer the way auto-analysis does. canAnalyze matters: it is where the stock
	 * propagator sets its options for the program (speculative references off for a 32-bit
	 * space, among others), so skipping it would hide what AEON adds. Whether the stock
	 * analyzer claims the processor depends on whether an AeonAddressAnalyzer has been
	 * constructed yet in this JVM, so only AEON's answer is checked; the control test runs
	 * the stock one either way.
	 */
	private void analyze(ConstantPropagationAnalyzer analyzer) throws Exception {
		boolean claims = analyzer.canAnalyze(program);
		if (analyzer instanceof AeonAddressAnalyzer) {
			assertTrue("AEON does not claim the program's processor", claims);
		}
		var log = new MessageLog();
		tx(program, () -> {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES)
					.getOptions(analyzer.getName());
			analyzer.registerOptions(options, program);
			analyzer.optionsChanged(options, program);
			analyzer.added(program, program.getMemory().getLoadedAndInitializedAddressSet(),
				TaskMonitor.DUMMY, log);
		});
	}

	private Reference dataRef(String from) {
		return Arrays.stream(program.getReferenceManager().getReferencesFrom(addr(from), 0))
				.filter(r -> r.getReferenceType() == RefType.DATA)
				.findFirst()
				.orElse(null);
	}

	private void assertDataRef(String from, String to) {
		Reference ref = dataRef(from);
		assertNotNull("no DATA reference at " + from, ref);
		assertEquals(addr(to), ref.getToAddress());
	}

	private void assertNoDataRef(String from) {
		assertNull("unexpected DATA reference at " + from, dataRef(from));
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
