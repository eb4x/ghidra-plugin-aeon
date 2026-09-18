package aeon;

import java.math.BigInteger;
import java.util.Set;

import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Constant propagation for AEON, plus a reference on every completed
 * {@code b.movhi} + {@code b.addi}/{@code b.ori} address.
 * <p>
 * The stock propagator already puts references on loads and stores through such
 * a base ({@code b.lbz r5,0x4a(r6)} gets a READ of base+0x4a). What it doesn't
 * reference is the address itself, when the code passes it on rather than using
 * it in place: a struct pointer handed to a callee, or a string handed to a
 * print routine. For those it only sees an integer. This analyzer records a DATA
 * reference on the instruction that completes the address, as MIPS does for
 * {@code lui} + {@code addiu}.
 * <p>
 * The reference goes to the program's data space: {@code ram} in the plain
 * languages, {@code data} in the Harvard one. Pairs that build a code address
 * feed an indirect call or jump, and the stock propagator references those
 * itself, in the code space, from the branch.
 * <p>
 * An address completed from {@code r0} is a plain constant, not a movhi pair, so
 * it is skipped. So are values under 64 KiB and values outside the program's
 * memory, which cannot be told apart from ordinary numbers.
 */
public class AeonAddressAnalyzer extends ConstantPropagationAnalyzer {

	private static final String PROCESSOR_NAME = "AEON";

	/** Mnemonics that complete a movhi pair (every encoding width prints the same). */
	private static final Set<String> COMPLETERS = Set.of("b.addi", "b.ori");

	/** Below this a value is as likely a count or a mask as an address. */
	private static final long MIN_ADDRESS = 0x10000;

	public AeonAddressAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public AddressSetView flowConstants(Program program, Address flowStart, AddressSetView flowSet,
			SymbolicPropogator symEval, TaskMonitor monitor) throws CancelledException {

		var eval = new ConstantPropagationContextEvaluator(monitor) {
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				markupAddress(program, context, instr);
				return false;
			}
		};
		eval.setTrustWritableMemory(trustWriteMemOption)
				.setMinSpeculativeOffset(minSpeculativeRefAddress)
				.setMaxSpeculativeOffset(maxSpeculativeRefAddress)
				.setMinStoreLoadOffset(minStoreLoadRefAddress)
				.setCreateComplexDataFromPointers(createComplexDataFromPointers);

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}

	private static void markupAddress(Program program, VarnodeContext context, Instruction instr) {
		if (!COMPLETERS.contains(instr.getMnemonicString())) {
			return;
		}
		if (instr.getNumOperands() < 3 || isZeroRegister(instr.getOpObjects(1))) {
			return;
		}
		Register dest = instr.getRegister(0);
		if (dest == null || instr.getOperandReferences(0).length > 0) {
			return;
		}
		BigInteger value = context.getValue(dest, false);
		if (value == null) {
			return;
		}
		long offset = value.longValue() & 0xffffffffL;
		if (offset < MIN_ADDRESS) {
			return;
		}
		Address target;
		try {
			target = program.getLanguage().getDefaultDataSpace().getAddress(offset);
		}
		catch (AddressOutOfBoundsException e) {
			return;
		}
		if (!program.getMemory().contains(target)) {
			return;
		}
		instr.addOperandReference(0, target, RefType.DATA, SourceType.ANALYSIS);
	}

	/** r0 reaches the operand either as the register or, through a read subtable, as 0. */
	private static boolean isZeroRegister(Object[] objects) {
		if (objects.length != 1) {
			return false;
		}
		return switch (objects[0]) {
			case Register r -> r.getName().equals("r0");
			case Scalar s -> s.getValue() == 0;
			default -> false;
		};
	}
}
