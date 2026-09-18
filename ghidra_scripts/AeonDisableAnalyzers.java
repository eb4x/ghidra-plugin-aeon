/* Turn named auto-analyzers off before analysis runs, to find out which one a
 * result depends on.
 *
 * Usage: analyzeHeadless ... -preScript AeonDisableAnalyzers.java "<analyzer>" ...
 */
//@category AEON

import ghidra.app.script.GhidraScript;

public class AeonDisableAnalyzers extends GhidraScript {

	@Override
	public void run() throws Exception {
		for (String name : getScriptArgs()) {
			setAnalysisOption(currentProgram, name, "false");
			println("disabled analyzer: " + name);
		}
	}
}
