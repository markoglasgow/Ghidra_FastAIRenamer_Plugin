/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fastairenamer;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.siegmar.fastcsv.reader.CsvReader;
import de.siegmar.fastcsv.reader.CsvRecord;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;



/**
 * Provide class-level documentation that describes what this plugin does.
 * @param <LlamaHelper>
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	//packageName = ExamplesPluginPackage.NAME,
    packageName = CorePluginPackage.NAME, // https://github.com/NationalSecurityAgency/ghidra/discussions/5175
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Plugin to use AI to rename Functions and Variables in the Decompiler.",
	description = "Plugin to use AI to rename Functions and Variables in the Decompiler."
)
//@formatter:on
public class FastAIRenamerPlugin extends ProgramPlugin {

	MyProvider provider;
	private volatile TaskMonitor activeMonitor = null;

	private String configBaseUrl = "http://localhost:8090";
	private String configApiKey = "my-key";
	private String configModelName = "google_gemma-4-E4B-it-Q8_0.gguf";
	private String configSystemPrompt = "You are a helpful assistant. You will help the user mark up some decompilation output to help with reverse engineering.";
	private int configHttpTimeoutSec = 300;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public FastAIRenamerPlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
		configBaseUrl       = Preferences.getProperty("fastairenamer.configBaseUrl",       configBaseUrl);
		configApiKey        = Preferences.getProperty("fastairenamer.configApiKey",        configApiKey);
		configModelName     = Preferences.getProperty("fastairenamer.configModelName",     configModelName);
		configSystemPrompt  = Preferences.getProperty("fastairenamer.configSystemPrompt",  configSystemPrompt);
		configHttpTimeoutSec = Integer.parseInt(
				Preferences.getProperty("fastairenamer.configHttpTimeoutSec", String.valueOf(configHttpTimeoutSec)));
	}

	// Called by the button in MyProvider
	private void listFunctions() {
		Program program = getCurrentProgram();
		if (program == null) {
			provider.setText("No program loaded.");
			return;
		}

		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager refMgr = program.getReferenceManager();
		Listing listing = program.getListing();

		List<Map.Entry<Function, Integer>> funcStringCounts = new ArrayList<>();

		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			AddressSetView body = function.getBody();
			int count = 0;
			AddressIterator addrIt = refMgr.getReferenceSourceIterator(body, true);
			while (addrIt.hasNext()) {
				for (Reference ref : refMgr.getReferencesFrom(addrIt.next())) {
					Data data = listing.getDataAt(ref.getToAddress());
					if (data != null && data.hasStringValue()) {
						count++;
					}
				}
			}
			funcStringCounts.add(new AbstractMap.SimpleEntry<>(function, count));
		}

		funcStringCounts.sort((a, b) -> b.getValue() - a.getValue());

		StringBuilder sb = new StringBuilder();
		sb.append("Top 3 functions by string references:\n");
		sb.append("─".repeat(40)).append("\n");
		int limit = Math.min(3, funcStringCounts.size());
		for (int i = 0; i < limit; i++) {
			Map.Entry<Function, Integer> e = funcStringCounts.get(i);
			sb.append(e.getKey().getName())
			  .append("  @  ").append(e.getKey().getEntryPoint())
			  .append("  :  ").append(e.getValue()).append(" string refs\n");
		}

		provider.setText(sb.toString());
	}

	private DecompileResults runDecompiler(Function function, TaskMonitor monitor) {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.openProgram(function.getProgram());
			return decompiler.decompileFunction(function, 30, monitor);
		} finally {
			decompiler.dispose();
		}
	}

	private void decompileCurrentFunction() {
		Program program = getCurrentProgram();
		if (program == null) {
			provider.setText("No program loaded.");
			return;
		}
		if (currentLocation == null) {
			provider.setText("No location selected.");
			return;
		}

		Function function = program.getFunctionManager()
				.getFunctionContaining(currentLocation.getAddress());
		if (function == null) {
			provider.setText("No function at current location.");
			return;
		}

		DecompileResults results = runDecompiler(function, TaskMonitor.DUMMY);
		if (results.decompileCompleted()) {
			provider.setText(results.getDecompiledFunction().getC());
		} else {
			provider.setText("Decompilation failed:\n" + results.getErrorMessage());
		}
	}

	private void evtButtonDoRenameFromCSV() {
		if (currentLocation == null) {
			provider.setText("No location selected.");
			return;
		}
		String csvText = provider.getText();
		if (csvText.trim().isEmpty()) {
			provider.setText("Text area is empty — paste a CSV first.");
			return;
		}
		Address address = currentLocation.getAddress();
		Task task = new Task("Rename from CSV", true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				doRenameFromCSV(address, csvText, monitor);
			}
		};
		new TaskLauncher(task, provider.getComponent());
	}

	private void doRenameFromCSV(Address address, String csvText, TaskMonitor monitor) {
		Program program = getCurrentProgram();
		if (program == null) {
			provider.setText("No program loaded.");
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			provider.setText("No function at current location.");
			return;
		}

		DecompileResults results = runDecompiler(function, monitor);
		if (!results.decompileCompleted()) {
			provider.setText("Decompilation failed:\n" + results.getErrorMessage());
			return;
		}
		HighFunction highFunction = results.getHighFunction();
		LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();

		Set<String> takenLocalNames = new HashSet<>();
		Iterator<HighSymbol> initIt = symbolMap.getSymbols();
		while (initIt.hasNext()) {
			takenLocalNames.add(initIt.next().getName());
		}
		Set<String> assignedGlobalNames = new HashSet<>();

		StringBuilder log = new StringBuilder();
		int txId = program.startTransaction("Rename from CSV");
		boolean committed = false;
		try {
			try (CsvReader<CsvRecord> csvReader = CsvReader.builder().skipEmptyLines(true).ofCsvRecord(csvText)) {
				for (CsvRecord record : csvReader) {
					if (monitor.isCancelled()) break;
					if (record.getFieldCount() < 2) {
						log.append("Skipped (bad format): ").append(String.join(",", record.getFields())).append("\n");
						continue;
					}
					String oldName = record.getField(0).trim();
					String newName = record.getField(1).trim();

					HighSymbol targetSymbol = null;
					Iterator<HighSymbol> symbols = symbolMap.getSymbols();
					while (symbols.hasNext()) {
						HighSymbol sym = symbols.next();
						if (sym.getName().equals(oldName)) {
							targetSymbol = sym;
							break;
						}
					}

					boolean found = false;
					if (targetSymbol != null) {
						takenLocalNames.remove(oldName);
						String effectiveName = newName;
						int suffix = 1;
						while (takenLocalNames.contains(effectiveName)) {
							effectiveName = newName + "_" + suffix++;
						}
						takenLocalNames.add(effectiveName);
						HighFunctionDBUtil.updateDBVariable(targetSymbol, effectiveName, null, SourceType.USER_DEFINED);
						if (effectiveName.equals(newName)) {
							log.append("Renamed local: ").append(oldName).append(" -> ").append(effectiveName).append("\n");
						} else {
							log.append("Renamed local: ").append(oldName).append(" -> ").append(effectiveName)
								.append(" (").append(newName).append(" already taken)\n");
						}
						found = true;
					}

					if (!found) {
						List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(oldName);
						if (!globalSymbols.isEmpty()) {
							String effectiveName = newName;
							int suffix = 1;
							while (!program.getSymbolTable().getGlobalSymbols(effectiveName).isEmpty()
									|| assignedGlobalNames.contains(effectiveName)) {
								effectiveName = newName + "_" + suffix++;
							}
							assignedGlobalNames.add(effectiveName);
							globalSymbols.get(0).setName(effectiveName, SourceType.USER_DEFINED);
							if (effectiveName.equals(newName)) {
								log.append("Renamed global: ").append(oldName).append(" -> ").append(effectiveName).append("\n");
							} else {
								log.append("Renamed global: ").append(oldName).append(" -> ").append(effectiveName)
									.append(" (").append(newName).append(" already taken)\n");
							}
							found = true;
						}
					}

					if (!found) {
						log.append("Not found: ").append(oldName).append("\n");
					}
				}
			}
			committed = true;
		} catch (Exception e) {
			log.append("Error: ").append(e.getMessage());
		} finally {
			program.endTransaction(txId, committed);
		}

		final String result = log.toString();
		SwingUtilities.invokeLater(() -> provider.setText(result));
	}

	private void evtButtonRenameVariables() {
		if (activeMonitor != null) {
			activeMonitor.cancel();
			return;
		}
		if (currentLocation == null) {
			provider.setText("No location selected.");
			return;
		}
		Address address = currentLocation.getAddress();
		provider.setRenamButtonText("Rename Variables (click to stop)");
		Task task = new Task("Rename Variables", true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				activeMonitor = monitor;
				try {
					renameVariables(address, monitor);
				} finally {
					activeMonitor = null;
					SwingUtilities.invokeLater(() -> provider.setRenamButtonText("Rename Variables"));
				}
			}
		};
		new TaskLauncher(task, provider.getComponent());
	}

	private void renameVariables(Address address, TaskMonitor monitor) {
		Program program = getCurrentProgram();
		if (program == null) {
			provider.setText("No program loaded.");
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			provider.setText("No function at current location.");
			return;
		}
		StringBuilder log = new StringBuilder();
		doRenameVariables(function, monitor, log);
		provider.setText(log.toString());
	}

	private void doRenameVariables(Function function, TaskMonitor monitor, StringBuilder log) {
		Program program = getCurrentProgram();
		if (program == null) {
			log.append("No program loaded.\n");
			return;
		}

		DecompileResults initialResults = runDecompiler(function, monitor);
		if (!initialResults.decompileCompleted()) {
			log.append("Decompilation failed:\n").append(initialResults.getErrorMessage());
			return;
		}
		HighFunction highFunction = initialResults.getHighFunction();
		String cCode = initialResults.getDecompiledFunction().getC();

		String csvText;
		try {
			csvText = aiGetRenameVariablesCSV(cCode);
		} catch (Exception e) {
			log.append("AI call failed: ").append(e.getMessage());
			return;
		}

		if (csvText.isEmpty()) {
			log.append("AI returned no CSV.\n");
			return;
		}

		LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();

		// Pre-populate with every name currently in the local symbol map so we can
		// detect conflicts without relying on Ghidra reflecting mid-transaction renames.
		Set<String> takenLocalNames = new HashSet<>();
		Iterator<HighSymbol> initIt = symbolMap.getSymbols();
		while (initIt.hasNext()) {
			takenLocalNames.add(initIt.next().getName());
		}

		// Track global names assigned during this batch (live DB handles pre-existing ones).
		Set<String> assignedGlobalNames = new HashSet<>();

		int txId = program.startTransaction("Rename Variables");
		boolean committed = false;
		try {
			try (CsvReader<CsvRecord> csvReader = CsvReader.builder().skipEmptyLines(true).ofCsvRecord(csvText)) {
			for (CsvRecord record : csvReader) {
				if (record.getFieldCount() < 2) {
					log.append("Skipped (bad format): ").append(String.join(",", record.getFields())).append("\n");
					continue;
				}
				String oldName = record.getField(0).trim();
				String newName = record.getField(1).trim();

				HighSymbol targetSymbol = null;
				Iterator<HighSymbol> symbols = symbolMap.getSymbols();
				while (symbols.hasNext()) {
					HighSymbol symbol = symbols.next();
					if (symbol.getName().equals(oldName)) {
						targetSymbol = symbol;
						break;
					}
				}

				boolean found = false;
				if (targetSymbol != null) {
					takenLocalNames.remove(oldName);
					String effectiveName = newName;
					int suffix = 1;
					while (takenLocalNames.contains(effectiveName)) {
						effectiveName = newName + "_" + suffix++;
					}
					takenLocalNames.add(effectiveName);
					HighFunctionDBUtil.updateDBVariable(targetSymbol, effectiveName, null, SourceType.USER_DEFINED);
					if (effectiveName.equals(newName)) {
						log.append("Renamed: ").append(oldName).append(" -> ").append(effectiveName).append("\n");
					} else {
						log.append("Renamed: ").append(oldName).append(" -> ").append(effectiveName)
							.append(" (").append(newName).append(" already taken)\n");
					}
					found = true;
				}
				if (!found) {
					List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(oldName);
					if (!globalSymbols.isEmpty()) {
						String effectiveName = newName;
						int suffix = 1;
						while (!program.getSymbolTable().getGlobalSymbols(effectiveName).isEmpty()
								|| assignedGlobalNames.contains(effectiveName)) {
							effectiveName = newName + "_" + suffix++;
						}
						assignedGlobalNames.add(effectiveName);
						globalSymbols.get(0).setName(effectiveName, SourceType.USER_DEFINED);
						if (effectiveName.equals(newName)) {
							log.append("Renamed global: ").append(oldName).append(" -> ").append(effectiveName).append("\n");
						} else {
							log.append("Renamed global: ").append(oldName).append(" -> ").append(effectiveName)
								.append(" (").append(newName).append(" already taken)\n");
						}
						found = true;
					}
				}
				if (!found) {
					log.append("Not found: ").append(oldName).append("\n");
				}
			}
			}
			committed = true;
		} catch (Exception e) {
			log.append("Error: ").append(e.getMessage());
		} finally {
			program.endTransaction(txId, committed);
		}

		// Get new decompiler results, use them to compute a function name.
		if (committed) {
			DecompileResults newResults = runDecompiler(function, monitor);
			if (newResults.decompileCompleted()) {
				String newCCode = newResults.getDecompiledFunction().getC();
				PropertyMapManager propMgrForName = program.getUsrPropertyManager();
				// If function rename suggestions exist from AI which worked on other functions, please
				// pass them in to the current AI.
				StringPropertyMap nameSuggestionMap = propMgrForName.getStringPropertyMap("FunctionRenameSuggestions");
				String priorSuggestions = null;
				if (nameSuggestionMap != null && nameSuggestionMap.hasProperty(function.getEntryPoint())) {
					priorSuggestions = nameSuggestionMap.getString(function.getEntryPoint());
				}

				try {
					String aiReply = aiSuggestFunctionName(newCCode, priorSuggestions);
					int backtickIdx = aiReply.indexOf("```");
					String reasoning = backtickIdx >= 0 ? aiReply.substring(0, backtickIdx).trim() : aiReply.trim();
					String suggestedName = ParseUtils.extractBetween(aiReply, "```", "```").trim();

					log.append("\n--- Function Name Suggestion ---\n");
					if (!reasoning.isEmpty()) {
						log.append(reasoning).append("\n");
					}

					if (!suggestedName.isEmpty()) {
						log.append("Suggested name: ").append(suggestedName).append("\n");
						if (function.getName().startsWith("FUN_")) {
							int renameTxId = program.startTransaction("Rename Function");
							boolean renameCommitted = false;
							try {
								function.setName(suggestedName, SourceType.USER_DEFINED);
								log.append("Function renamed to: ").append(suggestedName).append("\n");
								if (!reasoning.isEmpty()) {
									program.getListing().setComment(function.getEntryPoint(), CommentType.PLATE, reasoning);
								}
								renameCommitted = true;
							} catch (Exception e) {
								log.append("Function rename failed: ").append(e.getMessage()).append("\n");
							} finally {
								program.endTransaction(renameTxId, renameCommitted);
							}
						}
					}
				} catch (Exception e) {
					log.append("AI function name suggestion failed: ").append(e.getMessage()).append("\n");
				}

				// Lets get function rename suggestion for all undefined functions being called, based on what
				// they are doing in the current function.
				if (newCCode.contains("FUN_")) {
					Pattern funPattern = Pattern.compile("\\bFUN_[0-9a-fA-F]+");
					Matcher funMatcher = funPattern.matcher(newCCode);
					Set<String> undefinedFuncNames = new HashSet<>();
					while (funMatcher.find()) {
						undefinedFuncNames.add(funMatcher.group());
					}

					// Check if we have 3 or more function rename suggestions for each function call being made
					// from the current function. If we do, we don't need any more, and we can skip this step.
					if (!undefinedFuncNames.isEmpty()) {
						PropertyMapManager propMgr = program.getUsrPropertyManager();
						StringPropertyMap suggestionMap = propMgr.getStringPropertyMap("FunctionRenameSuggestions");

						boolean allHaveEnoughSuggestions = true;
						for (String funcName : undefinedFuncNames) {
							List<Symbol> funcSymbols = program.getSymbolTable().getGlobalSymbols(funcName);
							if (funcSymbols.isEmpty()) {
								allHaveEnoughSuggestions = false;
								break;
							}
							Address funcAddr = funcSymbols.get(0).getAddress();
							int count = 0;
							if (suggestionMap != null && suggestionMap.hasProperty(funcAddr)) {
								count = suggestionMap.getString(funcAddr).split("\n").length;
							}
							if (count < 3) {
								allHaveEnoughSuggestions = false;
								break;
							}
						}

						// Finally actually do get the function rename suggestions, and add them to the
						// FunctionRenameSuggestions StringProperyMap
						if (allHaveEnoughSuggestions) {
							log.append("\n--- Called Function Name Suggestions: all functions have sufficient suggestions, skipping ---\n");
						} else {
							log.append("\n--- Called Function Name Suggestions ---\n");
							try {
								String funcCsvText = aiGetRenameFunctionsCSV(newCCode);
								if (funcCsvText.isEmpty()) {
									log.append("AI returned no function name suggestions.\n");
								} else {
									int propTxId = program.startTransaction("Store Function Name Suggestions");
									boolean propCommitted = false;
									try {
										if (suggestionMap == null) {
											suggestionMap = propMgr.createStringPropertyMap("FunctionRenameSuggestions");
										}
										try (CsvReader<CsvRecord> funcCsvReader = CsvReader.builder().skipEmptyLines(true).ofCsvRecord(funcCsvText)) {
										for (CsvRecord record : funcCsvReader) {
											if (record.getFieldCount() < 2) continue;
											String line = String.join(",", record.getFields());
											log.append(line).append("\n");
											String oldFuncName = record.getField(0).trim();
											List<Symbol> funcSymbols = program.getSymbolTable().getGlobalSymbols(oldFuncName);
											if (!funcSymbols.isEmpty()) {
												Address funcAddr = funcSymbols.get(0).getAddress();
												String existing = suggestionMap.hasProperty(funcAddr)
														? suggestionMap.getString(funcAddr) : null;
												int existingCount = existing == null ? 0 : existing.split("\n").length;
												if (existingCount < 3) {
													String newValue = existing == null ? line : existing + "\n" + line;
													suggestionMap.add(funcAddr, newValue);
												}
											}
										}
										}
										propCommitted = true;
									} catch (Exception e) {
										log.append("Storing suggestions failed: ").append(e.getMessage()).append("\n");
									} finally {
										program.endTransaction(propTxId, propCommitted);
									}
								}
							} catch (Exception e) {
								log.append("AI called function name suggestions failed: ").append(e.getMessage()).append("\n");
							}
						}
					}
				}
			}
		}
	}

	private void evtButtonRenameAllFunctionsAndVariables() {
		if (activeMonitor != null) {
			activeMonitor.cancel();
			return;
		}
		provider.setRenameAllButtonText("Rename ALL (click to stop)");
		Task task = new Task("Rename ALL Functions and Variables", true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				activeMonitor = monitor;
				try {
					renameAllFunctionsAndVariables(monitor);
				} finally {
					activeMonitor = null;
					SwingUtilities.invokeLater(() -> provider.setRenameAllButtonText("Rename ALL Functions and Variables"));
				}
			}
		};
		new TaskLauncher(task, provider.getComponent());
	}

	private void renameAllFunctionsAndVariables(TaskMonitor monitor) {
		Program program = getCurrentProgram();
		if (program == null) {
			provider.setText("No program loaded.");
			return;
		}

		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager refMgr = program.getReferenceManager();
		Listing listing = program.getListing();

		// Build list of all functions sorted by string reference count (descending)
		List<Map.Entry<Function, Integer>> funcStringCounts = new ArrayList<>();
		FunctionIterator allFuncs = functionManager.getFunctions(true);
		while (allFuncs.hasNext()) {
			if (monitor.isCancelled()) return;
			Function function = allFuncs.next();
			AddressSetView body = function.getBody();
			int count = 0;
			AddressIterator addrIt = refMgr.getReferenceSourceIterator(body, true);
			while (addrIt.hasNext()) {
				for (Reference ref : refMgr.getReferencesFrom(addrIt.next())) {
					Data data = listing.getDataAt(ref.getToAddress());
					if (data != null && data.hasStringValue()) {
						count++;
					}
				}
			}
			funcStringCounts.add(new AbstractMap.SimpleEntry<>(function, count));
		}
		funcStringCounts.sort((a, b) -> b.getValue() - a.getValue());

		int totalFunctions = funcStringCounts.size();
		int processed = 0;
		Set<Address> processedAddresses = new HashSet<>();

		// Pre-mark functions with meaningful names as already done — nothing to rename.
		for (Map.Entry<Function, Integer> entry : funcStringCounts) {
			if (!entry.getKey().getName().startsWith("FUN_")) {
				processedAddresses.add(entry.getKey().getEntryPoint());
			}
		}
		int funCount = totalFunctions - processedAddresses.size();
		monitor.initialize(funCount);

		StringBuilder runningLog = new StringBuilder();

		provider.setText("Rename ALL: " + totalFunctions + " functions to process...\n");

		// Phase 1: functions with at least one string reference, most to least
		for (Map.Entry<Function, Integer> entry : funcStringCounts) {
			if (monitor.isCancelled()) return;
			if (entry.getValue() == 0) break;

			Function function = entry.getKey();
			Address entryPoint = function.getEntryPoint();
			processedAddresses.add(entryPoint);

			String oldName = function.getName();
			monitor.setMessage(oldName);
			StringBuilder funcLog = new StringBuilder();
			doRenameVariables(function, monitor, funcLog);
			String newName = function.getName();
			monitor.incrementProgress(1);

			processed++;
			int pct = (int) Math.round(100.0 * processed / totalFunctions);
			runningLog.append(String.format("[%d/%d %d%%] %s -> %s\n", processed, totalFunctions, pct, oldName, newName));
			runningLog.append(funcLog);
			provider.setText(runningLog.toString());
		}

		// Phase 2: 3 passes through FunctionRenameSuggestions for unprocessed functions
		for (int pass = 0; pass < 3; pass++) {
			if (monitor.isCancelled()) return;

			PropertyMapManager propMgr = program.getUsrPropertyManager();
			StringPropertyMap suggestionMap = propMgr.getStringPropertyMap("FunctionRenameSuggestions");
			if (suggestionMap == null) break;

			AddressIterator suggestionAddrs = suggestionMap.getPropertyIterator();
			while (suggestionAddrs.hasNext()) {
				if (monitor.isCancelled()) return;
				Address addr = suggestionAddrs.next();
				if (processedAddresses.contains(addr)) continue;

				Function function = functionManager.getFunctionContaining(addr);
				if (function == null) continue;

				processedAddresses.add(addr);

				String oldName = function.getName();
				monitor.setMessage(oldName);
				StringBuilder funcLog = new StringBuilder();
				doRenameVariables(function, monitor, funcLog);
				String newName = function.getName();
				monitor.incrementProgress(1);

				processed++;
				int pct = (int) Math.round(100.0 * processed / totalFunctions);
				runningLog.append(String.format("[%d/%d %d%%] %s -> %s\n", processed, totalFunctions, pct, oldName, newName));
				runningLog.append(funcLog);
				provider.setText(runningLog.toString());
			}
		}

		// Phase 3: all remaining unprocessed functions
		for (Map.Entry<Function, Integer> entry : funcStringCounts) {
			if (monitor.isCancelled()) return;
			Address entryPoint = entry.getKey().getEntryPoint();
			if (processedAddresses.contains(entryPoint)) continue;

			Function function = entry.getKey();
			processedAddresses.add(entryPoint);

			String oldName = function.getName();
			monitor.setMessage(oldName);
			StringBuilder funcLog = new StringBuilder();
			doRenameVariables(function, monitor, funcLog);
			String newName = function.getName();
			monitor.incrementProgress(1);

			processed++;
			int pct = (int) Math.round(100.0 * processed / totalFunctions);
			runningLog.append(String.format("[%d/%d %d%%] %s -> %s\n", processed, totalFunctions, pct, oldName, newName));
			runningLog.append(funcLog);
			provider.setText(runningLog.toString());
		}

		runningLog.append(String.format("\nDone! Processed %d/%d functions.\n", processed, totalFunctions));
		provider.setText(runningLog.toString());
	}

	private LlamaHelper createLlamaHelper() {
		return new LlamaHelper(configBaseUrl, configApiKey, configModelName, configHttpTimeoutSec)
				.setSystemPrompt(configSystemPrompt);
	}

	private String aiGetRenameVariablesCSV(String decompilerOutput) throws Exception {
		LlamaHelper llama = createLlamaHelper();

		String prompt = "I need your help in marking up some decompiler output."
				+ " Below you will find the decompiler output. Please rename the variables in it to something more useful."
				+ " Please also rename any global variables you find (they start with DAT_) to something meaningful as well. "
				+ " You should structure the output as a 2 column CSV (no header): <original variable name>,<new variable name> ."
				+ " Please place the CSV in between markdown triple backticks `, so that I can parse it out of the response easily.\n\n"
				+ "```\n" + decompilerOutput + "\n```\n";
		String reply = llama.getResponse(prompt);
		return ParseUtils.stripCodeFenceLanguageTag(ParseUtils.extractBetween(reply, "```", "```"));
	}

	private String aiSuggestFunctionName(String decompilerOutput, String priorSuggestions) throws Exception {
		LlamaHelper llama = createLlamaHelper();

		StringBuilder prompt = new StringBuilder();
		prompt.append("I need your help deciding on a function name based on decompiler output.")
			  .append(" Below you will find the decompiler output. All the variables have been renamed to something meaningful.")
			  .append(" Please read the decompiler output, and suggest a function name. Before giving the suggestion, please cite your reasoning.")
			  .append(" Your reasoning will be added to the decompiler listing, so please make sure it's short and appropriate.")
			  .append(" Please place the function name you suggest in between markdown triple backticks, so that I can parse it out of the response easily.\n\n");

		if (priorSuggestions != null && !priorSuggestions.isEmpty()) {
			prompt.append("Previous analysis of callers has already produced these name suggestions for this function")
				  .append(" (CSV format: original_name,suggested_name,reasoning). Please take these into account when choosing a name:\n")
				  .append(priorSuggestions).append("\n\n");
		}

		prompt.append("```\n").append(decompilerOutput).append("\n```\n");
		String reply = llama.getResponse(prompt.toString());
		return reply;
	}

	private String aiGetRenameFunctionsCSV(String decompilerOutput) throws Exception {
		LlamaHelper llama = createLlamaHelper();

		String prompt = "I need your help on deciding on function names in my decompiler output."
				+ " Below you will find the decompiler output. All the variables have been renamed to something meaningful."
				+ " Please read the decompiler output, and suggest a function name for each undefined function beginning with FUN_ . "
				+ " You should structure the output as a 3 column CSV (no header): <original function name>,<new function name>,<reasoning>"
				+ " Your reasoning will be added to the decompiler listing, so please make sure it's short and appropriate. "
				+ " Please place the CSV in between markdown triple backticks `, so that I can parse it out of the response easily.\n\n"
				+ "```\n" + decompilerOutput + "\n```\n";
		String reply = llama.getResponse(prompt);
		return ParseUtils.stripCodeFenceLanguageTag(ParseUtils.extractBetween(reply, "```", "```"));
	}

	private static class ConfigDialog extends JDialog {
		private final JTextField baseUrlField;
		private final JTextField apiKeyField;
		private final JTextField modelNameField;
		private final JTextField httpTimeoutField;
		private final JTextArea systemPromptArea;
		private final FastAIRenamerPlugin plugin;

		ConfigDialog(FastAIRenamerPlugin plugin, Component parent) {
			super(SwingUtilities.getWindowAncestor(parent), "LLM Configuration", Dialog.ModalityType.APPLICATION_MODAL);
			this.plugin = plugin;

			JPanel formPanel = new JPanel(new GridBagLayout());
			formPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));

			GridBagConstraints lc = new GridBagConstraints();
			lc.anchor = GridBagConstraints.NORTHWEST;
			lc.insets = new Insets(6, 0, 6, 10);
			lc.gridx = 0;
			lc.weightx = 0;

			GridBagConstraints fc = new GridBagConstraints();
			fc.fill = GridBagConstraints.HORIZONTAL;
			fc.insets = new Insets(4, 0, 4, 0);
			fc.gridx = 1;
			fc.weightx = 1;

			lc.gridy = 0; fc.gridy = 0;
			formPanel.add(new JLabel("Base URL:"), lc);
			baseUrlField = new JTextField(plugin.configBaseUrl, 40);
			formPanel.add(baseUrlField, fc);

			lc.gridy = 1; fc.gridy = 1;
			formPanel.add(new JLabel("API Key:"), lc);
			apiKeyField = new JTextField(plugin.configApiKey, 40);
			formPanel.add(apiKeyField, fc);

			lc.gridy = 2; fc.gridy = 2;
			formPanel.add(new JLabel("Model Name:"), lc);
			modelNameField = new JTextField(plugin.configModelName, 40);
			formPanel.add(modelNameField, fc);

			lc.gridy = 3; fc.gridy = 3;
			formPanel.add(new JLabel("HTTP Timeout (sec):"), lc);
			httpTimeoutField = new JTextField(String.valueOf(plugin.configHttpTimeoutSec), 10);
			formPanel.add(httpTimeoutField, fc);

			lc.gridy = 4;
			formPanel.add(new JLabel("System Prompt:"), lc);
			fc.gridy = 4;
			fc.fill = GridBagConstraints.BOTH;
			fc.weighty = 1;
			systemPromptArea = new JTextArea(plugin.configSystemPrompt, 6, 40);
			systemPromptArea.setLineWrap(true);
			systemPromptArea.setWrapStyleWord(true);
			formPanel.add(new JScrollPane(systemPromptArea), fc);

			JButton saveBtn = new JButton("Save");
			JButton cancelBtn = new JButton("Cancel");
			saveBtn.addActionListener(e -> onSave());
			cancelBtn.addActionListener(e -> dispose());
			JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
			buttonPanel.add(saveBtn);
			buttonPanel.add(cancelBtn);

			setLayout(new BorderLayout());
			add(formPanel, BorderLayout.CENTER);
			add(buttonPanel, BorderLayout.SOUTH);
			setMinimumSize(new Dimension(520, 320));
			pack();
			setLocationRelativeTo(parent);
		}

		private void onSave() {
			plugin.configBaseUrl      = baseUrlField.getText().trim();
			plugin.configApiKey       = apiKeyField.getText().trim();
			plugin.configModelName    = modelNameField.getText().trim();
			plugin.configSystemPrompt = systemPromptArea.getText();
			try {
				int t = Integer.parseInt(httpTimeoutField.getText().trim());
				if (t > 0) plugin.configHttpTimeoutSec = t;
			} catch (NumberFormatException ignored) {}

			Preferences.setProperty("fastairenamer.configBaseUrl",       plugin.configBaseUrl);
			Preferences.setProperty("fastairenamer.configApiKey",        plugin.configApiKey);
			Preferences.setProperty("fastairenamer.configModelName",     plugin.configModelName);
			Preferences.setProperty("fastairenamer.configSystemPrompt",  plugin.configSystemPrompt);
			Preferences.setProperty("fastairenamer.configHttpTimeoutSec", String.valueOf(plugin.configHttpTimeoutSec));
			Preferences.store();
			dispose();
		}
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private JTextArea textArea;
		private JButton renameButton;
		private JButton renameAllButton;
		private DockingAction action;
		private FastAIRenamerPlugin plugin;  // reference to call listFunctions()

		public MyProvider(FastAIRenamerPlugin plugin, String owner) {
			super(plugin.getTool(), "Fast AI Renamer", owner);
			this.plugin = plugin;  // store typed reference
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());

			JPanel buttonPanel = new JPanel(new GridLayout(0, 1));
			JButton configButton = new JButton("Config");
			configButton.addActionListener(e -> new ConfigDialog(plugin, panel).setVisible(true));
			buttonPanel.add(configButton);
			JButton listButton = new JButton("List Functions");
			listButton.addActionListener(e -> plugin.listFunctions());
			buttonPanel.add(listButton);
			JButton decompileButton = new JButton("Decompile Function");
			decompileButton.addActionListener(e -> plugin.decompileCurrentFunction());
			buttonPanel.add(decompileButton);
			JButton renameFromCsvButton = new JButton("Do Rename from CSV");
			renameFromCsvButton.addActionListener(e -> plugin.evtButtonDoRenameFromCSV());
			buttonPanel.add(renameFromCsvButton);
			renameButton = new JButton("Rename Variables");
			renameButton.addActionListener(e -> plugin.evtButtonRenameVariables());
			buttonPanel.add(renameButton);
			renameAllButton = new JButton("Rename ALL Functions and Variables");
			renameAllButton.addActionListener(e -> plugin.evtButtonRenameAllFunctionsAndVariables());
			buttonPanel.add(renameAllButton);
			panel.add(buttonPanel, BorderLayout.NORTH);

			// Scrollable text area in the center
			textArea = new JTextArea(5, 25);
			textArea.setEditable(true);
			panel.add(new JScrollPane(textArea), BorderLayout.CENTER);

			setVisible(true);
		}

		// Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		public void setText(String text) {
			textArea.setText(text);
		}

		public void setRenamButtonText(String text) {
			renameButton.setText(text);
		}

		public void setRenameAllButtonText(String text) {
			renameAllButton.setText(text);
		}

		public String getText() {
			return textArea.getText();
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
