# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Ghidra extension** — a plugin for the Ghidra software reverse engineering suite (developed by the NSA). It is written in Java and built with Gradle. The plugin assists with reverse engineering by providing AI-assisted variable renaming and decompilation tools inside Ghidra's UI.

## Build

Requires `GHIDRA_INSTALL_DIR` to point to a Ghidra installation (currently `C:/Tools/ghidra_12.0.4`):

```bash
export GHIDRA_INSTALL_DIR=C:/Tools/ghidra_12.0.4
gradle distributeExtension
```

The built extension zip lands in `dist/`. To test, install it in Ghidra via **File → Install Extensions**, then restart Ghidra and enable the plugin under **File → Configure**.

There are no automated tests. All testing is done manually inside a running Ghidra instance.

## Architecture

```
FastAIRenamerPlugin (extends ProgramPlugin)
  └── MyProvider (extends ComponentProvider, static inner class)
        ├── JPanel (BorderLayout)
        │     ├── NORTH: JPanel (GridLayout) with 4 buttons:
        │     │     ├── "List Functions"        → plugin.listFunctions()
        │     │     ├── "Decompile Function"    → plugin.decompileCurrentFunction()
        │     │     ├── "Rename Variables"      → plugin.evtButtonRenameVariables()
        │     │     └── "CSV Rename Variables"  → plugin.evtButtonCsvRenameVariables()
        │     └── CENTER: JScrollPane wrapping JTextArea (editable)
        └── DockingAction (toolbar ADD icon → shows "Hello!" dialog)

LlamaHelper       — HTTP client wrapper for OpenAI-compatible /v1/chat/completions endpoints
ParseUtils        — Static string utilities (extractBetween for parsing AI responses)
```

**`FastAIRenamerPlugin`** is the entry point. It is registered with Ghidra via the `@PluginInfo` annotation (status, package, category, descriptions). On construction it creates `MyProvider` and registers a `HelpLocation`.

**`MyProvider`** owns the Swing UI and is a dockable panel inside Ghidra's main window. It holds a typed back-reference to the plugin (`FastAIRenamerPlugin plugin`) to invoke analysis methods directly. The text area is editable — it serves as both input (for manual CSV paste) and output (results log).

**`listFunctions()`** shows the count of functions in the loaded binary. The detail loop (name + entry point) is currently commented out.

**`decompileCurrentFunction()`** decompiles the function at the current cursor location and displays the C output in the text area.

**`renameVariables()`** (triggered by "Rename Variables" button): decompiles the function at the current location, sends the C output to the local LLM via `aiGetRenameVariablesCSV()`, parses the returned CSV, then applies renames to both local variables (via `HighFunctionDBUtil.updateDBVariable`) and global symbols (via `Symbol.setName`). Conflict detection prevents duplicate names — suffixes like `_1`, `_2` are added as needed.

**`csvRenameVariables()`** (triggered by "CSV Rename Variables" button): same rename logic as above but reads the CSV directly from the text area instead of calling the AI. Use this to apply a manually edited or previously saved CSV.

**`aiGetRenameVariablesCSV()`**: calls the local LLM with the decompiler C output and asks it to produce a `old_name,new_name` CSV. The CSV is expected inside markdown triple backticks in the reply; `ParseUtils.extractBetween` pulls it out.

**`aiSuggestFunctionName()`**: calls the local LLM with the decompiler C output (after renaming) and asks it to suggest a function name with short reasoning. Returns the full reply including the reasoning; the suggested name is in triple backticks.

Both long-running rename operations run inside a `TaskLauncher` / `Task` so they don't block the Ghidra UI thread. Clicking the button again while the task is running cancels it via `TaskMonitor.cancel()`.

## AI Integration

The plugin talks to a **local LLM server** (llama.cpp or compatible) via an OpenAI-compatible REST API:

- Base URL: `http://localhost:8090`
- Model: `google_gemma-4-E4B-it-Q8_0.gguf`
- API key placeholder: `"my-key"` (ignored by local servers but required by the HTTP client)

`LlamaHelper` wraps the HTTP call: it builds a `messages` array with an optional system prompt and one user message, POSTs to `/v1/chat/completions`, and returns the content string from `choices[0].message.content`.

`ParseUtils.extractBetween(text, left, right)` extracts the substring between the first occurrence of `left` and the next occurrence of `right`. Used to pull the CSV or function name out of the AI response's triple-backtick fences.

## Key Ghidra APIs

| API | Purpose |
|-----|---------|
| `ProgramPlugin` | Base class; provides `getCurrentProgram()` and `currentLocation` |
| `ComponentProvider` | Base for dockable UI panels |
| `DockingAction` | Toolbar/menu actions within Ghidra |
| `FunctionManager` / `FunctionIterator` | Enumerate functions in the loaded binary |
| `DecompInterface` / `DecompileResults` | Decompile a function to C; always call `dispose()` in a finally block |
| `HighFunction` / `LocalSymbolMap` / `HighSymbol` | Access decompiler's high-level variable model |
| `HighFunctionDBUtil.updateDBVariable()` | Persist a local variable rename into the Ghidra database |
| `Program.getSymbolTable().getGlobalSymbols()` | Look up and rename global symbols |
| `SourceType.USER_DEFINED` | Mark renames as user-initiated (not auto-analysis) |
| `TaskLauncher` / `Task` / `TaskMonitor` | Run work off the Swing EDT; supports cancellation |
| `Msg.showInfo()` | Ghidra-aware dialog/logging utility |
| `Icons` | Built-in Ghidra icon constants |

## Package and Registration

- Package: `fastairenamer`
- Ghidra discovers the plugin automatically via classpath scanning of `@PluginInfo`-annotated classes — no `plugin.xml` or `MANIFEST.MF` needed.
- `extension.properties` holds metadata tokens (`@extname@`, `@extversion@`) that Gradle fills in during `buildExtension`.
