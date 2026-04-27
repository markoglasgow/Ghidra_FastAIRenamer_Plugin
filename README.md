# Ghidra FastAIRenamer Plugin

Plugin for Ghidra to use an OpenAI-compatible API endpoint to rename all the variables and functions in a binary to something meaningful. Great for using it to quickly mark up the decompilation of a binary and zoom in on interesting functionality.

The plugin code is extremely simple, and does everything through simple prompts to the API (no multi-turn conversations, no tool calling, no MCP servers). This means the plugin performs well with small local models such as [Google's Gemma 4](https://huggingface.co/google/gemma-4-E4B). The plugin was vibe-coded with Claude Code, so use it at your own risk. 

## Installation

To install it, download the plugin from the release page, and then move the zip file `ghidra_12.0.4_PUBLIC_20260427_FastAIRenamerPlugin.zip` to `${GHIDRA_HOME}\Extensions\Ghidra`, then run Ghidra by running `${GHIDRA_HOME}\ghidraRun.bat`. To activate the plugin, in the initial Ghidra screen on the top menu select `File -> Install Extensions`, then in the plugin browser check the checkbox next to `FastAIRenamerPlugin`, then click `Ok`. Ghidra will prompt you to restart itself, so do that right away. 

To configure the plugin, next time Ghidra starts, on the top menu go to `Tools -> Run Tool -> CodeBrowser`. Ghidra will say "New Extensions detected. Would you like to configure them?". Click yes, then again check the checkbox next to `FastAIRenamerPlugin`, then click Ok. When the CodeBrowser opens, in the top menu click `Window -> Fast AI Renamer`, then click the `Config` button. Here you will be able to configure your AI model. Close the plugin window and the empty CodeBrowser window once done. 

*Note*: if you have any problems loading the plugin, you might need to enable Developer mode in Ghidra (File -> Configure -> checkbox next to Developer)

*Note*: you can always check if the plugin is loaded by going to the CodeBrowser, clicking File -> Configure -> Ghidra Core -> click the blue configure button -> filter by "FastAIRenamer" -> make sure the checkbox next to its name is checked. You need to do this if you don't get the "New Extensions detected" prompt from Ghidra.

## Uninstall

To uninstall the plugin, first open CodeBrowser, File -> Configure -> Ghidra Core -> click the blue configure button -> filter by "FastAIRenamer" -> uncheck -> ok. Close CodeBrowser, then in initial Ghidra window, File -> Install Extensions -> uncheck "FastAIRenamer". Finally close Ghidra and delete `ghidra_12.0.4_PUBLIC_20260427_FastAIRenamerPlugin.zip` from `${GHIDRA_HOME}\Extensions\Ghidra`. To make sure the extension is deleted, next time you run Ghidra, on initial window to go to Help -> Runtime Information -> Extension Points -> filter by "FastAIRenamer" and make sure nothing shows up

## Configuration

You configure the plugin by pressing the Config button in the Plugin UI. The default plugin configuration is set up for working with a [llama.cpp server](https://github.com/ggml-org/llama.cpp) loading the [Google Gemma 4 E4B model](https://huggingface.co/bartowski/google_gemma-4-E4B-it-GGUF/blob/main/google_gemma-4-E4B-it-Q8_0.gguf) with the following CLI options:

```
..\llama-b8893-bin-win-cuda-13.1-x64\llama-server.exe ^
  --port 8090 ^
  --threads 12 ^
  --n-gpu-layers 256 ^
  --no-mmap ^
  --model "google_gemma-4-E4B-it-Q8_0.gguf" ^
  --ctx-size 32768 ^
  --temp 1.0 ^
  --top-k 64 ^
  --top-p 0.95 ^
  --offline
```

However, it's easy to set up the plugin to work with any model from OpenRouter. To do so, simply enter the following config:
```
Base URL: https://openrouter.ai/api/
API Key: <your OpenRouter API Key>
Model Name: qwen/qwen3-235b-a22b-2507
```
This example will run the plugin against the qwen3 model [here](https://openrouter.ai/qwen/qwen3-235b-a22b-2507)

## Usage

All plugin functionality is exposed through a series of buttons. They are as follows:

- `Config` - Open the Configuration window of the plugin, where you can specify the API URL, API key, model name, and system prompt
- `List Functions` - Debug functionality, not for general use. Lists the top functions with string references in the binary.
- `Decompile Function` - Gets the text of the decompilation listing of the currently selected function, and outputs it to the textarea.
- `Do Rename from CSV` - Convenience functionality. User can enter a CSV into the textarea, with two columns "<old variable name>,<new variable name>". This button will then read the CSV from the textarea, and rename all the local/global variables in the current decompilation window from `<old variable name>` to `<new variable name>`.

- `Rename Variables` - Main functionality. Use AI to rename all the variables and function name in the currently selected function in the decompiler window.
- `Rename ALL Functions and Variables`. - Main functionality. Use AI to rename ALL variables and functions in the binary to something meaningful.

## Tutorial

I wrote a tutorial on how to use this plugin here:
https://github.com/markoglasgow/gemma_crackme_tutorial
