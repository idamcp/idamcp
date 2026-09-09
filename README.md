# IDA Pro MCP Server

This project provides a Model Context Protocol (MCP) server for integrating IDA
Pro with AI agents like Gemini, Claude, and Jetski. It features a gateway-based
proxy architecture, an embedded relational SQLite query engine, and headless
session management to support advanced reverse engineering workflows.

<details>
<summary><b>Background & Motivation</b></summary>

Back in 2025, when we began integrating AI agents with IDA Pro, the upstream
[`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) project provided a
great initial starting point. At the time, it did not yet offer multi-session
workflows, which were essential for our daily reverse engineering needs.

To address our internal use cases, we began building experimental solutions:

*   **Gateway Proxy Architecture**: We developed a stateless proxy layer that
    automatically discovers and routes tool requests across concurrent GUI and
    headless IDA instances. *(While upstream has since added its own
    multi-session implementation, the two projects use fundamentally different
    architectural approaches).*
*   **Relational SQL Query Engine**: Answering high-level questions about a
    binary (e.g., finding functions with specific characteristics or exploring
    complex cross-reference patterns) typically required dozens of sequential
    API calls running on IDA's main thread. We integrated an on-demand,
    event-synchronized SQLite3 engine with an AST query-rewrite layer
    (`sqlglot`). Because queries execute against SQLite in worker threads, they
    support concurrent reads without acquiring IDA's main thread lock or
    blocking the UI.
*   **Architecture-Agnostic Tools & Bug Fixes**: Several tools in the early
    upstream code had x86-specific assumptions or heuristics. We rewrote them to
    be architecture-agnostic (supporting ARM, AArch64, MIPS, PowerPC, RISC-V,
    etc.) and fixed various stability and synchronization edge cases.

Over time, as we added more features, optimizations, and compatibility layers
across multiple IDA versions (IDA 7.7 through 9.4) and Python versions, the
codebase diverged substantially into an independent project with its own design
trade-offs.

We are sharing this project as an alternative, gateway- and SQL-centric approach
for connecting AI agents to IDA Pro, and we remain grateful to Duncan Ogilvie
and the upstream contributors for the foundational work that inspired this
effort.

</details>

<details>
<summary><b>Core Features</b></summary>

Key capabilities of this implementation include:

*   **Stateless Gateway**: A proxy layer allows agents to interact with multiple
    IDA Pro instances (GUI and Headless) concurrently. The gateway automatically
    discovers and manages connections, allowing users to open and close
    databases without reconfiguring the client.
*   **Headless Mode**: Perform analysis in the background without the IDA Pro
    GUI, suitable for automated workflows. Sessions can be managed directly by
    the AI agent.
*   **Relational SQL Engine**: Integrates a read-only SQLite relational database
    populated on-demand and synchronized via IDA event hooks. Tables
    (`functions`, `strings`, `names`, `imports`, `segments`, `local_types`,
    `xrefs`, `entries`) support concurrent background queries without blocking
    IDA's main UI thread, while an AST query layer (`sqlglot`) handles unsigned
    64-bit arithmetic, comparison rewriting, and hex literals.

*   **WYSIWYG Disassembly**: Disassembly tools (like `disassemble_function` and
    `disassemble_code`) return formatted text matching the IDA Pro UI, including
    opcode bytes, data definitions, and comments. Includes `get_ida_view` for
    viewing arbitrary memory ranges.

*   **Analysis & Modification Tools**: Includes tools for UI navigation
    (`jump_to_address`, `set_color`), memory inspection (`hexdump`), byte
    patching (`patch_bytes`), database exporting (`export_file`),
    cross-references (`get_xrefs_from`, `get_data_xrefs_from`), and structured
    data creation.

*   **Context-Aware Assembly Patching**: Powered by Keystone at the Gateway
    layer, the `patch_assembly` tool allows assembling and applying instructions
    directly at target addresses. It can resolve IDA symbols (function names,
    labels, globals) within assembly strings and evaluate basic operand math
    across supported architectures (x86/x64, ARM/AArch64, MIPS, PowerPC, etc.),
    making it convenient for quick hotpatching, stubbing out checks, or testing
    alternative execution paths.

*   **Pagination and Caching**: Implements paginated resource iteration for
    symbol and string listing, reducing memory overhead on large binaries.

*   **Security Dashboard**: A web-based interface for managing permissions for
    "unsafe" tools (e.g., Python code execution), providing control over agent
    capabilities.

*   **Unix Domain Socket (UDS) Support**: In addition to TCP, the server
    supports UDS for secure local communication in isolated environments
    (Linux/macOS).

</details>

<details>
<summary><b>Architecture Overview</b></summary>

The core of this project is the **Gateway Pattern**. A central gateway process
acts as a proxy that routes requests from the AI agent to the correct active IDA
instance.

*   **Discovery**: IDA instances (GUI or headless) register themselves by
    writing a metadata file to a shared directory.
*   **Routing**: The gateway monitors this directory and manages a routing
    table. When a tool call arrives with a specific `database_id`, the gateway
    forwards it to the corresponding IDA process.
*   **Statelessness**: This design decouples the agent from the backend. The
    agent communicates only with the gateway, and IDA instances can be opened or
    closed without affecting the agent's connection.

This architecture enables a multi-session analysis environment where the agent
can work with multiple binaries concurrently.

</details>

## Tested Environments & Prerequisites

Most tools in this project have been thoroughly tested and verified across:

*   **IDA Pro 7.7 + Python 3.11**
*   **IDA Pro 8.4 + Python 3.11**
*   **IDA Pro 9.3 + Python 3.13**
*   **IDA Pro 9.4 + Python 3.13**

### Prerequisites

*   **OS**: Linux, macOS, or Windows.
*   **IDA Pro**: Version 7.x or higher
*   **Python**: 3.11 or higher.

## Installation

Follow these steps to set up the IDA MCP server and configure your client.

**1. Quick Setup**

```bash
# a. Clone the repo
git clone https://github.com/idamcp/idamcp.git
cd idamcp

# b. Install the IDA Pro plugin
python3 install.py plugin

# c. Install the dependencies
python3 -m venv venv_idamcp

# Activate the virtual environment:
# On Linux / macOS:
source venv_idamcp/bin/activate
# On Windows (Command Prompt):
venv_idamcp\Scripts\activate.bat
# On Windows (PowerShell):
venv_idamcp\Scripts\activate.ps1

python3 -m pip install -r requirements.txt

# d. Install IDA Python library module, please update the path accordingly
cd </path/to/IDA/installation/idalib/python>

python3 -m pip install "idapro*.whl"
python3 py-activate-idalib.py


# f. Register the server with your preferred LLM client:

# For google antigravity-cli
python3 install.py agy

# For Codex
python3 install.py codex

# For Claude Code
python3 install.py claude

# For Gemini CLI
python3 install.py gemini
```

**2. Verify the Gateway (Optional / Testing Only)**

You can launch the standalone gateway proxy locally to verify that all
dependencies are met:

```bash
python3 -m gateway.proxy
```

*Note: Running the gateway standalone is strictly for testing/verification and
is **not required during normal use**. When configured as an MCP server, your
LLM client (e.g., Gemini CLI, Claude Code, Codex) automatically launches and
manages the gateway process via stdio in the background.*

**3. Recommended Configuration**

For the best experience, save these recommended settings to `~/.idamcp.json`:

```json
{
  "communication_channel": "uds",
  "registry_dir": "~/.ida_mcp_registry",
  "max_headless_instances": 8,
  "headless_open_timeout": 600.0,
  "enable_all_unsafe_tools": false,
  "enabled_unsafe_tools": ["idapython_eval"],
  "opcode_bytes": 8,
  "populate_tables_on_startup": true,
  "sqlite_persistent": true
}
```

## Configuration Explanation & Other Available Options

<details>
<summary><b>Configuration File Options & Full Example</b></summary>

The configuration file is located at `~/.idamcp.json`. Here is a complete
example of all available settings (showing defaults):

```json
{
  "communication_channel": "uds",
  "registry_dir": "~/.ida_mcp_registry",
  "uds_dir": "/tmp/ida_mcp_uds",
  "max_headless_instances": 1,
  "headless_open_timeout": 600.0,
  "python_path": "/usr/bin/python3",
  "enable_all_unsafe_tools": false,
  "enabled_unsafe_tools": ["idapython_eval", "dbg_step_over"],
  "opcode_bytes": 8,
  "populate_tables_on_startup": false,
  "sqlite_persistent": false,
  "check_entries_freshness": false,
  "disabled_tools": [],
  "proxy_host": "localhost",
  "proxy_port": 8000
}
```

*   **communication_channel**: Use `"uds"` for secure, local-only communication
    (Linux/macOS) or `"tcp"` for networked setups. Windows environments will
    default to `"tcp"`.
*   **max_headless_instances**: Limits how many background IDA processes the MCP
    Client (e.g., Gemini CLI) can spawn. This limit does not apply to manually
    launched instances.
*   **headless_open_timeout**: Timeout in seconds for opening a headless IDA
    instance. Increase this value if you're experiencing timeout errors with
    large binaries or on slower hardware.
*   **opcode_bytes**: Specifies how many instruction/data bytes to display in
    the disassembly or listing view when bytes are requested (defaults to 8).
*   **sqlite_persistent**: If `True`, the Sqlite database used by `sql_query`
    will be saved to a `.db` file in the same directory as your IDA IDB file.
    This avoids re-populating tables every time you open the database.
*   **check_entries_freshness**: If `True`, the server verifies whether entry
    points have changed in IDA (using a lightweight in-memory fingerprint)
    before executing queries against the `entries` table, automatically
    repopulating it if changes are detected. Because entry points represent
    static binary exports (functions and global data symbols) and are not
    expected to change after initial auto-analysis completes, this option
    defaults to `False`.
*   **disabled_tools**: A list of case-insensitive regular expressions. Any tool
    whose name matches a pattern in this list will not be registered. Use this
    to restrict the agent's capabilities.
*   **proxy_host**: The hostname or IP address the Gateway Proxy binds to when
    running in SSE or HTTP mode. Defaults to `localhost`.
*   **proxy_port**: The port the Gateway Proxy binds to when running in SSE or
    HTTP mode. Defaults to `8000`.

</details>

<details>
<summary><b>Environment Variables</b></summary>

You can override certain configuration settings using environment variables:

*   **POPULATE_TABLES_ON_STARTUP**: Set to `true`, `1`, or `yes` to enable table
    population at startup.
*   **SQLITE_PERSISTENT**: Set to `true`, `1`, or `yes` to enable persistent
    Sqlite storage.
*   **CHECK_ENTRIES_FRESHNESS**: Set to `true`, `1`, or `yes` to enable entry
    points freshness verification before querying the `entries` table.
*   **ENABLE_ALL_UNSAFE_TOOLS**: Set to `true` to enable all unsafe tools.
*   **ENABLED_UNSAFE_TOOLS**: A comma-separated list of specific unsafe tools to
    enable (e.g., `idapython_eval,dbg_step_over`).
*   **DISABLED_TOOLS**: A comma-separated list of regular expressions to disable
    specific tools (e.g., `^dbg_.*,^patch_.*`).
*   **PROXY_HOST**: The host for the Gateway Proxy to listen on.
*   **PROXY_PORT**: The port for the Gateway Proxy to listen on.

</details>

<details>
<summary><b>Security Dashboard & Unsafe Tools</b></summary>

Some powerful tools (like arbitrary Python execution) are marked as "unsafe" by
default. To manage these permissions and view active sessions:

1.  Start the Security Dashboard: `python3 -m frontend.security_dashboard`
2.  Open your browser to `http://127.0.0.1:8080` (the dashboard opens
    automatically by default).
3.  Use the interface to approve/deny tools.

The dashboard supports the following CLI arguments:

*   `--port <number>`: Specify the port to run on (default: 8080).
*   `--no-browser`: Disable automatic browser opening.

In case you just want to enable specific tools temporarily, you can use the
environment variables, for example:

```bash
ENABLE_ALL_UNSAFE_TOOLS=true <gemini/headless/ida>
ENABLED_UNSAFE_TOOLS=idapython_eval,dbg_step_over <gemini/headless/ida>
```

</details>

## Usage

### GUI Mode (Interactive)

1.  **Start IDA Pro** and open a database/binary.
2.  Press **`Ctrl + Alt + M`** to start the MCP server within IDA.
3.  The Gateway will automatically discover this new session, and you can begin
    your analysis with the AI agent.

### Headless Mode (Automated)

You can launch IDA instances in the background directly from the command line or
via the agent.

**Manual Launch:**

```bash
PYTHONPATH=/path/to/project python3 -m ida_mcp.headless /path/to/binary_or_idb
```

**Via LLM CLI / AI Agent:** You can ask the AI agent to open files for you:

*   **Open**: "Open the file `/path/to/binary` in headless mode."

    *   *Tool used*: `idalib_headless_open`
    *   Caveat: If the target binary is large, IDA Pro requires significant time
        to complete its initial auto-analysis. Consequently, the tool call may
        timeout and be cancelled. To resolve this, you may need to adjust both
        the `timeout` setting in the client settings and the
        `headless_open_timeout` in `~/.idamcp.json`. Alternatively, it is
        recommended to open the target binary manually the first time to allow
        the initial auto-analysis to finish.

*   **Close**: "Close the headless session for `/path/to/binary`."

    *   *Tool used*: `idalib_headless_close`

*Note: The `max_headless_instances` setting in `~/.idamcp.json` ensures the MCP
client doesn't spawn too many resource-heavy IDA processes. If the limit is
reached, `idalib_headless_open` raises an error instructing the client to close
an unused instance using `idalib_headless_close` before opening a new one. This
setting does not affect manually launched headless instances.*

*(**Prompting Tip**: LLM clients may not inherently recognize the versatility
and performance of `sql_query`, often defaulting to sequential, single-purpose
inspection tools like `list_functions`, `list_strings`, or `get_xrefs_to`. We
recommend reminding the model in system or session prompts to prioritize
`sql_query` for complex lookups, filtering, and relational joins).*

## Development

Whenever the backend RPC interfaces have been updated, developers must
regenerate `gateway/proxy.py` and run the test suite to ensure everything
functions properly:

```bash
# Generate and format the gateway/proxy
python3 -m generators.generate_proxy

# Format the file with [pyink](https://github.com/google/pyink)
pyink --line-length=80 --pyink-indentation=2 gateway/proxy.py

# Run the test suite
make test
```

## Authors & Acknowledgments

Developed and maintained by **Junfeng Yang** with the help of Google Gemini,
originally based on and inspired by the
[`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) project by Duncan
Ogilvie.

Special thanks to Hua Wu and Geoff Alexander for their thorough code reviews,
and to Genwei Jiang and Andriy Brukhovetskyy (doomedraven) for invaluable
feedback.

## Disclaimer

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

## License

This project is licensed under the [MIT License](LICENSE) and is based on the
`ida-pro-mcp` project by Duncan Ogilvie.
