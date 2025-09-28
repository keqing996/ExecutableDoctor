# ExecutableDoctor

A lightweight toolkit for inspecting native binaries with LLDB. ExecutableDoctor parses PE and ELF executables, ranks the largest functions, summarizes sections, and exports rich reports you can explore or share.

## What's inside

- **LLDB-powered analysis** — attach to a binary and walk its symbols, even without debug info.
- **Cross-platform file support** — understands PE (Windows) and ELF (Linux/macOS) formats.
- **Rich reporting** — produces Markdown summaries alongside CSV exports for imports/exports.
- **Modular building blocks** — reuse `BinaryAnalyzer`, `SectionAnalyzer`, `SymbolExtractor`, and friends in your own scripts.

The core package lives in `src/binary_analyzer/` and is organized into focused modules for symbols, sections, import/export tables, report generation, and CLI orchestration.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Python ≥ 3.8 | The package metadata supports 3.7+, but 3.8+ is recommended. |
| LLDB Python bindings | Install via an LLVM toolchain. On macOS they ship with Xcode Command Line Tools; on Linux/Windows install LLVM and export `LLVM_PATH` if needed. |
| Optional Python libs | `pefile` (PE parsing) and `pyelftools` (ELF parsing). Installed automatically from `requirements.txt`. |

> **Tip:** Set `LLVM_PATH` to the root of your LLVM install if LLDB cannot be imported automatically. The CLI also exposes a `--llvm-path` flag.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

LLDB itself is not shipped as a pip dependency. Follow your platform's instructions to install LLVM/LLDB beforehand.

## Quick start

### CLI workflow

```bash
python -m binary_analyzer.cli /path/to/binary
```

Key flags:

- `-o, --output <dir>` — store reports somewhere other than `<binary_dir>/output/`.
- `-n, --top-functions <N>` — limit the ranked function table (default 200).
- `--no-source-info` — skip source/line resolution for faster results.
- `--llvm-path <path>` — point directly at an LLVM install with LLDB bindings.

Successful runs print a summary and the path to the generated Markdown report.

### Library workflow

```python
from binary_analyzer import BinaryAnalyzer, AnalysisConfig

config = AnalysisConfig(top_functions=50, skip_source_info=True)
analyzer = BinaryAnalyzer(config)
result = analyzer.full_analysis("/path/to/binary")

if result["success"]:
    print(f"Report saved to: {result['report_path']}")
```

You can access intermediate steps too:

```python
functions = analyzer.analyze_binary("/path/to/binary")
sections = analyzer.get_sections_info("/path/to/binary")
imports = analyzer.get_imports_info("/path/to/binary")
exports = analyzer.get_exports_info("/path/to/binary")
```

## Output anatomy

- **Markdown report** — `<binary_name>_analysis_report.md` with sections, statistics, and detailed function breakdowns.
- **CSV exports** — `{binary_name}_imports.csv` and `{binary_name}_exports.csv` when import/export data is discovered.
- **Default location** — `<binary_dir>/output/` unless overridden via CLI flag or `AnalysisConfig.output_dir`.

## Configuration cheat sheet

| Option | CLI flag | Description |
| --- | --- | --- |
| `llvm_path` | `--llvm-path` | Directory containing LLDB's Python packages. |
| `top_functions` | `-n / --top-functions` | Number of largest functions to include in the report. |
| `skip_source_info` | `--no-source-info` | When true, avoids resolving file/line metadata. |
| `output_dir` | `-o / --output` | Destination directory for reports and CSVs. |

The same fields are exposed through `AnalysisConfig` for programmatic use.

## Project layout

```
src/binary_analyzer/
├── analyzer.py          # Coordinates LLDB, extraction, and report steps
├── cli.py               # User-facing command line entry point
├── imports_exports.py   # Parses PE/ELF import and export tables
├── sections.py          # Collects section metadata, permissions, and sizes
├── symbols.py           # Extracts and ranks function-sized symbols
├── report.py            # Builds Markdown + CSV artifacts
└── utils.py             # Shared helpers (paths, formatting, validation)
```

## Troubleshooting

- **"Error importing LLDB"** — ensure LLVM/LLDB is installed and `LLVM_PATH` points to it, or pass `--llvm-path` via CLI.
- **Missing import/export data** — install `pefile` and `pyelftools` (already listed in `requirements.txt`).
- **Permission denied** — verify the binary is readable and you have rights to analyze it.

