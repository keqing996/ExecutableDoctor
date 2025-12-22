# ExecutableDoctor

A toolkit for analyzing PE and ELF executable files.

## Project Structure

```
ExecutableDoctor/
├── builder.py                          # PyInstaller build script
├── src/
│   ├── section_doctor.py              # CLI entry point (wrapper)
│   └── executable_doctor/             # Core package
│       ├── __init__.py                # Package export interface
│       ├── analyzer.py                # Abstract base class ExecutableAnalyzer
│       ├── pe_analyzer.py             # PE format analyzer
│       ├── elf_analyzer.py            # ELF format analyzer
│       └── utils.py                   # Shared utility functions
├── artifact/                          # Output directory for packaged executables
└── build/                             # PyInstaller build temporary files
```

## Architecture Design

### Polymorphic Design

The project uses object-oriented polymorphic design:

1. **Abstract Base Class** (`ExecutableAnalyzer`):
   - Defines the common interface for all analyzers
   - Contains shared logic (e.g., section table formatting)
   - Enforces platform-specific method implementation in subclasses

2. **Concrete Implementation Classes**:
   - `PEAnalyzer`: Handles Windows PE format files
   - `ELFAnalyzer`: Handles Linux ELF format files

3. **Factory Function** (`create_analyzer`):
   - Automatically creates the correct analyzer instance based on file type
   - Simplifies client code

### Class Diagram

```
ExecutableAnalyzer (ABC)
├── get_file_type() [abstract]
├── parse_sections() [abstract]
├── get_debug_info() [abstract]
├── write_debug_info() [abstract]
├── get_sections_output() [abstract]
├── get_sections() [concrete]
├── write_sections_table() [concrete]
└── analyze() [concrete]
    ↑
    ├── PEAnalyzer
    │   ├── Implements PE-specific parsing logic
    │   └── Handles PDB debug information
    │
    └── ELFAnalyzer
        ├── Implements ELF-specific parsing logic
        ├── Handles DWARF debug information
        └── Detects DWARF32/DWARF64 format
```

## Type Hints

All code includes complete type annotations:
- Function parameter and return value types
- Class attribute types
- Advanced types from the `typing` module (`Optional`, `List`, `Dict`, `Tuple`, `Any`)

## Usage

### As a Command-Line Tool

```bash
# Run Python script directly
python src/section_doctor.py <target_executable>

# Or use the packaged binary
artifact/section_doctor.exe <target_executable>
```

### As a Python Package

```python
from executable_doctor import create_analyzer, get_file_type

# Automatically detect file type and create analyzer
analyzer = create_analyzer("path/to/executable")
analyzer.analyze("output_report.txt")

# Or manually create a specific type of analyzer
from executable_doctor import PEAnalyzer, ELFAnalyzer

pe_analyzer = PEAnalyzer("myapp.exe")
elf_analyzer = ELFAnalyzer("myapp.elf")
```

## PyInstaller Packaging

### Build All Scripts

```bash
python builder.py
```

### Key Configuration

Key configuration in builder.py:
- `--onefile`: Generate a single executable file
- `--paths src`: Add src directory to Python path to ensure the `executable_doctor` package is found
- Output directory: `artifact/`
- Build directory: `build/`

### Packaging Notes

Since `section_doctor.py` now depends on the `executable_doctor` package, PyInstaller needs to know the package location:

1. Use the `--paths` parameter to point to the `src` directory
2. PyInstaller will automatically analyze imports and package the entire `executable_doctor` package
3. The generated executable is fully standalone and doesn't require a Python environment

## Dependencies

- Python 3.7+
- LLVM toolchain (llvm-readobj must be in PATH)
- PyInstaller (for packaging)

## Features

### Supported File Formats

- **PE (Portable Executable)**: Windows executable files (.exe, .dll)
- **ELF (Executable and Linkable Format)**: Linux executable files

### Analysis Content

1. **Section Information**:
   - Section name
   - File offset
   - Section size (MB)
   - Special notes (e.g., DWARF format)

2. **Debug Information**:
   - **PE**: PDB file path
   - **ELF**: 
     - Internal debug information (.debug_* sections)
     - External debug file links (.gnu_debuglink)
     - DWARF format detection (DWARF32/DWARF64)

## Extensibility

To add support for new file formats:

1. Create a new analyzer class under `executable_doctor/` (e.g., `mach_o_analyzer.py`)
2. Inherit from `ExecutableAnalyzer` and implement all abstract methods
3. Add file type detection in `get_file_type()` in `utils.py`
4. Add factory logic in `create_analyzer()` in `__init__.py`
5. Export the new class in `__all__` in `__init__.py`

## License

[Add license information as needed]
