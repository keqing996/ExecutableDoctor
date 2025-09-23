"""
Configuration and constants for Binary Analyzer
"""

import os
import platform
from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisConfig:
    """Configuration for binary analysis"""
    
    # LLVM/LLDB settings
    llvm_path: Optional[str] = None
    
    # Analysis settings
    top_functions: int = 200
    skip_source_info: bool = False
    
    # Output settings
    output_dir: Optional[str] = None
    
    # Performance settings
    batch_size: int = 100
    progress_interval: int = 10
    
    def __post_init__(self):
        """Post-initialization processing"""
        if self.llvm_path is None:
            self.llvm_path = os.environ.get('LLVM_PATH')


# LLDB Section Type Constants
SECTION_TYPE_MAP = {
    # These will be set dynamically when LLDB is loaded
    # since we can't import lldb at module level
}

# Default section type names
DEFAULT_SECTION_TYPES = {
    'Code': 'Code',
    'Data': 'Data', 
    'C-String Data': 'C-String Data',
    'C-String Pointers': 'C-String Pointers',
    'Symbol Address': 'Symbol Address',
    'ObjC Message Refs': 'ObjC Message Refs',
    'ObjC CFStrings': 'ObjC CFStrings',
    'Zero Fill': 'Zero Fill',
    'Data Pointers': 'Data Pointers',
}

# Platform-specific LLDB paths
def get_default_lldb_python_path(llvm_path: str) -> str:
    """Get default LLDB Python bindings path based on platform"""
    if platform.system() == "Windows":
        return os.path.join(llvm_path, "lib", "site-packages")
    else:
        return os.path.join(llvm_path, "lib", "python3", "site-packages")


# File size formatting constants
BYTES_IN_MB = 1024 * 1024
BYTES_IN_KB = 1024

# Report templates
REPORT_HEADER_TEMPLATE = """# Binary Function Analysis Report

## Binary Information
- **File**: {binary_name}
- **Full Path**: {binary_path}
- **Analysis Date**: {analysis_date}
- **Total Functions Found**: {total_functions}
- **Report Shows**: Top {report_functions} functions (sorted by size)
"""

SECTIONS_TABLE_HEADER = """
## Binary Sections Information

| Section Name | Load Address | File Address | Size (bytes) | Size (hex) | Permissions | Type |
|--------------|-------------|-------------|--------------|------------|-------------|------|
"""

FUNCTIONS_TABLE_HEADER = """
## Function Analysis Summary

| Rank | Function Name | Start Address | Size (bytes) | Size (hex) | Type | Source File | Line |
|------|---------------|---------------|--------------|------------|------|-------------|------|
"""