"""
Configuration and constants for Binary Analyzer
"""

import os
import platform
from dataclasses import dataclass
from typing import Optional, Dict, Any

from .exceptions import ConfigurationError


@dataclass
class AnalysisConfig:
    """Configuration for binary analysis
    
    Attributes:
        llvm_path: Path to LLVM installation
        top_functions: Number of top functions to include in report
        skip_source_info: Whether to skip source file and line number lookup
        output_dir: Output directory for reports
    """
    
    # LLVM/LLDB settings
    llvm_path: Optional[str] = None
    
    # Analysis settings
    top_functions: int = 200
    skip_source_info: bool = False
    
    # Output settings
    output_dir: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Post-initialization processing and validation"""
        # Set default LLVM path from environment if not provided
        if self.llvm_path is None:
            self.llvm_path = os.environ.get('LLVM_PATH')
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate configuration parameters
        
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if self.top_functions <= 0:
            raise ConfigurationError("top_functions must be positive")
        
        # Validate LLVM path if provided
        if self.llvm_path and not os.path.exists(self.llvm_path):
            raise ConfigurationError(f"LLVM path does not exist: {self.llvm_path}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            'llvm_path': self.llvm_path,
            'top_functions': self.top_functions,
            'skip_source_info': self.skip_source_info,
            'output_dir': self.output_dir
        }


# LLDB Section Type Constants
SECTION_TYPE_MAP: Dict[str, str] = {
    # These will be set dynamically when LLDB is loaded
    # since we can't import lldb at module level
}

# Default section type names
DEFAULT_SECTION_TYPES: Dict[str, str] = {
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
BYTES_IN_MB: int = 1024 * 1024
BYTES_IN_KB: int = 1024

# Report templates
REPORT_HEADER_TEMPLATE: str = """# Binary Function Analysis Report

## Binary Information
- **File**: {binary_name}
- **Full Path**: {binary_path}
- **Analysis Date**: {analysis_date}
- **Total Functions Found**: {total_functions}
- **Report Shows**: Top {report_functions} functions (sorted by size)
"""

SECTIONS_TABLE_HEADER: str = """
## Binary Sections Information

| Section Name | Load Address | File Address | Size (bytes) | Size (hex) | Permissions | Type |
|--------------|-------------|-------------|--------------|------------|-------------|------|
"""

FUNCTIONS_TABLE_HEADER: str = """
## Function Analysis Summary

| Rank | Function Name | Start Address | Size (bytes) | Size (hex) | Type | Source File | Line |
|------|---------------|---------------|--------------|------------|------|-------------|------|
"""