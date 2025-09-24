"""
Binary Analyzer Package

A comprehensive binary file analyzer using LLDB to extract function information 
and section details from PE and ELF files.
"""

__version__ = "1.0.0"
__author__ = "Binary Analyzer Team"

from .analyzer import BinaryAnalyzer
from .config import AnalysisConfig
from .imports_exports import ImportExportAnalyzer
from .exceptions import (
    BinaryAnalyzerError,
    LLDBError,
    BinaryNotFoundError,
    TargetCreationError,
    SectionAnalysisError,
    SymbolExtractionError,
    ReportGenerationError,
    ConfigurationError,
    ValidationError,
)

__all__ = [
    "BinaryAnalyzer",
    "AnalysisConfig", 
    "ImportExportAnalyzer",
    "BinaryAnalyzerError",
    "LLDBError",
    "BinaryNotFoundError",
    "TargetCreationError",
    "SectionAnalysisError",
    "SymbolExtractionError", 
    "ReportGenerationError",
    "ConfigurationError",
    "ValidationError",
]


# Version information
def get_version() -> str:
    """Get package version
    
    Returns:
        Version string
    """
    return __version__


# Package metadata
PACKAGE_INFO = {
    "name": "binary-analyzer",
    "version": __version__,
    "author": __author__,
    "description": "A comprehensive binary file analyzer using LLDB",
    "python_requires": ">=3.7",
    "dependencies": [
        "lldb",  # Optional, provided by LLVM installation
        "pefile",  # Optional, for PE file analysis
        "pyelftools",  # Optional, for ELF file analysis
    ]
}