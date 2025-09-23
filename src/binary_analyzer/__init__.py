"""
Binary Analyzer Package

A comprehensive binary file analyzer using LLDB to extract function information 
and section details from PE and ELF files.
"""

__version__ = "1.0.0"
__author__ = "Binary Analyzer Team"

from .analyzer import BinaryAnalyzer
from .config import AnalysisConfig
from .exceptions import (
    BinaryAnalyzerError,
    LLDBError,
    BinaryNotFoundError,
    TargetCreationError,
)

__all__ = [
    "BinaryAnalyzer",
    "AnalysisConfig", 
    "BinaryAnalyzerError",
    "LLDBError",
    "BinaryNotFoundError",
    "TargetCreationError",
]