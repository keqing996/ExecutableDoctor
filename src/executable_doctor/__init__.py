"""
ExecutableDoctor - A package for analyzing PE and ELF executable files.

This package provides tools to analyze binary executable files, including:
- Section information (name, size, offset)
- Debug information (PDB files for PE, DWARF for ELF)
- File type detection
"""

from .analyzer import ExecutableAnalyzer, Section
from .pe_analyzer import PEAnalyzer
from .elf_analyzer import ELFAnalyzer
from .utils import check_llvm_tools, get_file_type, run_command

__version__ = "1.0.0"

__all__ = [
    "ExecutableAnalyzer",
    "Section",
    "PEAnalyzer",
    "ELFAnalyzer",
    "check_llvm_tools",
    "get_file_type",
    "run_command",
]


def create_analyzer(filepath: str) -> ExecutableAnalyzer:
    """
    Factory function to create the appropriate analyzer based on file type.
    
    Args:
        filepath: Path to the executable file
        
    Returns:
        An instance of PEAnalyzer or ELFAnalyzer
        
    Raises:
        ValueError: If the file type is not supported
    """
    file_type = get_file_type(filepath)
    
    if file_type == 'PE':
        return PEAnalyzer(filepath)
    elif file_type == 'ELF':
        return ELFAnalyzer(filepath)
    else:
        raise ValueError(f"Unsupported file type: {file_type}. Only PE and ELF are supported.")
