"""
Utility functions for Binary Analyzer
"""

import os
import sys
import platform
from typing import Optional

from .config import get_default_lldb_python_path, BYTES_IN_MB
from .exceptions import LLDBError


def setup_lldb_path(llvm_path: Optional[str] = None) -> None:
    """Setup LLDB Python bindings path"""
    if llvm_path:
        lldb_python_path = get_default_lldb_python_path(llvm_path)
        if os.path.exists(lldb_python_path) and lldb_python_path not in sys.path:
            sys.path.insert(0, lldb_python_path)


def import_lldb():
    """Import LLDB with proper error handling"""
    try:
        import lldb
        return lldb
    except ImportError as e:
        raise LLDBError(
            f"Error importing LLDB: {e}\n"
            "Make sure LLDB Python bindings are installed and LLVM_PATH is set correctly."
        )


def format_size(size_bytes: int) -> str:
    """Format size in bytes with MB in parentheses"""
    mb_size = size_bytes / BYTES_IN_MB
    return f"{size_bytes} ({mb_size:.2f} MB)"


def validate_binary_path(binary_path: str) -> bool:
    """Validate that binary file exists and is readable"""
    return os.path.exists(binary_path) and os.path.isfile(binary_path)


def ensure_output_directory(output_dir: str) -> None:
    """Ensure output directory exists, create if necessary"""
    os.makedirs(output_dir, exist_ok=True)


def generate_output_filename(binary_path: str, output_dir: str, suffix: str = "_analysis_report") -> str:
    """Generate output filename based on binary name"""
    binary_name = os.path.splitext(os.path.basename(binary_path))[0]
    return os.path.join(output_dir, f"{binary_name}{suffix}.md")


def get_default_output_dir(binary_path: str) -> str:
    """Get default output directory (binary_dir/output/)"""
    binary_dir = os.path.dirname(os.path.abspath(binary_path))
    return os.path.join(binary_dir, 'output')


def print_progress(current: int, total: int, prefix: str = "Progress") -> None:
    """Print progress indicator"""
    if total > 10 and current % max(1, total // 10) == 0:
        progress = (current / total) * 100
        print(f"{prefix}: {progress:.0f}% ({current}/{total})", end='\r')
        
        
def sanitize_filename(filename: str) -> str:
    """Sanitize filename to remove invalid characters"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename