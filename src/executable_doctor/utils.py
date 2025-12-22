"""Utility functions shared across executable analyzers."""
import shutil
import subprocess
from typing import List, Optional


def check_llvm_tools() -> bool:
    """Check if LLVM tools are available in the environment."""
    return shutil.which("llvm-readobj") is not None


def run_command(args: List[str]) -> Optional[str]:
    """Run a command and return its stdout."""
    try:
        # Use utf-8 and replace errors to avoid crashing on binary data in output if any
        result = subprocess.run(
            args, 
            capture_output=True, 
            text=True, 
            check=True, 
            encoding='utf-8', 
            errors='replace'
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def get_file_type(filepath: str) -> str:
    """Identify if the file is PE or ELF."""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            if header.startswith(b'MZ'):
                return 'PE'
            elif header.startswith(b'\x7fELF'):
                return 'ELF'
    except Exception:
        pass
    return 'UNKNOWN'
