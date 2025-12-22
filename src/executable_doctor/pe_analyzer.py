"""PE (Windows executable) analyzer implementation."""
import re
from typing import Any, List, Optional, Tuple

from .analyzer import ExecutableAnalyzer, Section
from .utils import run_command


class PEAnalyzer(ExecutableAnalyzer):
    """Analyzer for PE (Portable Executable) format files."""
    
    def get_file_type(self) -> str:
        """Return the file type."""
        return 'PE'
    
    def parse_sections(self, output: str) -> List[Section]:
        """Parse sections from llvm-readobj output for PE files."""
        sections: List[Section] = []
        # Split by "Section {" to isolate each section
        parts = output.split("Section {")
        
        for part in parts[1:]:
            name_match = re.search(r"Name:\s+(.*)", part)
            # For PE, we care about RawDataSize for disk usage
            size_match = re.search(r"RawDataSize:\s+(0x[0-9a-fA-F]+|\d+)", part)
            offset_match = re.search(r"Offset:\s+(0x[0-9a-fA-F]+|\d+)", part)

            if name_match and size_match:
                name: str = name_match.group(1).strip()
                # Remove string table index suffix if present (e.g. " .text (123)")
                name = re.sub(r"\s+\(\d+\)$", "", name)

                size_str: str = size_match.group(1).strip()
                size: int = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
                
                offset: int = 0
                if offset_match:
                    off_str = offset_match.group(1).strip()
                    offset = int(off_str, 16) if off_str.startswith("0x") else int(off_str)

                sections.append(Section(name=name, size=size, offset=offset))
        
        return sections
    
    def get_debug_info(self) -> Tuple[bool, Optional[str]]:
        """
        Get debug information for PE files.
        
        Returns:
            Tuple of (has_debug_info, pdb_file_path)
        """
        debug_out = run_command(["llvm-readobj", "--coff-debug-directory", self.filepath])
        if debug_out:
            return self._parse_debug_directory(debug_out)
        return False, None
    
    def _parse_debug_directory(self, output: str) -> Tuple[bool, Optional[str]]:
        """Parse PE debug directory output."""
        has_debug: bool = False
        ext_file: Optional[str] = None
        
        # Check for CodeView which usually points to PDB
        if "Type: CodeView" in output:
            has_debug = True
            pdb_match = re.search(r"PDBFileName:\s+(.*)", output)
            if pdb_match:
                ext_file = pdb_match.group(1).strip()
        
        return has_debug, ext_file
    
    def write_debug_info(self, f: Any) -> None:
        """Write debug information to report file."""
        _, ext_file = self.get_debug_info()
        
        # For PE, we only show the PDB path if it exists
        if ext_file:
            f.write(f"  PDB Path: {ext_file}\n")
        else:
            f.write("  PDB Path: None\n")
    
    def get_sections_output(self) -> Optional[str]:
        """Get sections output from llvm-readobj."""
        return run_command(["llvm-readobj", "--sections", self.filepath])
