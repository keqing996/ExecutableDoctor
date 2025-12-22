"""ELF (Linux executable) analyzer implementation."""
import re
import struct
from typing import Any, List, Optional, Tuple

from .analyzer import ExecutableAnalyzer, Section
from .utils import run_command


class ELFAnalyzer(ExecutableAnalyzer):
    """Analyzer for ELF (Executable and Linkable Format) files."""
    
    def get_file_type(self) -> str:
        """Return the file type."""
        return 'ELF'
    
    def parse_sections(self, output: str) -> List[Section]:
        """Parse sections from llvm-readobj output for ELF files."""
        sections: List[Section] = []
        # Split by "Section {" to isolate each section
        parts = output.split("Section {")
        
        for part in parts[1:]:
            name_match = re.search(r"Name:\s+(.*)", part)
            # For ELF, Size is the size
            size_match = re.search(r"Size:\s+(0x[0-9a-fA-F]+|\d+)", part)
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
        Get debug information for ELF files.
        
        Returns:
            Tuple of (has_internal_debug_info, external_debug_file_path)
        """
        sections = self.get_sections()
        
        # Check for internal debug info (presence of any .debug_ section)
        has_debug = any(s.name.startswith('.debug_') for s in sections)
        
        # Check for external debug info
        ext_file = self._get_debug_link()
        
        return has_debug, ext_file
    
    def _get_debug_link(self) -> Optional[str]:
        """Get external debug file path from .gnu_debuglink section."""
        output = run_command(["llvm-readobj", "--string-dump=.gnu_debuglink", self.filepath])
        if output:
            # Output format example:
            # String dump of section '.gnu_debuglink':
            # [     0]  foo.debug
            # We look for the line after the header or lines starting with [
            lines = output.splitlines()
            for line in lines:
                match = re.search(r"\[\s*[0-9a-fA-F]+\]\s+(.*)", line)
                if match:
                    return match.group(1).strip()
        return None
    
    def _check_dwarf_format(self, offset: int) -> str:
        """Check DWARF format (32-bit or 64-bit) at given offset."""
        try:
            with open(self.filepath, 'rb') as f:
                f.seek(offset)
                # Read unit header length (initial length field)
                # 4 bytes. If 0xffffffff, it's 64-bit DWARF.
                data = f.read(4)
                if len(data) < 4:
                    return "Unknown"
                val = struct.unpack('<I', data)[0]
                if val == 0xffffffff:
                    return "DWARF64"
                else:
                    return "DWARF32"
        except:
            return "Error"
    
    def _get_section_note(self, section: Section) -> str:
        """Get note for a section (DWARF format for debug sections)."""
        if section.name.startswith(".debug_") and section.size > 0:
            dwarf_header_sections = [
                '.debug_info', '.debug_types', '.debug_line', '.debug_aranges',
                '.debug_frame', '.debug_pubnames', '.debug_pubtypes',
                '.debug_loclists', '.debug_rnglists', '.debug_macro'
            ]
            if section.name in dwarf_header_sections:
                return self._check_dwarf_format(section.offset)
        return ""
    
    def write_debug_info(self, f: Any) -> None:
        """Write debug information to report file."""
        has_debug, ext_file = self.get_debug_info()
        
        f.write(f"  Contains Debug Info: {'Yes' if has_debug else 'No'}\n")
        f.write(f"  External Debug File: {ext_file if ext_file else 'None'}\n")
    
    def get_sections_output(self) -> Optional[str]:
        """Get sections output from llvm-readobj."""
        return run_command(["llvm-readobj", "--sections", self.filepath])
