"""Abstract base class for executable analyzers."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
import re


class Section:
    """Represents a section in an executable file."""
    
    def __init__(self, name: str, size: int, offset: int):
        self.name = name
        self.size = size
        self.offset = offset
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert section to dictionary."""
        return {
            "name": self.name,
            "size": self.size,
            "offset": self.offset
        }


class ExecutableAnalyzer(ABC):
    """Abstract base class for analyzing executable files."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self._sections: Optional[List[Section]] = None
    
    @abstractmethod
    def get_file_type(self) -> str:
        """Return the file type (PE or ELF)."""
        pass
    
    @abstractmethod
    def parse_sections(self, output: str) -> List[Section]:
        """Parse sections from llvm-readobj output."""
        pass
    
    @abstractmethod
    def get_debug_info(self) -> Tuple[bool, Optional[str]]:
        """
        Get debug information.
        
        Returns:
            Tuple of (has_debug_info, external_debug_file_path)
        """
        pass
    
    @abstractmethod
    def write_debug_info(self, f: Any) -> None:
        """Write debug information to report file."""
        pass
    
    @abstractmethod
    def get_sections_output(self) -> Optional[str]:
        """Get sections output from llvm-readobj."""
        pass
    
    def get_sections(self) -> List[Section]:
        """Get all sections from the executable."""
        if self._sections is None:
            output = self.get_sections_output()
            self._sections = self.parse_sections(output) if output else []
        return self._sections
    
    def write_sections_table(self, f: Any, sections: List[Section]) -> None:
        """Write sections table to report file."""
        if not sections:
            f.write("  No sections found.\n")
            return

        rows: List[Tuple[str, str, str, str]] = []
        has_notes: bool = False
        
        for sec in sections:
            name = sec.name
            offset_str = f"0x{sec.offset:X}"
            size_str = f"{sec.size / (1024*1024):.4f} MB"
            note = self._get_section_note(sec)
            
            if note:
                has_notes = True
            
            rows.append((name, offset_str, size_str, note))

        width_name = max([len(r[0]) for r in rows] + [len("Section Name")])
        width_offset = max([len(r[1]) for r in rows] + [len("Offset")])
        width_size = max([len(r[2]) for r in rows] + [len("Size")])
        width_note = max([len(r[3]) for r in rows] + [len("Note")]) if has_notes else 0

        def format_row(n: str, o: str, s: str, no: str) -> str:
            line = f"| {n:<{width_name}} | {o:>{width_offset}} | {s:>{width_size}} |"
            if has_notes:
                line += f" {no:<{width_note}} |"
            return line

        f.write(format_row("Section Name", "Offset", "Size", "Note") + "\n")
        
        sep_line = f"|-{'-' * width_name}-|-{'-' * width_offset}-|-{'-' * width_size}-|"
        if has_notes:
            sep_line += f"-{'-' * width_note}-|"
        f.write(sep_line + "\n")

        for r in rows:
            f.write(format_row(r[0], r[1], r[2], r[3]) + "\n")
    
    def _get_section_note(self, section: Section) -> str:
        """
        Get note for a section. Override in subclass if needed.
        
        Args:
            section: Section object
            
        Returns:
            Note string for the section
        """
        return ""
    
    def analyze(self, report_file: str) -> None:
        """Analyze the executable and write report."""
        sections = self.get_sections()
        
        with open(report_file, 'a') as f:
            f.write("Debug Information:\n")
            self.write_debug_info(f)
            f.write("\n")
            
            f.write("Sections:\n")
            self.write_sections_table(f, sections)
