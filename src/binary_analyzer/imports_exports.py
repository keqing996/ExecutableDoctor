"""
Import and Export table analysis functionality
"""

import csv
import os
from typing import List, Dict, Optional, Union

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.dynamic import DynamicSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False

from .exceptions import SectionAnalysisError
from .utils import sanitize_filename


class ImportExportAnalyzer:
    """Handles import and export table analysis for PE and ELF files"""
    
    def __init__(self, lldb_module=None):
        """Initialize import/export analyzer
        
        Args:
            lldb_module: LLDB module (imported dynamically) - now optional
        """
        self.lldb = lldb_module
    
    def extract_imports(self, target, binary_path: str) -> List[Dict]:
        """Extract import table information from binary file
        
        Args:
            target: LLDB target object (unused but kept for compatibility)
            binary_path: Path to the binary file
            
        Returns:
            List of import dictionaries with keys: dll_name, function_name, address, ordinal
        """
        if not os.path.exists(binary_path):
            raise SectionAnalysisError(f"Binary file not found: {binary_path}")
        
        # Detect file type and use appropriate parser
        if self._is_pe_file(binary_path):
            return self._extract_pe_imports(binary_path)
        elif self._is_elf_file(binary_path):
            return self._extract_elf_imports(binary_path)
        else:
            raise SectionAnalysisError(f"Unsupported file format: {binary_path}")
    
    def extract_exports(self, target, binary_path: str) -> List[Dict]:
        """Extract export table information from binary file
        
        Args:
            target: LLDB target object (unused but kept for compatibility)  
            binary_path: Path to the binary file
            
        Returns:
            List of export dictionaries with keys: function_name, address, ordinal, rva
        """
        if not os.path.exists(binary_path):
            raise SectionAnalysisError(f"Binary file not found: {binary_path}")
        
        # Detect file type and use appropriate parser
        if self._is_pe_file(binary_path):
            return self._extract_pe_exports(binary_path)
        elif self._is_elf_file(binary_path):
            return self._extract_elf_exports(binary_path)
        else:
            raise SectionAnalysisError(f"Unsupported file format: {binary_path}")
    
    def _is_pe_file(self, binary_path: str) -> bool:
        """Check if file is a PE file"""
        try:
            with open(binary_path, 'rb') as f:
                # Check for MZ header
                mz_header = f.read(2)
                if mz_header != b'MZ':
                    return False
                
                # Check for PE signature
                f.seek(60)  # Offset to PE header pointer
                pe_offset = int.from_bytes(f.read(4), byteorder='little')
                f.seek(pe_offset)
                pe_signature = f.read(4)
                return pe_signature == b'PE\x00\x00'
        except:
            return False
    
    def _is_elf_file(self, binary_path: str) -> bool:
        """Check if file is an ELF file"""
        try:
            with open(binary_path, 'rb') as f:
                # Check for ELF magic
                elf_header = f.read(4)
                return elf_header == b'\x7fELF'
        except:
            return False
    
    def _extract_pe_imports(self, binary_path: str) -> List[Dict]:
        """Extract imports from PE file using pefile"""
        if not PEFILE_AVAILABLE:
            raise SectionAnalysisError("pefile library not available for PE import analysis")
        
        imports = []
        
        try:
            pe = pefile.PE(binary_path)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8') if entry.dll else "Unknown"
                    
                    for func in entry.imports:
                        import_info = {
                            'dll_name': dll_name,
                            'function_name': func.name.decode('utf-8') if func.name else f"Ordinal_{func.ordinal}",
                            'address': f"0x{func.address:x}" if func.address else "0x0",
                            'ordinal': func.ordinal if func.ordinal else 0,
                            'original_symbol': func.name.decode('utf-8') if func.name else f"Ordinal_{func.ordinal}"
                        }
                        imports.append(import_info)
                        
        except Exception as e:
            raise SectionAnalysisError(f"Error parsing PE imports: {e}")
        
        return imports
    
    def _extract_pe_exports(self, binary_path: str) -> List[Dict]:
        """Extract exports from PE file using pefile"""
        if not PEFILE_AVAILABLE:
            raise SectionAnalysisError("pefile library not available for PE export analysis")
        
        exports = []
        
        try:
            pe = pefile.PE(binary_path)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_info = {
                        'function_name': exp.name.decode('utf-8') if exp.name else f"Ordinal_{exp.ordinal}",
                        'address': f"0x{exp.address:x}" if exp.address else "0x0",
                        'ordinal': exp.ordinal if exp.ordinal else 0,
                        'rva': f"0x{exp.address:x}" if exp.address else "0x0",
                        'size': 0  # PE exports don't typically have size info
                    }
                    exports.append(export_info)
                    
        except Exception as e:
            raise SectionAnalysisError(f"Error parsing PE exports: {e}")
        
        return exports
    
    def _extract_elf_imports(self, binary_path: str) -> List[Dict]:
        """Extract imports from ELF file using pyelftools"""
        if not ELFTOOLS_AVAILABLE:
            raise SectionAnalysisError("pyelftools library not available for ELF import analysis")
        
        imports = []
        
        try:
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Look for dynamic section to find needed libraries
                dynamic_section = None
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        dynamic_section = section
                        break
                
                # Extract needed libraries
                needed_libs = []
                if dynamic_section:
                    for tag in dynamic_section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            needed_libs.append(tag.needed)
                
                # Look for symbol tables to find imported symbols
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol['st_shndx'] == 'SHN_UNDEF' and symbol.name:
                                # This is an undefined symbol (import)
                                import_info = {
                                    'dll_name': "Unknown",  # ELF doesn't specify which lib a symbol comes from in symbol table
                                    'function_name': symbol.name,
                                    'address': f"0x{symbol['st_value']:x}",
                                    'ordinal': 0,
                                    'original_symbol': symbol.name
                                }
                                imports.append(import_info)
                
                # Add needed libraries as imports without specific functions
                for lib in needed_libs:
                    import_info = {
                        'dll_name': lib,
                        'function_name': "(library dependency)",
                        'address': "0x0",
                        'ordinal': 0,
                        'original_symbol': lib
                    }
                    imports.append(import_info)
                    
        except Exception as e:
            raise SectionAnalysisError(f"Error parsing ELF imports: {e}")
        
        return imports
    
    def _extract_elf_exports(self, binary_path: str) -> List[Dict]:
        """Extract exports from ELF file using pyelftools"""
        if not ELFTOOLS_AVAILABLE:
            raise SectionAnalysisError("pyelftools library not available for ELF export analysis")
        
        exports = []
        
        try:
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Look for symbol tables to find exported symbols
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            # Export criteria: defined symbol, not local binding, has a name
                            if (symbol['st_shndx'] != 'SHN_UNDEF' and 
                                symbol['st_info']['bind'] != 'STB_LOCAL' and 
                                symbol.name and
                                symbol['st_value'] != 0):
                                
                                export_info = {
                                    'function_name': symbol.name,
                                    'address': f"0x{symbol['st_value']:x}",
                                    'ordinal': 0,  # ELF doesn't use ordinals
                                    'rva': f"0x{symbol['st_value']:x}",
                                    'size': symbol['st_size']
                                }
                                exports.append(export_info)
                                
        except Exception as e:
            raise SectionAnalysisError(f"Error parsing ELF exports: {e}")
        
        return exports
    
    def save_imports_csv(self, imports: List[Dict], output_dir: str, binary_name: str) -> str:
        """Save imports to CSV file
        
        Args:
            imports: List of import dictionaries
            output_dir: Output directory path
            binary_name: Name of the analyzed binary
            
        Returns:
            Path to the generated CSV file
        """
        safe_binary_name = sanitize_filename(os.path.splitext(binary_name)[0])
        csv_path = os.path.join(output_dir, f"{safe_binary_name}_imports.csv")
        
        os.makedirs(output_dir, exist_ok=True)
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['dll_name', 'function_name', 'address', 'ordinal', 'original_symbol']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for import_item in imports:
                writer.writerow(import_item)
        
        return csv_path
    
    def save_exports_csv(self, exports: List[Dict], output_dir: str, binary_name: str) -> str:
        """Save exports to CSV file
        
        Args:
            exports: List of export dictionaries
            output_dir: Output directory path
            binary_name: Name of the analyzed binary
            
        Returns:
            Path to the generated CSV file
        """
        safe_binary_name = sanitize_filename(os.path.splitext(binary_name)[0])
        csv_path = os.path.join(output_dir, f"{safe_binary_name}_exports.csv")
        
        os.makedirs(output_dir, exist_ok=True)
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['function_name', 'address', 'ordinal', 'rva', 'size']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for export_item in exports:
                writer.writerow(export_item)
        
        return csv_path
    
    def get_imports_summary(self, imports: List[Dict]) -> Dict:
        """Get summary statistics for imports
        
        Args:
            imports: List of import dictionaries
            
        Returns:
            Dictionary with summary statistics
        """
        if not imports:
            return {
                'total_imports': 0,
                'unique_dlls': 0,
                'dll_counts': {},
                'top_dlls': []
            }
        
        # Count imports per DLL
        dll_counts = {}
        for imp in imports:
            dll = imp.get('dll_name', 'Unknown')
            dll_counts[dll] = dll_counts.get(dll, 0) + 1
        
        # Sort DLLs by import count
        top_dlls = sorted(dll_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total_imports': len(imports),
            'unique_dlls': len(dll_counts),
            'dll_counts': dll_counts,
            'top_dlls': top_dlls[:10]  # Top 10 DLLs
        }
    
    def get_exports_summary(self, exports: List[Dict]) -> Dict:
        """Get summary statistics for exports
        
        Args:
            exports: List of export dictionaries
            
        Returns:
            Dictionary with summary statistics
        """
        if not exports:
            return {
                'total_exports': 0,
                'total_size': 0,
                'average_size': 0,
                'largest_export': None,
                'smallest_export': None
            }
        
        # Calculate sizes (only for exports that have size info)
        exports_with_size = [exp for exp in exports if exp.get('size', 0) > 0]
        total_size = sum(exp.get('size', 0) for exp in exports_with_size)
        avg_size = total_size / len(exports_with_size) if exports_with_size else 0
        
        # Find largest and smallest exports by size
        largest_export = max(exports_with_size, key=lambda x: x.get('size', 0)) if exports_with_size else None
        smallest_export = min(exports_with_size, key=lambda x: x.get('size', 0)) if exports_with_size else None
        
        return {
            'total_exports': len(exports),
            'total_size': total_size,
            'average_size': int(avg_size),
            'largest_export': largest_export,
            'smallest_export': smallest_export
        }