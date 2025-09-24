"""
Binary section analysis functionality
"""

from typing import List, Dict, Optional, Any

from .exceptions import SectionAnalysisError
from .config import DEFAULT_SECTION_TYPES
from .utils import format_hex_address, is_valid_address


class SectionAnalyzer:
    """Handles binary section analysis"""
    
    def __init__(self, lldb_module: Any) -> None:
        """Initialize section analyzer
        
        Args:
            lldb_module: LLDB module (imported dynamically)
        """
        self.lldb = lldb_module
        self.section_type_map: Dict[int, str] = {}
        self._init_section_type_map()
    
    def _init_section_type_map(self) -> None:
        """Initialize section type mapping with LLDB constants"""
        try:
            self.section_type_map = {
                self.lldb.eSectionTypeCode: 'Code',
                self.lldb.eSectionTypeData: 'Data',
                self.lldb.eSectionTypeDataCString: 'C-String Data',
                self.lldb.eSectionTypeDataCStringPointers: 'C-String Pointers',
                self.lldb.eSectionTypeDataSymbolAddress: 'Symbol Address',
                self.lldb.eSectionTypeDataObjCMessageRefs: 'ObjC Message Refs',
                self.lldb.eSectionTypeDataObjCCFStrings: 'ObjC CFStrings',
                self.lldb.eSectionTypeZeroFill: 'Zero Fill',
                self.lldb.eSectionTypeDataPointers: 'Data Pointers',
            }
        except AttributeError:
            # Fallback to default types if LLDB constants are not available
            self.section_type_map = {}
    
    def get_sections_info(self, target: Any) -> List[Dict[str, Any]]:
        """Get information about sections in the binary file
        
        Args:
            target: LLDB target object
            
        Returns:
            List of section dictionaries
            
        Raises:
            SectionAnalysisError: If section analysis fails
        """
        if not target or not target.IsValid():
            raise SectionAnalysisError("Invalid LLDB target provided")
        
        sections: List[Dict[str, Any]] = []
        
        try:
            # Iterate through all modules to get section information
            for module in target.module_iter():
                if not module.IsValid():
                    continue
                
                num_sections = module.GetNumSections()
                module_name = module.GetFileSpec().GetFilename() if module.GetFileSpec() else "Unknown"
                print(f"Found {num_sections} sections in module: {module_name}")
                
                for section_idx in range(num_sections):
                    section = module.GetSectionAtIndex(section_idx)
                    if section and section.IsValid():
                        section_info = self._extract_section_info(section, target)
                        if section_info:
                            sections.append(section_info)
        
        except Exception as e:
            raise SectionAnalysisError(f"Error analyzing sections: {e}")
        
        # Sort sections by size (largest first)
        sections.sort(key=lambda x: x.get('size', 0), reverse=True)
        return sections
    
    def _extract_section_info(self, section: Any, target: Any) -> Optional[Dict[str, Any]]:
        """Extract information from a section
        
        Args:
            section: LLDB section object
            target: LLDB target object
            
        Returns:
            Section information dictionary or None if extraction fails
        """
        try:
            section_name = section.GetName()
            if not section_name:  # Skip unnamed sections
                return None
            
            load_address = section.GetLoadAddress(target)
            file_address = section.GetFileAddress()
            size = section.GetByteSize()
            
            # Validate addresses
            if not is_valid_address(load_address) and not is_valid_address(file_address):
                return None
            
            section_info = {
                'name': str(section_name),
                'address': format_hex_address(load_address) if is_valid_address(load_address) else "N/A",
                'file_address': format_hex_address(file_address) if is_valid_address(file_address) else "N/A",
                'size': int(size) if size >= 0 else 0,
                'permissions': self._get_section_permissions(section),
                'type': self._get_section_type(section)
            }
            return section_info
        except Exception as e:
            print(f"Warning: Error extracting section info: {e}")
            return None
    
    def _get_section_permissions(self, section: Any) -> str:
        """Get section permissions as a string
        
        Args:
            section: LLDB section object
            
        Returns:
            Permission string (e.g., 'RWX', 'RX', etc.)
        """
        permissions = []
        
        try:
            section_permissions = section.GetPermissions()
            if section_permissions & self.lldb.ePermissionsReadable:
                permissions.append('R')
            if section_permissions & self.lldb.ePermissionsWritable:
                permissions.append('W')
            if section_permissions & self.lldb.ePermissionsExecutable:
                permissions.append('X')
        except (AttributeError, TypeError):
            # Fallback if permission detection fails
            pass
        
        return ''.join(permissions) if permissions else 'None'
    
    def _get_section_type(self, section: Any) -> str:
        """Get section type description
        
        Args:
            section: LLDB section object
            
        Returns:
            Section type description string
        """
        try:
            section_type = section.GetSectionType()
            return self.section_type_map.get(section_type, f'Unknown ({section_type})')
        except (AttributeError, TypeError):
            return 'Unknown'
    
    def get_sections_summary(self, sections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics for sections
        
        Args:
            sections: List of section dictionaries
            
        Returns:
            Dictionary with summary statistics
        """
        if not sections:
            return {
                'total_sections': 0,
                'total_size': 0,
                'largest_section': None,
                'smallest_section': None,
                'code_sections': [],
                'data_sections': [],
            }
        
        try:
            total_size = sum(s.get('size', 0) for s in sections)
            code_sections = [s for s in sections if 'Code' in s.get('type', '')]
            data_sections = [s for s in sections if 'Data' in s.get('type', '')]
            
            return {
                'total_sections': len(sections),
                'total_size': total_size,
                'largest_section': sections[0] if sections else None,
                'smallest_section': sections[-1] if sections else None,
                'code_sections': code_sections,
                'data_sections': data_sections,
            }
        except Exception as e:
            raise SectionAnalysisError(f"Error generating sections summary: {e}")