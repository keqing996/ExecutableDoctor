"""
Binary section analysis functionality
"""

from typing import List, Dict

from .exceptions import SectionAnalysisError
from .config import DEFAULT_SECTION_TYPES


class SectionAnalyzer:
    """Handles binary section analysis"""
    
    def __init__(self, lldb_module):
        """Initialize section analyzer
        
        Args:
            lldb_module: LLDB module (imported dynamically)
        """
        self.lldb = lldb_module
        self._init_section_type_map()
    
    def _init_section_type_map(self):
        """Initialize section type mapping with LLDB constants"""
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
    
    def get_sections_info(self, target) -> List[Dict]:
        """Get information about sections in the binary file
        
        Args:
            target: LLDB target object
            
        Returns:
            List of section dictionaries
        """
        sections = []
        
        try:
            # Iterate through all modules to get section information
            for module in target.module_iter():
                num_sections = module.GetNumSections()
                print(f"Found {num_sections} sections in module: {module.GetFileSpec().GetFilename()}")
                
                for section_idx in range(num_sections):
                    section = module.GetSectionAtIndex(section_idx)
                    if section.IsValid():
                        section_name = section.GetName()
                        if section_name:  # Skip unnamed sections
                            section_info = {
                                'name': section_name,
                                'address': f"0x{section.GetLoadAddress(target):x}",
                                'file_address': f"0x{section.GetFileAddress():x}",
                                'size': section.GetByteSize(),
                                'permissions': self._get_section_permissions(section),
                                'type': self._get_section_type(section)
                            }
                            sections.append(section_info)
        
        except Exception as e:
            raise SectionAnalysisError(f"Error analyzing sections: {e}")
        
        # Sort sections by size (largest first)
        sections.sort(key=lambda x: x['size'], reverse=True)
        return sections
    
    def _get_section_permissions(self, section) -> str:
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
        except Exception:
            # Fallback if permission detection fails
            pass
        
        return ''.join(permissions) if permissions else 'None'
    
    def _get_section_type(self, section) -> str:
        """Get section type description
        
        Args:
            section: LLDB section object
            
        Returns:
            Section type description string
        """
        try:
            section_type = section.GetSectionType()
            return self.section_type_map.get(section_type, f'Unknown ({section_type})')
        except Exception:
            return 'Unknown'
    
    def get_sections_summary(self, sections: List[Dict]) -> Dict:
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
        
        total_size = sum(s['size'] for s in sections)
        code_sections = [s for s in sections if 'Code' in s['type']]
        data_sections = [s for s in sections if 'Data' in s['type']]
        
        return {
            'total_sections': len(sections),
            'total_size': total_size,
            'largest_section': sections[0] if sections else None,
            'smallest_section': sections[-1] if sections else None,
            'code_sections': code_sections,
            'data_sections': data_sections,
        }