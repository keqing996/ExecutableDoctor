"""
Symbol and function extraction functionality
"""

from typing import List, Dict, Optional

from .exceptions import SymbolExtractionError
from .utils import format_size


class SymbolExtractor:
    """Handles symbol and function extraction from binary files"""
    
    def __init__(self, lldb_module, min_function_size: int = 4):
        """Initialize symbol extractor
        
        Args:
            lldb_module: LLDB module (imported dynamically)
            min_function_size: Minimum function size in bytes
        """
        self.lldb = lldb_module
        self.min_function_size = min_function_size
    
    def extract_functions_from_target(self, target) -> List[Dict]:
        """Extract function information from LLDB target
        
        Args:
            target: LLDB target object
            
        Returns:
            List of function dictionaries
        """
        functions = []
        
        try:
            # Iterate through all modules
            for module in target.module_iter():
                print(f"Processing module: {module.GetFileSpec().GetFilename()}")
                
                # Get symbols from the module
                for sym_idx in range(module.GetNumSymbols()):
                    symbol = module.GetSymbolAtIndex(sym_idx)
                    if symbol.IsValid():
                        # Check if it's a function symbol
                        if symbol.GetType() == self.lldb.eSymbolTypeCode:
                            func_info = self._extract_symbol_info(symbol, target)
                            if func_info:
                                functions.append(func_info)
        
        except Exception as e:
            raise SymbolExtractionError(f"Error extracting functions: {e}")
        
        return functions
    
    def _extract_symbol_info(self, symbol, target) -> Optional[Dict]:
        """Extract information from an LLDB symbol object
        
        Args:
            symbol: LLDB symbol object
            target: LLDB target object
            
        Returns:
            Dictionary with symbol information or None
        """
        try:
            # Get symbol address
            addr = symbol.GetStartAddress()
            if not addr.IsValid():
                return None
            
            start_offset = addr.GetFileAddress()
            if start_offset == self.lldb.LLDB_INVALID_ADDRESS:
                start_offset = addr.GetLoadAddress(target)
            
            if start_offset == self.lldb.LLDB_INVALID_ADDRESS:
                return None
            
            # Get symbol size
            size = symbol.GetSize()
            if size < self.min_function_size:
                return None
            
            # Get symbol name
            name = symbol.GetName()
            if not name:
                name = f"sym_{start_offset:x}"
            
            return {
                'name': name,
                'address': f"0x{start_offset:x}",
                'size': size,
                'start_offset': start_offset,
                'end_offset': start_offset + size,
                'type': 'symbol'
            }
        except Exception as e:
            print(f"Error extracting symbol info: {e}")
            return None
    
    def sort_and_filter_functions(self, functions: List[Dict], top_n: int = 200) -> List[Dict]:
        """Sort functions by size (largest first) and return top N
        
        Args:
            functions: List of function dictionaries
            top_n: Number of top functions to return
            
        Returns:
            Sorted and filtered list of functions
        """
        # Sort by size in descending order
        sorted_functions = sorted(functions, key=lambda x: x['size'], reverse=True)
        
        # Return top N functions
        return sorted_functions[:top_n]
    
    def get_source_info_batch(self, functions: List[Dict], target, skip_source_info: bool = False) -> None:
        """Get source information for functions in batch
        
        Args:
            functions: List of function dictionaries to update
            target: LLDB target object
            skip_source_info: Whether to skip source info lookup
        """
        if skip_source_info:
            print("Skipping source information lookup for faster processing...")
            for func in functions:
                func['source_file'] = "Unknown"
                func['line_number'] = 0
            return
        
        print(f"Getting source information for {len(functions)} functions...")
        
        # Simple approach: try to get source info for each function individually
        file_spec_cache = {}
        
        for i, func in enumerate(functions):
            try:
                start_offset = func['start_offset']
                
                # Create address and try to resolve it
                addr = target.ResolveFileAddress(start_offset)
                if addr.IsValid():
                    line_entry = addr.GetLineEntry()
                    if line_entry.IsValid():
                        file_spec = line_entry.GetFileSpec()
                        if file_spec.IsValid():
                            # Use caching for file specs
                            file_key = f"{file_spec.GetDirectory()}_{file_spec.GetFilename()}"
                            
                            if file_key not in file_spec_cache:
                                directory = file_spec.GetDirectory() or ""
                                filename = file_spec.GetFilename() or "Unknown"
                                if directory and filename:
                                    source_file = f"{directory}\\{filename}".replace("/", "\\")
                                else:
                                    source_file = filename
                                file_spec_cache[file_key] = source_file
                            
                            func['source_file'] = file_spec_cache[file_key]
                            func['line_number'] = line_entry.GetLine()
                        else:
                            func['source_file'] = "Unknown"
                            func['line_number'] = 0
                    else:
                        func['source_file'] = "Unknown"
                        func['line_number'] = 0
                else:
                    func['source_file'] = "Unknown"
                    func['line_number'] = 0
                    
            except Exception:
                func['source_file'] = "Unknown"
                func['line_number'] = 0
            
            # Progress indicator
            if len(functions) > 10 and (i + 1) % max(1, len(functions) // 10) == 0:
                progress = ((i + 1) / len(functions)) * 100
                print(f"Progress: {progress:.0f}% ({i + 1}/{len(functions)})", end='\r')
        
        print(f"\nCompleted source info lookup for {len(functions)} functions.")