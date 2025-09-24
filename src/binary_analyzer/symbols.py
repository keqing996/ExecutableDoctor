"""
Symbol and function extraction functionality
"""

from typing import List, Dict, Optional, Any

from .exceptions import SymbolExtractionError
from .utils import format_size, format_hex_address, is_valid_address


class SymbolExtractor:
    """Handles symbol and function extraction from binary files"""
    
    def __init__(self, lldb_module: Any) -> None:
        """Initialize symbol extractor
        
        Args:
            lldb_module: LLDB module (imported dynamically)
        """
        self.lldb = lldb_module
    
    def extract_functions_from_target(self, target: Any) -> List[Dict[str, Any]]:
        """Extract function information from LLDB target
        
        Args:
            target: LLDB target object
            
        Returns:
            List of function dictionaries
            
        Raises:
            SymbolExtractionError: If extraction fails
        """
        if not target or not target.IsValid():
            raise SymbolExtractionError("Invalid LLDB target provided")
        
        functions: List[Dict[str, Any]] = []
        
        try:
            # Iterate through all modules
            for module in target.module_iter():
                module_name = module.GetFileSpec().GetFilename() if module.IsValid() else "Unknown"
                print(f"Processing module: {module_name}")
                
                # Get symbols from the module
                num_symbols = module.GetNumSymbols()
                for sym_idx in range(num_symbols):
                    symbol = module.GetSymbolAtIndex(sym_idx)
                    if symbol and symbol.IsValid():
                        # Check if it's a function symbol
                        if symbol.GetType() == self.lldb.eSymbolTypeCode:
                            func_info = self._extract_symbol_info(symbol, target)
                            if func_info:
                                functions.append(func_info)
        
        except Exception as e:
            raise SymbolExtractionError(f"Error extracting functions: {e}")
        
        return functions
    
    def _extract_symbol_info(self, symbol: Any, target: Any) -> Optional[Dict[str, Any]]:
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
            if not addr or not addr.IsValid():
                return None
            
            start_offset = addr.GetFileAddress()
            if start_offset == self.lldb.LLDB_INVALID_ADDRESS:
                start_offset = addr.GetLoadAddress(target)
            
            if start_offset == self.lldb.LLDB_INVALID_ADDRESS or not is_valid_address(start_offset):
                return None
            
            # Get symbol size
            size = symbol.GetSize()
            if size <= 0:
                size = 1  # Default minimum size
            
            # Get symbol name
            name = symbol.GetName()
            if not name:
                name = f"sym_{start_offset:x}"
            
            return {
                'name': str(name),
                'address': format_hex_address(start_offset),
                'size': int(size),
                'start_offset': int(start_offset),
                'end_offset': int(start_offset + size),
                'type': 'symbol',
                'source_file': "Unknown",  # Will be filled later if needed
                'line_number': 0  # Will be filled later if needed
            }
        except Exception as e:
            print(f"Error extracting symbol info: {e}")
            return None
    
    def sort_and_filter_functions(self, functions: List[Dict[str, Any]], top_n: int = 200) -> List[Dict[str, Any]]:
        """Sort functions by size (largest first) and return top N
        
        Args:
            functions: List of function dictionaries
            top_n: Number of top functions to return
            
        Returns:
            Sorted and filtered list of functions
            
        Raises:
            ValueError: If top_n is not positive
        """
        if top_n <= 0:
            raise ValueError("top_n must be positive")
        
        if not functions:
            return []
        
        # Sort by size in descending order
        try:
            sorted_functions = sorted(functions, key=lambda x: x.get('size', 0), reverse=True)
        except (KeyError, TypeError) as e:
            raise SymbolExtractionError(f"Error sorting functions: {e}")
        
        # Return top N functions
        return sorted_functions[:top_n]
    
    def get_source_info_batch(self, functions: List[Dict[str, Any]], target: Any, skip_source_info: bool = False) -> None:
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
        
        if not functions:
            return
        
        print(f"Getting source information for {len(functions)} functions...")
        
        # Simple approach: try to get source info for each function individually
        file_spec_cache: Dict[str, str] = {}
        
        for i, func in enumerate(functions):
            try:
                start_offset = func.get('start_offset')
                if not is_valid_address(start_offset):
                    func['source_file'] = "Unknown"
                    func['line_number'] = 0
                    continue
                
                # Create address and try to resolve it
                addr = target.ResolveFileAddress(start_offset)
                if addr and addr.IsValid():
                    line_entry = addr.GetLineEntry()
                    if line_entry and line_entry.IsValid():
                        file_spec = line_entry.GetFileSpec()
                        if file_spec and file_spec.IsValid():
                            # Use caching for file specs
                            directory = file_spec.GetDirectory() or ""
                            filename = file_spec.GetFilename() or "Unknown"
                            file_key = f"{directory}_{filename}"
                            
                            if file_key not in file_spec_cache:
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
                    
            except Exception as e:
                print(f"Warning: Error getting source info for function {func.get('name', 'unknown')}: {e}")
                func['source_file'] = "Unknown"
                func['line_number'] = 0
            
            # Progress indicator
            if len(functions) > 10 and (i + 1) % max(1, len(functions) // 10) == 0:
                progress = ((i + 1) / len(functions)) * 100
                print(f"Progress: {progress:.0f}% ({i + 1}/{len(functions)})", end='\r')
        
        print(f"\nCompleted source info lookup for {len(functions)} functions.")