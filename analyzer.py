#!/usr/bin/env python3
"""
Binary File Analyzer using LLDB
Analyzes PE and ELF files to extract function information from code sections.
"""

import argparse
import os
import sys
import platform
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import datetime


class BinaryAnalyzer:
    """Binary file analyzer using LLDB."""
    
    def __init__(self, llvm_path: Optional[str] = None):
        """Initialize the analyzer with LLVM path."""
        self.llvm_path = llvm_path or os.environ.get('LLVM_PATH')
        self.lldb = None
        self.debugger = None
        self.target = None
        self.current_binary_path = None
        self._setup_lldb()
    
    def __del__(self):
        """Destructor to clean up LLDB resources."""
        self._cleanup()
    
    def _cleanup(self):
        """Clean up LLDB debugger and target."""
        if self.debugger:
            self.debugger.Destroy(self.debugger)
            self.debugger = None
            self.target = None
            self.current_binary_path = None
    
    def _setup_lldb(self):
        """Setup LLDB Python bindings."""
        if self.llvm_path:
            # Add LLDB Python bindings to path
            if platform.system() == "Windows":
                lldb_python_path = os.path.join(self.llvm_path, "lib", "site-packages")
            else:
                lldb_python_path = os.path.join(self.llvm_path, "lib", "python3", "site-packages")
            
            if os.path.exists(lldb_python_path):
                sys.path.insert(0, lldb_python_path)
        
        try:
            import lldb
            self.lldb = lldb
            print(f"LLDB Python bindings loaded successfully.")
        except ImportError as e:
            print(f"Error importing LLDB: {e}")
            print("Make sure LLDB Python bindings are installed and LLVM_ROOT is set correctly.")
            sys.exit(1)
    
    def _ensure_target(self, binary_path: str):
        """Ensure target is created for the given binary path."""
        if self.current_binary_path != binary_path or self.target is None:
            # Clean up previous target if exists
            self._cleanup()
            
            # Create new debugger and target
            self.debugger = self.lldb.SBDebugger.Create()
            self.debugger.SetAsync(False)
            
            self.target = self.debugger.CreateTarget(binary_path)
            if not self.target:
                raise RuntimeError(f"Failed to create target for {binary_path}")
            
            self.current_binary_path = binary_path
            print(f"Created target for: {binary_path}")
            print(f"Architecture: {self.target.GetTriple()}")
    
    def analyze_binary(self, binary_path: str) -> List[Dict]:
        """Analyze binary file and extract function information."""
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        # Ensure target is created/reused
        self._ensure_target(binary_path)
        
        print(f"Analyzing binary: {binary_path}")
        
        functions = []
        
        # Iterate through all modules
        for module in self.target.module_iter():
            print(f"Processing module: {module.GetFileSpec().GetFilename()}")
            
            # Get symbols from the module - this is the main way to find functions
            for sym_idx in range(module.GetNumSymbols()):
                symbol = module.GetSymbolAtIndex(sym_idx)
                if symbol.IsValid():
                    # Check if it's a function symbol
                    symbol_type = symbol.GetType()
                    if (symbol_type == self.lldb.eSymbolTypeCode):
                        func_info = self._extract_symbol_info(symbol, self.target)
                        if func_info:
                            functions.append(func_info)
        
        return functions
    
    def _extract_function_info(self, function, target) -> Optional[Dict]:
        """Extract information from an LLDB function object."""
        try:
            start_addr = function.GetStartAddress()
            end_addr = function.GetEndAddress()
            
            if not start_addr.IsValid() or not end_addr.IsValid():
                return None
            
            start_offset = start_addr.GetFileAddress()
            end_offset = end_addr.GetFileAddress()
            size = end_offset - start_offset
            
            if size <= 0:
                return None
            
            return {
                'name': function.GetName() or f"func_{start_offset:x}",
                'address': f"0x{start_offset:x}",
                'size': size,
                'start_offset': start_offset,
                'end_offset': end_offset,
                'type': 'function'
            }
        except Exception as e:
            print(f"Error extracting function info: {e}")
            return None
    
    def _extract_symbol_info(self, symbol, target) -> Optional[Dict]:
        """Extract information from an LLDB symbol object."""
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
            if size < 4:  # Too small to be a meaningful function
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
        """Sort functions by size (largest first) and return top N."""
        # Sort by size in descending order
        sorted_functions = sorted(functions, key=lambda x: x['size'], reverse=True)
        
        # Return top N functions
        return sorted_functions[:top_n]
    
    def _get_source_info_batch(self, functions: List[Dict], target) -> None:
        """Batch process source information for better performance."""
        print(f"Getting source information for {len(functions)} functions...")
        
        # Simple approach: try to get source info for each function individually
        # but with optimized error handling and caching
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
    
    def _format_size(self, size_bytes: int) -> str:
        """Format size in bytes with MB in parentheses."""
        mb_size = size_bytes / (1024 * 1024)
        return f"{size_bytes} ({mb_size:.2f} MB)"
    
    def generate_markdown_report(self, functions: List[Dict], binary_path: str, output_path: str, skip_source_info: bool = False):
        """Generate markdown report of function analysis."""
        binary_name = os.path.basename(binary_path)
        
        if skip_source_info:
            print("Skipping source information lookup for faster processing...")
            # Set default values for all functions
            for func in functions:
                func['source_file'] = "Unknown"
                func['line_number'] = 0
        else:
            # Ensure target is available for source info lookup
            self._ensure_target(binary_path)
            # Use full batch processing for better performance
            self._get_source_info_batch(functions, self.target)
        
        report_content = f"""# Binary Function Analysis Report

## Binary Information
- **File**: {binary_name}
- **Full Path**: {binary_path}
- **Analysis Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total Functions Found**: {len(functions)}
- **Report Shows**: Top {len(functions)} functions (sorted by size)

## Function Analysis Summary

| Rank | Function Name | Start Address | Size (bytes) | Size (hex) | Type | Source File | Line |
|------|---------------|---------------|--------------|------------|------|-------------|------|
"""
        
        for i, func in enumerate(functions, 1):
            size_hex = f"0x{func['size']:x}"
            size_formatted = self._format_size(func['size'])
            source_file = func.get('source_file', 'Unknown')
            line_number = func.get('line_number', 0)
            line_str = str(line_number) if line_number > 0 else 'N/A'
            report_content += f"| {i} | `{func['name']}` | {func['address']} | {size_formatted} | {size_hex} | {func['type']} | `{source_file}` | {line_str} |\n"
        
        report_content += f"""
## Statistics

- **Largest Function**: `{functions[0]['name'] if functions else 'N/A'}` ({self._format_size(functions[0]['size']) if functions else '0 (0.00 MB)'})
- **Smallest Function in Top {len(functions)}**: `{functions[-1]['name'] if functions else 'N/A'}` ({self._format_size(functions[-1]['size']) if functions else '0 (0.00 MB)'})
- **Total Size of Top {len(functions)} Functions**: {self._format_size(sum(f['size'] for f in functions))}
- **Average Function Size**: {self._format_size(sum(f['size'] for f in functions) // len(functions) if functions else 0)}

## Detailed Function Information

"""
        
        for i, func in enumerate(functions[:50], 1):  # Show detailed info for top 50
            source_file = func.get('source_file', 'Unknown')
            line_number = func.get('line_number', 0)
            line_str = f"Line {line_number}" if line_number > 0 else 'N/A'
            
            report_content += f"""### {i}. {func['name']}

- **Address Range**: {func['address']} - 0x{func['end_offset']:x}
- **Size**: {self._format_size(func['size'])} (0x{func['size']:x})
- **Type**: {func['type']}
- **Source File**: `{source_file}`
- **Line Number**: {line_str}

"""
        
        if len(functions) > 50:
            report_content += f"\n*... and {len(functions) - 50} more functions*\n"
        
        # Write report to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"Markdown report generated: {output_path}")


def main():
    """Main function to handle command line arguments and execute analysis."""
    parser = argparse.ArgumentParser(
        description="Analyze PE and ELF binary files to extract function information using LLDB."
    )
    
    parser.add_argument(
        'binary_path',
        help='Path to the binary file to analyze (PE or ELF)'
    )
    
    parser.add_argument(
        '--output',
        '-o',
        help='Output directory for the analysis report (default: <binary_dir>/output/)'
    )
    
    parser.add_argument(
        '--llvm-path',
        help='Path to LLVM installation (default: use LLVM_PATH environment variable)'
    )
    
    parser.add_argument(
        '--top-functions',
        '-n',
        type=int,
        default=200,
        help='Number of top functions to include in the report (default: 200)'
    )
    
    parser.add_argument(
        '--no-source-info',
        action='store_true',
        help='Skip source file and line number lookup for faster analysis'
    )
    
    args = parser.parse_args()
    
    # Validate binary file
    if not os.path.exists(args.binary_path):
        print(f"Error: Binary file '{args.binary_path}' not found.")
        sys.exit(1)
    
    # Determine output directory
    if args.output:
        output_dir = args.output
    else:
        binary_dir = os.path.dirname(os.path.abspath(args.binary_path))
        output_dir = os.path.join(binary_dir, 'output')
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate output file name
    binary_name = os.path.splitext(os.path.basename(args.binary_path))[0]
    output_file = os.path.join(output_dir, f"{binary_name}_analysis_report.md")
    
    try:
        # Initialize analyzer
        analyzer = BinaryAnalyzer(args.llvm_path)
        
        # Analyze binary
        print("Starting binary analysis...")
        functions = analyzer.analyze_binary(args.binary_path)
        
        if not functions:
            print("No functions found in the binary file.")
            return
        
        print(f"Found {len(functions)} functions in total.")
        
        # Sort and filter functions
        top_functions = analyzer.sort_and_filter_functions(functions, args.top_functions)
        print(f"Selected top {len(top_functions)} functions by size.")
        
        # Generate report
        analyzer.generate_markdown_report(top_functions, args.binary_path, output_file, args.no_source_info)
        
        print(f"\nAnalysis completed successfully!")
        print(f"Report saved to: {output_file}")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)
    finally:
        # Ensure cleanup
        if 'analyzer' in locals():
            analyzer._cleanup()


if __name__ == "__main__":
    main()