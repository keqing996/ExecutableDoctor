"""
Main Binary Analyzer class
"""

import os
from typing import List, Dict, Optional

from .config import AnalysisConfig
from .exceptions import (
    BinaryNotFoundError, 
    TargetCreationError,
    LLDBError
)
from .utils import (
    setup_lldb_path, 
    import_lldb, 
    validate_binary_path,
    ensure_output_directory,
    generate_output_filename,
    get_default_output_dir
)
from .symbols import SymbolExtractor
from .sections import SectionAnalyzer
from .report import ReportGenerator


class BinaryAnalyzer:
    """Main binary file analyzer using LLDB"""
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        """Initialize the analyzer
        
        Args:
            config: Analysis configuration object
        """
        self.config = config or AnalysisConfig()
        self.lldb = None
        self.debugger = None
        self.target = None
        self.current_binary_path = None
        
        # Initialize LLDB
        self._setup_lldb()
        
        # Initialize components
        self.symbol_extractor = SymbolExtractor(self.lldb, self.config.min_function_size)
        self.section_analyzer = SectionAnalyzer(self.lldb)
        self.report_generator = ReportGenerator()
    
    def __del__(self):
        """Destructor to clean up LLDB resources"""
        self._cleanup()
    
    def _setup_lldb(self):
        """Setup LLDB Python bindings"""
        setup_lldb_path(self.config.llvm_path)
        self.lldb = import_lldb()
        print("LLDB Python bindings loaded successfully.")
    
    def _cleanup(self):
        """Clean up LLDB debugger and target"""
        if self.debugger:
            self.debugger.Destroy(self.debugger)
            self.debugger = None
            self.target = None
            self.current_binary_path = None
    
    def _ensure_target(self, binary_path: str):
        """Ensure target is created for the given binary path
        
        Args:
            binary_path: Path to binary file
            
        Raises:
            TargetCreationError: If target creation fails
        """
        if self.current_binary_path != binary_path or self.target is None:
            # Clean up previous target if exists
            self._cleanup()
            
            # Create new debugger and target
            self.debugger = self.lldb.SBDebugger.Create()
            self.debugger.SetAsync(False)
            
            self.target = self.debugger.CreateTarget(binary_path)
            if not self.target:
                raise TargetCreationError(f"Failed to create target for {binary_path}")
            
            self.current_binary_path = binary_path
            print(f"Created target for: {binary_path}")
            print(f"Architecture: {self.target.GetTriple()}")
    
    def analyze_binary(self, binary_path: str) -> List[Dict]:
        """Analyze binary file and extract function information
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            List of function dictionaries
            
        Raises:
            BinaryNotFoundError: If binary file doesn't exist
        """
        if not validate_binary_path(binary_path):
            raise BinaryNotFoundError(f"Binary file not found: {binary_path}")
        
        # Ensure target is created/reused
        self._ensure_target(binary_path)
        
        print(f"Analyzing binary: {binary_path}")
        
        # Extract functions using symbol extractor
        functions = self.symbol_extractor.extract_functions_from_target(self.target)
        
        return functions
    
    def get_sections_info(self, binary_path: str) -> List[Dict]:
        """Get information about sections in the binary file
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            List of section dictionaries
        """
        self._ensure_target(binary_path)
        return self.section_analyzer.get_sections_info(self.target)
    
    def sort_and_filter_functions(self, functions: List[Dict]) -> List[Dict]:
        """Sort functions by size and return top N
        
        Args:
            functions: List of function dictionaries
            
        Returns:
            Sorted and filtered list of functions
        """
        return self.symbol_extractor.sort_and_filter_functions(
            functions, self.config.top_functions
        )
    
    def generate_report(
        self, 
        functions: List[Dict], 
        binary_path: str, 
        output_path: Optional[str] = None,
        report_format: str = "markdown"
    ) -> str:
        """Generate analysis report
        
        Args:
            functions: List of function dictionaries
            binary_path: Path to analyzed binary
            output_path: Optional output file path
            report_format: Report format ('markdown' or 'json')
            
        Returns:
            Path to generated report file
        """
        # Determine output path
        if output_path is None:
            output_dir = self.config.output_dir or get_default_output_dir(binary_path)
            ensure_output_directory(output_dir)
            
            suffix = "_analysis_report"
            if report_format == "json":
                suffix += ".json"
                output_path = generate_output_filename(binary_path, output_dir, suffix).replace(".md", ".json")
            else:
                output_path = generate_output_filename(binary_path, output_dir, suffix)
        
        # Get sections information
        print("Analyzing binary sections...")
        sections = self.get_sections_info(binary_path)
        
        # Get source information for functions
        if not self.config.skip_source_info:
            self._ensure_target(binary_path)
            self.symbol_extractor.get_source_info_batch(
                functions, self.target, self.config.skip_source_info
            )
        else:
            # Set default values for all functions
            for func in functions:
                func['source_file'] = "Unknown"
                func['line_number'] = 0
        
        # Generate report
        if report_format == "json":
            self.report_generator.generate_json_report(
                functions, sections, binary_path, output_path
            )
        else:
            self.report_generator.generate_markdown_report(
                functions, sections, binary_path, output_path
            )
        
        return output_path
    
    def full_analysis(self, binary_path: str, output_path: Optional[str] = None) -> Dict:
        """Perform complete binary analysis
        
        Args:
            binary_path: Path to binary file
            output_path: Optional output file path
            
        Returns:
            Dictionary with analysis results and paths
        """
        try:
            # Analyze binary
            print("Starting binary analysis...")
            functions = self.analyze_binary(binary_path)
            
            if not functions:
                print("No functions found in the binary file.")
                return {
                    'success': False,
                    'message': 'No functions found',
                    'functions_count': 0
                }
            
            print(f"Found {len(functions)} functions in total.")
            
            # Sort and filter functions
            top_functions = self.sort_and_filter_functions(functions)
            print(f"Selected top {len(top_functions)} functions by size.")
            
            # Generate report
            report_path = self.generate_report(top_functions, binary_path, output_path)
            
            print(f"\nAnalysis completed successfully!")
            print(f"Report saved to: {report_path}")
            
            return {
                'success': True,
                'message': 'Analysis completed successfully',
                'functions_count': len(functions),
                'top_functions_count': len(top_functions),
                'report_path': report_path,
                'functions': top_functions
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Analysis failed: {e}',
                'error': str(e)
            }
        finally:
            # Ensure cleanup
            self._cleanup()