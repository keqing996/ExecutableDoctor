"""
Command Line Interface for Binary Analyzer
"""

import argparse
import sys
from pathlib import Path
from typing import Union

from .analyzer import BinaryAnalyzer
from .config import AnalysisConfig
from .exceptions import BinaryAnalyzerError


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser
    
    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="Analyze PE and ELF binary files to extract function information using LLDB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  binary-analyzer binary.exe
  binary-analyzer binary.exe --output /tmp/reports/
  binary-analyzer binary.exe --top-functions 100 --no-source-info
  binary-analyzer binary.exe --llvm-path /usr/local/llvm
        """
    )
    
    # Required arguments
    parser.add_argument(
        'binary_path',
        help='Path to the binary file to analyze (PE or ELF)'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        help='Output directory for the analysis report (default: <binary_dir>/output/)'
    )
    
    # Analysis options
    parser.add_argument(
        '--top-functions', '-n',
        type=int,
        default=200,
        help='Number of top functions to include in the report (default: 200)'
    )
    
    parser.add_argument(
        '--no-source-info',
        action='store_true',
        help='Skip source file and line number lookup for faster analysis'
    )
    
    # LLVM/LLDB options
    parser.add_argument(
        '--llvm-path',
        help='Path to LLVM installation (default: use LLVM_PATH environment variable)'
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments
    
    Args:
        args: Parsed arguments
        
    Raises:
        SystemExit: If validation fails
    """
    # Validate binary file exists
    binary_path = Path(args.binary_path)
    if not binary_path.exists():
        print(f"Error: Binary file '{args.binary_path}' not found.", file=sys.stderr)
        sys.exit(1)
    
    if not binary_path.is_file():
        print(f"Error: '{args.binary_path}' is not a file.", file=sys.stderr)
        sys.exit(1)
    
    # Validate top_functions argument
    if args.top_functions <= 0:
        print(f"Error: --top-functions must be positive, got {args.top_functions}", file=sys.stderr)
        sys.exit(1)


def create_config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    """Create AnalysisConfig from command line arguments
    
    Args:
        args: Parsed arguments
        
    Returns:
        AnalysisConfig object
    """
    return AnalysisConfig(
        llvm_path=args.llvm_path,
        top_functions=args.top_functions,
        skip_source_info=args.no_source_info,
        output_dir=args.output
    )


def main() -> int:
    """Main entry point for CLI
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Parse arguments
        parser = create_parser()
        args = parser.parse_args()
        
        # Validate arguments
        validate_arguments(args)
        
        # Create configuration
        config = create_config_from_args(args)
        
        # Initialize analyzer
        analyzer = BinaryAnalyzer(config)
        
        # Perform analysis
        result = analyzer.full_analysis(args.binary_path)
        
        if result['success']:
            print(f"\n✓ Analysis completed successfully!")
            print(f"✓ Found {result['functions_count']} functions total")
            print(f"✓ Report shows top {result['top_functions_count']} functions")
            print(f"✓ Report saved to: {result['report_path']}")
            return 0
        else:
            print(f"\n✗ Analysis failed: {result['message']}", file=sys.stderr)
            return 1
            
    except BinaryAnalyzerError as e:
        print(f"\n✗ Binary Analyzer Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n✗ Analysis interrupted by user", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())