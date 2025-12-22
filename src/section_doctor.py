"""
Section Doctor - Executable file analyzer.

This script serves as a command-line interface to the executable_doctor package.
"""
import sys
import os

# Import from the executable_doctor package
from executable_doctor import (
    check_llvm_tools,
    get_file_type,
    create_analyzer
)


def main() -> None:
    """Main entry point for the section doctor CLI."""
    if len(sys.argv) != 2:
        print("Usage: python section_doctor.py <target_file>")
        sys.exit(1)

    target_file = sys.argv[1]
    if not os.path.exists(target_file):
        print(f"Error: File {target_file} not found.")
        sys.exit(1)

    report_file = f"{target_file}_section_report.txt"
    
    # Check if LLVM tools are available
    if not check_llvm_tools():
        with open(report_file, 'w') as f:
            f.write("Error: LLVM toolchain not found in environment variables.\n")
        print("Error: LLVM toolchain not found. Please install LLVM and ensure llvm-readobj is in PATH.")
        sys.exit(1)

    # Get file type
    file_type = get_file_type(target_file)
    
    # Write report header
    with open(report_file, 'w') as f:
        if file_type == 'UNKNOWN':
            f.write(f"Error: Unknown file type for {target_file}. Only PE and ELF are supported.\n")
            print(f"Error: Unknown file type for {target_file}. Only PE and ELF are supported.")
            sys.exit(1)

        f.write(f"File Analysis Report: {os.path.basename(target_file)}\n")
        f.write(f"File Type: {file_type}\n")
        f.write("-" * 40 + "\n")

    # Create analyzer and run analysis
    try:
        analyzer = create_analyzer(target_file)
        analyzer.analyze(report_file)
        print(f"Analysis complete. Report saved to: {report_file}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

