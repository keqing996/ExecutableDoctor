"""
Report generation functionality
"""

import datetime
import os
from typing import List, Dict, Optional, Any

from .exceptions import ReportGenerationError
from .utils import format_size, sanitize_filename
from .config import (
    REPORT_HEADER_TEMPLATE,
    SECTIONS_TABLE_HEADER,
    FUNCTIONS_TABLE_HEADER
)


class ReportGenerator:
    """Handles markdown report generation"""
    
    def __init__(self) -> None:
        """Initialize report generator"""
        pass
    
    def generate_markdown_report(
        self, 
        functions: List[Dict[str, Any]], 
        sections: List[Dict[str, Any]],
        imports: List[Dict[str, Any]],
        exports: List[Dict[str, Any]],
        binary_path: str, 
        output_path: str
    ) -> None:
        """Generate comprehensive markdown report
        
        Args:
            functions: List of function dictionaries
            sections: List of section dictionaries
            imports: List of import dictionaries
            exports: List of export dictionaries
            binary_path: Path to analyzed binary
            output_path: Output file path
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        try:
            if not binary_path or not output_path:
                raise ReportGenerationError("Binary path and output path are required")
            
            binary_name = os.path.basename(binary_path)
            
            # Generate report header
            report_content = REPORT_HEADER_TEMPLATE.format(
                binary_name=binary_name,
                binary_path=binary_path,
                analysis_date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total_functions=len(functions) if functions else 0,
                report_functions=len(functions) if functions else 0
            )
            
            # Add sections information
            sections_content = self._generate_sections_content(sections)
            report_content += sections_content
            
            # Add imports information
            imports_content = self._generate_imports_content(imports, binary_name)
            report_content += imports_content
            
            # Add exports information
            exports_content = self._generate_exports_content(exports, binary_name)
            report_content += exports_content
            
            # Add functions table
            functions_content = self._generate_functions_content(functions)
            report_content += functions_content
            
            # Add statistics
            stats_content = self._generate_statistics_content(functions)
            report_content += stats_content
            
            # Add detailed function information
            detailed_content = self._generate_detailed_functions_content(functions)
            report_content += detailed_content
            
            # Write report to file
            self._write_report_to_file(report_content, output_path)
            
        except Exception as e:
            raise ReportGenerationError(f"Error generating report: {e}")
    
    def _write_report_to_file(self, content: str, output_path: str) -> None:
        """Write report content to file
        
        Args:
            content: Report content to write
            output_path: Output file path
            
        Raises:
            ReportGenerationError: If file writing fails
        """
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except (OSError, IOError) as e:
            raise ReportGenerationError(f"Error writing report to file: {e}")
            self._write_report_file(report_content, output_path)
            
            print(f"Markdown report generated: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Error generating report: {e}")
    
    def _generate_sections_content(self, sections: List[Dict]) -> str:
        """Generate sections table content
        
        Args:
            sections: List of section dictionaries
            
        Returns:
            Formatted sections content string
        """
        if not sections:
            return "\n## Binary Sections Information\n\nNo sections found.\n"
        
        content = SECTIONS_TABLE_HEADER
        
        for section in sections:
            size_hex = f"0x{section['size']:x}"
            size_formatted = format_size(section['size'])
            content += (
                f"| `{section['name']}` | {section['address']} | "
                f"{section['file_address']} | {size_formatted} | {size_hex} | "
                f"{section['permissions']} | {section['type']} |\n"
            )
        
        # Add sections summary
        total_sections_size = sum(s['size'] for s in sections)
        content += f"""
### Sections Summary
- **Total Sections**: {len(sections)}
- **Total Size**: {format_size(total_sections_size)}
- **Largest Section**: `{sections[0]['name']}` ({format_size(sections[0]['size'])})
- **Smallest Section**: `{sections[-1]['name']}` ({format_size(sections[-1]['size'])})
"""
        return content
    
    def _generate_imports_content(self, imports: List[Dict], binary_name: str) -> str:
        """Generate imports table content
        
        Args:
            imports: List of import dictionaries
            binary_name: Name of the analyzed binary
            
        Returns:
            Formatted imports content string
        """
        if not imports:
            return "\n## Import Table Information\n\nNo imports found.\n"
        
        # Group imports by DLL
        dll_groups = {}
        for imp in imports:
            dll = imp.get('dll_name', 'Unknown')
            if dll not in dll_groups:
                dll_groups[dll] = []
            dll_groups[dll].append(imp)
        
        # Generate content
        safe_binary_name = os.path.splitext(binary_name)[0].replace(' ', '_')
        content = f"""
## Import Table Information

**CSV Export**: `{safe_binary_name}_imports.csv`

| DLL Name | Function Name | Address | Original Symbol |
|----------|---------------|---------|----------------|
"""
        
        # Sort imports by DLL name, then by function name
        sorted_imports = sorted(imports, key=lambda x: (x.get('dll_name', 'Unknown'), x.get('function_name', '')))
        
        for imp in sorted_imports[:100]:  # Limit to first 100 for readability
            content += (
                f"| `{imp.get('dll_name', 'Unknown')}` | "
                f"`{imp.get('function_name', 'N/A')}` | "
                f"{imp.get('address', '0x0')} | "
                f"`{imp.get('original_symbol', 'N/A')}` |\n"
            )
        
        if len(imports) > 100:
            content += f"\n*... and {len(imports) - 100} more imports (see CSV file for complete list)*\n"
        
        # Add imports summary
        unique_dlls = len(dll_groups)
        top_dlls = sorted(dll_groups.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        
        content += f"""
### Import Summary
- **Total Imports**: {len(imports)}
- **Unique DLLs**: {unique_dlls}
- **Top DLLs by Import Count**:
"""
        for dll, imp_list in top_dlls:
            content += f"  - `{dll}`: {len(imp_list)} imports\n"
        
        return content
    
    def _generate_exports_content(self, exports: List[Dict], binary_name: str) -> str:
        """Generate exports table content
        
        Args:
            exports: List of export dictionaries
            binary_name: Name of the analyzed binary
            
        Returns:
            Formatted exports content string
        """
        if not exports:
            return "\n## Export Table Information\n\nNo exports found.\n"
        
        safe_binary_name = os.path.splitext(binary_name)[0].replace(' ', '_')
        content = f"""
## Export Table Information

**CSV Export**: `{safe_binary_name}_exports.csv`

| Function Name | Address | RVA | Size |
|---------------|---------|-----|------|
"""
        
        # Sort exports by address
        sorted_exports = sorted(exports, key=lambda x: x.get('address', '0x0'))
        
        for exp in sorted_exports[:100]:  # Limit to first 100 for readability
            size_str = format_size(exp.get('size', 0)) if exp.get('size', 0) > 0 else 'N/A'
            content += (
                f"| `{exp.get('function_name', 'N/A')}` | "
                f"{exp.get('address', '0x0')} | "
                f"{exp.get('rva', '0x0')} | "
                f"{size_str} |\n"
            )
        
        if len(exports) > 100:
            content += f"\n*... and {len(exports) - 100} more exports (see CSV file for complete list)*\n"
        
        # Add exports summary
        exports_with_size = [exp for exp in exports if exp.get('size', 0) > 0]
        total_size = sum(exp.get('size', 0) for exp in exports_with_size)
        avg_size = total_size / len(exports_with_size) if exports_with_size else 0
        
        content += f"""
### Export Summary
- **Total Exports**: {len(exports)}
- **Functions with Size Info**: {len(exports_with_size)}
- **Total Size**: {format_size(total_size)}
- **Average Size**: {format_size(int(avg_size))}
"""
        
        if exports_with_size:
            largest = max(exports_with_size, key=lambda x: x.get('size', 0))
            smallest = min(exports_with_size, key=lambda x: x.get('size', 0))
            content += f"- **Largest Export**: `{largest.get('function_name', 'N/A')}` ({format_size(largest.get('size', 0))})\n"
            content += f"- **Smallest Export**: `{smallest.get('function_name', 'N/A')}` ({format_size(smallest.get('size', 0))})\n"
        
        return content
    
    def _generate_functions_content(self, functions: List[Dict]) -> str:
        """Generate functions table content
        
        Args:
            functions: List of function dictionaries
            
        Returns:
            Formatted functions content string
        """
        content = FUNCTIONS_TABLE_HEADER
        
        for i, func in enumerate(functions, 1):
            size_hex = f"0x{func['size']:x}"
            size_formatted = format_size(func['size'])
            source_file = func.get('source_file', 'Unknown')
            line_number = func.get('line_number', 0)
            line_str = str(line_number) if line_number > 0 else 'N/A'
            
            content += (
                f"| {i} | `{func['name']}` | {func['address']} | "
                f"{size_formatted} | {size_hex} | {func['type']} | "
                f"`{source_file}` | {line_str} |\n"
            )
        
        return content
    
    def _generate_statistics_content(self, functions: List[Dict]) -> str:
        """Generate statistics section content
        
        Args:
            functions: List of function dictionaries
            
        Returns:
            Formatted statistics content string
        """
        if not functions:
            return "\n## Statistics\n\nNo functions to analyze.\n"
        
        total_size = sum(f['size'] for f in functions)
        avg_size = total_size // len(functions) if functions else 0
        
        content = f"""
## Statistics

- **Largest Function**: `{functions[0]['name']}` ({format_size(functions[0]['size'])})
- **Smallest Function in Top {len(functions)}**: `{functions[-1]['name']}` ({format_size(functions[-1]['size'])})
- **Total Size of Top {len(functions)} Functions**: {format_size(total_size)}
- **Average Function Size**: {format_size(avg_size)}

"""
        return content
    
    def _generate_detailed_functions_content(self, functions: List[Dict]) -> str:
        """Generate detailed function information content
        
        Args:
            functions: List of function dictionaries
            
        Returns:
            Formatted detailed content string
        """
        content = "## Detailed Function Information\n\n"
        
        # Show detailed info for top 50 functions
        detail_count = min(50, len(functions))
        
        for i, func in enumerate(functions[:detail_count], 1):
            source_file = func.get('source_file', 'Unknown')
            line_number = func.get('line_number', 0)
            line_str = f"Line {line_number}" if line_number > 0 else 'N/A'
            
            content += f"""### {i}. {func['name']}

- **Address Range**: {func['address']} - 0x{func['end_offset']:x}
- **Size**: {format_size(func['size'])} (0x{func['size']:x})
- **Type**: {func['type']}
- **Source File**: `{source_file}`
- **Line Number**: {line_str}

"""
        
        if len(functions) > detail_count:
            content += f"\n*... and {len(functions) - detail_count} more functions*\n"
        
        return content
    
    def _write_report_file(self, content: str, output_path: str) -> None:
        """Write report content to file
        
        Args:
            content: Report content string
            output_path: Output file path
        """
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            raise ReportGenerationError(f"Error writing report file: {e}")