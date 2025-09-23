"""
Report generation functionality
"""

import datetime
import os
from typing import List, Dict

from .exceptions import ReportGenerationError
from .utils import format_size
from .config import (
    REPORT_HEADER_TEMPLATE,
    SECTIONS_TABLE_HEADER,
    FUNCTIONS_TABLE_HEADER
)


class ReportGenerator:
    """Handles markdown report generation"""
    
    def __init__(self):
        """Initialize report generator"""
        pass
    
    def generate_markdown_report(
        self, 
        functions: List[Dict], 
        sections: List[Dict],
        binary_path: str, 
        output_path: str
    ) -> None:
        """Generate comprehensive markdown report
        
        Args:
            functions: List of function dictionaries
            sections: List of section dictionaries
            binary_path: Path to analyzed binary
            output_path: Output file path
        """
        try:
            binary_name = os.path.basename(binary_path)
            
            # Generate report header
            report_content = REPORT_HEADER_TEMPLATE.format(
                binary_name=binary_name,
                binary_path=binary_path,
                analysis_date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total_functions=len(functions),
                report_functions=len(functions)
            )
            
            # Add sections information
            sections_content = self._generate_sections_content(sections)
            report_content += sections_content
            
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
    
    def generate_json_report(
        self,
        functions: List[Dict],
        sections: List[Dict], 
        binary_path: str,
        output_path: str
    ) -> None:
        """Generate JSON format report
        
        Args:
            functions: List of function dictionaries
            sections: List of section dictionaries
            binary_path: Path to analyzed binary
            output_path: Output file path
        """
        import json
        
        try:
            report_data = {
                'metadata': {
                    'binary_name': os.path.basename(binary_path),
                    'binary_path': binary_path,
                    'analysis_date': datetime.datetime.now().isoformat(),
                    'total_functions': len(functions),
                    'total_sections': len(sections)
                },
                'sections': sections,
                'functions': functions,
                'statistics': {
                    'largest_function': functions[0] if functions else None,
                    'smallest_function': functions[-1] if functions else None,
                    'total_function_size': sum(f['size'] for f in functions),
                    'average_function_size': sum(f['size'] for f in functions) // len(functions) if functions else 0
                }
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            print(f"JSON report generated: {output_path}")
            
        except Exception as e:
            raise ReportGenerationError(f"Error generating JSON report: {e}")