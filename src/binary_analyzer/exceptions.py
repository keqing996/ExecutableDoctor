"""
Custom exceptions for Binary Analyzer
"""

from typing import Optional, Any


class BinaryAnalyzerError(Exception):
    """Base exception for Binary Analyzer
    
    Attributes:
        message: Error message
        details: Optional additional error details
    """
    
    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        """Initialize the exception
        
        Args:
            message: Error message
            details: Optional additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        """Return string representation of the exception"""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class LLDBError(BinaryAnalyzerError):
    """Exception raised when LLDB operations fail"""
    pass


class BinaryNotFoundError(BinaryAnalyzerError):
    """Exception raised when binary file is not found"""
    pass


class TargetCreationError(BinaryAnalyzerError):
    """Exception raised when LLDB target creation fails"""
    pass


class SectionAnalysisError(BinaryAnalyzerError):
    """Exception raised during section analysis"""
    pass


class SymbolExtractionError(BinaryAnalyzerError):
    """Exception raised during symbol extraction"""
    pass


class ReportGenerationError(BinaryAnalyzerError):
    """Exception raised during report generation"""
    pass


class ConfigurationError(BinaryAnalyzerError):
    """Exception raised for configuration-related errors"""
    pass


class ValidationError(BinaryAnalyzerError):
    """Exception raised for validation failures"""
    pass