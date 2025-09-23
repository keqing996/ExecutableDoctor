"""
Custom exceptions for Binary Analyzer
"""


class BinaryAnalyzerError(Exception):
    """Base exception for Binary Analyzer"""
    pass


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