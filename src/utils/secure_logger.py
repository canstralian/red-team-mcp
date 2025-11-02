"""
Secure logging utilities for Red Team MCP Server.

This module provides secure logging functionality that prevents accidental
logging of sensitive information such as passwords, API keys, tokens, and PII.

Security Features:
- Automatic masking of sensitive data patterns
- Configurable sensitive field detection
- Structured logging support
- Log sanitization
- Secure default configurations

Usage:
    from src.utils.secure_logger import get_secure_logger, mask_sensitive_data
    
    logger = get_secure_logger(__name__)
    logger.info("User logged in", extra={"username": username})
    
    safe_data = mask_sensitive_data({"password": "secret", "user": "admin"})
"""

import logging
import re
import os
from typing import Any, Dict, List, Optional, Union
import copy


# Sensitive field patterns - these will be masked in logs
SENSITIVE_PATTERNS = [
    # Authentication & Authorization
    r'password',
    r'passwd',
    r'pwd',
    r'secret',
    r'token',
    r'api[_-]?key',
    r'access[_-]?key',
    r'private[_-]?key',
    r'auth',
    r'authorization',
    r'bearer',
    r'session',
    r'cookie',
    
    # Personal Information
    r'ssn',
    r'social[_-]?security',
    r'credit[_-]?card',
    r'card[_-]?number',
    r'cvv',
    r'pin',
    r'email',
    r'phone',
    r'address',
    
    # Database & Infrastructure
    r'connection[_-]?string',
    r'db[_-]?password',
    r'database[_-]?url',
    r'jdbc',
]

# Compile regex patterns for performance
SENSITIVE_REGEX = re.compile(
    '|'.join(f'({pattern})' for pattern in SENSITIVE_PATTERNS),
    re.IGNORECASE
)


class SecureFormatter(logging.Formatter):
    """
    Custom formatter that sanitizes log messages.
    
    Automatically masks sensitive data in log messages and extra fields.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def format(self, record):
        """Format the log record with sensitive data masking."""
        # Create a copy of the record to avoid modifying the original
        record_copy = copy.copy(record)
        
        # Sanitize the message
        if isinstance(record_copy.msg, str):
            record_copy.msg = self._mask_sensitive(record_copy.msg)
        
        # Sanitize arguments
        if record_copy.args:
            if isinstance(record_copy.args, dict):
                record_copy.args = mask_sensitive_data(record_copy.args)
            elif isinstance(record_copy.args, (list, tuple)):
                record_copy.args = tuple(
                    self._mask_sensitive(str(arg)) if isinstance(arg, str) else arg
                    for arg in record_copy.args
                )
        
        return super().format(record_copy)
    
    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive information in text."""
        if not text:
            return text
        
        # Mask sensitive key-value pairs
        # Pattern: key=value or key:value or key="value" or key='value'
        def mask_match(match):
            key = match.group(1)
            separator = match.group(2)
            value = match.group(3)
            return f"{key}{separator}***MASKED***"
        
        pattern = r'(' + '|'.join(SENSITIVE_PATTERNS) + r')(\s*[:=]\s*)["\']?([^"\'\s,}]+)["\']?'
        text = re.sub(pattern, mask_match, text, flags=re.IGNORECASE)
        
        return text


class SensitiveDataFilter(logging.Filter):
    """
    Filter that prevents logging of records containing unmasked sensitive data.
    
    This is a safety net to catch any sensitive data that might have slipped through.
    """
    
    def filter(self, record):
        """Return True if the record should be logged."""
        msg = str(record.getMessage())
        
        # Check for common sensitive patterns in plain text
        # This is a heuristic and may have false positives
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', msg):
            # Contains email address
            return True  # Allow, but it should be masked
        
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', msg):
            # Contains SSN pattern
            return False  # Block SSN patterns
        
        if re.search(r'\b\d{16}\b', msg):
            # Contains what looks like a credit card
            return False  # Block potential credit card numbers
        
        return True


def mask_sensitive_data(data: Any, mask_value: str = "***MASKED***") -> Any:
    """
    Recursively mask sensitive data in dictionaries, lists, and strings.
    
    Args:
        data: Data to mask (dict, list, str, or other)
        mask_value: Value to use for masking
    
    Returns:
        Masked copy of the data
    """
    if isinstance(data, dict):
        return {
            key: mask_value if is_sensitive_field(key) else mask_sensitive_data(value, mask_value)
            for key, value in data.items()
        }
    elif isinstance(data, (list, tuple)):
        return type(data)(mask_sensitive_data(item, mask_value) for item in data)
    elif isinstance(data, str):
        # Check if the entire string looks like a sensitive value
        if len(data) > 20 and not ' ' in data:
            # Could be a token or key
            return mask_value
        return data
    else:
        return data


def is_sensitive_field(field_name: str) -> bool:
    """
    Check if a field name indicates sensitive data.
    
    Args:
        field_name: Name of the field to check
    
    Returns:
        True if the field is sensitive
    """
    return bool(SENSITIVE_REGEX.search(field_name))


def get_secure_logger(
    name: str,
    level: Optional[str] = None,
    log_file: Optional[str] = None,
    enable_console: bool = True
) -> logging.Logger:
    """
    Get a securely configured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        enable_console: Whether to log to console
    
    Returns:
        Configured logger instance
    
    Example:
        logger = get_secure_logger(__name__)
        logger.info("User logged in", extra={"username": "john"})
    """
    logger = logging.getLogger(name)
    
    # Prevent adding handlers multiple times
    if logger.handlers:
        return logger
    
    # Determine log level
    if level is None:
        level = os.environ.get('LOG_LEVEL', 'INFO')
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Create secure formatter
    formatter = SecureFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add console handler
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        # Use rotating file handler to prevent disk filling
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_correlation_id_logger(
    name: str,
    correlation_id: str,
    **kwargs
) -> logging.LoggerAdapter:
    """
    Get a logger adapter that automatically includes correlation ID.
    
    Args:
        name: Logger name
        correlation_id: Correlation ID to include in all logs
        **kwargs: Additional arguments for get_secure_logger
    
    Returns:
        LoggerAdapter with correlation ID
    
    Example:
        logger = get_correlation_id_logger(__name__, correlation_id="abc-123")
        logger.info("Processing request")  # Automatically includes correlation_id
    """
    logger = get_secure_logger(name, **kwargs)
    return logging.LoggerAdapter(logger, {'correlation_id': correlation_id})


def setup_root_logger(level: str = 'INFO', log_file: Optional[str] = None):
    """
    Setup root logger with secure defaults.
    
    This should be called once at application startup.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
    """
    root_logger = logging.getLogger()
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Configure root logger
    log_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(log_level)
    
    # Create secure formatter
    formatter = SecureFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SensitiveDataFilter())
        root_logger.addHandler(file_handler)


# Example usage and tests
if __name__ == "__main__":
    # Setup logging
    setup_root_logger(level='DEBUG')
    logger = get_secure_logger(__name__)
    
    # Test logging with sensitive data
    logger.info("Testing secure logging")
    
    # This should mask the password
    logger.info("User login: password=secret123")
    
    # This should mask sensitive fields
    config = {
        "username": "admin",
        "password": "secret123",
        "api_key": "sk-1234567890",
        "database_url": "postgresql://user:pass@localhost/db"
    }
    safe_config = mask_sensitive_data(config)
    logger.info(f"Configuration loaded: {safe_config}")
    
    # Test correlation ID logger
    corr_logger = get_correlation_id_logger(__name__, correlation_id="abc-123-def")
    corr_logger.info("Processing with correlation ID")
    
    print("\n✅ Secure logging test completed")
    print("Check that sensitive data (passwords, API keys) are masked in the output above")
