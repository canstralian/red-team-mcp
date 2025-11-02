"""
Secure logging module with sensitive data sanitization.

This module provides secure logging capabilities for the Red Team MCP Server,
ensuring that sensitive information like passwords, tokens, and credentials
are never written to log files.
"""

import logging
import json
import re
from typing import Any, Dict, Optional
from datetime import datetime
import uuid
import os


class SecureJSONFormatter(logging.Formatter):
    """JSON formatter that sanitizes sensitive data before logging."""
    
    # Patterns for sensitive data that should be redacted
    SENSITIVE_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', '***REDACTED***'),
        (r'token["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', '***REDACTED***'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', '***REDACTED***'),
        (r'secret["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', '***REDACTED***'),
        (r'authorization["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', '***REDACTED***'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***EMAIL***'),
        (r'\b\d{3}-\d{2}-\d{4}\b', '***SSN***'),  # SSN pattern
        (r'\b\d{16}\b', '***CARD***'),  # Credit card pattern
    ]
    
    def sanitize_message(self, message: str) -> str:
        """
        Remove sensitive information from log messages.
        
        Args:
            message: Log message to sanitize
            
        Returns:
            Sanitized message with sensitive data redacted
        """
        if not isinstance(message, str):
            message = str(message)
            
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)
        
        return message
    
    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize dictionary data.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data
            
        sanitized = {}
        sensitive_keys = {'password', 'token', 'secret', 'api_key', 'apikey', 
                         'authorization', 'auth', 'credential', 'private_key'}
        
        for key, value in data.items():
            if key.lower() in sensitive_keys:
                sanitized[key] = '***REDACTED***'
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, str):
                sanitized[key] = self.sanitize_message(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_dict(item) if isinstance(item, dict)
                    else self.sanitize_message(str(item)) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
                
        return sanitized
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON with sanitization.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON-formatted log string
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': self.sanitize_message(record.getMessage()),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add correlation ID if present
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id
            
        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            log_data['extra'] = self.sanitize_dict(record.extra_data)
            
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': self.formatException(record.exc_info)
            }
            
        return json.dumps(log_data)


def setup_secure_logger(
    name: str,
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    console_output: bool = True
) -> logging.Logger:
    """
    Setup secure logger with JSON formatting and sanitization.
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        console_output: Whether to output logs to console
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
        
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.propagate = False
    
    formatter = SecureJSONFormatter()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


class CorrelationContext:
    """
    Context manager for correlation IDs across requests.
    
    Correlation IDs help trace requests across distributed components
    and multiple log entries.
    """
    
    _correlation_id: Optional[str] = None
    
    @classmethod
    def get_correlation_id(cls) -> str:
        """
        Get current correlation ID or generate a new one.
        
        Returns:
            Current or new correlation ID
        """
        if cls._correlation_id is None:
            cls._correlation_id = str(uuid.uuid4())
        return cls._correlation_id
    
    @classmethod
    def set_correlation_id(cls, correlation_id: str) -> None:
        """
        Set correlation ID for current context.
        
        Args:
            correlation_id: Correlation ID to set
        """
        cls._correlation_id = correlation_id
    
    @classmethod
    def clear(cls) -> None:
        """Clear correlation ID from context."""
        cls._correlation_id = None
    
    @classmethod
    def new_correlation_id(cls) -> str:
        """
        Generate and set new correlation ID.
        
        Returns:
            New correlation ID
        """
        correlation_id = str(uuid.uuid4())
        cls.set_correlation_id(correlation_id)
        return correlation_id


class CorrelationAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically adds correlation IDs to log records.
    
    Usage:
        logger = setup_secure_logger(__name__)
        logger = CorrelationAdapter(logger, {})
        
        CorrelationContext.set_correlation_id("req-123")
        logger.info("Processing request")  # Will include correlation_id
    """
    
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Process log message to add correlation ID.
        
        Args:
            msg: Log message
            kwargs: Additional keyword arguments
            
        Returns:
            Tuple of (message, kwargs) with correlation ID added
        """
        correlation_id = CorrelationContext.get_correlation_id()
        
        # Add correlation ID to extra data
        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        kwargs['extra']['correlation_id'] = correlation_id
        
        # Store extra data on record for formatter
        if 'extra_data' not in kwargs['extra']:
            kwargs['extra']['extra_data'] = kwargs.get('extra', {}).copy()
            
        return msg, kwargs


# Convenience function for quick setup
def get_logger(
    name: str,
    use_correlation: bool = True,
    log_level: Optional[str] = None
) -> logging.Logger:
    """
    Get a configured secure logger, optionally with correlation support.
    
    Args:
        name: Logger name
        use_correlation: Whether to enable correlation ID support
        log_level: Optional log level override
        
    Returns:
        Configured logger instance
    """
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO')
    
    log_file = os.getenv('LOG_FILE', 'logs/app.log')
    
    logger = setup_secure_logger(
        name=name,
        log_level=log_level,
        log_file=log_file,
        console_output=True
    )
    
    if use_correlation:
        logger = CorrelationAdapter(logger, {})
    
    return logger
