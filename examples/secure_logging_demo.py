#!/usr/bin/env python3
"""
Example demonstrating secure logging with the Red Team MCP Server.

This example shows:
- Setting up secure logging
- Using correlation IDs
- Automatic sanitization of sensitive data
- Structured JSON logging

Usage:
    # From repository root
    python3 examples/secure_logging_demo.py
    
    # Or install in development mode first
    pip3 install -e .
    python3 examples/secure_logging_demo.py
"""

import sys
import os

# Try relative import, fall back to sys.path manipulation for development
try:
    from src.utils.secure_logger import (
        setup_secure_logger,
        CorrelationAdapter,
        CorrelationContext,
        get_logger
    )
except ImportError:
    # Add parent directory to path for development
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from src.utils.secure_logger import (
        setup_secure_logger,
        CorrelationAdapter,
        CorrelationContext,
        get_logger
    )


def example_basic_logging():
    """Example 1: Basic secure logging."""
    print("\n=== Example 1: Basic Secure Logging ===\n")
    
    # Setup logger
    logger = setup_secure_logger(
        name="example_basic",
        log_level="DEBUG",
        log_file="logs/example.log",
        console_output=True
    )
    
    # Various log levels
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    print("\n✓ Check logs/example.log for JSON-formatted output\n")


def example_sensitive_data_sanitization():
    """Example 2: Automatic sanitization of sensitive data."""
    print("\n=== Example 2: Sensitive Data Sanitization ===\n")
    
    logger = get_logger("example_sanitization", use_correlation=False)
    
    # These will be automatically sanitized
    logger.info("User login attempt with password=secret123")
    logger.info("API request with api_key=sk-1234567890abcdef")
    logger.info("Auth header: token=bearer_token_xyz")
    logger.info("Database connection: postgresql://user:password@localhost/db")
    
    # Email addresses will be redacted
    logger.info("User registered: user@example.com")
    
    print("✓ Check the logs - all sensitive data should be redacted as ***REDACTED***\n")


def example_correlation_ids():
    """Example 3: Using correlation IDs for request tracing."""
    print("\n=== Example 3: Correlation IDs ===\n")
    
    logger = get_logger("example_correlation", use_correlation=True)
    
    # Simulate multiple requests
    for request_num in range(1, 4):
        # Set correlation ID for this request
        correlation_id = CorrelationContext.new_correlation_id()
        print(f"Processing request {request_num} with correlation_id: {correlation_id}")
        
        # All logs will include this correlation ID
        logger.info(f"Request {request_num} started")
        logger.debug(f"Processing step 1 for request {request_num}")
        logger.debug(f"Processing step 2 for request {request_num}")
        logger.info(f"Request {request_num} completed")
        
        # Clear correlation ID
        CorrelationContext.clear()
    
    print("\n✓ All logs have correlation_id field for tracing\n")


def example_structured_logging():
    """Example 4: Structured logging with extra data."""
    print("\n=== Example 4: Structured Logging ===\n")
    
    logger = get_logger("example_structured")
    
    # Log with structured data
    CorrelationContext.set_correlation_id("req-abc-123")
    
    logger.info(
        "Payload generated",
        extra={
            'extra_data': {
                'payload_type': 'reverse_shell',
                'shell_type': 'bash',
                'target_port': 4444,
                'encoding': 'base64',
                'user_id': 'user123'
            }
        }
    )
    
    logger.info(
        "Tool execution completed",
        extra={
            'extra_data': {
                'tool_name': 'redteam_reverse_shell',
                'execution_time_ms': 145,
                'success': True
            }
        }
    )
    
    print("✓ Logs include structured extra data in JSON format\n")


def example_exception_logging():
    """Example 5: Logging exceptions."""
    print("\n=== Example 5: Exception Logging ===\n")
    
    logger = get_logger("example_exceptions")
    CorrelationContext.set_correlation_id("req-error-456")
    
    try:
        # Simulate an error
        result = 10 / 0
    except Exception as e:
        logger.error(
            "Error processing request",
            exc_info=True,
            extra={
                'extra_data': {
                    'operation': 'calculate_result',
                    'input_value': 10
                }
            }
        )
    
    print("✓ Exception details logged with stack trace\n")


def example_security_best_practices():
    """Example 6: Security best practices."""
    print("\n=== Example 6: Security Best Practices ===\n")
    
    logger = get_logger("example_security")
    
    # ✓ GOOD: Log authentication events without credentials
    logger.info(
        "Authentication successful",
        extra={
            'extra_data': {
                'user_id': 'user123',
                'ip_address': '192.168.1.100',
                'auth_method': 'api_key'
            }
        }
    )
    
    # ✓ GOOD: Log authorization decisions
    logger.info(
        "Access denied",
        extra={
            'extra_data': {
                'user_id': 'user456',
                'requested_resource': '/admin/tools',
                'reason': 'insufficient_permissions'
            }
        }
    )
    
    # ✓ GOOD: Log tool usage (sanitized)
    logger.info(
        "Tool executed",
        extra={
            'extra_data': {
                'tool_name': 'redteam_reverse_shell',
                'user_id': 'user123',
                'target_approved': True
            }
        }
    )
    
    # ✗ BAD: Don't log sensitive payload contents
    # logger.info(f"Generated payload: {actual_payload_content}")  # Don't do this!
    
    # ✓ GOOD: Log metadata about payload, not the payload itself
    logger.info(
        "Payload generated",
        extra={
            'extra_data': {
                'payload_type': 'web_shell',
                'payload_size_bytes': 2048,
                'obfuscation_method': 'base64'
            }
        }
    )
    
    print("✓ Security-focused logging examples completed\n")


def main():
    """Run all examples."""
    print("=" * 60)
    print("Red Team MCP Server - Secure Logging Examples")
    print("=" * 60)
    
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    try:
        example_basic_logging()
        example_sensitive_data_sanitization()
        example_correlation_ids()
        example_structured_logging()
        example_exception_logging()
        example_security_best_practices()
        
        print("=" * 60)
        print("All examples completed successfully!")
        print("Check logs/example.log and logs/app.log for output")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
