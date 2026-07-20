#!/usr/bin/env python3
"""
Example script demonstrating secure logging practices.

This script shows how to use the secure logger in various scenarios
and demonstrates what gets masked vs what doesn't.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.utils.secure_logger import (
    get_secure_logger,
    mask_sensitive_data,
    get_correlation_id_logger,
    setup_root_logger
)
import uuid


def example_basic_logging():
    """Example of basic secure logging."""
    print("\n" + "="*60)
    print("Example 1: Basic Secure Logging")
    print("="*60)
    
    logger = get_secure_logger(__name__)
    
    # Safe logging - no sensitive data
    logger.info("Application started successfully")
    logger.debug("Configuration loaded from config.yml")
    
    # This will be masked automatically
    logger.info("User authentication: username=admin password=secret123")
    logger.info("API key configuration: api_key=sk-1234567890abcdef")
    
    print("\n✅ Notice how password and api_key are masked in the logs above")


def example_structured_logging():
    """Example of structured logging with extra fields."""
    print("\n" + "="*60)
    print("Example 2: Structured Logging")
    print("="*60)
    
    logger = get_secure_logger(__name__)
    
    # Good: Structured logging with safe data
    logger.info(
        "User login attempt",
        extra={
            "username": "john_doe",
            "ip_address": "192.168.1.100",
            "success": True,
            "timestamp": "2025-01-15T10:30:00Z"
        }
    )
    
    # Sensitive data in structured format
    user_data = {
        "username": "admin",
        "password": "secret123",  # Will be masked
        "email": "admin@example.com",
        "role": "administrator"
    }
    
    safe_data = mask_sensitive_data(user_data)
    logger.info(f"User data loaded: {safe_data}")
    
    print("\n✅ Notice how sensitive fields are masked in the dictionary")


def example_correlation_id():
    """Example of correlation ID logging for distributed tracing."""
    print("\n" + "="*60)
    print("Example 3: Correlation ID Logging")
    print("="*60)
    
    correlation_id = str(uuid.uuid4())
    logger = get_correlation_id_logger(__name__, correlation_id)
    
    # All logs will automatically include the correlation ID
    logger.info("Request received")
    logger.debug("Processing payload")
    logger.info("Request completed")
    
    print(f"\n✅ All logs include correlation_id: {correlation_id}")


def example_error_logging():
    """Example of error logging with stack traces."""
    print("\n" + "="*60)
    print("Example 4: Error Logging")
    print("="*60)
    
    logger = get_secure_logger(__name__)
    
    try:
        # Simulate an error
        result = 1 / 0
    except ZeroDivisionError as e:
        # Log the error with stack trace
        logger.error("Division error occurred", exc_info=True)
        
        # Or log with context
        logger.error(
            "Error processing request",
            extra={
                "error_type": type(e).__name__,
                "error_message": str(e),
                "operation": "calculate_result"
            }
        )
    
    print("\n✅ Errors are logged with context but without sensitive data")


def example_security_sensitive_operations():
    """Example of logging security-sensitive operations."""
    print("\n" + "="*60)
    print("Example 5: Security-Sensitive Operations")
    print("="*60)
    
    logger = get_secure_logger(__name__)
    
    # Simulating a security operation
    target = "192.168.1.10"
    operation = "reverse_shell"
    
    # Log the operation (never log credentials/keys)
    logger.warning(
        f"Security tool executed: {operation}",
        extra={
            "tool": operation,
            "target": target,
            "authorized": True,
            "user": "security_team"
        }
    )
    
    # Bad practice - don't do this!
    # logger.info(f"Connecting with password: {password}")  # ❌
    
    # Good practice - log outcome without credentials
    logger.info(
        "Connection established",
        extra={
            "target": target,
            "method": "ssh",
            "status": "success"
        }
    )
    
    print("\n✅ Security operations logged without exposing credentials")


def example_configuration_logging():
    """Example of safely logging configuration."""
    print("\n" + "="*60)
    print("Example 6: Configuration Logging")
    print("="*60)
    
    logger = get_secure_logger(__name__)
    
    # Simulated configuration
    config = {
        "server": {
            "host": "0.0.0.0",
            "port": 3001,
            "debug": True
        },
        "database": {
            "host": "localhost",
            "port": 5432,
            "database": "redteam_db",
            "username": "admin",
            "password": "super_secret_password"  # Will be masked
        },
        "api": {
            "endpoint": "https://api.example.com",
            "api_key": "sk-1234567890abcdef",  # Will be masked
            "timeout": 30
        }
    }
    
    # Mask sensitive data before logging
    safe_config = mask_sensitive_data(config)
    logger.info(f"Configuration loaded: {safe_config}")
    
    print("\n✅ Configuration logged with sensitive fields masked")


def example_performance_logging():
    """Example of performance/timing logging."""
    print("\n" + "="*60)
    print("Example 7: Performance Logging")
    print("="*60)
    
    import time
    logger = get_secure_logger(__name__)
    
    operation_name = "payload_generation"
    start_time = time.time()
    
    # Simulate operation
    time.sleep(0.1)
    
    duration_ms = (time.time() - start_time) * 1000
    
    logger.info(
        f"Operation completed: {operation_name}",
        extra={
            "operation": operation_name,
            "duration_ms": duration_ms,
            "status": "success"
        }
    )
    
    print("\n✅ Performance metrics logged without sensitive data")


def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("Secure Logging Examples")
    print("="*60)
    print("\nThese examples demonstrate secure logging practices")
    print("and how sensitive data is automatically masked.")
    
    # Setup root logger
    setup_root_logger(level='DEBUG')
    
    # Run examples
    example_basic_logging()
    example_structured_logging()
    example_correlation_id()
    example_error_logging()
    example_security_sensitive_operations()
    example_configuration_logging()
    example_performance_logging()
    
    print("\n" + "="*60)
    print("Examples completed!")
    print("="*60)
    print("\n📝 Key Takeaways:")
    print("  1. Sensitive data (passwords, keys, tokens) is automatically masked")
    print("  2. Use structured logging with 'extra' parameter for better analysis")
    print("  3. Use correlation IDs for distributed tracing")
    print("  4. Log errors with context but never with credentials")
    print("  5. Always mask configuration before logging")
    print("\n⚠️  Remember: When in doubt, don't log it!")
    print("\n")


if __name__ == "__main__":
    main()
