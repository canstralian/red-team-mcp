# Examples Directory

This directory contains example scripts and demonstrations for the Red Team MCP Server.

## Available Examples

### secure_logging_demo.py

Demonstrates secure logging practices with the Red Team MCP Server:

**Features:**
- Basic secure logging setup
- Automatic sanitization of sensitive data (passwords, tokens, API keys)
- Correlation IDs for request tracing
- Structured JSON logging
- Exception logging with stack traces
- Security best practices for logging

**Usage:**
```bash
# Run from repository root
python3 examples/secure_logging_demo.py

# Check the generated logs
cat logs/example.log | jq .
cat logs/app.log | jq .
```

**What it demonstrates:**

1. **Basic Logging**: Different log levels (DEBUG, INFO, WARNING, ERROR)
2. **Automatic Sanitization**: Sensitive data like passwords and tokens are automatically redacted
3. **Correlation IDs**: Track requests across multiple log entries
4. **Structured Data**: Log with additional context in JSON format
5. **Exception Handling**: Proper exception logging with stack traces
6. **Security Best Practices**: What to log and what not to log

**Example Output:**
```json
{
  "timestamp": "2025-11-02T20:46:00.882670Z",
  "level": "INFO",
  "logger": "example_structured",
  "message": "Payload generated",
  "module": "secure_logging_demo",
  "function": "example_structured_logging",
  "line": 98,
  "correlation_id": "req-abc-123",
  "extra": {
    "payload_type": "reverse_shell",
    "shell_type": "bash",
    "target_port": 4444,
    "encoding": "base64",
    "user_id": "user123"
  }
}
```

## Adding New Examples

When adding new examples:

1. Create a new Python file in this directory
2. Include clear docstrings explaining what the example demonstrates
3. Add usage instructions
4. Update this README with a description of your example
5. Ensure examples follow security best practices
6. Make scripts executable: `chmod +x examples/your_example.py`

## Security Considerations

⚠️ **IMPORTANT**: All examples are for authorized security testing only.

- Never use examples on systems without explicit written permission
- Examples demonstrate security tools and techniques
- Always sanitize logs before sharing
- Review generated payloads before using in production
- Follow responsible disclosure practices

## Getting Help

For more information:
- See the main [Debugging Guide](../docs/debugging-guide.md)
- Check the [README](../README.md) for project overview
- Review [SECURITY.md](../SECURITY.md) for security policies

## Contributing

To contribute new examples:

1. Ensure your example is well-documented
2. Include error handling and security considerations
3. Test thoroughly before submitting
4. Follow the existing code style
5. Update this README

---

**Last Updated:** November 2025
