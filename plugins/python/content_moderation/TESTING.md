# Testing the Content Moderation Plugin

This document describes how to develop, test, and validate the Content Moderation Plugin.

## Quick Start

### Prerequisites

- Python 3.11+
- `uv` package manager

### Development Setup

```bash
cd plugins/python/content_moderation
uv sync --dev          # Install dependencies
make test-all          # Run all tests with coverage
```

## Test Structure

The test suite is organized into the following categories:

### 1. **Configuration Tests** (`TestModerationConfig`)
- Tests configuration validation
- Tests default values
- Tests threshold bounds validation
- Tests optional provider configurations

### 2. **Pattern Matching Tests** (`TestPatternMatching`)
- Tests profanity detection
- Tests hate speech detection
- Tests violence detection
- Tests self-harm detection
- Tests harassment detection
- Tests case-insensitive matching
- Tests clean content passes through

### 3. **Moderation Actions Tests** (`TestModerationActions`)
- Tests BLOCK action removes content
- Tests REDACT action replaces content
- Tests WARN action returns original
- Tests TRANSFORM action filters problematic content

### 4. **Content Extraction Tests** (`TestContentExtraction`)
- Tests text extraction from simple strings
- Tests extraction from nested dictionaries
- Tests filtering of short texts

### 5. **Hook Implementation Tests**
- **`TestPromptPreFetchHook`**: Tests prompt pre-fetch hook behavior
- **`TestToolPreInvokeHook`**: Tests tool pre-invoke hook behavior
- **`TestToolPostInvokeHook`**: Tests tool post-invoke hook behavior

### 6. **Caching Tests** (`TestCaching`)
- Tests cache stores results
- Tests cache can be disabled
- Tests cache key generation

### 7. **Text Length Tests** (`TestMaxTextLength`)
- Tests long text truncation
- Tests max_text_length enforcement

### 8. **Fallback Provider Tests** (`TestFallbackProvider`)
- Tests fallback provider used on primary failure
- Tests cascade fallback to pattern matching

### 9. **Context Manager Tests** (`TestAsyncContextManager`)
- Tests plugin cleanup on exit
- Tests HTTP client resource management

### 10. **Model Tests** (`TestModerationResult`, `TestEnumTypes`)
- Tests result model validation
- Tests enum types and values

## Running Tests

### Run All Tests

```bash
make test-all
```

This runs all tests with coverage reporting.

### Run Tests Only (No Coverage)

```bash
make test
```

### Run Tests with Verbose Output

```bash
make test-verbose
```

### Run Specific Test File

```bash
uv run pytest tests/test_content_moderation.py -v
```

### Run Specific Test Class

```bash
uv run pytest tests/test_content_moderation.py::TestPatternMatching -v
```

### Run Specific Test Function

```bash
uv run pytest tests/test_content_moderation.py::TestPatternMatching::test_profanity_detection -v
```

### Run with Coverage Report

```bash
uv run pytest tests/ --cov=cpex_content_moderation --cov-report=term-missing
```

### Run with Coverage HTML Report

```bash
uv run pytest tests/ --cov=cpex_content_moderation --cov-report=html
open htmlcov/index.html
```

## Code Quality

### Format Code

```bash
make fmt
```

### Check Formatting (CI)

```bash
make fmt-check
```

### Run Linter

```bash
make lint
```

### Type Checking

```bash
make type-check
```

### Run All Checks

```bash
make check-all
```

This runs: fmt-check, lint, type-check, and all tests.

## CI/CD Integration

### Full CI Verification

```bash
make ci
```

This runs all checks and verifies the plugin can be imported successfully.

### Pre-commit Hook

```bash
make pre-commit
```

This runs: fmt, lint, and tests (good for local pre-commit setup).

## Debugging Tests

### Run Tests with Print Output

```bash
uv run pytest tests/ -v -s
```

### Run Tests with Full Traceback

```bash
uv run pytest tests/ -v --tb=long
```

### Run Tests with PDB Debugger

```bash
uv run pytest tests/ -v --pdb
```

### Run Tests with PDB on Failure

```bash
uv run pytest tests/ -v --pdb-trace
```

## Test Dependencies

Test dependencies are defined in `pyproject.toml` under `dependency-groups.dev`:

- `pytest>=8.0` - Testing framework
- `pytest-asyncio>=0.23` - Async test support
- `pytest-cov>=4.0` - Coverage reporting
- `pytest-mock>=3.10` - Mocking utilities
- `black>=23.0` - Code formatter
- `isort>=5.12` - Import sorter
- `ruff>=0.1.0` - Linter
- `mypy>=1.0` - Type checker

## Mocking and Testing External Providers

The test suite uses `unittest.mock` to mock external API calls:

```python
@pytest.mark.asyncio
async def test_ibm_watson_integration():
    """Test IBM Watson provider with mocked HTTP calls."""
    plugin = make_plugin()
    
    with patch.object(plugin._client, 'post') as mock_post:
        mock_post.return_value = AsyncMock()
        mock_post.return_value.json.return_value = {
            "emotion": {"document": {"emotion": {"anger": 0.8}}}
        }
        
        result = await plugin._moderate_with_ibm_watson("test content")
        
        assert result.provider == ModerationProvider.IBM_WATSON
```

## Coverage Requirements

Aim for at least 80% code coverage:

```bash
make test-all
# Check the "TOTAL" line in the coverage report
```

## Testing New Features

When adding new features:

1. Write tests first (TDD approach)
2. Implement the feature
3. Ensure all tests pass
4. Run full check suite: `make check-all`
5. Generate coverage: `make test-all`

## Known Issues and Limitations

- Mock provider tests assume the provider API contract remains stable
- Integration tests with real providers (Watson, OpenAI) require API keys and may incur costs
- Performance tests are not yet implemented

## Contributing Tests

When contributing tests:

1. Follow the existing test structure and naming conventions
2. Use descriptive test names that explain what is being tested
3. Include docstrings explaining the test purpose
4. Use fixtures for setup and teardown
5. Mock external dependencies (HTTP calls, file I/O, etc.)
6. Aim for isolated, independent tests
7. Test both happy path and error cases

## Integration Testing

For integration testing with real provider APIs:

1. Set environment variables for provider credentials:
   ```bash
   export IBM_WATSON_API_KEY=your_key
   export IBM_WATSON_URL=your_url
   export OPENAI_API_KEY=your_key
   ```

2. Run integration tests (marked with `@pytest.mark.integration`):
   ```bash
   uv run pytest tests/ -v -m integration
   ```

## Performance Testing

To measure plugin performance:

```bash
uv run pytest tests/ -v --durations=10
```

This shows the 10 slowest tests.

## Troubleshooting

### Import Errors

If you get import errors, ensure you're in the correct directory and have run `uv sync`:

```bash
cd plugins/python/content_moderation
uv sync --dev
```

### Async Test Issues

If async tests fail with event loop errors, ensure `pytest-asyncio` is installed:

```bash
uv sync --dev
```

### Mock Not Working

Ensure you're patching at the right location:

```python
# Correct
with patch('cpex_content_moderation.content_moderation.httpx.AsyncClient'):
    ...

# Wrong (patch where it's imported from)
with patch('httpx.AsyncClient'):
    ...
```

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://github.com/pytest-dev/pytest-asyncio)
- [unittest.mock](https://docs.python.org/3/library/unittest.mock.html)
- [Coverage.py](https://coverage.readthedocs.io/)

This guide covers comprehensive testing strategies for the Content Moderation Plugin including unit tests, integration tests, and manual testing with various AI providers.

## Test Structure

```
tests/unit/mcpgateway/plugins/plugins/content_moderation/
├── test_content_moderation.py              # Unit tests
├── test_content_moderation_integration.py  # Integration tests
└── __init__.py                             # Test package init
```

## 1. Unit Tests

### Running Unit Tests
```bash
# Run all content moderation tests
pytest tests/unit/mcpgateway/plugins/plugins/content_moderation/ -v

# Run specific test file
pytest tests/unit/mcpgateway/plugins/plugins/content_moderation/test_content_moderation.py -v

# Run with coverage
pytest tests/unit/mcpgateway/plugins/plugins/content_moderation/ --cov=plugins.content_moderation --cov-report=html
```

### Unit Test Coverage
- ✅ Plugin initialization and configuration
- ✅ IBM Watson NLU moderation
- ✅ IBM Granite Guardian moderation
- ✅ OpenAI moderation API
- ✅ Pattern-based fallback moderation
- ✅ Content caching functionality
- ✅ Text extraction from payloads
- ✅ Moderation action application
- ✅ Error handling and fallbacks
- ✅ Category threshold evaluation
- ✅ Audit logging functionality

## 2. Integration Tests

### Running Integration Tests
```bash
# Run integration tests with plugin manager
pytest tests/unit/mcpgateway/plugins/plugins/content_moderation/test_content_moderation_integration.py -v
```

### Integration Test Scenarios
- ✅ Plugin manager initialization with content moderation
- ✅ End-to-end content moderation through hooks
- ✅ Fallback provider handling
- ✅ Multi-provider configurations
- ✅ Content blocking and redaction workflows

## 3. Manual Testing

### Prerequisites

#### For IBM Granite Guardian Testing
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull Granite Guardian model
ollama pull granite3-guardian

# Verify model is available
ollama list
```

#### For IBM Watson NLU Testing
```bash
# Set environment variables
export IBM_WATSON_API_KEY="your-api-key"
export IBM_WATSON_URL="https://api.us-south.natural-language-understanding.watson.cloud.ibm.com"
```

#### For OpenAI Testing
```bash
# Set environment variables
export OPENAI_API_KEY="your-openai-api-key"
```

### Testing Approach 1: Pattern-Based Fallback (No API Keys Required)

1. **Configure Plugin for Pattern Testing**:
```yaml
# Update plugins/config.yaml
- name: "ContentModeration"
  config:
    provider: "ibm_watson"  # Will fallback to patterns when API fails
    fallback_provider: null
    fallback_on_error: "warn"
    # Don't set ibm_watson config - will force fallback to patterns
```

2. **Start Gateway**:
```bash
cd /Users/mg/mg-work/manav/work/ai-experiments/mcp-context-forge
export PLUGINS_ENABLED=true
export AUTH_REQUIRED=false
make dev
```

3. **Test Content Moderation**:
```bash
# Test hate speech detection
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "test_tool",
      "arguments": {"query": "I hate all those racist people"}
    }
  }'

# Test violence detection
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "call_tool",
    "params": {
      "name": "search",
      "arguments": {"query": "I am going to kill you"}
    }
  }'

# Test profanity detection
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "call_tool",
    "params": {
      "name": "search",
      "arguments": {"query": "This fucking thing does not work"}
    }
  }'

# Test clean content (should pass)
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "call_tool",
    "params": {
      "name": "search",
      "arguments": {"query": "What is the weather like today?"}
    }
  }'
```

### Testing Approach 2: IBM Granite Guardian (Local)

1. **Ensure Ollama is Running**:
```bash
# Start Ollama (if not already running)
ollama serve

# Test Granite model
ollama run granite3-guardian "Analyze this text for harmful content: I hate everyone"
```

2. **Configure Plugin for Granite**:
```yaml
# Update plugins/config.yaml
- name: "ContentModeration"
  config:
    provider: "ibm_granite"
    ibm_granite:
      ollama_url: "http://localhost:11434"
      model: "granite3-guardian"
      temperature: 0.1
```

3. **Test with Granite**:
```bash
# Test various content types
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "analyze",
      "arguments": {"text": "I want to hurt myself and end it all"}
    }
  }'
```

### Testing Approach 3: IBM Watson NLU (API Key Required)

1. **Set Environment Variables**:
```bash
export IBM_WATSON_API_KEY="your-api-key"
export IBM_WATSON_URL="your-watson-url"
```

2. **Configure Plugin**:
```yaml
# Update plugins/config.yaml
- name: "ContentModeration"
  config:
    provider: "ibm_watson"
    ibm_watson:
      api_key: "${env.IBM_WATSON_API_KEY}"
      url: "${env.IBM_WATSON_URL}"
      version: "2022-04-07"
```

3. **Test Watson Integration**:
```bash
# Test emotional content analysis
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "sentiment_analysis",
      "arguments": {"text": "I am so angry at this terrible situation"}
    }
  }'
```

### Testing Approach 4: OpenAI Moderation (API Key Required)

1. **Set Environment Variables**:
```bash
export OPENAI_API_KEY="your-openai-api-key"
```

2. **Configure Plugin**:
```yaml
# Update plugins/config.yaml
- name: "ContentModeration"
  config:
    provider: "openai"
    openai:
      api_key: "${env.OPENAI_API_KEY}"
      model: "text-moderation-latest"
```

3. **Test OpenAI Integration**:
```bash
# Test OpenAI moderation
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "content_check",
      "arguments": {"message": "I want to kill all politicians"}
    }
  }'
```

## 4. Testing Different Actions

### Testing Block Action
```yaml
categories:
  hate:
    threshold: 0.5  # Lower threshold for easier testing
    action: "block"
```

```bash
# Should be blocked
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "test",
      "arguments": {"query": "I hate everyone"}
    }
  }'
```

### Testing Redact Action
```yaml
categories:
  profanity:
    threshold: 0.5
    action: "redact"
```

```bash
# Content should be redacted
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "test",
      "arguments": {"query": "This damn thing is broken"}
    }
  }'
```

### Testing Warn Action
```yaml
categories:
  toxic:
    threshold: 0.5
    action: "warn"
```

```bash
# Should continue but log warning
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "test",
      "arguments": {"query": "You are such an idiot"}
    }
  }'
```

## 5. Testing Webhook Integration

If you have the webhook plugin enabled, content moderation violations should trigger webhook notifications:

1. **Enable Both Plugins**:
```yaml
plugins:
  - name: "ContentModeration"
    # ... config
  - name: "WebhookNotification"
    # ... config with harmful_content event
```

2. **Test Violation Webhook**:
```bash
# This should trigger both moderation and webhook
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call_tool",
    "params": {
      "name": "test",
      "arguments": {"query": "violent harmful content here"}
    }
  }'
```

3. **Check webhook.site** for notifications with:
   - Event type: "harmful_content" or "violation"
   - Moderation details in metadata

## 6. Performance Testing

### Load Testing Content Moderation
```python
import asyncio
import aiohttp

async def test_concurrent_moderation():
    """Test concurrent content moderation requests."""

    test_contents = [
        "This is clean content",
        "I hate this stupid thing",
        "What is the weather today?",
        "This damn computer is broken",
        "I want to hurt someone",
    ]

    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, content in enumerate(test_contents * 20):  # 100 total requests
            payload = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "call_tool",
                "params": {
                    "name": "test",
                    "arguments": {"query": content}
                }
            }

            task = session.post(
                'http://localhost:8000/',
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            tasks.append(task)

        # Execute concurrently
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        print(f"Completed {len(responses)} requests")
        print(f"Successful: {len([r for r in responses if not isinstance(r, Exception)])}")

# Run the test
asyncio.run(test_concurrent_moderation())
```

## 7. Error Scenario Testing

### Testing Provider Failures
```yaml
# Set invalid configuration to test fallback
ibm_watson:
  api_key: "invalid-key"
  url: "https://invalid-url.com"
```

### Testing Network Timeouts
```yaml
# Set very short timeout
ibm_watson:
  timeout: 1  # 1 second - may cause timeouts
```

### Testing Content Size Limits
```bash
# Test with very large content
large_content=$(python -c "print('test content ' * 1000)")
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 1,
    \"method\": \"call_tool\",
    \"params\": {
      \"name\": \"test\",
      \"arguments\": {\"query\": \"$large_content\"}
    }
  }"
```

## 8. Monitoring and Debugging

### Enable Debug Logging
```bash
export LOG_LEVEL=DEBUG
make dev

# Look for content moderation logs
tail -f logs/mcpgateway.log | grep -i moderation
```

### Check Plugin Status
```bash
# Verify plugin is loaded
curl http://localhost:8000/health
```

### Audit Trail Analysis
```bash
# Check audit logs for moderation decisions
grep "Content moderation" logs/mcpgateway.log | jq .
```

## 9. Test Data Sets

### Harmful Content Samples
```python
HATE_SPEECH_SAMPLES = [
    "I hate all people from that country",
    "Those people should not exist",
    "All [group] are terrible people"
]

VIOLENCE_SAMPLES = [
    "I'm going to kill you",
    "Let's bomb that building",
    "How to make weapons"
]

SELF_HARM_SAMPLES = [
    "I want to kill myself",
    "Life is not worth living",
    "How to end it all"
]

PROFANITY_SAMPLES = [
    "This fucking system sucks",
    "What the hell is wrong",
    "Damn this stupid thing"
]

CLEAN_CONTENT_SAMPLES = [
    "What is the weather today?",
    "How do I learn programming?",
    "Can you help me with math?"
]
```

### Edge Cases
```python
EDGE_CASES = [
    "",  # Empty content
    "a" * 50000,  # Very long content
    "Mixed clean and I hate everyone together",  # Mixed content
    "Context matters: 'I hate' is in this quote",  # Quoted content
    "Medical: patient shows self-harm ideation",  # Medical context
]
```

## 10. CI/CD Integration

### GitHub Actions Test
```yaml
name: Content Moderation Tests
on: [push, pull_request]

jobs:
  test-content-moderation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: make venv install-dev

      - name: Install Ollama for Granite testing
        run: |
          curl -fsSL https://ollama.com/install.sh | sh
          ollama pull granite3-guardian

      - name: Run unit tests
        run: |
          pytest tests/unit/mcpgateway/plugins/plugins/content_moderation/ -v --cov

      - name: Run integration tests
        run: |
          pytest tests/unit/mcpgateway/plugins/plugins/content_moderation/test_content_moderation_integration.py -v
```

## Summary

This comprehensive testing guide ensures the Content Moderation Plugin works correctly across all supported providers and scenarios. The plugin provides robust content safety with multiple fallback layers, making it suitable for production environments requiring reliable content moderation.
