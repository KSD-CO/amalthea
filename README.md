# <img src="https://amalthea.cloud/amalthea.png" alt="Amalthea" width="75px"> Amalthea

[![Crates.io](https://img.shields.io/crates/v/amalthea.svg)](https://crates.io/crates/amalthea)
[![Docker](https://img.shields.io/badge/docker-ksdco%2Famalthea-blue.svg)](https://hub.docker.com/r/ksdco/amalthea)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-blue.svg)](https://www.rust-lang.org)

**Amalthea** - AI-powered API testing tool with comprehensive test generation, execution, and security scanning capabilities!

## 🚀 **Production Ready v0.2.5**

✅ **Multi-Provider AI Support**: OpenAI, Anthropic Claude, Google Gemini, Local models (Ollama)  
✅ **Test Generation & Execution**: Generate test cases AND execute them automatically  
✅ **Security Testing**: Comprehensive vulnerability scanning with detailed reports  
✅ **Test Data Fuzzing**: Advanced fuzzing with 20+ strategies for security vulnerability testing  
✅ **Universal AI Client**: Unified interface for all AI providers  
✅ **Postman Collections**: Full support for Postman collection imports  
✅ **Smart Date Generation**: Automatic current date injection in test data (no more 2023 dates!)  
✅ **Docker Ready**: `docker pull ksdco/amalthea:0.2.5`  

## ✨ Features

- 🤖 **Multi-Provider AI Support** - OpenAI, Anthropic Claude, Google Gemini, Local models (Ollama)
- 🧪 **Test Generation & Execution** - Generate comprehensive test cases and execute them automatically
- 🛡️ **Security Testing** - Built-in security vulnerability scanning (SQL injection, XSS, auth bypass, rate limiting, security headers, etc.)
- 🎯 **Test Data Fuzzing** - Advanced fuzzing with 20+ strategies including SQL injection, XSS, buffer overflow, unicode attacks, and malicious payloads for comprehensive security testing
- 📊 **Knowledge Base Integration** - Custom knowledge bases with valid data patterns and examples for realistic test generation
- 📊 **Execution Reports** - Detailed pass/fail results with comprehensive statistics
- 🔍 **Smart URL Detection** - Automatic base URL extraction from OpenAPI specs and Postman collections
- 📝 **OpenAPI/Swagger Support** - Full OpenAPI 3.0 and 2.0 specification support
- 📮 **Postman Collection Support** - Import and test from Postman Collections with variable support
- 🔄 **Universal AI Client** - Unified interface routing to appropriate AI providers
- 📅 **Smart Date Generation** - Automatic current date injection in test data (no more 2023 dates!)
- � **HTML Reports** - Beautiful interactive reports with charts and visualizations
- �💰 **Cost Optimization** - Per-endpoint processing to avoid token limits and save costs
- 🐳 **Docker Ready** - Available on Docker Hub as `ksdco/amalthea`
- ⚡ **Fast & Reliable** - Built with Rust for maximum performance
- 🏗️ **Professional Architecture** - Modular, maintainable codebase

## 📋 Version History & New Features

### 🎉 v0.2.5 - Current (October 2025)
- 🎯 **Advanced Test Data Fuzzing** - Comprehensive fuzzing with 5 intensity levels and 20+ strategies
- 🛡️ **Enhanced Security Testing** - Comprehensive vulnerability scanning with 8+ security checks  
- 🔀 **Fuzzing vs Security Distinction** - Clear separation between robustness testing and vulnerability detection
- 🎲 **Configurable Fuzzing Intensity** - 5 levels from light (CI/CD) to extreme (stress testing)
- 🔍 **Smart URL Detection** - Automatic base URL extraction from OpenAPI specs and Postman collections
- 📮 **Advanced Postman Support** - Full Postman Collection v2.0+ support with variable handling
- 🔄 **Universal AI Client** - Unified interface routing to all AI providers automatically
- 📅 **Smart Date Generation** - Automatic current date injection (2025+ dates, not 2023!)
- 🧪 **Enhanced Test Generation** - 8-12 comprehensive test cases per endpoint (vs 3-5 previously)
- 📊 **HTML Reports** - Beautiful interactive reports with charts and security dashboards
- 🛠️ **Improved Error Handling** - Better error messages and graceful fallbacks
- 📊 **Enhanced Reporting** - Detailed security vulnerability reports with severity levels

### 🚀 v0.2.4 - Previous Release
- 🛡️ **Enhanced Security Testing** - Comprehensive vulnerability scanning with 8+ security checks
- 🎯 **Test Data Fuzzing** - Advanced fuzzing system with 20+ strategies for security vulnerability testing
- 🔍 **Smart URL Detection** - Automatic base URL extraction from OpenAPI specs and Postman collections
- 📮 **Advanced Postman Support** - Full Postman Collection v2.0+ support with variable handling
- 🔄 **Universal AI Client** - Unified interface routing to all AI providers automatically
- 📅 **Smart Date Generation** - Automatic current date injection (2025+ dates, not 2023!)
- 🧪 **Enhanced Test Generation** - 8-12 comprehensive test cases per endpoint (vs 3-5 previously)
- 📊 **HTML Reports** - Beautiful interactive reports with charts and security dashboards
- 🛠️ **Improved Error Handling** - Better error messages and graceful fallbacks
- 📊 **Enhanced Reporting** - Detailed security vulnerability reports with severity levels

### 🚀 v0.2.2 - Previous Release
- 🤖 **Multi-Provider AI Support** - Added support for OpenAI, Anthropic Claude, Google Gemini, Local models
- 🧪 **Test Generation & Execution** - Combined test generation with automatic execution
- 📝 **OpenAPI/Swagger Support** - Full OpenAPI 3.0 and 2.0 specification support
- 🐳 **Docker Integration** - Complete Docker support with automated builds

### 🌟 v0.2.1 - Foundation Release
- ⚡ **Core Architecture** - Built with Rust for maximum performance
- 💰 **Cost Optimization** - Per-endpoint processing to save API costs
- 📊 **Execution Reports** - Pass/fail statistics and detailed results
- 🏗️ **Professional Codebase** - Modular, maintainable architecture

## 📅 Smart Date Generation

Amalthea automatically injects current dates into test data to avoid outdated timestamps:

**Before (v0.2.2):**
```json
{
  "dateRange": {
    "start": "2023-01-01",
    "end": "2023-12-31"
  }
}
```

**After (v0.2.4):**
```json
{
  "dateRange": {
    "start": "2025-01-01", 
    "end": "2026-12-31"
  }
}
```

**Features:**
- 🗓️ **Current Year Injection** - Uses actual current year (2025+)
- 📈 **Date Range Intelligence** - Current year to next year ranges
- ⏰ **ISO Timestamp Support** - Realistic current timestamps
- 🔄 **Dynamic Updates** - Always uses current date, never hardcoded

## 🎯 Test Data Fuzzing vs Security Testing

Amalthea provides two distinct but complementary testing approaches:

### 🎲 Fuzzing (`--fuzz`) - API Robustness Testing

**Purpose:** Test API stability and robustness with random/malformed data

**What it does:**
- Generates random, oversized, or malformed data to stress-test APIs
- Tests how APIs handle unexpected input gracefully
- Finds crashes, errors, and edge cases in data processing
- Validates input validation and error handling logic

**Example fuzz data:**
```json
{
  "invoice_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA...",  // Extremely long strings
  "amount": 999999999999999999,                    // Boundary values
  "items": [null, null, null, ...],               // Unexpected nulls
  "🔥🔥🔥": "unicode_data",                         // Unicode/emoji
  "nested": {"very": {"deep": {"object": "test"}}} // Deep nesting
}
```

**Intensity Levels (1-5):**
- **Level 1**: Light fuzzing (2-3 test cases per endpoint)
- **Level 2**: Moderate fuzzing (3-5 test cases)  
- **Level 3**: Standard fuzzing (5-7 test cases) - Default
- **Level 4**: Heavy fuzzing (7-10 test cases)
- **Level 5**: Extreme fuzzing (10+ test cases)

### 🛡️ Security Testing (`--security`) - Vulnerability Detection

**Purpose:** Detect specific security vulnerabilities and attack vectors

**What it does:**
- Tests for known security vulnerabilities (OWASP Top 10)
- Uses crafted payloads to detect injection attacks
- Validates authentication and authorization controls
- Checks security headers and configurations

**Example security payloads:**
```json
{
  "username": "' OR '1'='1",                       // SQL injection
  "comment": "<script>alert('XSS')</script>",      // XSS attack
  "file_path": "../../../etc/passwd",              // Path traversal
  "command": "; ls -la",                           // Command injection
  "ldap_query": ")(cn=*))(|(cn=*"                  // LDAP injection
}
```

**Security Test Categories:**
- 💉 **Injection Attacks** - SQL, NoSQL, LDAP, XPath injection
- 🚨 **Cross-Site Scripting (XSS)** - Reflected, stored, DOM-based XSS
- 💻 **Command Injection** - OS command execution attempts
- 📂 **Path Traversal** - Directory traversal and file access
- 🔐 **Authentication Bypass** - Token validation, session handling
- 📋 **Security Headers** - Missing security headers check
- ⏱️ **Rate Limiting** - Brute force and DoS protection

### 🤝 When to Use What

| Scenario | Recommended Approach |
|----------|---------------------|
| **Development Testing** | `--fuzz --fuzz-intensity 2` |
| **Security Audit** | `--security` |
| **Pre-Production** | `--fuzz --security` (both) |
| **CI/CD Pipeline** | `--fuzz --fuzz-intensity 1 --security` |
| **Stress Testing** | `--fuzz --fuzz-intensity 4-5` |
| **Compliance Check** | `--security` |

### 🔗 Combining Both (Recommended)

```bash
# Comprehensive testing with both fuzzing and security
cargo run -- --file api.json --fuzz --fuzz-intensity 3 --security --generate-only

# Light testing for CI/CD
cargo run -- --file api.json --fuzz --fuzz-intensity 1 --security --generate-only

# Heavy stress + security testing
cargo run -- --file api.json --fuzz --fuzz-intensity 5 --security --kb knowledge-base.json
```

## 🎯 Test Data Fuzzing

Amalthea includes advanced fuzzing capabilities to test API robustness and security with comprehensive vulnerability testing:

### Fuzzing Strategies

**Data Generation (20+ Strategies):**
- 🔤 **String Fuzzing** - Special characters, encoding attacks, format strings
- 🔢 **Number Fuzzing** - Boundary values, overflow attempts, invalid formats
- 📝 **JSON Fuzzing** - Malformed structures, type confusion, nested attacks
- 🌐 **Unicode Fuzzing** - Multi-byte sequences, normalization attacks
- 📊 **Array Fuzzing** - Size attacks, type mixing, nested structures

**Security-Focused Fuzzing (12+ Vulnerability Types):**
- 💉 **SQL Injection** - Various SQL attack vectors and bypasses
- 🚨 **XSS (Cross-Site Scripting)** - Script injection and encoding bypasses
- 💻 **Command Injection** - OS command execution attempts
- 📂 **Path Traversal** - Directory traversal and file access attacks
- 📊 **Buffer Overflow** - Memory corruption and boundary attacks
- 🔗 **LDAP/XPath Injection** - Directory and XML query attacks
- 📋 **Template Injection** - Server-side template attacks
- 🌐 **Header Injection** - HTTP header manipulation
- 🔄 **Type Confusion** - Data type mismatch attacks
- 📦 **Deserialization** - Object deserialization vulnerabilities

### Fuzzing Usage

```bash
# Enable fuzzing mode
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz

# Fuzzing with custom intensity (1-5, default: 3)
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --fuzz-intensity 5

# Fuzzing with security testing
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --security

# Fuzzing with knowledge base for realistic base data
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --kb knowledge-base.json

# Generate fuzzing data only (no execution)
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --generate-only

# Fuzzing with HTML report
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --security --html-report
```

### Fuzzing Benefits

- 🛡️ **Security Hardening** - Discover vulnerabilities before attackers do
- 🔍 **Edge Case Discovery** - Find unexpected API behaviors and crashes  
- 📊 **Robustness Testing** - Ensure APIs handle malformed input gracefully
- 🎯 **Targeted Testing** - Focus on specific vulnerability types
- 📈 **Scalable Testing** - Adjustable intensity levels for different testing phases

## 🧪 Enhanced Test Generation

### Comprehensive Test Coverage

**Before (v0.2.2):** 3-5 basic test cases
**After (v0.2.3):** 8-12 comprehensive test cases covering:

1. **Success Scenarios** (200/201/204) - 3+ cases
2. **Client Errors** (400/401/403/404/422) - 3+ cases  
3. **Server Errors** (500/502/503) - 2+ cases
4. **Edge Cases** (boundary values, special characters) - 2+ cases
5. **Security Scenarios** (unauthorized access, injection attempts) - 2+ cases

### Example Generated Test Case

```json
{
  "name": "Create Invoice - Success with Current Date",
  "method": "POST",
  "url": "/api/v1/invoices",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer test-token",
    "User-Agent": "Amalthea-Test-Client"
  },
  "body": {
    "invoiceNumber": "INV-2025-001",
    "issueDate": "2025-10-01",
    "dueDate": "2025-11-01",
    "amount": 1250.00,
    "currency": "USD",
    "items": [
      {
        "description": "Software License",
        "quantity": 1,
        "unitPrice": 1250.00,
        "total": 1250.00
      }
    ]
  },
  "expected_status": 201,
  "description": "Create a new invoice with valid current date data and comprehensive item details"
}
```

## 🚀 Quick Start

### Installation

```bash
# Install from crates.io (recommended)
cargo install amalthea

# Or build from source
git clone https://github.com/KSD-CO/amalthea.git
cd amalthea
make build

# Via Docker (ready to use)
docker pull ksdco/amalthea:0.2.5
docker pull ksdco/amalthea:latest

# Pre-built binaries (GitHub Releases)
wget https://github.com/KSD-CO/amalthea/releases/download/v0.2.5/amalthea-linux-x86_64
chmod +x amalthea-linux-x86_64
```

### Basic Usage

```bash
# Generate and execute test cases with OpenAI
amalthea --provider openai --model gpt-4o-mini --file api.json

# Generate only (no execution)
amalthea --provider openai --model gpt-4o-mini --file api.json --generate-only

# Use with local model (Ollama)
amalthea --provider local --model mistral:latest --file api.json

# Use with Claude
amalthea --provider anthropic --model claude-3-haiku --file api.json

# Use with Gemini
amalthea --provider google --model gemini-1.5-flash --file api.json

# Generate beautiful HTML report
amalthea --provider openai --model gpt-4o-mini --file api.json --format html --output report.html

# HTML report with security testing
amalthea --provider openai --model gpt-4o-mini --file api.json --security --html-report --output security-report.html

# Use knowledge base for realistic test data
amalthea --provider openai --model gpt-4o-mini --file api.json --kb knowledge-base.json --html-report

# Enable fuzzing for security vulnerability testing
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz

# Fuzzing with custom intensity and security testing
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --fuzz-intensity 5 --security

# Light fuzzing for CI/CD pipelines
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --fuzz-intensity 1 --security --generate-only

# Comprehensive testing: Fuzzing + Security + Knowledge Base + HTML Report
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --security --kb knowledge-base.json --html-report
```

### Security Testing

```bash
# Run comprehensive security tests
amalthea --provider openai --model gpt-4o-mini --file api.json --security

# Security testing with Postman collections
amalthea --provider openai --model gpt-4o-mini --file collection.json --security

# Security testing with custom base URL
amalthea --provider openai --model gpt-4o-mini --file api.json --security --base-url https://api.example.com

# Security testing only (no test generation)
amalthea --provider openai --model gpt-4o-mini --file api.json --security --generate-only

# Fuzzing mode for comprehensive security testing
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --security

# Fuzzing with custom intensity level (1-5)
amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --fuzz-intensity 4
```

### Universal AI Client

```bash
# Use universal client for automatic provider routing
amalthea --provider universal --model gpt-4o-mini --file api.json

# Universal client with security testing
amalthea --provider universal --model gpt-4o-mini --file api.json --security

# Universal client with different models
amalthea --provider universal --model claude-3-haiku --file api.json
amalthea --provider universal --model gemini-1.5-flash --file api.json
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file for API keys:

```bash
# OpenAI
OPENAI_API_KEY="sk-proj-your-openai-key"

# Anthropic Claude  
ANTHROPIC_API_KEY="sk-ant-your-claude-key"

# Google Gemini
GOOGLE_API_KEY="your-google-gemini-key"

# Local Ollama (optional)
OLLAMA_HOST="http://localhost:11434"
```

### AI Provider Setup

#### 🤖 OpenAI Models

```bash
# Set OpenAI API key
export OPENAI_API_KEY="sk-proj-your-openai-key"

# Use different OpenAI models
amalthea --provider openai --model gpt-4o-mini --file api.json      # Cost-effective
amalthea --provider openai --model gpt-4o --file api.json           # High performance
amalthea --provider openai --model gpt-4 --file api.json            # Most capable
amalthea --provider openai --model gpt-3.5-turbo --file api.json    # Fast & affordable
```

#### 🧠 Anthropic Claude

```bash
# Set Claude API key
export ANTHROPIC_API_KEY="sk-ant-your-claude-key"

# Use different Claude models
amalthea --provider anthropic --model claude-3-haiku --file api.json     # Fast
amalthea --provider anthropic --model claude-3-sonnet --file api.json    # Balanced
amalthea --provider anthropic --model claude-3-opus --file api.json      # Most capable
```

#### 🌟 Google Gemini

```bash
# Set Gemini API key
export GOOGLE_API_KEY="your-google-gemini-key"

# Use different Gemini models
amalthea --provider google --model gemini-1.5-flash --file api.json      # Fast
amalthea --provider google --model gemini-1.5-pro --file api.json        # High performance
```

#### 🏠 Local Models (Ollama)

```bash
# Install and start Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve

# Pull models
ollama pull mistral:latest
ollama pull llama3.2:latest
ollama pull codellama:latest

# Use local models
amalthea --provider local --model mistral:latest --file api.json        # Mistral 7B
amalthea --provider local --model llama3.2:latest --file api.json       # Llama 3.2
amalthea --provider local --model codellama:latest --file api.json      # Code Llama

# Custom base URL for local models
amalthea --provider local --model mistral:latest --base-url http://localhost:11434 --file api.json
```

## 🧪 Test Execution

Amalthea not only generates test cases but also executes them automatically:

```bash
# Generate and execute tests (default behavior)
amalthea --provider openai --model gpt-4o-mini --file api.json

# Generate test cases only
amalthea --provider openai --model gpt-4o-mini --file api.json --generate-only

# Execute with custom output file
amalthea --provider openai --model gpt-4o-mini --file api.json --output my_tests.json

# Combined: Generate tests + Security scan
amalthea --provider openai --model gpt-4o-mini --file api.json --security
```

## 🛡️ Security Testing

Amalthea includes comprehensive security vulnerability scanning:

**Security Test Categories:**
- 🔍 SQL Injection detection
- 🚨 Cross-Site Scripting (XSS)
- 🔐 Authentication bypass testing
- 🛡️ Authorization flaw detection
- ✅ Input validation analysis
- 📋 Security headers check
- ⏱️ Rate limiting verification
- 📊 Information disclosure detection

```bash
# Run security tests only
amalthea --security --generate-only --file api.json

# Security tests with AI provider
amalthea --provider openai --model gpt-4o-mini --file api.json --security

# Example security report output:
# 🛡️ Security Test Report
# ==================================================
# 
# 📋 SQL Injection - /users/{id}
#    Status: 🔴 VULNERABLE
#    Severity: CRITICAL
#    Details: SQL error detected with payload: ' OR '1'='1
#    Recommendation: Use parameterized queries and input validation
# 
# 📋 Missing Security Headers - X-Frame-Options
#    Status: 🟡 WARNING
#    Severity: MEDIUM
#    Details: Header X-Frame-Options is missing
#    Recommendation: Add X-Frame-Options header
# 
# 📊 Summary:
#    🔴 Critical: 1
#    🟠 High: 2
#    🟡 Medium: 3
#    🔵 Low: 1
```

## 🔄 Universal AI Client

The Universal AI Client provides a unified interface for all AI providers, automatically routing requests to the appropriate provider:

```bash
# Universal client automatically detects provider from model
amalthea --provider universal --model gpt-4o-mini --file api.json       # Routes to OpenAI
amalthea --provider universal --model claude-3-haiku --file api.json    # Routes to Anthropic
amalthea --provider universal --model gemini-1.5-flash --file api.json  # Routes to Google

# Universal client with security testing
amalthea --provider universal --model gpt-4o-mini --file api.json --security

# Universal client with different configurations
amalthea --provider universal --model gpt-4o-mini --file api.json --temperature 0.5 --max-tokens 2048
```

**Benefits:**
- 🔄 **Automatic Provider Routing** - No need to specify provider manually
- 🧩 **Consistent Interface** - Same API across all providers
- 🛡️ **Error Handling** - Graceful fallbacks and error management
- ⚡ **Performance** - Optimized routing and connection pooling

## 🛠️ Development

### Build from Source

```bash
# Clone repository
git clone https://github.com/KSD-CO/amalthea.git
cd amalthea

# Build with Cargo
cargo build --release

# Run tests
cargo test

# Install locally
cargo install --path .
```

### Using Make

```bash
# Build project
make build

# Run tests
make test

# Check code quality
make check

# Clean artifacts
make clean

# Complete development workflow
make dev

# Publish release (maintainers only)
make publish
```

### Publishing Workflow

```bash
# Complete publishing workflow
make publish

# This will:
# 1. Build optimized binary for Linux x86_64
# 2. Publish to crates.io
# 3. Push Docker images (ksdco/amalthea:0.2.3, ksdco/amalthea:latest)
```

## ⚙️ Advanced Configuration

### Custom Prompts & Templates

Amalthea allows you to customize AI prompts for specific testing needs:

```bash
# Create custom prompt templates
mkdir -p ~/.amalthea/templates

# Custom OpenAPI prompt template
cat > ~/.amalthea/templates/openapi_custom.txt << 'EOF'
You are an expert API testing specialist. Generate comprehensive test cases for the OpenAPI specification.

Current date: {current_date}
Current year: {current_year}

Requirements:
- Generate {test_count} test cases per endpoint
- Use realistic data with current dates ({current_year}+)
- Include authentication scenarios
- Cover edge cases and error conditions
- Add performance considerations

Format: JSON test cases with detailed descriptions.
EOF

# Use custom template
amalthea --provider openai --model gpt-4o-mini --file api.json --template ~/.amalthea/templates/openapi_custom.txt
```

### Advanced AI Provider Configuration

#### Fine-tuning Parameters

```bash
# Temperature control (creativity vs consistency)
amalthea --provider openai --model gpt-4o-mini --file api.json --temperature 0.2  # Conservative
amalthea --provider openai --model gpt-4o-mini --file api.json --temperature 0.7  # Balanced (default)
amalthea --provider openai --model gpt-4o-mini --file api.json --temperature 0.9  # Creative

# Token limits for cost control
amalthea --provider openai --model gpt-4o-mini --file api.json --max-tokens 1024   # Concise
amalthea --provider openai --model gpt-4o-mini --file api.json --max-tokens 4096   # Detailed (default)

# Request timeout and retries
amalthea --provider openai --model gpt-4o-mini --file api.json --timeout 30 --retries 3
```

#### Custom Model Endpoints

```bash
# Custom OpenAI-compatible endpoints
export OPENAI_BASE_URL="https://api.custom-provider.com/v1"
amalthea --provider openai --model custom-gpt-4 --file api.json

# Azure OpenAI configuration
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/"
export AZURE_OPENAI_API_KEY="your-azure-key"
amalthea --provider azure --model gpt-4o-mini --file api.json

# Local model with custom parameters
amalthea --provider local --model llama3.2:latest \
  --base-url http://localhost:11434 \
  --temperature 0.5 \
  --max-tokens 2048 \
  --file api.json
```

### Configuration Files

#### `.amalthea.toml` Configuration

Create a configuration file for persistent settings:

```toml
# .amalthea.toml
[general]
default_provider = "openai"
default_model = "gpt-4o-mini"
output_dir = "./test_results"
parallel_requests = 5

[providers]
[providers.openai]
api_key_env = "OPENAI_API_KEY"
base_url = "https://api.openai.com/v1"
timeout = 30
retries = 3

[providers.anthropic]
api_key_env = "ANTHROPIC_API_KEY"
timeout = 45
retries = 2

[providers.local]
base_url = "http://localhost:11434"
timeout = 60

[testing]
default_test_count = 12
include_security = true
generate_only = false

[security]
enabled_checks = [
  "sql_injection",
  "xss", 
  "auth_bypass",
  "rate_limiting",
  "security_headers"
]
severity_threshold = "medium"
```

#### Environment Configuration

```bash
# Create comprehensive .env file
cat > .env << 'EOF'
# AI Provider Keys
OPENAI_API_KEY=sk-proj-your-openai-key
ANTHROPIC_API_KEY=sk-ant-your-claude-key
GOOGLE_API_KEY=your-google-gemini-key

# Azure OpenAI (if using)
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_KEY=your-azure-key
AZURE_OPENAI_API_VERSION=2024-02-15-preview

# Local Models
OLLAMA_HOST=http://localhost:11434

# Advanced Settings
AMALTHEA_LOG_LEVEL=info
AMALTHEA_OUTPUT_FORMAT=json
AMALTHEA_CACHE_DIR=~/.amalthea/cache
AMALTHEA_MAX_PARALLEL=5

# Testing Configuration
DEFAULT_TIMEOUT=30
DEFAULT_RETRIES=3
ENABLE_CACHE=true
EOF
```

## 📚 Knowledge Base & Best Practices

### 🧠 Knowledge Base Integration

Amalthea supports custom knowledge bases to generate more realistic and domain-specific test data. Knowledge bases contain valid data patterns, examples, and constraints specific to your API domain.

#### Creating a Knowledge Base

Create a `knowledge-base.json` file with your API's valid data patterns:

```json
{
  "api_name": "E-Invoice API",
  "description": "Knowledge base for e-invoice API testing with valid data patterns and examples",
  "valid_data": {
    "invoice_id": {
      "description": "Valid invoice ID patterns for e-invoice system",
      "examples": [
        "INV-2024-001234",
        "INV-2024-005678",
        "INV-2025-000001"
      ],
      "data_type": "string",
      "pattern": "^INV-\\d{4}-\\d{6}$"
    },
    "customer_info": {
      "description": "Valid customer information structure",
      "examples": [
        {
          "customer_id": "CUST-001234",
          "name": "Công ty TNHH ABC",
          "tax_code": "0123456789",
          "address": "123 Đường ABC, Quận 1, TP.HCM",
          "email": "contact@abc.com",
          "phone": "0901234567"
        }
      ],
      "data_type": "object"
    },
    "payment_method": {
      "description": "Valid payment methods",
      "examples": [
        "CASH",
        "BANK_TRANSFER", 
        "CREDIT_CARD",
        "E_WALLET"
      ],
      "data_type": "string"
    }
  }
}
```

#### Using Knowledge Base

```bash
# Generate tests with knowledge base
amalthea --provider openai --model gpt-4o-mini --file api.json --kb knowledge-base.json

# Combine with security testing
amalthea --provider openai --model gpt-4o-mini --file api.json --kb knowledge-base.json --security

# Generate HTML report with knowledge base data
amalthea --provider openai --model gpt-4o-mini --file api.json --kb knowledge-base.json --html-report
```

#### Knowledge Base Benefits

- **Realistic Test Data**: Generate test cases with domain-specific, valid data patterns
- **Better Coverage**: AI understands your data constraints and generates appropriate edge cases
- **Consistency**: Ensure all test cases follow your API's data standards
- **Domain Expertise**: Embed business logic and validation rules into test generation

### API Testing Patterns

#### Common Test Scenarios

```bash
# E-commerce API Testing with Knowledge Base
amalthea --provider openai --model gpt-4o-mini --file ecommerce-api.json --kb ecommerce-kb.json

# Banking API Security Focus with Knowledge Base
amalthea --provider openai --model gpt-4o-mini --file banking-api.json --kb banking-kb.json --security

# Healthcare API with Compliance Data
amalthea --provider openai --model gpt-4o-mini --file healthcare-api.json --kb healthcare-kb.json --security
```

#### Test Case Categories Explained

1. **Success Scenarios (200/201/204)**
   - Valid data with current timestamps
   - Different payload variations
   - Boundary value testing
   - Happy path flows

2. **Client Errors (400/401/403/404/422)**
   - Invalid input validation
   - Authentication failures
   - Authorization checks
   - Missing required fields

3. **Server Errors (500/502/503)**
   - Stress testing scenarios
   - Invalid server states
   - Dependency failures
   - Rate limiting responses

4. **Edge Cases**
   - Extremely large/small values
   - Special characters and encoding
   - Concurrent request handling
   - Data format variations

5. **Security Scenarios**
   - Injection attack attempts
   - Authentication bypass
   - Data exposure checks
   - Header security validation

### Performance Optimization

#### Cost-Effective Testing

```bash
# Optimize for cost with smaller models
amalthea --provider openai --model gpt-3.5-turbo --file api.json --max-tokens 1024

# Use local models for development
amalthea --provider local --model mistral:7b --file api.json

# Batch process multiple APIs
for api in api1.json api2.json api3.json; do
  amalthea --provider openai --model gpt-4o-mini --file $api --output "results_$(basename $api)"
done
```

#### Caching Strategies

```bash
# Enable response caching
export AMALTHEA_ENABLE_CACHE=true
export AMALTHEA_CACHE_TTL=3600  # 1 hour

# Cache location
export AMALTHEA_CACHE_DIR=~/.amalthea/cache

# Clear cache when needed
rm -rf ~/.amalthea/cache/*
```

### Integration Patterns

#### CI/CD Pipeline Integration

```yaml
# .github/workflows/api-testing.yml
name: API Testing with Amalthea

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  api-test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Amalthea
      run: |
        wget https://github.com/KSD-CO/amalthea/releases/download/v0.2.3/amalthea-linux-x86_64
        chmod +x amalthea-linux-x86_64
        sudo mv amalthea-linux-x86_64 /usr/local/bin/amalthea
    
    - name: Run API Tests
      env:
        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      run: |
        amalthea --provider openai --model gpt-4o-mini --file api/openapi.json --security
    
    - name: Upload Test Results
      uses: actions/upload-artifact@v3
      with:
        name: api-test-results
        path: test_results.json
```

#### Docker Integration

```dockerfile
# Dockerfile for API testing container
FROM rust:1.82-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/amalthea /usr/local/bin/amalthea

# Create test script
COPY <<EOF /usr/local/bin/run-tests.sh
#!/bin/bash
set -e

echo "🚀 Starting API Testing with Amalthea"

# Run tests with all providers
amalthea --provider openai --model gpt-4o-mini --file /data/api.json --security --output /results/openai-results.json
amalthea --provider anthropic --model claude-3-haiku --file /data/api.json --security --output /results/claude-results.json

echo "✅ Testing completed! Results saved to /results/"
EOF

RUN chmod +x /usr/local/bin/run-tests.sh

ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
```

### Troubleshooting Guide

#### Common Issues

1. **API Key Issues**
   ```bash
   # Verify API key format
   echo $OPENAI_API_KEY | grep -E "^sk-proj-"
   
   # Test API connectivity
   curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
   ```

2. **Local Model Issues**
   ```bash
   # Check Ollama status
   ollama list
   ollama ps
   
   # Test model availability
   curl http://localhost:11434/api/generate -d '{"model":"mistral:latest","prompt":"test"}'
   ```

3. **Performance Issues**
   ```bash
   # Monitor resource usage
   amalthea --provider openai --model gpt-4o-mini --file large-api.json --verbose
   
   # Use smaller models for large APIs
   amalthea --provider openai --model gpt-3.5-turbo --file large-api.json --max-tokens 1024
   ```

#### Debug Mode

```bash
# Enable detailed logging
export RUST_LOG=debug
amalthea --provider openai --model gpt-4o-mini --file api.json --verbose

# Save debug output
amalthea --provider openai --model gpt-4o-mini --file api.json --debug > debug.log 2>&1
```

## � CLI Reference

### Complete Command Line Options

```bash
USAGE:
    amalthea [OPTIONS] --file <FILE>

OPTIONS:
    -f, --file <FILE>                    Input file (OpenAPI spec or Postman collection)
    -m, --model <MODEL>                  AI model to use [default: gpt-4o-mini]
    -p, --provider <PROVIDER>            AI provider (openai, anthropic, google, local, universal)
        --api-key <API_KEY>              API key for the AI provider
        --base-url <BASE_URL>            Base URL for API requests (for local models)
        --temperature <TEMPERATURE>      Temperature for AI responses (0.0-1.0) [default: 0.7]
        --max-tokens <MAX_TOKENS>        Maximum tokens in response [default: 4096]
        --timeout <TIMEOUT>              Request timeout in seconds [default: 30]
        --retries <RETRIES>              Number of retries for failed requests [default: 3]
    -o, --output <OUTPUT>                Output file for test results
        --kb <KB_FILE>                   Knowledge base file path for realistic test data generation
        --generate-only                  Generate test cases only (skip execution)
        --security                       Enable security vulnerability testing
        --fuzz                           Enable fuzzing mode - generate random/malicious test data
        --fuzz-intensity <LEVEL>         Fuzzing intensity level (1-5, default: 3)
        --scenarios <SCENARIOS>          Test scenario type (ecommerce, banking, realtime, etc.)
        --test-count <COUNT>             Number of test cases to generate per endpoint [default: 12]
        --parallel <PARALLEL>            Number of parallel requests [default: 5]
        --cache                          Enable response caching
        --cache-ttl <TTL>                Cache TTL in seconds [default: 3600]
        --template <TEMPLATE>            Custom prompt template file
        --config <CONFIG>                Configuration file path [default: .amalthea.toml]
        --verbose                        Enable verbose output
        --debug                          Enable debug mode
        --no-color                       Disable colored output
        --format <FORMAT>                Output format (json, yaml, xml, html) [default: json]
        --html-report                    Generate HTML report with visual charts and statistics
        --report-title <TITLE>           Custom title for HTML report [default: "API Test Report"]
    -h, --help                           Print help information
    -V, --version                        Print version information

EXAMPLES:
    # Basic usage
    amalthea --provider openai --model gpt-4o-mini --file api.json
    
    # With security testing
    amalthea --provider openai --model gpt-4o-mini --file api.json --security
    
    # With knowledge base for realistic test data
    amalthea --provider openai --model gpt-4o-mini --file api.json --kb knowledge-base.json
    
    # Knowledge base + security testing + HTML report
    amalthea --provider openai --model gpt-4o-mini --file api.json --kb knowledge-base.json --security --html-report
    
    # Custom configuration
    amalthea --provider openai --model gpt-4o-mini --file api.json --test-count 15 --temperature 0.5
    
    # Local model with custom settings
    amalthea --provider local --model mistral:latest --base-url http://localhost:11434 --file api.json
    
    # Generate only with custom template
    amalthea --provider openai --model gpt-4o-mini --file api.json --generate-only --template custom.txt
    
    # Generate HTML report with visual charts
    amalthea --provider openai --model gpt-4o-mini --file api.json --format html --output report.html
    
    # Custom HTML report with title and security testing
    amalthea --provider openai --model gpt-4o-mini --file api.json --security --html-report --report-title "My API Security Report" --output security-report.html
    
    # Enable fuzzing for comprehensive security testing
    amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --security
    
    # Fuzzing with custom intensity and knowledge base
    amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --fuzz-intensity 5 --kb knowledge-base.json
    
    # Light fuzzing for development/CI pipelines
    amalthea --provider openai --model gpt-4o-mini --file api.json --fuzz --fuzz-intensity 1 --generate-only
    
    # Security-only testing
    amalthea --provider openai --model gpt-4o-mini --file api.json --security --generate-only
```

### Environment Variables Reference

```bash
# AI Provider Configuration
OPENAI_API_KEY              # OpenAI API key
ANTHROPIC_API_KEY           # Anthropic Claude API key  
GOOGLE_API_KEY              # Google Gemini API key
AZURE_OPENAI_ENDPOINT       # Azure OpenAI endpoint
AZURE_OPENAI_API_KEY        # Azure OpenAI API key
AZURE_OPENAI_API_VERSION    # Azure OpenAI API version
OLLAMA_HOST                 # Ollama host URL

# Application Configuration
AMALTHEA_LOG_LEVEL          # Log level (error, warn, info, debug, trace)
AMALTHEA_OUTPUT_FORMAT      # Default output format (json, yaml, xml)
AMALTHEA_CACHE_DIR          # Cache directory path
AMALTHEA_MAX_PARALLEL       # Maximum parallel requests
AMALTHEA_ENABLE_CACHE       # Enable caching (true/false)
AMALTHEA_CACHE_TTL          # Cache TTL in seconds

# Testing Configuration  
DEFAULT_TIMEOUT             # Default request timeout
DEFAULT_RETRIES             # Default retry count
DEFAULT_TEMPERATURE         # Default AI temperature
DEFAULT_MAX_TOKENS          # Default max tokens
DEFAULT_TEST_COUNT          # Default test cases per endpoint

# Debug and Development
RUST_LOG                    # Rust logging configuration
RUST_BACKTRACE              # Enable Rust backtraces (1, full)
```

## � HTML Reports & Visualization

### Beautiful HTML Reports

Amalthea generates stunning HTML reports with interactive charts and comprehensive test results:

```bash
# Generate HTML report with all features
amalthea --provider openai --model gpt-4o-mini --file api.json --security --format html --output report.html

# Custom HTML report with title
amalthea --provider openai --model gpt-4o-mini --file api.json --html-report --report-title "E-commerce API Test Report" --output ecommerce-report.html

# Security-focused HTML report
amalthea --provider openai --model gpt-4o-mini --file api.json --security --html-report --report-title "Security Vulnerability Assessment" --output security-report.html
```

### HTML Report Features

#### 📈 **Interactive Dashboard**
- **Real-time Charts** - Pass/fail rates, response times, error distributions
- **Test Coverage Matrix** - Visual endpoint coverage with color-coded status
- **Security Risk Dashboard** - Vulnerability severity breakdown with recommendations
- **Performance Metrics** - Response time histograms and latency analysis

#### 🎨 **Visual Elements**
```html
<!-- Example HTML Report Structure -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Amalthea API Test Report - {report_title}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-50">
    <!-- Header with Logo and Summary -->
    <header class="bg-blue-600 text-white p-6">
        <div class="flex items-center justify-between">
            <div class="flex items-center">
                <img src="https://amalthea.cloud/amalthea.png" alt="Amalthea" class="w-12 h-12 mr-4">
                <h1 class="text-3xl font-bold">{report_title}</h1>
            </div>
            <div class="text-right">
                <p class="text-sm">Generated: {current_date}</p>
                <p class="text-sm">Provider: {ai_provider} ({model})</p>
            </div>
        </div>
    </header>

    <!-- Executive Summary Cards -->
    <section class="p-6 grid grid-cols-1 md:grid-cols-4 gap-6">
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Total Tests</h3>
            <p class="text-4xl font-bold text-blue-600">{total_tests}</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Success Rate</h3>
            <p class="text-4xl font-bold text-green-600">{success_rate}%</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Security Issues</h3>
            <p class="text-4xl font-bold text-red-600">{security_issues}</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Avg Response</h3>
            <p class="text-4xl font-bold text-purple-600">{avg_response}ms</p>
        </div>
    </section>

    <!-- Interactive Charts Section -->
    <section class="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Test Results Pie Chart -->
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-xl font-semibold mb-4">Test Results Distribution</h3>
            <canvas id="testResultsChart"></canvas>
        </div>
        
        <!-- Security Vulnerability Radar -->
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-xl font-semibold mb-4">Security Risk Assessment</h3>
            <canvas id="securityRadarChart"></canvas>
        </div>
        
        <!-- Response Time Timeline -->
        <div class="bg-white rounded-lg shadow p-6 lg:col-span-2">
            <h3 class="text-xl font-semibold mb-4">Response Time Analysis</h3>
            <canvas id="responseTimeChart"></canvas>
        </div>
    </section>
</body>
</html>
```

#### 📋 **Detailed Test Results**
- **Endpoint Coverage Table** - Complete list with status, method, response codes
- **Test Case Details** - Expandable sections with request/response data
- **Error Analysis** - Categorized failures with troubleshooting suggestions
- **Performance Insights** - Slowest endpoints and optimization recommendations

#### 🛡️ **Security Report Section**
```html
<!-- Security Vulnerability Dashboard -->
<section class="p-6">
    <h2 class="text-2xl font-bold mb-6 text-red-600">🛡️ Security Assessment</h2>
    
    <!-- Severity Level Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div class="bg-red-100 border-l-4 border-red-500 p-4">
            <h4 class="font-semibold text-red-700">Critical</h4>
            <p class="text-3xl font-bold text-red-600">{critical_count}</p>
        </div>
        <div class="bg-orange-100 border-l-4 border-orange-500 p-4">
            <h4 class="font-semibold text-orange-700">High</h4>
            <p class="text-3xl font-bold text-orange-600">{high_count}</p>
        </div>
        <div class="bg-yellow-100 border-l-4 border-yellow-500 p-4">
            <h4 class="font-semibold text-yellow-700">Medium</h4>
            <p class="text-3xl font-bold text-yellow-600">{medium_count}</p>
        </div>
        <div class="bg-blue-100 border-l-4 border-blue-500 p-4">
            <h4 class="font-semibold text-blue-700">Low</h4>
            <p class="text-3xl font-bold text-blue-600">{low_count}</p>
        </div>
    </div>
    
    <!-- Detailed Vulnerability List -->
    <div class="space-y-4">
        <!-- SQL Injection Example -->
        <div class="bg-white rounded-lg shadow p-6 border-l-4 border-red-500">
            <div class="flex justify-between items-start">
                <div>
                    <h4 class="text-lg font-semibold text-red-700">🔍 SQL Injection Vulnerability</h4>
                    <p class="text-gray-600">Endpoint: /api/v1/users/{id}</p>
                    <p class="text-sm text-gray-500">Detected: {timestamp}</p>
                </div>
                <span class="bg-red-100 text-red-800 px-3 py-1 rounded-full text-sm font-medium">CRITICAL</span>
            </div>
            <div class="mt-4">
                <p class="text-gray-700"><strong>Details:</strong> SQL error detected with payload: ' OR '1'='1</p>
                <p class="text-gray-700"><strong>Risk:</strong> Potential data breach and unauthorized access</p>
                <p class="text-gray-700"><strong>Recommendation:</strong> Use parameterized queries and input validation</p>
            </div>
        </div>
    </div>
</section>
```

### Interactive Features

#### 🎯 **Clickable Elements**
- **Test Case Expansion** - Click to view full request/response details
- **Filter by Status** - Show only passed, failed, or security tests
- **Sort by Performance** - Order endpoints by response time
- **Search Functionality** - Find specific endpoints or test cases

#### 📱 **Responsive Design**
- **Mobile-Friendly** - Optimized for phones and tablets
- **Print-Ready** - Clean printing layout without interactive elements
- **Dark Mode Support** - Toggle between light and dark themes
- **Export Options** - Save charts as images or PDF

### Advanced HTML Report Options

```bash
# Comprehensive report with all features
amalthea --provider openai --model gpt-4o-mini --file api.json \
  --security \
  --html-report \
  --report-title "Production API Security Audit" \
  --format html \
  --output comprehensive-report.html \
  --include-charts \
  --include-timeline \
  --dark-mode

# Performance-focused report
amalthea --provider openai --model gpt-4o-mini --file api.json \
  --html-report \
  --report-title "API Performance Analysis" \
  --format html \
  --output performance-report.html \
  --include-performance-metrics \
  --response-time-threshold 200

# Executive summary report (minimal details)
amalthea --provider openai --model gpt-4o-mini --file api.json \
  --security \
  --html-report \
  --report-title "Executive API Status Report" \
  --format html \
  --output executive-summary.html \
  --summary-only \
  --hide-technical-details
```

### Report Customization

#### 🎨 **Branding Options**
```bash
# Custom branding and colors
amalthea --provider openai --model gpt-4o-mini --file api.json \
  --html-report \
  --report-title "Company API Testing Report" \
  --format html \
  --output branded-report.html \
  --logo "https://company.com/logo.png" \
  --primary-color "#1e40af" \
  --company-name "Your Company Name"
```

#### 📊 **Chart Customization**
- **Chart Types**: Pie, bar, line, radar, doughnut charts
- **Color Schemes**: Professional, colorful, monochrome themes  
- **Data Visualization**: Response times, success rates, security scores
- **Interactive Tooltips**: Hover for detailed information

### Sample HTML Report Output

When you run Amalthea with HTML output, you'll get a beautiful report like this:

```
📊 Generated HTML Report: report.html
   
   📈 Dashboard Overview:
   ├── 🧪 Total Tests: 156
   ├── ✅ Success Rate: 87.2%
   ├── 🛡️ Security Issues: 3 Critical, 5 High
   └── ⚡ Avg Response: 245ms
   
   📋 Detailed Sections:
   ├── 📊 Interactive Charts (4 visualizations)
   ├── 📋 Test Results Table (12 endpoints)
   ├── 🛡️ Security Assessment (8 vulnerability types)
   ├── ⚡ Performance Analysis (response time breakdown)
   └── 📄 Executive Summary (key findings)
   
   🌐 Open in browser: file://./report.html
```

## �🐳 Advanced Docker Usage

### Production Docker Setup

```bash
# Production-ready container with all features
docker run --rm \
  --name amalthea-testing \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e GOOGLE_API_KEY="$GOOGLE_API_KEY" \
  -v $(pwd)/apis:/data \
  -v $(pwd)/results:/results \
  -v $(pwd)/config:/config \
  ksdco/amalthea:0.2.3 \
  --provider universal --model gpt-4o-mini \
  --file /data/api.json \
  --security \
  --config /config/.amalthea.toml \
  --output /results/test-results.json

# Multi-provider testing with Docker Compose
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  amalthea-openai:
    image: ksdco/amalthea:0.2.5
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./apis:/data
      - ./results:/results
    command: >
      --provider openai --model gpt-4o-mini 
      --file /data/api.json --security 
      --output /results/openai-results.json

  amalthea-claude:
    image: ksdco/amalthea:0.2.5
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    volumes:
      - ./apis:/data
      - ./results:/results
    command: >
      --provider anthropic --model claude-3-haiku 
      --file /data/api.json --security 
      --output /results/claude-results.json

  amalthea-local:
    image: ksdco/amalthea:0.2.5
    network_mode: host
    volumes:
      - ./apis:/data
      - ./results:/results
    command: >
      --provider local --model mistral:latest 
      --base-url http://localhost:11434
      --file /data/api.json --security 
      --output /results/local-results.json
    depends_on:
      - ollama

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    command: serve

volumes:
  ollama_data:
EOF

# Run multi-provider testing
docker-compose up --abort-on-container-exit
```

### Kubernetes Deployment

```yaml
# k8s/amalthea-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: api-testing-job
spec:
  template:
    spec:
      containers:
      - name: amalthea
        image: ksdco/amalthea:0.2.3
        command: ["/usr/local/bin/amalthea"]
        args:
          - --provider
          - openai
          - --model
          - gpt-4o-mini
          - --file
          - /data/api.json
          - --security
          - --output
          - /results/test-results.json
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: ai-keys
              key: openai-key
        volumeMounts:
        - name: api-specs
          mountPath: /data
        - name: results
          mountPath: /results
      volumes:
      - name: api-specs
        configMap:
          name: api-specifications
      - name: results
        persistentVolumeClaim:
          claimName: test-results-pvc
      restartPolicy: Never
  backoffLimit: 3

---
apiVersion: v1
kind: Secret
metadata:
  name: ai-keys
type: Opaque
data:
  openai-key: <base64-encoded-openai-key>
  anthropic-key: <base64-encoded-anthropic-key>
  google-key: <base64-encoded-google-key>
```

### Custom Docker Images

```dockerfile
# Dockerfile.custom - Custom image with additional tools
FROM ksdco/amalthea:0.2.5

USER root

# Install additional testing tools
RUN apt-get update && apt-get install -y \
    jq \
    curl \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Python tools for result processing
RUN pip3 install \
    requests \
    jsonschema \
    pyyaml \
    tabulate

# Add custom scripts
COPY scripts/ /usr/local/scripts/
RUN chmod +x /usr/local/scripts/*.sh

# Custom entrypoint with pre/post processing
COPY <<EOF /usr/local/bin/custom-entrypoint.sh
#!/bin/bash
set -e

echo "🚀 Starting Custom API Testing Pipeline"

# Pre-processing
/usr/local/scripts/preprocess.sh

# Main testing
amalthea "$@"

# Post-processing
/usr/local/scripts/postprocess.sh

echo "✅ Testing pipeline completed!"
EOF

RUN chmod +x /usr/local/bin/custom-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/custom-entrypoint.sh"]
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Support

- ⭐ Star this repository if you find it helpful
- 🐛 Report bugs via [GitHub Issues](https://github.com/KSD-CO/amalthea/issues)
- 💬 Join discussions in [GitHub Discussions](https://github.com/KSD-CO/amalthea/discussions)
- 📚 Read the documentation at [amalthea.cloud](https://amalthea.cloud)

---

Built with ❤️ by [KSD.CO](https://ksd.co) using Rust 🦀
