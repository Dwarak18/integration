# Cyber Security Analysis System

A multi-agent system for analyzing security threats using AI-powered agents.

## Features

- **Attack Agent**: Analyzes API requests for SQL injection, XSS, command injection, and malicious payloads
- **Network Agent**: Detects suspicious network activity including port scans, DDoS attempts, and suspicious IPs
- **Investigation Agent**: Correlates findings from other agents and provides comprehensive security reports
- **Orchestrator Agent**: Coordinates the analysis pipeline and manages agent interactions

## Recent Corrections & Improvements

### Error Handling
- Added comprehensive error handling for API calls
- Graceful handling of API quota exceeded errors
- Proper exception handling for service unavailability
- Input validation for all agent methods

### Configuration
- Added API key validation in config.py
- Better error messages for missing configuration
- Environment variable validation

### Logging
- Enhanced logging throughout the system
- Better error tracking and debugging information
- Graceful shutdown handling with cleanup

### Code Quality
- Fixed import statements in agent modules
- Added input validation for empty or invalid logs
- Better structure and organization
- Added signal handlers for graceful shutdown

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file with your Gemini API key:
```
GEMINI_API_KEY=your_gemini_api_key_here
```

## Usage

Run the main analysis:
```bash
python main.py
```

## Requirements

- Python 3.7+
- Google Generative AI SDK
- python-dotenv
- Google API Core

## Note

The gRPC timeout warning at the end is a known harmless issue with the Google AI SDK and does not affect functionality.
