"""
Environment Configuration for Docker Integration
This file provides environment-based configuration for all services
"""

import os

# Service URLs for Docker environment
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://rag-service:8000")
SECURITY_BACKEND_URL = os.getenv("SECURITY_BACKEND_URL", "http://security-backend:9000")
APP_BACKEND_URL = os.getenv("APP_BACKEND_URL", "http://app-backend:9000")
CHROMADB_URL = os.getenv("CHROMADB_URL", "http://chromadb:8000")

# Route mapping for API Gateway
ROUTE_MAP = {
    "/auth": APP_BACKEND_URL,
    "/users": APP_BACKEND_URL,
    "/orders": APP_BACKEND_URL,
    "/api": APP_BACKEND_URL,
}

# Default backend for security checks
DEFAULT_BACKEND = SECURITY_BACKEND_URL

# ChromaDB Configuration
CHROMA_HOST = os.getenv("CHROMA_HOST", "chromadb")
CHROMA_PORT = os.getenv("CHROMA_PORT", "8000")

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Security Configuration
MAX_PAYLOAD_SIZE = int(os.getenv("MAX_PAYLOAD_SIZE", "10240"))  # 10KB default
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds

# RAG Configuration
RAG_CONFIDENCE_THRESHOLD = float(os.getenv("RAG_CONFIDENCE_THRESHOLD", "0.7"))
RAG_MAX_RESULTS = int(os.getenv("RAG_MAX_RESULTS", "5"))

print(f"🔧 Environment Configuration Loaded:")
print(f"  - RAG Service: {RAG_SERVICE_URL}")
print(f"  - Security Backend: {SECURITY_BACKEND_URL}")
print(f"  - App Backend: {APP_BACKEND_URL}")
print(f"  - ChromaDB: {CHROMADB_URL}")
print(f"  - Log Level: {LOG_LEVEL}")