"""
Updated RAG Service Configuration for Docker
Add this to your rag_service.py file to support Docker environment
"""

import os
import logging
from typing import Optional

from assr.rag_service import RAG_PIPELINE_AVAILABLE

# Docker Environment Configuration
def get_chromadb_config():
    """Get ChromaDB configuration for Docker environment"""
    chroma_host = os.getenv("CHROMA_HOST", "localhost")
    chroma_port = os.getenv("CHROMA_PORT", "8001")
    
    if chroma_host != "localhost":
        # Running in Docker, use internal service name
        return f"http://{chroma_host}:{chroma_port}"
    else:
        # Running locally, use localhost
        return f"http://localhost:{chroma_port}"

def init_rag_pipeline():
    """Initialize the RAG pipeline with ChromaDB"""
    global rag_pipeline
    if RAG_PIPELINE_AVAILABLE:
        try:
            from rag_pipeline.main_pipeline import RAGPipelineOrchestrator, RAGPipelineConfig
            
            config = RAGPipelineConfig()
            config.vector_db_path = get_chromadb_config()
            
            rag_pipeline = RAGPipelineOrchestrator(config)
            logging.info(f"RAG Pipeline initialized with ChromaDB at {config.vector_db_path}")
            return rag_pipeline
        except Exception as e:
            logging.warning(f"Failed to initialize RAG Pipeline: {e}")
            return None
    return None

# Health check endpoint for Docker
def add_health_endpoint(app):
    """Add health check endpoint"""
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "service": "rag-service",
            "version": "1.0.0",
            "chromadb_url": get_chromadb_config()
        }

# Add this to your FastAPI app initialization:
# add_health_endpoint(app)