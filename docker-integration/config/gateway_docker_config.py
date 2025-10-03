"""
Updated API Gateway Configuration for Docker
Add this to your main.py file to support Docker environment
"""

import os
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# Docker Environment Configuration
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://localhost:8000")
SECURITY_BACKEND_URL = os.getenv("SECURITY_BACKEND_URL", "http://localhost:9000")
APP_BACKEND_URL = os.getenv("APP_BACKEND_URL", "http://localhost:9001")

# Route mapping
ROUTE_MAP = {
    "/auth": APP_BACKEND_URL,
    "/users": APP_BACKEND_URL,
    "/orders": APP_BACKEND_URL,
    "/api": APP_BACKEND_URL,
}

DEFAULT_BACKEND = SECURITY_BACKEND_URL

async def forward_request_to_service(request: Request, target_url: str):
    """Forward request to target service"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=f"{target_url}{request.url.path}",
                params=request.query_params,
                headers=dict(request.headers),
                content=await request.body()
            )
            return JSONResponse(
                content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"response": response.text},
                status_code=response.status_code
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Service unavailable: {str(e)}")

# Health check endpoint for Docker
def add_health_endpoint(app: FastAPI):
    """Add health check endpoint"""
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "service": "api-gateway",
            "version": "1.0.0",
            "endpoints": {
                "rag_service": RAG_SERVICE_URL,
                "security_backend": SECURITY_BACKEND_URL,
                "app_backend": APP_BACKEND_URL
            }
        }

# Add this to your FastAPI app initialization:
# add_health_endpoint(app)