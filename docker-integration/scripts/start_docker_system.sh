#!/bin/bash

echo "🚀 Starting Cybersecurity RAG System with Docker..."

# Navigate to docker integration directory
cd "$(dirname "$0")"

# Build and start all services
docker-compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to initialize..."
sleep 30

# Check service health
echo "🔍 Checking service health..."
services=("chromadb:8001" "rag-service:8000" "security-backend:9000" "app-backend:9001" "api-gateway:8080")

for service in "${services[@]}"; do
    name=${service%:*}
    port=${service#*:}
    
    if curl -s http://localhost:$port/health > /dev/null 2>&1 || curl -s http://localhost:$port/api/v1/heartbeat > /dev/null 2>&1; then
        echo "✅ $name is healthy"
    else
        echo "❌ $name is not responding"
    fi
done

echo ""
echo "🎉 System is ready!"
echo "📊 Service URLs:"
echo "  - API Gateway: http://localhost:8080"
echo "  - RAG Service: http://localhost:8000"
echo "  - Security Backend: http://localhost:9000"
echo "  - App Backend: http://localhost:9001"
echo "  - ChromaDB: http://localhost:8001"
echo ""
echo "📋 To view logs:"
echo "  docker-compose logs -f [service-name]"
echo ""
echo "🛑 To stop the system:"
echo "  ./stop_docker_system.sh"