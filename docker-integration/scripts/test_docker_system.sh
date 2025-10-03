#!/bin/bash

echo "🧪 Testing Dockerized Cybersecurity System..."

# Wait a moment for services to be ready
sleep 5

echo ""
echo "1. Testing ChromaDB Service..."
if curl -s http://localhost:8001/api/v1/heartbeat > /dev/null; then
    echo "✅ ChromaDB is running"
else
    echo "❌ ChromaDB is not responding"
fi

echo ""
echo "2. Testing RAG Service..."
curl -X POST http://localhost:8000/check_payload \
  -H "Content-Type: application/json" \
  -d '{"payload": "SELECT * FROM users WHERE id=1 OR 1=1"}' \
  -w "\nResponse Code: %{http_code}\n" 2>/dev/null || echo "❌ RAG Service not responding"

echo ""
echo "3. Testing API Gateway with malicious payload..."
curl -X GET "http://localhost:8080/api/users?id=1' OR 1=1--" \
  -w "\nResponse Code: %{http_code}\n" 2>/dev/null || echo "❌ API Gateway not responding"

echo ""
echo "4. Testing API Gateway with legitimate request..."
curl -X GET "http://localhost:8080/api/users" \
  -w "\nResponse Code: %{http_code}\n" 2>/dev/null || echo "❌ API Gateway not responding"

echo ""
echo "5. Testing Security Backend..."
curl -X POST http://localhost:9000/security_check \
  -H "Content-Type: application/json" \
  -d '{"payload": "normal request"}' \
  -w "\nResponse Code: %{http_code}\n" 2>/dev/null || echo "❌ Security Backend not responding"

echo ""
echo "6. Testing Application Backend..."
curl -X GET http://localhost:9001/health \
  -w "\nResponse Code: %{http_code}\n" 2>/dev/null || echo "❌ Application Backend not responding"

echo ""
echo "🔍 Service Status Summary:"
echo "=================="
services=("chromadb:8001" "rag-service:8000" "security-backend:9000" "app-backend:9001" "api-gateway:8080")

for service in "${services[@]}"; do
    name=${service%:*}
    port=${service#*:}
    
    if curl -s http://localhost:$port/health > /dev/null 2>&1 || curl -s http://localhost:$port/api/v1/heartbeat > /dev/null 2>&1; then
        echo "✅ $name (port $port) - Healthy"
    else
        echo "❌ $name (port $port) - Not responding"
    fi
done

echo ""
echo "✅ Testing complete!"
echo ""
echo "💡 To view real-time logs:"
echo "  docker-compose logs -f [service-name]"
echo ""
echo "📊 Available services:"
echo "  - API Gateway: http://localhost:8080"
echo "  - RAG Service: http://localhost:8000"  
echo "  - Security Backend: http://localhost:9000"
echo "  - App Backend: http://localhost:9001"
echo "  - ChromaDB: http://localhost:8001"