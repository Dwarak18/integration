#!/bin/bash

echo "🛑 Stopping Cybersecurity RAG System..."

# Navigate to docker integration directory
cd "$(dirname "$0")"

# Stop all services
docker-compose down

# Optional: Remove volumes (use with caution)
if [ "$1" = "--clean" ]; then
    echo "🧹 Cleaning up volumes..."
    docker-compose down -v
    docker system prune -f
    echo "⚠️  All data has been removed!"
fi

echo "✅ System stopped successfully!"

if [ "$1" != "--clean" ]; then
    echo ""
    echo "💡 To clean up all data and volumes, use:"
    echo "  ./stop_docker_system.sh --clean"
fi