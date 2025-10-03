# Docker Integration Setup Instructions

## Overview
This folder contains all the necessary Docker configurations to run your cybersecurity RAG system in containers.

## System Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Gateway   │────│ Security Backend │────│   RAG Service   │
│   (Port 8080)   │    │   (Port 9000)    │    │   (Port 8000)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐    ┌─────────────────┐
                    │  App Backend    │    │    ChromaDB     │
                    │  (Port 9001)    │    │   (Port 8001)   │
                    └─────────────────┘    └─────────────────┘
```

## Quick Start

1. **Make scripts executable:**
   ```bash
   chmod +x scripts/*.sh
   ```

2. **Start the system:**
   ```bash
   cd docker-integration
   ./scripts/start_docker_system.sh
   ```

3. **Test the system:**
   ```bash
   ./scripts/test_docker_system.sh
   ```

4. **Stop the system:**
   ```bash
   ./scripts/stop_docker_system.sh
   ```

## File Structure
```
docker-integration/
├── docker-compose.yml          # Main orchestration file
├── dockerfiles/               # All Docker image definitions
│   ├── Dockerfile.rag         # RAG service with ML dependencies
│   ├── Dockerfile.gateway     # API Gateway with payload inspection
│   ├── Dockerfile.security    # Security backend with OWASP rules
│   ├── Dockerfile.backend     # Application backend
│   └── Dockerfile.nginx       # Nginx reverse proxy
├── config/                    # Configuration files
│   ├── docker_config.py       # Environment configuration
│   ├── rag_docker_config.py   # RAG service Docker config
│   ├── gateway_docker_config.py # Gateway Docker config
│   ├── requirements-rag.txt   # RAG service dependencies
│   └── requirements-gateway.txt # Gateway dependencies
└── scripts/                   # Management scripts
    ├── start_docker_system.sh # Start all services
    ├── stop_docker_system.sh  # Stop all services
    └── test_docker_system.sh  # Test system functionality
```

## Services

### 1. ChromaDB (Port 8001)
- Vector database for RAG pipeline
- Persistent storage for embeddings
- Health check: `http://localhost:8001/api/v1/heartbeat`

### 2. RAG Service (Port 8000)
- ML-based payload analysis
- Connects to ChromaDB for vector operations
- Health check: `http://localhost:8000/health`

### 3. Security Backend (Port 9000)
- OWASP rules and regex pattern matching
- Integrates with RAG service for unknown patterns
- Health check: `http://localhost:9000/health`

### 4. App Backend (Port 9001)
- Business logic endpoints
- User management, orders, etc.
- Health check: `http://localhost:9001/health`

### 5. API Gateway (Port 8080)
- Entry point for all requests
- Payload inspection and routing
- Health check: `http://localhost:8080/health`

### 6. Nginx (Ports 80/443) - Optional
- Reverse proxy for production
- SSL termination
- Load balancing

## Environment Variables

The system uses these environment variables:
- `RAG_SERVICE_URL`: RAG service endpoint
- `SECURITY_BACKEND_URL`: Security backend endpoint  
- `APP_BACKEND_URL`: Application backend endpoint
- `CHROMA_HOST`: ChromaDB hostname
- `CHROMA_PORT`: ChromaDB port
- `LOG_LEVEL`: Logging level (INFO, DEBUG, etc.)

## Data Persistence

- `chromadb_data`: ChromaDB vector database
- `rag_logs`: RAG service logs
- `security_logs`: Security backend logs
- `app_logs`: Application backend logs
- `gateway_logs`: API Gateway logs
- `nginx_logs`: Nginx access/error logs

## Troubleshooting

### View logs:
```bash
docker-compose logs -f [service-name]
```

### Restart a service:
```bash
docker-compose restart [service-name]
```

### Rebuild a service:
```bash
docker-compose up --build [service-name]
```

### Clean restart:
```bash
./scripts/stop_docker_system.sh --clean
./scripts/start_docker_system.sh
```

## Development

### Adding new dependencies:
1. Update appropriate requirements file in `config/`
2. Rebuild the service: `docker-compose up --build [service-name]`

### Modifying configurations:
1. Update files in `config/` directory
2. Restart affected services

### Custom environment:
Create `.env` file in docker-integration directory with your variables.

## Production Deployment

1. Enable nginx service in docker-compose.yml
2. Configure SSL certificates
3. Set production environment variables
4. Use `restart: unless-stopped` policy
5. Configure log rotation
6. Set up monitoring and alerts

## Security Notes

- All inter-service communication uses internal Docker network
- Only necessary ports are exposed to host
- Health checks ensure service availability
- Logs are centralized and rotatable
- No sensitive data in environment variables (use Docker secrets for production)