# 🛡️ Cybersecurity RAG System

## Overview
A comprehensive cybersecurity threat detection system that integrates Retrieval-Augmented Generation (RAG) with multi-layer security analysis. The system provides real-time payload inspection, threat detection, and security automation using machine learning and pattern matching.

## 🏗️ Architecture

### Core Components
- **RAG Service** (Port 8000): ML-based payload analysis using ChromaDB vector database
- **API Gateway** (Port 8080): Main entry point with multi-layer security filtering  
- **Security Backend** (Port 9000): Advanced security decision engine
- **App Backend** (Port 9001): Application logic and user management
- **ChromaDB** (Port 8001): Vector database for cybersecurity knowledge base
- **Nginx** (Ports 80/443): Load balancer and reverse proxy

### Features
- 🎯 **Real-time Threat Detection**: Pattern matching and ML-based analysis
- 🧠 **RAG-Enhanced Analysis**: Context-aware security decisions using vector embeddings
- 🔄 **Fallback Mechanisms**: Multiple analysis layers with graceful degradation
- 📊 **Comprehensive Logging**: Detailed threat analysis and incident tracking
- 🐳 **Containerized Deployment**: Full Docker support with health monitoring
- 🔧 **OWASP Integration**: Industry-standard security rule implementation

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+
- 8GB+ RAM recommended

### One-Step Deployment
```bash
cd docker-integration/scripts
./start_docker_system.sh
```

This script will:
- 🏗️ Build all Docker containers
- 🚀 Start the complete system
- ⏳ Wait for service initialization
- 🔍 Perform health checks
- 📊 Display service URLs

### Manual Deployment
```bash
cd docker-integration
docker-compose up --build -d
```

## 📡 API Endpoints

### RAG Service (Port 8000)
- **POST /check_payload**: Analyze payload for threats
  ```json
  {
    "payload": "<payload_string>",
    "source_ip": "192.168.1.100"
  }
  ```
- **GET /health**: Service health status
- **GET /stats**: System statistics

### API Gateway (Port 8080)
- **All Routes**: Protected with multi-layer security analysis
- **GET /health**: Gateway health status

### Security Backend (Port 9000)
- **POST /analyze**: Advanced threat analysis
- **GET /health**: Backend health status

## 🧪 Testing the System

### Test Malicious Payload
```bash
curl -X POST http://localhost:8000/check_payload \
  -H "Content-Type: application/json" \
  -d '{"payload": "<script>alert(1)</script> UNION SELECT * FROM users"}'
```

### Test Legitimate Request
```bash
curl -X GET http://localhost:8080/api/users
```

### Health Check All Services
```bash
curl http://localhost:8000/health  # RAG Service
curl http://localhost:8080/health  # API Gateway  
curl http://localhost:9000/health  # Security Backend
```

## 📁 Project Structure

```
api-integrate/
├── 🐳 docker-integration/          # Docker orchestration
│   ├── dockerfiles/                # Individual service Dockerfiles
│   ├── scripts/                    # Deployment scripts
│   └── docker-compose.yml          # Main composition file
├── 🧠 assr/                        # RAG Service & ML Pipeline
│   ├── rag_service.py              # Main RAG service
│   ├── rag_pipeline/               # ML pipeline components
│   └── cyberagents/                # Cybersecurity agents
├── 🛡️ API-gateway/                 # API Gateway & Security
│   ├── main.py                     # Gateway main service
│   ├── security_backend.py         # Security analysis
│   └── owasp_rules.py              # OWASP rule engine
├── 📊 logs/                        # System logs (excluded from Git)
├── 🗄️ cybersecurity_vectordb/      # Vector database (excluded)
└── 🔧 requirements.txt             # Python dependencies
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file (optional):
```bash
CHROMA_HOST=chromadb
CHROMA_PORT=8000
PYTHONPATH=/app
LOG_LEVEL=INFO
```

### Docker Compose Override
For development, create `docker-compose.override.yml`:
```yaml
version: '3.8'
services:
  rag-service:
    volumes:
      - ./assr:/app
    ports:
      - "8000:8000"
```

## 🔍 Monitoring & Logs

### View Service Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f rag-service
docker-compose logs -f api-gateway
```

### System Management
```bash
# Stop system
./docker-integration/scripts/stop_docker_system.sh

# Restart specific service
docker-compose restart rag-service

# Remove all containers and volumes
docker-compose down -v
```

## 🛠️ Development

### Local Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r assr/requirements.txt
pip install -r API-gateway/requirements.txt

# Run services locally
cd assr && python rag_service.py
cd API-gateway && uvicorn main:app --port 8080
```

### Adding New Security Rules
1. Edit `API-gateway/owasp_rules.py`
2. Add patterns to `API-gateway/regex_rules.py`
3. Rebuild containers: `docker-compose build`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Troubleshooting

### Common Issues

#### "RAG pipeline not available"
- This is normal - system uses fallback pattern matching
- Check ChromaDB connectivity: `curl http://localhost:8001/api/v1/heartbeat`

#### Port conflicts
- Change ports in `docker-compose.yml`
- Check running services: `docker ps`

#### Memory issues
- Reduce ChromaDB memory: Edit `docker-compose.yml`
- Increase Docker memory allocation

#### Container health checks failing
- Wait longer for initialization (especially RAG service)
- Check logs: `docker-compose logs [service-name]`

### Support
- 📧 Create an issue on GitHub
- 📚 Check the logs in `docker-integration/logs/`
- 🔍 Use health endpoints for debugging
Check a payload using curl:
```sh
curl -X POST http://localhost:8000/check_payload -H "Content-Type: application/json" -d '{"payload": "username=admin&password=password"}'
```

### 4. Test API-Gateway Integration
Send a request to any API-Gateway endpoint. The payload will be inspected and blocked/forwarded based on the RAG verdict.

### 5. Retrain the Vector DB
Rebuild Qdrant index from the latest dataset:
```sh
curl -X POST http://localhost:8000/retrain
```

### 6. Check Logs
Malicious verdicts are logged in `assr/malicious_verdicts.log`.

---

## Deployment
- Dockerfile and docker-compose.yml provided for containerized deployment.
- Persistent volumes for Qdrant and logs.

---

## Notes
- Ensure ports 8000, 9000, and 6333 are open.
- For production, secure API keys and network.
- Customize backend URLs in API-Gateway as needed.

---

## Authors
- Integration and automation by your team.
