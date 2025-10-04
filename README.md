## Requirements

### System Requirements
- **Operating System**: Linux, Windows (WSL), or macOS
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: 10GB available disk space
- **CPU**: Multi-core processor recommended

### Software Dependencies
- **Docker**: Version 20.10 or higher
- **Docker Compose**: Version 2.0 or higher
- **Python**: 3.11+ (for development only)
- **Git**: For repository cloning

## Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd <project-directory>
```

### 2. Environment Setup
Create environment file:
```bash
cp .env.example .env  # If available, or create manually
```

Required environment variables:
```bash
# MongoDB Configuration
MONGODB_HOST=mongodb
MONGODB_PORT=27017
MONGODB_USERNAME=admin
MONGODB_PASSWORD=admin123
MONGODB_DATABASE=threat_intelligence

# RAG Service Configuration
RAG_HOST=localhost
RAG_PORT=8000
```

### 3. Docker Deployment

#### Project Structure
```
docker-integration/
├── docker-compose.yml          # Main orchestration file
├── dockerfiles/               # Individual service containers
│   ├── Dockerfile.backend     # API Gateway container
│   ├── Dockerfile.gateway     # Gateway service
│   ├── Dockerfile.nginx       # Load balancer
│   ├── Dockerfile.rag         # RAG service container
│   └── Dockerfile.security    # Security backend
├── scripts/                   # Automated deployment scripts
│   ├── start_docker_system.sh # One-click system startup
│   ├── stop_docker_system.sh  # Clean system shutdown
│   └── test_docker_system.sh  # System validation tests
├── config/                    # Service configurations
│   ├── docker_config.py       # Docker environment settings
│   ├── gateway_docker_config.py
│   ├── rag_docker_config.py
│   └── requirements-*.txt     # Service-specific dependencies
└── README.md                  # Docker deployment guide
```

#### Option A: Automated Deployment (Recommended)
```bash
# Navigate to docker integration directory
cd docker-integration

# Make scripts executable
chmod +x scripts/*.sh

# Start entire system with health checks
./scripts/start_docker_system.sh

# Test system functionality
./scripts/test_docker_system.sh

# Stop system (with optional cleanup)
./scripts/stop_docker_system.sh [--clean]
```

#### Option B: Manual Deployment
```bash
# Navigate to docker integration directory
cd docker-integration

# Build and start all services
docker-compose up --build -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

#### Deployment Scripts Details

**start_docker_system.sh**:
- Builds all Docker containers
- Starts services in correct order
- Waits for initialization (30s)
- Performs health checks on all endpoints
- Reports service status

**test_docker_system.sh**:
- Tests ChromaDB connectivity
- Validates RAG service with sample payloads
- Tests API Gateway security filtering
- Verifies end-to-end threat detection

**stop_docker_system.sh**:
- Gracefully stops all services
- Optional `--clean` flag removes all data volumes
- Performs system cleanup

### 4. Verify Installation

After running the deployment scripts, verify all services:

```bash
# Check all containers are running
docker-compose ps

# Expected output: All services with "Up" status
#   rag-service    Up      0.0.0.0:8000->8000/tcp
#   mongodb        Up      0.0.0.0:27017->27017/tcp
```

#### Service Health Checks
```bash
# RAG Service health
curl http://localhost:8000/health
# Expected: {"status": "healthy", "services": {...}}

# MongoDB connection test
curl http://localhost:8000/threat_statistics
# Expected: Statistics with verdict breakdowns
```

#### Quick Functionality Test
```bash
# Test malicious payload detection
curl -X POST "http://localhost:8000/check_payload" \
  -H "Content-Type: application/json" \
  -d '{"payload": "1 UNION SELECT password FROM users", "source_ip": "192.168.1.1"}'

# Expected response:
# {
#   "verdict": "malicious",
#   "confidence_score": 0.7,
#   "threat_details": {
#     "attack_type": "Authentication Bypass",
#     "severity": "Critical",
#     "mitre_techniques": ["T1078"]
#   }
# }
```

## Configuration

### Service Ports
- **RAG Service**: 8000 (Main threat analysis API)
- **MongoDB**: 27017 (Database storage)
- **ChromaDB**: Internal container communication

### Database Configuration
The system automatically creates MongoDB collections:
- `threat_verdicts` - Stores malicious payload analysis
- `payload_analysis` - Performance metrics  
- `system_logs` - Service events and errors

### CSV Data Sources
- `mitre_attack_structured_dataset.csv` - MITRE ATT&CK techniques
- `payload_dataset.csv` - Known malicious patterns

## API Usage

### Health Check
```bash
curl http://localhost:8000/health
```

### Analyze Payload
```bash
curl -X POST "http://localhost:8000/check_payload" \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "1 UNION SELECT password FROM users",
    "source_ip": "192.168.1.100"
  }'
```

### Get Threat Statistics
```bash
curl http://localhost:8000/threat_statistics
```

## Common Setup Errors & Solutions

### 1. Docker Issues

**Error**: `Cannot connect to the Docker daemon`
```bash
# Solution: Start Docker service
sudo systemctl start docker    # Linux
# Or restart Docker Desktop    # Windows/macOS
```

**Error**: `Port already in use`
```bash
# Solution: Check and kill processes using ports
sudo lsof -i :8000  # Check port 8000
sudo kill -9 <PID>  # Kill process
```

**Error**: `docker-compose command not found`
```bash
# Solution: Install Docker Compose
sudo apt-get install docker-compose-plugin  # Linux
# Or update Docker Desktop                   # Windows/macOS
```

### 2. Memory Issues

**Error**: Container exits with code 137 (Out of Memory)
```bash
# Solution: Increase Docker memory allocation
# Docker Desktop → Settings → Resources → Memory (minimum 8GB)
```

**Error**: ChromaDB startup fails
```bash
# Solution: Clear vector database and restart
docker-compose down -v
docker-compose up -d
```

### 3. Database Connection Issues

**Error**: `MongoDB connection failed`
```bash
# Check MongoDB container status
docker-compose logs mongodb

# Restart MongoDB service
docker-compose restart mongodb
```

**Error**: `ChromaDB not responding`
```bash
# Check ChromaDB directory permissions
ls -la assr/cybersecurity_vectordb/

# Recreate ChromaDB data
docker-compose down
docker volume rm <project>_mongodb_data
docker-compose up -d
```

### 4. Network Connectivity

**Error**: `Service unavailable` (503)
```bash
# Check all services are running
docker-compose ps

# Check logs for specific service
docker-compose logs rag-service
```

**Error**: `Connection refused`
```bash
# Verify service ports
netstat -tlnp | grep :8000

# Check firewall settings
sudo ufw status  # Linux
```

### 5. Data Loading Issues

**Error**: `CSV files not found`
```bash
# Ensure CSV files exist in assr/ directory
ls -la assr/*.csv

# If missing, create sample data or contact maintainer
```

**Error**: `Vector database empty`
```bash
# Check ChromaDB initialization
docker-compose logs rag-service | grep -i chroma

# Force regenerate embeddings (if applicable)
docker-compose restart rag-service
```

## Verification

### 1. Service Health Check
```bash
# Check all services are running
docker-compose ps

# Expected output: All services with "Up" status
```

### 2. Test Basic Functionality
```bash
# Health check
curl http://localhost:8000/health

# Expected response: {"status": "healthy", "services": {...}}
```

### 3. Test Threat Detection
```bash
# Test SQL injection detection
curl -X POST "http://localhost:8000/check_payload" \
  -H "Content-Type: application/json" \
  -d '{"payload": "1 UNION SELECT password FROM users", "source_ip": "192.168.1.1"}'

# Expected: verdict="malicious", MITRE techniques, severity level
```

### 4. Verify Database Storage
```bash
# Check MongoDB data
curl http://localhost:8000/threat_statistics

# Expected: Statistics showing threat counts and attack types
```

## Development Setup

### Local Development (Optional)
```bash
# Install Python dependencies
cd assr
pip install -r requirements.txt

# Run RAG service locally (for development)
python rag_service.py
```

### File Structure
```
├── assr/                     # Main RAG service
│   ├── rag_service.py       # FastAPI application
│   ├── db_logging.py        # MongoDB integration
│   ├── requirements.txt     # Python dependencies
│   └── *.csv               # Threat intelligence data
├── docker-integration/      # Docker deployment
│   ├── docker-compose.yml  # Service orchestration
│   └── dockerfiles/        # Container definitions
└── API-gateway/            # Security gateway service
```

## Maintenance

### Regular Tasks
```bash
# View logs
docker-compose logs -f

# Update containers
docker-compose pull
docker-compose up -d

# Backup MongoDB data
docker exec mongodb mongodump --out /backup

# Clean up old containers
docker system prune -f
```

### Performance Monitoring
```bash
# Monitor resource usage
docker stats

# Check disk usage  
df -h
du -sh assr/cybersecurity_vectordb/
```

## Support

### Getting Help
- Check service logs: `docker-compose logs -f [service-name]`
- Verify all services are running: `docker-compose ps`
- Review this README for common errors and solutions
- Ensure system requirements are met

### Service Status
All services should show "Up" status in `docker-compose ps`. If any service shows "Exit" status, check its logs for error details.

## Security Notes

This system is designed for threat detection and includes:
- Real-time payload analysis using machine learning
- MongoDB logging for audit trails  
- ChromaDB vector database for intelligent pattern matching
- CSV-based threat intelligence integration

Ensure proper network security when deploying in production environments.
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
ChromaDB automatically handles vector indexing:
```sh
# Vector database is automatically maintained
# No manual retraining required
```

### 6. Check Logs
Malicious verdicts are logged in `assr/malicious_verdicts.log`.

---

## Deployment
- Dockerfile and docker-compose.yml provided for containerized deployment.
- Persistent volumes for ChromaDB and MongoDB data.

---

## Notes
- Ensure ports 8000 (RAG service) and 27017 (MongoDB) are open.
- ChromaDB runs internally within the RAG service container.
- For production, secure API keys and network.
- Customize backend URLs in API-Gateway as needed.

