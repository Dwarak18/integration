# RAG Service & API-Gateway Integration

## Overview
This project integrates a Retrieval-Augmented Generation (RAG) microservice with an API-Gateway for payload inspection and security automation. It uses Qdrant as the vector database and supports Gemini API fallback for unknown payloads.

---

## Endpoints

### RAG Service (FastAPI, port 8000)
- **POST /check_payload**
  - Request: `{ "payload": "<payload string>" }`
  - Response: `{ "verdict": "malicious|legit", "score": <float>, "results": {...} }`
- **POST /ingest_example**
  - Request: `{ "payload": "<payload string>" }`
  - Response: `{ "status": "inserted" }`
- **POST /retrain**
  - Request: None
  - Response: `{ "status": "retrained" }`
- **GET /stats**
  - Request: None
  - Response: `{ "status": "not implemented" }`

### API-Gateway (FastAPI, port 9000)
- All incoming requests are inspected by middleware:
  - Payload is sent to RAG service `/check_payload`.
  - If verdict is `malicious`, request is blocked and logged.
  - If `legit`, request is forwarded to backend.
  - If `unknown`, returns 503 error.

---


## How to Run

### 1. Build and Start All Services (Qdrant + RAG Service)
In your workspace root, run:
```sh
docker-compose up --build
```
This will start Qdrant (port 6333) and the RAG service (port 8000).

### 2. Start API-Gateway (in a separate terminal)
```sh
cd API-gateway
uvicorn main:app --host 0.0.0.0 --port 9000
```
This will start the API-Gateway on port 9000.

### 3. Test the RAG Service Endpoint
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
