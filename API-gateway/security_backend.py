from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
import httpx
import logging
import uvicorn
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import os
import time

# Import security rules
try:
    import owasp_rules
    import regex_rules
    import incident_logger
    RULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import security rules: {e}")
    RULES_AVAILABLE = False

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/security_backend.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Enhanced Security Backend Service", version="2.0.0")

# Initialize security components - these are modules, not classes
owasp_rules_module = None
regex_rules_module = None
incident_logger_module = None

if RULES_AVAILABLE:
    try:
        owasp_rules_module = owasp_rules
        regex_rules_module = regex_rules
        incident_logger_module = incident_logger
        logger.info("✅ OWASP and Regex rules loaded successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize security rules: {e}")
        RULES_AVAILABLE = False

# Configuration
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://localhost:8000")
BLOCKED_IPS = set()  # In-memory blocked IPs (use Redis in production)

# Security statistics
SECURITY_STATS = {
    "total_requests": 0,
    "blocked_requests": 0,
    "owasp_detections": 0,
    "regex_detections": 0,
    "rag_detections": 0,
    "ip_blocks": 0
}

class PayloadRequest(BaseModel):
    payload: str
    source_ip: Optional[str] = Field(None, description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    endpoint: Optional[str] = Field(None, description="Requested endpoint")
    method: Optional[str] = Field(None, description="HTTP method")
    headers: Optional[Dict[str, str]] = Field(None, description="Request headers")

class SecurityDecision(BaseModel):
    action: str  # 'allow', 'block', 'monitor'
    verdict: str
    confidence_score: float
    threat_details: Dict[str, Any]
    processing_time_ms: int
    timestamp: str
    blocking_reason: Optional[str] = None
    rule_source: Optional[str] = None  # 'owasp', 'regex', 'rag', 'heuristic'

@app.middleware("http")
async def enhanced_security_middleware(request: Request, call_next):
    """Enhanced security middleware with multi-layer protection"""
    start_time = time.time()
    client_ip = request.client.host if request.client else "unknown"
    
    # Increment total requests
    SECURITY_STATS["total_requests"] += 1
    
    # Step 1: IP Blocklist Check
    if client_ip in BLOCKED_IPS:
        SECURITY_STATS["blocked_requests"] += 1
        logger.warning(f"🚫 Blocked request from banned IP: {client_ip}")
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Access denied",
                "reason": "IP blocked due to previous malicious activity",
                "incident_id": f"BLOCKED-IP-{int(time.time())}"
            }
        )
    
    # Step 2: Extract payload from request
    payload = await extract_payload_from_request(request)
    
    if payload:
        # Step 3: Enhanced security analysis
        security_decision = await enhanced_security_analysis(
            payload=payload,
            source_ip=client_ip,
            user_agent=request.headers.get("user-agent", ""),
            endpoint=str(request.url.path),
            method=request.method,
            headers=dict(request.headers)
        )
        
        # Step 4: Take action based on security decision
        if security_decision.action == "block":
            SECURITY_STATS["blocked_requests"] += 1
            
            # Auto-block IP for high-confidence threats
            if security_decision.confidence_score > 0.8:
                BLOCKED_IPS.add(client_ip)
                SECURITY_STATS["ip_blocks"] += 1
                logger.warning(f"🔒 Auto-blocked IP {client_ip} for high-confidence threat")
            
            # Log security incident
            await log_enhanced_security_incident(security_decision, client_ip, payload, request)
            
            logger.warning(f"🚫 Blocked malicious request from {client_ip}: {security_decision.blocking_reason}")
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Request blocked due to security threat",
                    "threat_type": security_decision.threat_details.get("attack_type", "Unknown"),
                    "severity": security_decision.threat_details.get("severity", "Unknown"),
                    "rule_source": security_decision.rule_source,
                    "confidence": security_decision.confidence_score,
                    "incident_id": f"INC-{int(time.time())}"
                }
            )
        
        elif security_decision.action == "monitor":
            # Log for monitoring but allow request
            await log_enhanced_security_incident(security_decision, client_ip, payload, request)
    
    # Process the request
    response = await call_next(request)
    
    # Add security headers to response
    response.headers["X-Security-Scan"] = "completed"
    response.headers["X-Processing-Time"] = f"{(time.time() - start_time) * 1000:.2f}ms"
    
    return response

async def extract_payload_from_request(request: Request) -> Optional[str]:
    """Enhanced payload extraction from various request parts"""
    try:
        payload_parts = []
        
        # Get URL path (check for path traversal, etc.)
        if request.url.path:
            payload_parts.append(f"path:{request.url.path}")
        
        # Get query parameters
        if request.query_params:
            query_string = str(request.query_params)
            payload_parts.append(f"query:{query_string}")
        
        # Get request body (for POST/PUT requests)
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    body_str = body.decode('utf-8', errors='ignore')
                    payload_parts.append(f"body:{body_str}")
            except Exception as e:
                logger.warning(f"Could not read request body: {e}")
        
        # Get critical headers
        suspicious_headers = ['x-forwarded-for', 'x-real-ip', 'referer', 'origin']
        for header in suspicious_headers:
            if header in request.headers:
                payload_parts.append(f"{header}:{request.headers[header]}")
        
        return " | ".join(payload_parts) if payload_parts else None
        
    except Exception as e:
        logger.error(f"Error extracting payload: {e}")
        return None

async def enhanced_security_analysis(
    payload: str,
    source_ip: str,
    user_agent: str,
    endpoint: str,
    method: str,
    headers: Dict[str, str]
) -> SecurityDecision:
    """Multi-layer security analysis with OWASP, Regex, and RAG"""
    start_time = time.time()
    
    try:
        # Step 1: OWASP Rules Check (Fastest - Rule-based)
        if RULES_AVAILABLE and owasp_rules:
            try:
                owasp_result = await check_owasp_rules(payload)
                if owasp_result:
                    SECURITY_STATS["owasp_detections"] += 1
                    processing_time = int((time.time() - start_time) * 1000)
                    
                    return SecurityDecision(
                        action="block",
                        verdict="malicious",
                        confidence_score=owasp_result.get("confidence", 0.95),
                        threat_details={
                            "source": "owasp",
                            "attack_type": owasp_result.get("rule_name", "OWASP violation"),
                            "rule_id": owasp_result.get("rule_id"),
                            "description": owasp_result.get("description", ""),
                            "severity": "high",
                            "payload_snippet": payload[:100]
                        },
                        processing_time_ms=processing_time,
                        timestamp=datetime.now().isoformat(),
                        blocking_reason=f"OWASP rule violation: {owasp_result.get('rule_name')}",
                        rule_source="owasp"
                    )
            except Exception as e:
                logger.warning(f"OWASP check failed: {e}")

        # Step 2: Regex Rules Check (Fast - Pattern matching)
        if RULES_AVAILABLE and regex_rules:
            try:
                regex_result = await check_regex_rules(payload)
                if regex_result:
                    SECURITY_STATS["regex_detections"] += 1
                    processing_time = int((time.time() - start_time) * 1000)
                    
                    return SecurityDecision(
                        action="block",
                        verdict="malicious",
                        confidence_score=regex_result.get("confidence", 0.85),
                        threat_details={
                            "source": "regex",
                            "attack_type": regex_result.get("pattern_name", "Pattern match"),
                            "pattern": regex_result.get("pattern", ""),
                            "matched_text": regex_result.get("matched_text", ""),
                            "severity": "medium",
                            "payload_snippet": payload[:100]
                        },
                        processing_time_ms=processing_time,
                        timestamp=datetime.now().isoformat(),
                        blocking_reason=f"Malicious pattern detected: {regex_result.get('pattern_name')}",
                        rule_source="regex"
                    )
            except Exception as e:
                logger.warning(f"Regex check failed: {e}")

        # Step 3: Heuristic Checks (Fast - Built-in patterns)
        heuristic_result = await check_heuristic_patterns(payload, user_agent, endpoint, headers)
        if heuristic_result:
            processing_time = int((time.time() - start_time) * 1000)
            
            return SecurityDecision(
                action=heuristic_result.get("action", "block"),
                verdict="suspicious",
                confidence_score=heuristic_result.get("confidence", 0.7),
                threat_details=heuristic_result.get("threat_details", {}),
                processing_time_ms=processing_time,
                timestamp=datetime.now().isoformat(),
                blocking_reason=heuristic_result.get("reason", "Heuristic pattern match"),
                rule_source="heuristic"
            )

        # Step 4: RAG Service Check (Slower - ML analysis for unknown patterns)
        rag_result = await check_rag_service(payload, source_ip, user_agent, endpoint)
        if rag_result and rag_result.get("verdict") == "malicious":
            SECURITY_STATS["rag_detections"] += 1
            processing_time = int((time.time() - start_time) * 1000)
            
            action = "block" if rag_result.get("confidence_score", 0) > 0.7 else "monitor"
            
            return SecurityDecision(
                action=action,
                verdict=rag_result.get("verdict", "malicious"),
                confidence_score=rag_result.get("confidence_score", 0.7),
                threat_details=rag_result.get("threat_details", {}),
                processing_time_ms=processing_time,
                timestamp=datetime.now().isoformat(),
                blocking_reason=f"ML model detected: {rag_result.get('threat_details', {}).get('attack_type', 'malicious activity')}",
                rule_source="rag"
            )

        # Step 5: Default Allow (All checks passed)
        processing_time = int((time.time() - start_time) * 1000)
        
        return SecurityDecision(
            action="allow",
            verdict="clean",
            confidence_score=0.95,
            threat_details={
                "status": "clean",
                "checks_performed": ["owasp", "regex", "heuristic", "rag"],
                "source_ip": source_ip,
                "endpoint": endpoint
            },
            processing_time_ms=processing_time,
            timestamp=datetime.now().isoformat(),
            blocking_reason=None,
            rule_source="multi_layer"
        )

    except Exception as e:
        logger.error(f"Error in enhanced security analysis: {e}")
        processing_time = int((time.time() - start_time) * 1000)
        
        # Fail securely - block on system errors
        return SecurityDecision(
            action="block",
            verdict="system_error",
            confidence_score=0.5,
            threat_details={"error": str(e), "status": "system_error"},
            processing_time_ms=processing_time,
            timestamp=datetime.now().isoformat(),
            blocking_reason=f"Security analysis system error: {str(e)}",
            rule_source="system"
        )

async def check_owasp_rules(payload: str) -> Optional[Dict[str, Any]]:
    """Check payload against OWASP rules"""
    try:
        if owasp_rules_module and hasattr(owasp_rules_module, 'OWASP_RULES'):
            for rule_name, rule_func in owasp_rules_module.OWASP_RULES.items():
                if rule_func(payload):
                    return {
                        "is_malicious": True,
                        "rule_name": rule_name,
                        "rule_id": rule_name.replace(" ", "_").upper(),
                        "description": f"OWASP {rule_name} detected",
                        "confidence": 0.95,
                        "pattern": rule_name
                    }
    except Exception as e:
        logger.warning(f"OWASP rules check error: {e}")
    
    return None

async def check_regex_rules(payload: str) -> Optional[Dict[str, Any]]:
    """Check payload against regex rules"""
    try:
        if regex_rules_module and hasattr(regex_rules_module, 'check_regex_rules'):
            matched_rules = regex_rules_module.check_regex_rules(payload)
            if matched_rules:
                # Get details of the first matched rule
                rule_name = matched_rules[0]
                rule_details = regex_rules_module.get_rule_details(rule_name)
                
                return {
                    "is_malicious": True,
                    "pattern_name": rule_name,
                    "pattern": rule_details.get("attack_type", rule_name) if rule_details else rule_name,
                    "matched_text": payload[:50],  # First 50 chars of payload
                    "confidence": 0.85,
                    "description": f"Regex pattern match: {rule_name}",
                    "all_matched_rules": matched_rules
                }
    except Exception as e:
        logger.warning(f"Regex rules check error: {e}")
    
    return None

async def check_heuristic_patterns(
    payload: str, 
    user_agent: str, 
    endpoint: str, 
    headers: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """Built-in heuristic security checks"""
    try:
        # Check for suspicious user agents
        malicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'burpsuite', 'acunetix', 
            'w3af', 'paros', 'webscarab', 'nessus', 'openvas'
        ]
        
        if user_agent:
            user_agent_lower = user_agent.lower()
            for agent in malicious_agents:
                if agent in user_agent_lower:
                    return {
                        "action": "block",
                        "confidence": 0.9,
                        "reason": f"Malicious user agent detected: {agent}",
                        "threat_details": {
                            "source": "heuristic",
                            "attack_type": "security_tool",
                            "user_agent": user_agent,
                            "severity": "high"
                        }
                    }

        # Check for suspicious headers
        if 'x-forwarded-for' in headers:
            xff = headers['x-forwarded-for']
            # Check for header injection attempts
            if any(char in xff for char in ['\n', '\r', '<', '>', '"', '\'']):
                return {
                    "action": "block",
                    "confidence": 0.85,
                    "reason": "Header injection attempt detected",
                    "threat_details": {
                        "source": "heuristic",
                        "attack_type": "header_injection",
                        "header": "x-forwarded-for",
                        "severity": "medium"
                    }
                }

        # Check for excessive request size
        if len(payload) > 10000:  # 10KB limit
            return {
                "action": "monitor",
                "confidence": 0.6,
                "reason": "Unusually large request payload",
                "threat_details": {
                    "source": "heuristic",
                    "attack_type": "large_payload",
                    "payload_size": len(payload),
                    "severity": "low"
                }
            }

        # Check for directory traversal patterns
        traversal_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
        for pattern in traversal_patterns:
            if pattern in payload.lower():
                return {
                    "action": "block",
                    "confidence": 0.8,
                    "reason": "Directory traversal attempt detected",
                    "threat_details": {
                        "source": "heuristic",
                        "attack_type": "directory_traversal",
                        "pattern": pattern,
                        "severity": "high"
                    }
                }

    except Exception as e:
        logger.warning(f"Heuristic check error: {e}")
    
    return None

async def check_rag_service(
    payload: str, 
    source_ip: str, 
    user_agent: str, 
    endpoint: str
) -> Optional[Dict[str, Any]]:
    """Check with RAG service for ML-based analysis"""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{RAG_SERVICE_URL}/check_payload",
                json={
                    "payload": payload,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "endpoint": endpoint,
                    "timestamp": datetime.now().isoformat()
                }
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"RAG service returned status {response.status_code}")
                
    except Exception as e:
        logger.warning(f"RAG service communication error: {e}")
    
    return None

async def log_enhanced_security_incident(
    decision: SecurityDecision, 
    source_ip: str, 
    payload: str, 
    request: Request
):
    """Enhanced security incident logging"""
    try:
        incident = {
            "timestamp": decision.timestamp,
            "source_ip": source_ip,
            "action": decision.action,
            "verdict": decision.verdict,
            "confidence_score": decision.confidence_score,
            "rule_source": decision.rule_source,
            "threat_details": decision.threat_details,
            "blocking_reason": decision.blocking_reason,
            "processing_time_ms": decision.processing_time_ms,
            "endpoint": str(request.url.path),
            "method": request.method,
            "user_agent": request.headers.get("user-agent", ""),
            "payload": payload[:500],  # Limit payload size in logs
            "request_size": len(payload),
            "headers": {k: v for k, v in request.headers.items() 
                       if k.lower() not in ['authorization', 'cookie', 'x-api-key']}
        }
        
        # Log to file
        os.makedirs('logs', exist_ok=True)
        with open('logs/security_incidents.log', 'a', encoding='utf-8') as f:
            f.write(json.dumps(incident) + '\n')
        
        # Log with incident logger if available
        if incident_logger_module and hasattr(incident_logger_module, 'log_incident'):
            incident_logger_module.log_incident(
                incident.get("source_ip", "unknown"),
                incident.get("payload", ""),
                incident.get("rule_source", "security_check")
            )
            
    except Exception as e:
        logger.error(f"Error logging security incident: {e}")

# Enhanced API Endpoints

@app.get("/health")
async def enhanced_health_check():
    """Enhanced health check with component status"""
    try:
        # Check RAG service health
        rag_healthy = False
        rag_response_time = None
        
        try:
            start_time = time.time()
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{RAG_SERVICE_URL}/health")
                rag_healthy = response.status_code == 200
                rag_response_time = int((time.time() - start_time) * 1000)
        except Exception as e:
            logger.warning(f"RAG health check failed: {e}")
    
        return {
            "status": "healthy",
            "service": "enhanced-security-backend",
            "version": "2.0.0",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "owasp_rules": owasp_rules_module is not None,
                "regex_rules": regex_rules_module is not None,
                "incident_logger": incident_logger_module is not None,
                "rag_service": {
                    "healthy": rag_healthy,
                    "url": RAG_SERVICE_URL,
                    "response_time_ms": rag_response_time
                }
            },
            "statistics": SECURITY_STATS,
            "blocked_ips_count": len(BLOCKED_IPS)
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")

@app.post("/analyze")
async def enhanced_analyze_endpoint(request: PayloadRequest):
    """Enhanced payload analysis endpoint"""
    decision = await enhanced_security_analysis(
        payload=request.payload,
        source_ip=request.source_ip or "unknown",
        user_agent=request.user_agent or "",
        endpoint=request.endpoint or "/analyze",
        method="POST",
        headers=request.headers or {}
    )
    
    return decision

@app.get("/security-stats")
async def get_enhanced_security_stats():
    """Get comprehensive security statistics"""
    try:
        # Read recent security incidents
        incidents = []
        try:
            with open('logs/security_incidents.log', 'r', encoding='utf-8') as f:
                lines = f.readlines()[-100:]  # Last 100 incidents
                for line in lines:
                    try:
                        incidents.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logger.info("No security incidents log found")
        
        # Calculate detailed stats
        threat_types = {}
        rule_sources = {}
        hourly_stats = {}
        
        for incident in incidents:
            # Threat type distribution
            threat_type = incident.get('threat_details', {}).get('attack_type', 'unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # Rule source distribution
            rule_source = incident.get('rule_source', 'unknown')
            rule_sources[rule_source] = rule_sources.get(rule_source, 0) + 1
            
            # Hourly distribution
            try:
                hour = datetime.fromisoformat(incident.get('timestamp', '')).hour
                hourly_stats[hour] = hourly_stats.get(hour, 0) + 1
            except:
                pass
        
        malicious_count = sum(1 for inc in incidents if inc.get('verdict') == 'malicious')
        blocked_count = sum(1 for inc in incidents if inc.get('action') == 'block')
        avg_confidence = sum(inc.get('confidence_score', 0) for inc in incidents) / len(incidents) if incidents else 0
        avg_processing_time = sum(inc.get('processing_time_ms', 0) for inc in incidents) / len(incidents) if incidents else 0
        
        return {
            "overview": {
                "total_incidents": len(incidents),
                "malicious_incidents": malicious_count,
                "blocked_requests": blocked_count,
                "blocked_ips": len(BLOCKED_IPS),
                "avg_confidence_score": round(avg_confidence, 3),
                "avg_processing_time_ms": round(avg_processing_time, 2)
            },
            "runtime_stats": SECURITY_STATS,
            "threat_analysis": {
                "threat_types": threat_types,
                "rule_sources": rule_sources,
                "hourly_distribution": hourly_stats
            },
            "recent_incidents": incidents[-10:],  # Last 10 incidents
            "blocked_ips": list(BLOCKED_IPS),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        return {"error": f"Failed to retrieve security stats: {str(e)}"}

@app.get("/blocked-ips")
async def get_blocked_ips():
    """Get detailed blocked IPs information"""
    return {
        "blocked_ips": list(BLOCKED_IPS),
        "count": len(BLOCKED_IPS),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/block-ip/{ip}")
async def manual_block_ip(ip: str, reason: str = "Manual block"):
    """Manually block an IP address"""
    BLOCKED_IPS.add(ip)
    SECURITY_STATS["ip_blocks"] += 1
    
    # Log the manual block
    if incident_logger_module:
        incident_logger_module.log_incident(ip, f"Manual block: {reason}", "MANUAL_IP_BLOCK")
    
    logger.info(f"Manually blocked IP: {ip} - Reason: {reason}")
    return {"message": f"IP {ip} has been blocked", "reason": reason, "total_blocked": len(BLOCKED_IPS)}

@app.delete("/unblock-ip/{ip}")
async def unblock_ip(ip: str):
    """Unblock a specific IP address"""
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
        
        # Log the unblock
        if incident_logger_module:
            incident_logger_module.log_incident(ip, "Manual unblock", "MANUAL_IP_UNBLOCK")
        
        logger.info(f"Unblocked IP: {ip}")
        return {"message": f"IP {ip} has been unblocked", "total_blocked": len(BLOCKED_IPS)}
    else:
        return {"message": f"IP {ip} was not in the blocked list", "total_blocked": len(BLOCKED_IPS)}

@app.post("/clear-blocked-ips")
async def clear_all_blocked_ips():
    """Clear all blocked IPs"""
    count = len(BLOCKED_IPS)
    BLOCKED_IPS.clear()
    
    logger.info(f"Cleared all blocked IPs ({count} IPs)")
    return {"message": f"Cleared {count} blocked IPs", "remaining_blocked": 0}

@app.get("/test-security")
async def test_security_components():
    """Test all security components"""
    test_payloads = [
        {"name": "SQL Injection", "payload": "' OR 1=1--"},
        {"name": "XSS Attack", "payload": "<script>alert('xss')</script>"},
        {"name": "Directory Traversal", "payload": "../../../etc/passwd"},
        {"name": "Command Injection", "payload": "; rm -rf /"},
        {"name": "Clean Request", "payload": "normal search query"}
    ]
    
    results = []
    for test in test_payloads:
        try:
            request = PayloadRequest(
                payload=test["payload"],
                source_ip="127.0.0.1",
                user_agent="Security-Test-Agent/1.0",
                endpoint="/test",
                method="POST",
                headers={}
            )
            
            result = await enhanced_security_analysis(
                payload=request.payload,
                source_ip=request.source_ip or "127.0.0.1",
                user_agent=request.user_agent or "",
                endpoint="/test",
                method="POST",
                headers={}
            )
            
            results.append({
                "test_name": test["name"],
                "payload": test["payload"],
                "action": result.action,
                "verdict": result.verdict,
                "confidence": result.confidence_score,
                "rule_source": result.rule_source,
                "processing_time_ms": result.processing_time_ms
            })
            
        except Exception as e:
            results.append({
                "test_name": test["name"],
                "payload": test["payload"],
                "error": str(e)
            })
    
    return {
        "test_results": results,
        "components_tested": {
            "owasp_rules": owasp_rules_module is not None,
            "regex_rules": regex_rules_module is not None,
            "heuristic_checks": True,
            "rag_service": RAG_SERVICE_URL
        },
        "timestamp": datetime.now().isoformat()
    }

@app.post("/test_payload")
async def test_payload_endpoint(request: PayloadRequest):
    """
    Test a single payload against all security layers
    Useful for manual testing and integration testing
    """
    try:
        logger.info(f"Testing payload from {request.source_ip}: {request.payload[:50]}...")
        
        # Run the full security analysis
        result = await enhanced_security_analysis(
            payload=request.payload,
            source_ip=request.source_ip or "test-client",
            user_agent=request.user_agent or "test-agent",
            endpoint=request.endpoint or "/test_payload",
            method=request.method or "POST",
            headers=request.headers or {}
        )
        
        # Enhanced response with detailed breakdown
        response = {
            "test_result": {
                "action": result.action,
                "verdict": result.verdict,
                "confidence_score": result.confidence_score,
                "rule_source": result.rule_source,
                "blocking_reason": result.blocking_reason,
                "processing_time_ms": result.processing_time_ms
            },
            "payload_analysis": {
                "original_payload": request.payload,
                "payload_length": len(request.payload),
                "threat_details": result.threat_details
            },
            "security_layers_checked": {
                "owasp_rules": owasp_rules_module is not None,
                "regex_rules": regex_rules_module is not None,
                "heuristic_patterns": True,
                "rag_ml_model": RAG_SERVICE_URL
            },
            "recommendation": get_security_recommendation(result),
            "timestamp": result.timestamp
        }
        
        # Don't log this as a real incident (it's just testing)
        logger.info(f"Payload test completed: {result.action} - {result.verdict}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error testing payload: {e}")
        return {
            "error": "Payload testing failed",
            "details": str(e),
            "timestamp": datetime.now().isoformat()
        }

def get_security_recommendation(result: SecurityDecision) -> str:
    """Get security recommendation based on analysis result"""
    if result.action == "block":
        if result.confidence_score > 0.9:
            return "HIGH RISK: Immediate blocking recommended"
        elif result.confidence_score > 0.7:
            return "MEDIUM RISK: Consider blocking or rate limiting"
        else:
            return "LOW RISK: Monitor and review"
    elif result.action == "monitor":
        return "SUSPICIOUS: Log and monitor for patterns"
    else:
        return "CLEAN: Payload appears safe"

# Default protected endpoints for testing
@app.get("/")
async def root():
    return {
        "message": "Enhanced Security Backend Service",
        "version": "2.0.0",
        "protection_layers": ["OWASP Rules", "Regex Patterns", "Heuristic Analysis", "RAG ML Model"],
        "status": "🛡️ PROTECTED",
        "stats": SECURITY_STATS
    }

@app.get("/api/users")
async def get_users():
    return {
        "users": ["alice", "bob", "charlie"],
        "message": "This endpoint is protected by multi-layer security analysis",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/submit")
async def submit_data(data: Dict[str, Any]):
    return {
        "message": "Data received and processed successfully",
        "data": data,
        "status": "✅ success",
        "security_check": "passed",
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    logger.info("🚀 Starting Enhanced Security Backend Service...")
    logger.info(f"🔗 RAG Service URL: {RAG_SERVICE_URL}")
    logger.info(f"🛡️ OWASP Rules: {'✅ Loaded' if owasp_rules_module else '❌ Not available'}")
    logger.info(f"🔍 Regex Rules: {'✅ Loaded' if regex_rules_module else '❌ Not available'}")
    logger.info(f"📊 Incident Logger: {'✅ Available' if incident_logger_module else '❌ Not available'}")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=9000, 
        log_level="info",
        access_log=True
    )