from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
import os
import sys
import uvicorn
import asyncio
import logging
import time
import pandas as pd
import json
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any, Union, TYPE_CHECKING
from datetime import datetime

# Set up logging FIRST (before any imports that use logger)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the rag_pipeline to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

# Create fallback classes first
class MockRAGPipelineOrchestrator:
    def __init__(self, config): 
        self.vector_db = None

class MockRAGPipelineConfig:
    def __init__(self): 
        self.vector_db_path = ""

class MockRAGSecurityAgent:
    def __init__(self, vector_db): 
        self.vector_db = vector_db
    def analyze_threat(self, indicators): 
        return None
    def analyze_payload(self, payload): 
        return None

# Try to import RAG pipeline components with proper error handling
RAG_PIPELINE_AVAILABLE = False
RAGPipelineOrchestrator = MockRAGPipelineOrchestrator
RAGPipelineConfig = MockRAGPipelineConfig  
RAGSecurityAgent = MockRAGSecurityAgent

try:
    from rag_pipeline.main_pipeline import RAGPipelineOrchestrator as _RAGPipelineOrchestrator
    from rag_pipeline.main_pipeline import RAGPipelineConfig as _RAGPipelineConfig
    from rag_pipeline.rag_agent import RAGSecurityAgent as _RAGSecurityAgent
    
    # Override with real classes if available
    RAGPipelineOrchestrator = _RAGPipelineOrchestrator  # type: ignore
    RAGPipelineConfig = _RAGPipelineConfig  # type: ignore
    RAGSecurityAgent = _RAGSecurityAgent  # type: ignore
    RAG_PIPELINE_AVAILABLE = True
    logger.info("RAG Pipeline modules imported successfully")
except ImportError as e:
    logger.warning(f"RAG Pipeline not available, using fallback mode: {e}")
    # Keep using mock classes

# Global variables - Only ChromaDB through RAG pipeline
rag_pipeline = None

def init_rag_pipeline():
    """Initialize the RAG pipeline with ChromaDB"""
    global rag_pipeline
    if RAG_PIPELINE_AVAILABLE:
        try:
            config = RAGPipelineConfig()
            config.vector_db_path = os.path.join(os.path.dirname(__file__), "cybersecurity_vectordb")
            
            # Create directory if it doesn't exist
            os.makedirs(config.vector_db_path, exist_ok=True)
            
            rag_pipeline = RAGPipelineOrchestrator(config)  # type: ignore
            logger.info("RAG Pipeline with ChromaDB initialized successfully")
            return rag_pipeline
        except Exception as e:
            logger.warning(f"Failed to initialize RAG Pipeline: {e}")
            return None
    else:
        logger.info("RAG Pipeline not available, service will use fallback analysis")
        return None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting RAG service...")
    
    global rag_pipeline
    try:
        # Initialize RAG pipeline (uses ChromaDB internally)
        rag_pipeline = init_rag_pipeline()
        
        if rag_pipeline:
            logger.info("RAG service with ChromaDB initialized successfully")
        else:
            logger.warning("RAG pipeline not initialized - service will use fallback analysis")
        
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        rag_pipeline = None
    
    yield
    
    # Shutdown
    logger.info("RAG service shutting down")
    if rag_pipeline:
        try:
            # Add cleanup if needed
            pass
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

app = FastAPI(lifespan=lifespan, title="Enhanced RAG Security Service (ChromaDB)", version="2.0.0")

# Health check endpoint - SINGLE ENDPOINT ONLY
@app.get("/health")
async def rag_service_health():
    """Comprehensive health check endpoint"""
    try:
        health_status = {
            "status": "healthy",
            "service": "rag-service",
            "version": "2.0.0",
            "rag_pipeline_available": RAG_PIPELINE_AVAILABLE,
            "rag_pipeline_initialized": rag_pipeline is not None,
            "timestamp": datetime.now().isoformat(),
            "fallback_mode": not RAG_PIPELINE_AVAILABLE
        }
        
        if rag_pipeline is None and RAG_PIPELINE_AVAILABLE:
            health_status["status"] = "degraded"
            health_status["message"] = "RAG pipeline failed to initialize"
            
        return health_status
    except Exception as e:
        return {
            "status": "error",
            "service": "rag-service", 
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

class PayloadRequest(BaseModel):
    payload: str
    source_ip: Optional[str] = Field(None, description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    timestamp: Optional[str] = Field(None, description="Request timestamp")

class ThreatDetails(BaseModel):
    signature: str = ""
    attack_type: str = ""
    severity: str = ""
    mitre_techniques: List[str] = []
    description: str = ""
    confidence_score: float = 0.0
    risk_level: str = ""
    affected_systems: List[str] = []
    recommendations: List[str] = []

class PayloadAnalysisResponse(BaseModel):
    verdict: str  # 'malicious', 'legit', 'unknown'
    confidence_score: float
    threat_details: ThreatDetails
    payload: str
    analysis_timestamp: str
    processing_time_ms: int
    similar_threats: List[Dict[str, Any]] = []
    blocking_recommended: bool = False

@app.get('/stats')
async def stats():
    try:
        if rag_pipeline is None:
            return {
                'status': 'fallback',
                'message': 'RAG Pipeline not initialized, using fallback analysis',
                'vector_db': 'ChromaDB',
                'mode': 'fallback'
            }
        
        # Get stats from ChromaDB through RAG pipeline
        stats_info = {
            'status': 'ok',
            'vector_db': 'ChromaDB',
            'cybersecurity_vectordb': 'connected',
            'mode': 'full_rag'
        }
        
        return stats_info
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {'status': 'error', 'message': str(e)}

@app.post('/check_payload')
async def check_payload(req: PayloadRequest) -> PayloadAnalysisResponse:
    start_time = time.time()
    analysis_timestamp = datetime.now().isoformat()
    
    try:
        # Initialize default response
        threat_details = ThreatDetails()
        verdict = 'unknown'
        confidence_score = 0.0
        similar_threats = []
        blocking_recommended = False
        
        # Method 1: Try RAG Pipeline first (most comprehensive)
        if rag_pipeline and RAG_PIPELINE_AVAILABLE:
            try:
                logger.info("Using RAG Pipeline for analysis")
                analysis_result = await analyze_with_rag_pipeline(req.payload)
                if analysis_result:
                    verdict = analysis_result['verdict']
                    confidence_score = analysis_result['confidence_score']
                    threat_details = ThreatDetails(**analysis_result['threat_details'])
                    similar_threats = analysis_result.get('similar_threats', [])
                    blocking_recommended = analysis_result.get('blocking_recommended', False)
            except Exception as e:
                logger.warning(f"RAG Pipeline analysis failed: {e}")
        
        # Method 2: Fallback to simple pattern matching
        if verdict == 'unknown':
            logger.info("Using pattern matching fallback")
            verdict = await call_pattern_matching(req.payload)
            confidence_score = 0.6 if verdict == 'malicious' else 0.4
            
            if verdict == 'malicious':
                threat_details = ThreatDetails(
                    attack_type="Pattern-based detection",
                    severity="Medium",
                    description="Detected based on payload patterns",
                    confidence_score=confidence_score,
                    recommendations=["Further investigation recommended", "Consider blocking this payload"]
                )
                blocking_recommended = True
        
        # Log malicious verdicts
        if verdict == 'malicious':
            log_malicious_detailed(req.payload, confidence_score, threat_details, req.source_ip)
        
        processing_time = int((time.time() - start_time) * 1000)
        
        return PayloadAnalysisResponse(
            verdict=verdict,
            confidence_score=confidence_score,
            threat_details=threat_details,
            payload=req.payload,
            analysis_timestamp=analysis_timestamp,
            processing_time_ms=processing_time,
            similar_threats=similar_threats,
            blocking_recommended=blocking_recommended
        )
    
    except Exception as e:
        logger.error(f"Error in check_payload: {e}")
        processing_time = int((time.time() - start_time) * 1000)
        
        return PayloadAnalysisResponse(
            verdict='unknown',
            confidence_score=0.0,
            threat_details=ThreatDetails(
                description=f"Analysis failed: {str(e)}",
                recommendations=["Manual review required"]
            ),
            payload=req.payload,
            analysis_timestamp=analysis_timestamp,
            processing_time_ms=processing_time,
            blocking_recommended=False
        )

async def analyze_with_rag_pipeline(payload: str) -> Optional[Dict[str, Any]]:
    """Analyze payload using the RAG pipeline"""
    try:
        if not rag_pipeline or not RAG_PIPELINE_AVAILABLE:
            logger.info("RAG pipeline not available for analysis")
            return None
        
        # Use the RAG pipeline for comprehensive analysis
        try:
            security_agent = RAGSecurityAgent(rag_pipeline.vector_db)  # type: ignore
        except Exception as e:
            logger.error(f"Failed to create RAGSecurityAgent: {e}")
            return None
        
        # Analyze the payload - convert string to list format expected by RAG
        threat_indicators = [payload]  # Convert single payload to list
        
        try:
            threat_analysis = security_agent.analyze_threat(threat_indicators)
            payload_analysis = security_agent.analyze_payload(payload)
        except Exception as e:
            logger.error(f"RAG analysis failed: {e}")
            return None
        
        # Determine verdict based on analysis
        verdict = 'unknown'
        confidence_score = 0.5
        
        if threat_analysis and hasattr(threat_analysis, 'threat_level'):
            threat_level = str(threat_analysis.threat_level).lower()
            if threat_level in ['high', 'critical']:
                verdict = 'malicious'
                confidence_score = getattr(threat_analysis, 'confidence_score', 0.8)
            elif threat_level in ['low', 'none']:
                verdict = 'legit'
                confidence_score = getattr(threat_analysis, 'confidence_score', 0.7)
        
        # Build comprehensive threat details
        threat_details = {
            'signature': getattr(payload_analysis, 'attack_classification', '') if payload_analysis else '',
            'attack_type': getattr(payload_analysis, 'payload_type', '') if payload_analysis else '',
            'severity': getattr(payload_analysis, 'severity_level', '') if payload_analysis else '',
            'mitre_techniques': getattr(threat_analysis, 'mitre_techniques', []) if threat_analysis else [],
            'description': getattr(threat_analysis, 'analysis_summary', '') if threat_analysis else '',
            'confidence_score': confidence_score,
            'risk_level': getattr(threat_analysis, 'threat_level', '') if threat_analysis else '',
            'affected_systems': getattr(threat_analysis, 'affected_systems', []) if threat_analysis else [],
            'recommendations': getattr(threat_analysis, 'recommendations', []) if threat_analysis else []
        }
        
        similar_threats = []
        if threat_analysis and hasattr(threat_analysis, 'evidence'):
            similar_threats = getattr(threat_analysis, 'evidence', [])[:3]  # Top 3 similar threats
        
        return {
            'verdict': verdict,
            'confidence_score': confidence_score,
            'threat_details': threat_details,
            'similar_threats': similar_threats,
            'blocking_recommended': verdict == 'malicious' and confidence_score > 0.7
        }
        
    except Exception as e:
        logger.error(f"Unexpected error in RAG Pipeline analysis: {e}")
        return None

# Logging functions
def log_malicious(payload, score):
    try:
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        with open(os.path.join(log_dir, 'malicious_verdicts.log'), 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()}\t{payload}\t{score}\n")
    except Exception as e:
        logger.error(f"Error logging malicious payload: {e}")

def log_malicious_detailed(payload: str, score: float, threat_details: ThreatDetails, source_ip: Optional[str] = None):
    """Enhanced logging for malicious payloads with detailed threat information"""
    try:
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'payload': payload,
            'confidence_score': score,
            'threat_details': {
                'signature': threat_details.signature,
                'attack_type': threat_details.attack_type,
                'severity': threat_details.severity,
                'mitre_techniques': threat_details.mitre_techniques,
                'description': threat_details.description,
                'risk_level': threat_details.risk_level
            },
            'source_ip': source_ip,
            'blocking_recommended': score > 0.7
        }
        
        # Write to detailed log file
        with open(os.path.join(log_dir, 'detailed_malicious_verdicts.log'), 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
            
        # Also write to simple log for backward compatibility
        log_malicious(payload, score)
        
    except Exception as e:
        logger.error(f"Error logging detailed malicious payload: {e}")

async def call_pattern_matching(payload: str) -> str:
    """Enhanced pattern matching fallback with more comprehensive patterns"""
    try:
        # SQL Injection patterns
        sql_patterns = ['union', 'select', 'drop', 'delete', 'insert', 'update', 'exec', 'execute', '--', ';--']
        
        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'alert(', 'document.cookie', 'eval(', 'onload=', 'onerror=']
        
        # Command injection patterns
        cmd_patterns = ['&&', '||', '|', ';', '`', '$(' ]
        
        # Directory traversal patterns
        path_patterns = ['../', '..\\', '/etc/passwd', '/etc/shadow', 'c:\\windows']
        
        # Authentication bypass patterns
        auth_patterns = ['admin', 'root', 'password', "'or'1'='1", '"or"1"="1']
        
        all_patterns = sql_patterns + xss_patterns + cmd_patterns + path_patterns + auth_patterns
        payload_lower = payload.lower()
        
        threat_count = 0
        for pattern in all_patterns:
            if pattern.lower() in payload_lower:
                threat_count += 1
        
        # More sophisticated scoring
        if threat_count >= 2:
            return 'malicious'
        elif threat_count == 1 and len(payload) > 50:  # Single pattern in long payload
            return 'malicious'
        else:
            return 'legit'
            
    except Exception as e:
        logger.error(f"Error in pattern matching: {e}")
        return 'legit'

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")