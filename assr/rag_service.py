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
import csv
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any, Union, TYPE_CHECKING
from datetime import datetime
from difflib import SequenceMatcher

# Set up logging FIRST (before any imports that use logger)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import MongoDB logging module
try:
    from db_logging import mongo_logger, initialize_mongodb, close_mongodb
    MONGODB_AVAILABLE = True
    logger.info("MongoDB logging module imported successfully")
except ImportError as e:
    logger.warning(f"MongoDB logging not available: {e}")
    MONGODB_AVAILABLE = False

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
payload_dataset = None

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

def load_payload_dataset():
    """Load the payload dataset from CSV file once"""
    global payload_dataset
    
    if payload_dataset is not None:
        return payload_dataset
    
    try:
        dataset_path = os.path.join(os.path.dirname(__file__), "payload_dataset.csv")
        payload_dataset = []
        
        with open(dataset_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                payload_dataset.append({
                    'payload': row.get('Payload', '').strip(),
                    'signature': row.get('Signature', '').strip(),
                    'attack_type': row.get('AttackType', '').strip(),
                    'severity': row.get('Severity', '').strip(),
                    'mitre': row.get('MITRE', '').strip(),
                    'label': row.get('Label', '').strip(),
                    'description': row.get('Description', '').strip()
                })
        
        logger.info(f"Loaded {len(payload_dataset)} payload signatures from dataset")
        return payload_dataset
        
    except Exception as e:
        logger.error(f"Failed to load payload dataset: {str(e)}")
        return []

def enrich_threat_details_from_csv(payload, attack_type_hint=None):
    """Enrich threat details using CSV dataset for malicious payloads"""
    dataset = load_payload_dataset()
    
    if not dataset:
        return None
    
    best_match = None
    best_ratio = 0.0
    
    # Clean user payload for comparison
    user_payload_clean = payload.lower().strip()
    
    # First try exact matching by attack type if hint is provided
    if attack_type_hint:
        for entry in dataset:
            if entry['attack_type'].lower() == attack_type_hint.lower():
                payload_clean = entry['payload'].lower().strip()
                ratio = SequenceMatcher(None, user_payload_clean, payload_clean).ratio()
                
                if ratio > best_ratio and ratio > 0.2:  # Lower threshold for type-specific matches
                    best_ratio = ratio
                    best_match = entry
    
    # If no good type-specific match, try general matching
    if not best_match or best_ratio < 0.4:
        for entry in dataset:
            payload_clean = entry['payload'].lower().strip()
            
            # Calculate similarity ratio
            ratio = SequenceMatcher(None, user_payload_clean, payload_clean).ratio()
            
            # Also check if user payload contains key parts of the dataset payload
            if any(part in user_payload_clean for part in payload_clean.split() if len(part) > 3):
                ratio += 0.1  # Boost for partial matches
            
            if ratio > best_ratio and ratio > 0.3:  # Minimum threshold
                best_ratio = ratio
                best_match = entry
    
    return best_match if best_ratio > 0.3 else None

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
        
        # Initialize MongoDB logging
        if MONGODB_AVAILABLE:
            mongodb_connected = await initialize_mongodb()
            if mongodb_connected:
                logger.info("MongoDB logging initialized successfully")
                await mongo_logger.log_system_event(
                    'INFO', 'RAG service started with MongoDB logging', 'rag_service',
                    {'rag_pipeline_available': rag_pipeline is not None}
                )
            else:
                logger.warning("MongoDB connection failed - logging to files only")
        else:
            logger.info("MongoDB not available - using file logging only")
        
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        rag_pipeline = None
    
    yield
    
    # Shutdown
    logger.info("RAG service shutting down")
    
    # Close MongoDB connection
    if MONGODB_AVAILABLE:
        try:
            await mongo_logger.log_system_event(
                'INFO', 'RAG service shutting down', 'rag_service'
            )
            await close_mongodb()
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
    
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

@app.get('/threat_statistics')
async def get_threat_statistics(hours: int = 24):
    """Get threat statistics from MongoDB for the last N hours"""
    try:
        if not MONGODB_AVAILABLE or not mongo_logger.connected:
            return {
                'status': 'error',
                'message': 'MongoDB not available',
                'hours': hours
            }
        
        stats = await mongo_logger.get_threat_statistics(hours)
        
        if not stats:
            return {
                'status': 'error',
                'message': 'Failed to retrieve statistics',
                'hours': hours
            }
        
        return {
            'status': 'success',
            'data': stats,
            'mongodb_connected': True
        }
        
    except Exception as e:
        logger.error(f"Error getting threat statistics: {e}")
        return {
            'status': 'error',
            'message': str(e),
            'hours': hours
        }

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
            pattern_result = await call_pattern_matching(req.payload)
            verdict = pattern_result['verdict']
            confidence_score = pattern_result['confidence_score']
            threat_details = ThreatDetails(**pattern_result['threat_details'])
            similar_threats = pattern_result.get('similar_threats', [])
            blocking_recommended = pattern_result.get('blocking_recommended', False)
        
        processing_time = int((time.time() - start_time) * 1000)
        
        # Log malicious verdicts
        if verdict == 'malicious':
            await log_malicious_detailed(
                req.payload, confidence_score, threat_details, req.source_ip,
                processing_time, similar_threats, blocking_recommended
            )
        
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
        
        # Build base threat details from ChromaDB analysis
        base_threat_details = {
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
        
        # If payload is identified as malicious, enrich with CSV dataset details
        if verdict == 'malicious':
            attack_type_hint = base_threat_details.get('attack_type', '')
            csv_match = enrich_threat_details_from_csv(payload, attack_type_hint)
            
            if csv_match:
                # Enrich with CSV data while keeping ChromaDB analysis
                threat_details = {
                    'signature': csv_match['signature'] or base_threat_details['signature'],
                    'attack_type': csv_match['attack_type'] or base_threat_details['attack_type'],
                    'severity': csv_match['severity'] or base_threat_details['severity'],
                    'mitre_techniques': [csv_match['mitre']] if csv_match['mitre'] else base_threat_details['mitre_techniques'],
                    'description': csv_match['description'] or base_threat_details['description'],
                    'confidence_score': confidence_score,
                    'risk_level': csv_match['severity'] or base_threat_details['risk_level'],
                    'affected_systems': base_threat_details['affected_systems'],
                    'recommendations': base_threat_details['recommendations']
                }
                logger.info(f"Enriched malicious payload with CSV data: {csv_match['attack_type']} - {csv_match['severity']}")
            else:
                threat_details = base_threat_details
        else:
            threat_details = base_threat_details
        
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

async def log_malicious_detailed(payload: str, score: float, threat_details: ThreatDetails, 
                               source_ip: Optional[str] = None, processing_time_ms: int = 0,
                               similar_threats: Optional[List[Dict]] = None, blocking_recommended: bool = False):
    """Enhanced logging for malicious payloads with detailed threat information"""
    try:
        # MongoDB logging (primary)
        if MONGODB_AVAILABLE and mongo_logger.connected:
            threat_details_dict = {
                'signature': threat_details.signature,
                'attack_type': threat_details.attack_type,
                'severity': threat_details.severity,
                'mitre_techniques': threat_details.mitre_techniques,
                'description': threat_details.description,
                'risk_level': threat_details.risk_level,
                'affected_systems': threat_details.affected_systems,
                'recommendations': threat_details.recommendations
            }
            
            await mongo_logger.log_threat_verdict(
                payload=payload,
                verdict='malicious',
                confidence_score=score,
                threat_details=threat_details_dict,
                source_ip=source_ip,
                processing_time_ms=processing_time_ms,
                similar_threats=similar_threats or [],
                blocking_recommended=blocking_recommended
            )
        
        # File logging (backup/legacy)
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
            'blocking_recommended': blocking_recommended
        }
        
        # Write to detailed log file
        with open(os.path.join(log_dir, 'detailed_malicious_verdicts.log'), 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
            
        # Also write to simple log for backward compatibility
        log_malicious(payload, score)
        
    except Exception as e:
        logger.error(f"Error logging detailed malicious payload: {e}")

async def call_pattern_matching(payload: str) -> Dict[str, Any]:
    """Pattern matching fallback with CSV enrichment for malicious payloads"""
    try:
        
        # Fallback to pattern matching if no CSV match
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
        detected_types = []
        
        for pattern in all_patterns:
            if pattern.lower() in payload_lower:
                threat_count += 1
                if pattern in sql_patterns:
                    detected_types.append("SQL Injection")
                elif pattern in xss_patterns:
                    detected_types.append("Cross-Site Scripting")
                elif pattern in cmd_patterns:
                    detected_types.append("Command Injection")
                elif pattern in path_patterns:
                    detected_types.append("Directory Traversal")
                elif pattern in auth_patterns:
                    detected_types.append("Authentication Bypass")
        
        # More sophisticated scoring
        if threat_count >= 2:
            verdict = 'malicious'
            confidence = 0.7
        elif threat_count == 1 and len(payload) > 50:  # Single pattern in long payload
            verdict = 'malicious'
            confidence = 0.6
        else:
            verdict = 'legit'
            confidence = 0.3
        
        # Build base threat details for pattern matching
        attack_types = list(set(detected_types)) if detected_types else ["Unknown"]
        severity = "High" if threat_count >= 2 else "Medium" if threat_count == 1 else "Low"
        
        base_threat_details = {
            'signature': f"Pattern-based detection: {', '.join(attack_types)}",
            'attack_type': ', '.join(attack_types),
            'severity': severity,
            'mitre_techniques': [],
            'description': f"Detected {threat_count} suspicious pattern(s) in payload",
            'confidence_score': confidence,
            'risk_level': severity,
            'affected_systems': [],
            'recommendations': ["Monitor payload", "Consider blocking if confirmed malicious"]
        }
        
        # If malicious, try to enrich with CSV data
        if verdict == 'malicious' and attack_types and attack_types[0] != "Unknown":
            csv_match = enrich_threat_details_from_csv(payload, attack_types[0])
            
            if csv_match:
                # Enrich with CSV data
                threat_details = {
                    'signature': csv_match['signature'] or base_threat_details['signature'],
                    'attack_type': csv_match['attack_type'] or base_threat_details['attack_type'],
                    'severity': csv_match['severity'] or base_threat_details['severity'],
                    'mitre_techniques': [csv_match['mitre']] if csv_match['mitre'] else base_threat_details['mitre_techniques'],
                    'description': csv_match['description'] or base_threat_details['description'],
                    'confidence_score': confidence,
                    'risk_level': csv_match['severity'] or base_threat_details['risk_level'],
                    'affected_systems': base_threat_details['affected_systems'],
                    'recommendations': base_threat_details['recommendations']
                }
                logger.info(f"Pattern matching enriched with CSV data: {csv_match['attack_type']} - {csv_match['severity']}")
            else:
                threat_details = base_threat_details
        else:
            threat_details = base_threat_details
        
        return {
            'verdict': verdict,
            'confidence_score': confidence,
            'threat_details': threat_details,
            'similar_threats': [],
            'blocking_recommended': verdict == 'malicious' and confidence > 0.6
        }
            
    except Exception as e:
        logger.error(f"Error in pattern matching: {e}")
        return {
            'verdict': 'unknown',
            'confidence_score': 0.0,
            'threat_details': {
                'signature': '',
                'attack_type': '',
                'severity': '',
                'mitre_techniques': [],
                'description': f"Pattern matching failed: {str(e)}",
                'confidence_score': 0.0,
                'risk_level': '',
                'affected_systems': [],
                'recommendations': ["Manual review required"]
            },
            'similar_threats': [],
            'blocking_recommended': False
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")