"""
MongoDB logging module for threat intelligence and verdict data
"""

import os
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
try:
    from motor.motor_asyncio import AsyncIOMotorClient # type: ignore
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError # type: ignore
except ImportError:
    # For IDE compatibility when packages aren't installed locally
    AsyncIOMotorClient = None
    ConnectionFailure = Exception
    ServerSelectionTimeoutError = Exception
import json

logger = logging.getLogger(__name__)

class MongoDBLogger:
    def __init__(self):
        self.client: Optional[Any] = None
        self.database: Optional[Any] = None
        self.collections: Dict[str, Any] = {}
        self.connected = False
        
        # MongoDB connection settings from environment
        self.host = os.getenv('MONGODB_HOST', 'mongodb')
        self.port = int(os.getenv('MONGODB_PORT', '27017'))
        self.username = os.getenv('MONGODB_USERNAME', 'admin')
        self.password = os.getenv('MONGODB_PASSWORD', 'admin123')
        self.database_name = os.getenv('MONGODB_DATABASE', 'threat_intelligence')
        
        # Collection names
        self.THREAT_VERDICTS = 'threat_verdicts'
        self.PAYLOAD_ANALYSIS = 'payload_analysis'
        self.SYSTEM_LOGS = 'system_logs'
        
    async def initialize(self) -> bool:
        """Initialize MongoDB connection and collections"""
        try:
            # Create connection string
            connection_string = f"mongodb://{self.username}:{self.password}@{self.host}:{self.port}/{self.database_name}?authSource=admin"
            
            # Create client with timeout settings
            if AsyncIOMotorClient is None:
                logger.error("Motor package not available")
                return False
                
            self.client = AsyncIOMotorClient(
                connection_string,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                maxPoolSize=10
            )
            
            # Test connection
            if self.client is not None:
                await self.client.admin.command('ping')
                # Get database
                self.database = self.client[self.database_name]
            
            # Initialize collections
            await self._initialize_collections()
            
            self.connected = True
            logger.info(f"MongoDB connected successfully to {self.host}:{self.port}/{self.database_name}")
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self.connected = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            self.connected = False
            return False
    
    async def _initialize_collections(self):
        """Initialize collections with indexes"""
        try:
            # Create collections if they don't exist
            if self.database is not None:
                collection_names = await self.database.list_collection_names()
                
                collections_to_create = [
                    self.THREAT_VERDICTS,
                    self.PAYLOAD_ANALYSIS,
                    self.SYSTEM_LOGS
                ]
                
                for collection_name in collections_to_create:
                    if collection_name not in collection_names:
                        await self.database.create_collection(collection_name)
                        logger.info(f"Created collection: {collection_name}")
                    
                    self.collections[collection_name] = self.database[collection_name]
            
            # Create indexes for better performance
            await self._create_indexes()
            
        except Exception as e:
            logger.error(f"Error initializing collections: {e}")
            raise
    
    async def _create_indexes(self):
        """Create indexes for better query performance"""
        try:
            # Indexes for threat_verdicts collection
            if self.THREAT_VERDICTS in self.collections:
                verdicts_collection = self.collections[self.THREAT_VERDICTS]
                await verdicts_collection.create_index([("timestamp", -1)])  # Recent first
                await verdicts_collection.create_index([("verdict", 1)])
                await verdicts_collection.create_index([("source_ip", 1)])
                await verdicts_collection.create_index([("threat_details.severity", 1)])
                await verdicts_collection.create_index([("threat_details.attack_type", 1)])
                
            # Indexes for payload_analysis collection
            if self.PAYLOAD_ANALYSIS in self.collections:
                analysis_collection = self.collections[self.PAYLOAD_ANALYSIS]
                await analysis_collection.create_index([("timestamp", -1)])
                await analysis_collection.create_index([("processing_time_ms", 1)])
                await analysis_collection.create_index([("confidence_score", -1)])
                
            # Indexes for system_logs collection
            if self.SYSTEM_LOGS in self.collections:
                logs_collection = self.collections[self.SYSTEM_LOGS]
                await logs_collection.create_index([("timestamp", -1)])
                await logs_collection.create_index([("level", 1)])
                
            logger.info("MongoDB indexes created successfully")
            
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
    
    async def log_threat_verdict(self, payload: str, verdict: str, confidence_score: float, 
                               threat_details: Dict[str, Any], source_ip: Optional[str] = None,
                               processing_time_ms: int = 0, similar_threats: Optional[List[Dict]] = None,
                               blocking_recommended: bool = False) -> bool:
        """Log a threat verdict to MongoDB"""
        if not self.connected or self.THREAT_VERDICTS not in self.collections:
            logger.warning("MongoDB not connected, skipping threat verdict logging")
            return False
        
        try:
            document = {
                'timestamp': datetime.utcnow(),
                'payload': payload,
                'verdict': verdict,
                'confidence_score': confidence_score,
                'threat_details': {
                    'signature': threat_details.get('signature', ''),
                    'attack_type': threat_details.get('attack_type', ''),
                    'severity': threat_details.get('severity', ''),
                    'mitre_techniques': threat_details.get('mitre_techniques', []),
                    'description': threat_details.get('description', ''),
                    'risk_level': threat_details.get('risk_level', ''),
                    'affected_systems': threat_details.get('affected_systems', []),
                    'recommendations': threat_details.get('recommendations', [])
                },
                'source_ip': source_ip,
                'processing_time_ms': processing_time_ms,
                'similar_threats': similar_threats or [],
                'blocking_recommended': blocking_recommended,
                'service_version': '2.0.0',
                'analysis_method': 'chromadb_csv_enriched'
            }
            
            result = await self.collections[self.THREAT_VERDICTS].insert_one(document)
            logger.info(f"Threat verdict logged to MongoDB with ID: {result.inserted_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error logging threat verdict to MongoDB: {e}")
            return False
    
    async def log_payload_analysis(self, payload: str, analysis_timestamp: str,
                                 processing_time_ms: int, analysis_method: str,
                                 success: bool = True, error_message: Optional[str] = None) -> bool:
        """Log payload analysis metrics"""
        if not self.connected or self.PAYLOAD_ANALYSIS not in self.collections:
            return False
        
        try:
            document = {
                'timestamp': datetime.utcnow(),
                'payload': payload,
                'analysis_timestamp': analysis_timestamp,
                'processing_time_ms': processing_time_ms,
                'analysis_method': analysis_method,
                'success': success,
                'error_message': error_message,
                'payload_length': len(payload),
                'service_version': '2.0.0'
            }
            
            result = await self.collections[self.PAYLOAD_ANALYSIS].insert_one(document)
            return True
            
        except Exception as e:
            logger.error(f"Error logging payload analysis to MongoDB: {e}")
            return False
    
    async def log_system_event(self, level: str, message: str, component: str,
                             metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Log system events and errors"""
        if not self.connected or self.SYSTEM_LOGS not in self.collections:
            return False
        
        try:
            document = {
                'timestamp': datetime.utcnow(),
                'level': level,  # INFO, WARNING, ERROR, CRITICAL
                'message': message,
                'component': component,
                'metadata': metadata or {},
                'service_version': '2.0.0'
            }
            
            result = await self.collections[self.SYSTEM_LOGS].insert_one(document)
            return True
            
        except Exception as e:
            logger.error(f"Error logging system event to MongoDB: {e}")
            return False
    
    async def get_threat_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat statistics for the last N hours"""
        if not self.connected or self.THREAT_VERDICTS not in self.collections:
            return {}
        
        try:
            from datetime import timedelta
            
            since = datetime.utcnow() - timedelta(hours=hours)
            
            pipeline = [
                {'$match': {'timestamp': {'$gte': since}}},
                {'$group': {
                    '_id': '$verdict',
                    'count': {'$sum': 1},
                    'avg_confidence': {'$avg': '$confidence_score'}
                }}
            ]
            
            results = await self.collections[self.THREAT_VERDICTS].aggregate(pipeline).to_list(None)
            
            # Also get attack type breakdown
            attack_type_pipeline = [
                {'$match': {
                    'timestamp': {'$gte': since},
                    'verdict': 'malicious'
                }},
                {'$group': {
                    '_id': '$threat_details.attack_type',
                    'count': {'$sum': 1}
                }},
                {'$sort': {'count': -1}}
            ]
            
            attack_types = await self.collections[self.THREAT_VERDICTS].aggregate(attack_type_pipeline).to_list(None)
            
            return {
                'period_hours': hours,
                'verdict_breakdown': results,
                'top_attack_types': attack_types,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {}
    
    async def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.connected = False
            logger.info("MongoDB connection closed")

# Global MongoDB logger instance
mongo_logger = MongoDBLogger()

async def initialize_mongodb():
    """Initialize MongoDB connection"""
    return await mongo_logger.initialize()

async def close_mongodb():
    """Close MongoDB connection"""
    await mongo_logger.close()