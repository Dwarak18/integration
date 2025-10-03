import logging
import os
import time
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import json
from datetime import datetime
from dataclasses import asdict

from .vector_db import CybersecurityVectorDB
from .data_processor import ComprehensiveDataProcessor
from .ingestion import DataIngestionPipeline, IncrementalIngestionManager
from .retrieval import AdvancedRAGRetriever, RAGQueryOptimizer
from .rag_agent import RAGSecurityAgent, ThreatAnalysisResult, PayloadAnalysisResult, SecurityRecommendation

class RAGPipelineConfig:
    def __init__(self):
        self.vector_db_path = "cybersecurity_vectordb"
        self.processed_data_cache = "processed_data_cache.json"
        self.pipeline_logs = "rag_pipeline.log"
        self.similarity_threshold = 0.3  # Lowered to work with available data
        self.top_k_results = 10
        self.max_context_length = 2000
        self.batch_size = 50
        self.enable_caching = True
        self.auto_update_db = True
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vector_db_path': self.vector_db_path,
            'processed_data_cache': self.processed_data_cache,
            'pipeline_logs': self.pipeline_logs,
            'similarity_threshold': self.similarity_threshold,
            'top_k_results': self.top_k_results,
            'max_context_length': self.max_context_length,
            'batch_size': self.batch_size,
            'enable_caching': self.enable_caching,
            'auto_update_db': self.auto_update_db
        }

class RAGPipelineOrchestrator:
    def __init__(self, config: Optional[RAGPipelineConfig] = None):
        self.config = config or RAGPipelineConfig()
        self.setup_logging()
        
        self.vector_db = CybersecurityVectorDB(self.config.vector_db_path)
        self.data_processor = ComprehensiveDataProcessor()
        self.ingestion_manager = IncrementalIngestionManager(self.vector_db)
        self.retriever = AdvancedRAGRetriever(self.vector_db)
        self.optimizer = RAGQueryOptimizer(self.retriever)
        self.security_agent = RAGSecurityAgent(self.vector_db)
        
        self.pipeline_stats = {
            'initialization_time': datetime.now().isoformat(),
            'total_documents_processed': 0,
            'total_queries_processed': 0,
            'average_query_time': 0,
            'last_update': None
        }
        
        logging.info("RAG Pipeline Orchestrator initialized successfully")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.pipeline_logs),
                logging.StreamHandler()
            ]
        )
        
    def initialize_pipeline(self, mitre_csv_path: str, payload_csv_path: str, 
                          cyberagents_path: str, force_rebuild: bool = False) -> Dict[str, Any]:
        logging.info("Initializing RAG Pipeline...")
        
        start_time = time.time()
        
        try:
            if force_rebuild:
                logging.info("Force rebuild requested - clearing existing data")
                self.vector_db.reset_collection()
            
            collection_info = self.vector_db.get_collection_info()
            
            if collection_info['document_count'] == 0 or force_rebuild:
                logging.info("No existing data found - performing full data ingestion")
                
                ingestion_stats = self.ingestion_manager.full_reingest(
                    mitre_csv_path, payload_csv_path, cyberagents_path
                )
                
                self.pipeline_stats['total_documents_processed'] = ingestion_stats.get('total', 0)
                logging.info(f"Ingested {ingestion_stats.get('total', 0)} documents")
            else:
                logging.info(f"Found existing collection with {collection_info['document_count']} documents")
                self.pipeline_stats['total_documents_processed'] = collection_info['document_count']
            
            verification_results = self._verify_pipeline_health()
            
            end_time = time.time()
            initialization_time = end_time - start_time
            
            self.pipeline_stats['last_update'] = datetime.now().isoformat()
            
            result = {
                'status': 'success',
                'initialization_time': initialization_time,
                'pipeline_stats': self.pipeline_stats,
                'verification_results': verification_results,
                'collection_info': self.vector_db.get_collection_info()
            }
            
            logging.info(f"Pipeline initialized in {initialization_time:.2f} seconds")
            return result
            
        except Exception as e:
            logging.error(f"Pipeline initialization failed: {e}")
            return {
                'status': 'error',
                'error_message': str(e),
                'pipeline_stats': self.pipeline_stats
            }
    
    def analyze_security_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        logging.info("Analyzing security incident")
        
        start_time = time.time()
        
        try:
            threat_indicators = incident_data.get('indicators', [])
            context = incident_data.get('context', '')
            payloads = incident_data.get('payloads', [])
            
            analysis_results = {}
            
            if threat_indicators:
                threat_analysis = self.security_agent.analyze_threat(threat_indicators, context)
                analysis_results['threat_analysis'] = asdict(threat_analysis)
            
            payload_analyses = []
            for payload in payloads:
                payload_analysis = self.security_agent.analyze_payload(payload, context)
                payload_analyses.append(asdict(payload_analysis))
            
            if payload_analyses:
                analysis_results['payload_analyses'] = payload_analyses
            
            if threat_indicators:
                pattern_investigation = self.security_agent.investigate_attack_pattern(threat_indicators)
                analysis_results['pattern_investigation'] = pattern_investigation
            
            security_context = f"{context} {' '.join(threat_indicators)}"
            recommendations = self.security_agent.get_security_recommendations(security_context)
            analysis_results['security_recommendations'] = [asdict(rec) for rec in recommendations]
            
            end_time = time.time()
            analysis_time = end_time - start_time
            
            self.pipeline_stats['total_queries_processed'] += 1
            self._update_average_query_time(analysis_time)
            
            result = {
                'status': 'success',
                'analysis_time': analysis_time,
                'timestamp': datetime.now().isoformat(),
                'results': analysis_results
            }
            
            logging.info(f"Incident analysis completed in {analysis_time:.2f} seconds")
            return result
            
        except Exception as e:
            logging.error(f"Incident analysis failed: {e}")
            return {
                'status': 'error',
                'error_message': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def query_knowledge_base(self, query: str, query_type: str = "general", 
                           top_k: int = None) -> Dict[str, Any]:
        logging.info(f"Querying knowledge base: {query[:50]}...")
        
        start_time = time.time()
        
        try:
            top_k = top_k or self.config.top_k_results
            
            if query_type == "optimized":
                rag_context = self.optimizer.optimize_retrieval(query, top_k=top_k)
            else:
                rag_context = self.retriever.retrieve(query, top_k=top_k, 
                                                    similarity_threshold=self.config.similarity_threshold)
            
            results = []
            for doc in rag_context.retrieved_documents:
                results.append({
                    'content': doc.content,
                    'metadata': doc.metadata,
                    'similarity_score': doc.similarity_score,
                    'relevance_score': doc.relevance_score,
                    'source_type': doc.source_type,
                    'mitre_techniques': doc.mitre_techniques
                })
            
            end_time = time.time()
            query_time = end_time - start_time
            
            self.pipeline_stats['total_queries_processed'] += 1
            self._update_average_query_time(query_time)
            
            result = {
                'status': 'success',
                'query': query,
                'query_type': rag_context.query_type.value,
                'query_time': query_time,
                'confidence_score': rag_context.confidence_score,
                'aggregated_context': rag_context.aggregated_context,
                'sources': rag_context.sources,
                'results': results,
                'timestamp': datetime.now().isoformat()
            }
            
            logging.info(f"Knowledge base query completed in {query_time:.2f} seconds")
            return result
            
        except Exception as e:
            logging.error(f"Knowledge base query failed: {e}")
            return {
                'status': 'error',
                'error_message': str(e),
                'query': query,
                'timestamp': datetime.now().isoformat()
            }
    
    def analyze_payload_batch(self, payloads: List[str], 
                            additional_context: str = "") -> Dict[str, Any]:
        logging.info(f"Analyzing batch of {len(payloads)} payloads")
        
        start_time = time.time()
        
        try:
            batch_results = []
            
            for i, payload in enumerate(payloads):
                try:
                    analysis = self.security_agent.analyze_payload(payload, additional_context)
                    batch_results.append({
                        'payload_index': i,
                        'payload': payload[:100] + "..." if len(payload) > 100 else payload,
                        'analysis': asdict(analysis)
                    })
                except Exception as e:
                    batch_results.append({
                        'payload_index': i,
                        'payload': payload[:100] + "..." if len(payload) > 100 else payload,
                        'error': str(e)
                    })
            
            summary_stats = self._generate_batch_summary(batch_results)
            
            end_time = time.time()
            analysis_time = end_time - start_time
            
            self.pipeline_stats['total_queries_processed'] += len(payloads)
            self._update_average_query_time(analysis_time / len(payloads))
            
            result = {
                'status': 'success',
                'batch_size': len(payloads),
                'analysis_time': analysis_time,
                'results': batch_results,
                'summary_stats': summary_stats,
                'timestamp': datetime.now().isoformat()
            }
            
            logging.info(f"Batch payload analysis completed in {analysis_time:.2f} seconds")
            return result
            
        except Exception as e:
            logging.error(f"Batch payload analysis failed: {e}")
            return {
                'status': 'error',
                'error_message': str(e),
                'batch_size': len(payloads),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        collection_info = self.vector_db.get_collection_info()
        
        stats = {
            'pipeline_stats': self.pipeline_stats,
            'collection_info': collection_info,
            'config': self.config.to_dict(),
            'system_health': self._check_system_health(),
            'recent_activity': self._get_recent_activity()
        }
        
        return stats
    
    def update_knowledge_base(self, mitre_csv_path: str, payload_csv_path: str, 
                            cyberagents_path: str, incremental: bool = True) -> Dict[str, Any]:
        logging.info("Updating knowledge base")
        
        start_time = time.time()
        
        try:
            if incremental:
                processed_data = self.data_processor.process_all_datasets(
                    mitre_csv_path, payload_csv_path, cyberagents_path
                )
                
                ingestion_pipeline = DataIngestionPipeline(self.vector_db)
                stats = ingestion_pipeline.incremental_ingestion(processed_data)
            else:
                stats = self.ingestion_manager.full_reingest(
                    mitre_csv_path, payload_csv_path, cyberagents_path
                )
            
            end_time = time.time()
            update_time = end_time - start_time
            
            self.pipeline_stats['last_update'] = datetime.now().isoformat()
            self.pipeline_stats['total_documents_processed'] += stats.get('total', 0)
            
            result = {
                'status': 'success',
                'update_time': update_time,
                'ingestion_stats': stats,
                'timestamp': datetime.now().isoformat()
            }
            
            logging.info(f"Knowledge base updated in {update_time:.2f} seconds")
            return result
            
        except Exception as e:
            logging.error(f"Knowledge base update failed: {e}")
            return {
                'status': 'error',
                'error_message': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def export_analysis_results(self, results: Dict[str, Any], 
                              output_format: str = "json") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format.lower() == "json":
            filename = f"rag_analysis_results_{timestamp}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2, default=str)
        elif output_format.lower() == "txt":
            filename = f"rag_analysis_results_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self._format_results_as_text(results))
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        logging.info(f"Analysis results exported to {filename}")
        return filename
    
    def _verify_pipeline_health(self) -> Dict[str, Any]:
        verification_results = {
            'vector_db_accessible': False,
            'sample_queries_working': False,
            'data_retrieval_working': False,
            'agent_analysis_working': False,
            'overall_health': 'Unknown'
        }
        
        try:
            collection_info = self.vector_db.get_collection_info()
            verification_results['vector_db_accessible'] = True
            logging.info(f"Vector DB accessible with {collection_info['document_count']} documents")
            
            if collection_info['document_count'] > 0:
                test_query = "attack"
                results = self.retriever.retrieve(test_query, top_k=3)
                
                # Check if we got any results (sample queries working)
                verification_results['sample_queries_working'] = len(results.retrieved_documents) > 0
                logging.info(f"Sample query returned {len(results.retrieved_documents)} results")
                
                # Check if data retrieval is working (less strict - just need results with reasonable similarity)
                if results.retrieved_documents:
                    # Check if we have documents with reasonable similarity scores (> 0.3)
                    has_meaningful_results = any(doc.similarity_score > 0.3 for doc in results.retrieved_documents)
                    verification_results['data_retrieval_working'] = has_meaningful_results
                    logging.info(f"Data retrieval working: {has_meaningful_results} (best similarity: {max(doc.similarity_score for doc in results.retrieved_documents):.3f})")
                else:
                    verification_results['data_retrieval_working'] = False
                    logging.warning("No documents retrieved for test query")
                
                # Test agent analysis
                test_payload = "' OR '1'='1"
                analysis = self.security_agent.analyze_payload(test_payload)
                verification_results['agent_analysis_working'] = analysis.payload_type != 'Unknown'
                logging.info(f"Agent analysis working: {verification_results['agent_analysis_working']} (detected: {analysis.payload_type})")
            
            health_score = sum(verification_results[key] for key in verification_results if key != 'overall_health')
            if health_score == 4:
                verification_results['overall_health'] = 'Excellent'
            elif health_score >= 3:
                verification_results['overall_health'] = 'Good'
            elif health_score >= 2:
                verification_results['overall_health'] = 'Fair'
            else:
                verification_results['overall_health'] = 'Poor'
            
            logging.info(f"Pipeline health check completed: {health_score}/4 components working")
                
        except Exception as e:
            logging.error(f"Pipeline health check failed: {e}")
            verification_results['overall_health'] = f'Error: {str(e)}'
        
        return verification_results
    
    def _update_average_query_time(self, query_time: float):
        total_queries = self.pipeline_stats['total_queries_processed']
        current_avg = self.pipeline_stats['average_query_time']
        
        if total_queries == 1:
            self.pipeline_stats['average_query_time'] = query_time
        else:
            self.pipeline_stats['average_query_time'] = ((current_avg * (total_queries - 1)) + query_time) / total_queries
    
    def _generate_batch_summary(self, batch_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        successful_analyses = [r for r in batch_results if 'analysis' in r]
        
        if not successful_analyses:
            return {'error': 'No successful analyses in batch'}
        
        payload_types = {}
        severity_levels = {}
        attack_classifications = {}
        
        for result in successful_analyses:
            analysis = result['analysis']
            
            payload_type = analysis.get('payload_type', 'Unknown')
            payload_types[payload_type] = payload_types.get(payload_type, 0) + 1
            
            severity = analysis.get('severity_level', 'Medium')
            severity_levels[severity] = severity_levels.get(severity, 0) + 1
            
            attack_class = analysis.get('attack_classification', 'Unknown')
            attack_classifications[attack_class] = attack_classifications.get(attack_class, 0) + 1
        
        summary = {
            'total_payloads': len(batch_results),
            'successful_analyses': len(successful_analyses),
            'failed_analyses': len(batch_results) - len(successful_analyses),
            'payload_type_distribution': payload_types,
            'severity_distribution': severity_levels,
            'attack_classification_distribution': attack_classifications
        }
        
        return summary
    
    def _check_system_health(self) -> Dict[str, Any]:
        health_info = {
            'vector_db_size': 0,
            'memory_usage': 'Unknown',
            'disk_space': 'Unknown',
            'response_time_avg': self.pipeline_stats['average_query_time']
        }
        
        try:
            collection_info = self.vector_db.get_collection_info()
            health_info['vector_db_size'] = collection_info['document_count']
            
            if hasattr(os, 'statvfs'):
                statvfs = os.statvfs('.')
                free_space = statvfs.f_frsize * statvfs.f_availr
                health_info['disk_space'] = f"{free_space / (1024**3):.2f} GB available"
            
        except Exception as e:
            health_info['error'] = str(e)
        
        return health_info
    
    def _get_recent_activity(self) -> Dict[str, Any]:
        return {
            'last_query_time': 'Not tracked',
            'recent_query_count': self.pipeline_stats['total_queries_processed'],
            'last_update': self.pipeline_stats['last_update']
        }
    
    def _format_results_as_text(self, results: Dict[str, Any]) -> str:
        text_output = []
        text_output.append("=== RAG PIPELINE ANALYSIS RESULTS ===")
        text_output.append(f"Generated at: {results.get('timestamp', 'Unknown')}")
        text_output.append("")
        
        if 'results' in results and 'threat_analysis' in results['results']:
            threat = results['results']['threat_analysis']
            text_output.append("THREAT ANALYSIS:")
            text_output.append(f"  Threat Level: {threat.get('threat_level', 'Unknown')}")
            text_output.append(f"  Confidence: {threat.get('confidence_score', 0):.2f}")
            text_output.append(f"  Attack Vectors: {', '.join(threat.get('attack_vectors', []))}")
            text_output.append("")
        
        if 'results' in results and 'payload_analyses' in results['results']:
            text_output.append("PAYLOAD ANALYSES:")
            for i, payload in enumerate(results['results']['payload_analyses']):
                text_output.append(f"  Payload {i+1}:")
                text_output.append(f"    Type: {payload.get('payload_type', 'Unknown')}")
                text_output.append(f"    Severity: {payload.get('severity_level', 'Unknown')}")
                text_output.append("")
        
        return "\n".join(text_output)


def create_rag_pipeline(mitre_csv_path: str, payload_csv_path: str, 
                       cyberagents_path: str, config: Optional[RAGPipelineConfig] = None) -> RAGPipelineOrchestrator:
    pipeline = RAGPipelineOrchestrator(config)
    
    init_result = pipeline.initialize_pipeline(
        mitre_csv_path, payload_csv_path, cyberagents_path
    )
    
    if init_result['status'] != 'success':
        raise RuntimeError(f"Pipeline initialization failed: {init_result.get('error_message', 'Unknown error')}")
    
    return pipeline
