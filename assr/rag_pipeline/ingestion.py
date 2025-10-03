import logging
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
from tqdm import tqdm

from .vector_db import CybersecurityVectorDB
from .data_processor import ComprehensiveDataProcessor

class DataIngestionPipeline:
    def __init__(self, vector_db: Optional[CybersecurityVectorDB] = None):
        self.vector_db = vector_db or CybersecurityVectorDB()
        self.data_processor = ComprehensiveDataProcessor()
        self.batch_size = 50
        
    def ingest_processed_data(self, processed_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
        ingestion_stats = {
            'mitre_data': 0,
            'payload_data': 0,
            'agent_knowledge': 0,
            'total': 0,
            'errors': 0
        }
        
        logging.info("Starting data ingestion into vector database...")
        
        for data_type, data_list in processed_data.items():
            if not data_list:
                continue
                
            logging.info(f"Ingesting {len(data_list)} items of type: {data_type}")
            
            try:
                if data_type == 'mitre_data':
                    count = self._ingest_mitre_data(data_list)
                    ingestion_stats['mitre_data'] = count
                elif data_type == 'payload_data':
                    count = self._ingest_payload_data(data_list)
                    ingestion_stats['payload_data'] = count
                elif data_type == 'agent_knowledge':
                    count = self._ingest_agent_knowledge(data_list)
                    ingestion_stats['agent_knowledge'] = count
                    
            except Exception as e:
                logging.error(f"Error ingesting {data_type}: {e}")
                ingestion_stats['errors'] += 1
        
        ingestion_stats['total'] = (
            ingestion_stats['mitre_data'] + 
            ingestion_stats['payload_data'] + 
            ingestion_stats['agent_knowledge']
        )
        
        logging.info(f"Ingestion completed. Stats: {ingestion_stats}")
        return ingestion_stats
    
    def _ingest_mitre_data(self, mitre_data: List[Dict[str, Any]]) -> int:
        count = 0
        batch_documents = []
        batch_metadata = []
        
        for item in tqdm(mitre_data, desc="Ingesting MITRE data"):
            try:
                content = item.get('content', '')
                if not content.strip():
                    continue
                
                metadata = {
                    'type': 'mitre_attack',
                    'mitre_id': item.get('mitre_id', ''),
                    'attack_type': item.get('attack_type', ''),
                    'severity': item.get('severity', 'Medium'),
                    'payload': item.get('payload', ''),
                    'signature': item.get('signature', ''),
                    'label': item.get('label', ''),
                    'source': item.get('source', 'mitre_attack_dataset'),
                    'chunk_id': item.get('chunk_id', 0),
                    'total_chunks': item.get('total_chunks', 1),
                    'row_index': item.get('row_index', 0),
                    'mitre_techniques': json.dumps(item.get('mitre_techniques', []))
                }
                
                batch_documents.append(content)
                batch_metadata.append(metadata)
                count += 1
                
                if len(batch_documents) >= self.batch_size:
                    self.vector_db.add_documents(batch_documents, batch_metadata)
                    batch_documents = []
                    batch_metadata = []
                    
            except Exception as e:
                logging.warning(f"Error processing MITRE item: {e}")
                continue
        
        if batch_documents:
            self.vector_db.add_documents(batch_documents, batch_metadata)
        
        return count
    
    def _ingest_payload_data(self, payload_data: List[Dict[str, Any]]) -> int:
        count = 0
        batch_documents = []
        batch_metadata = []
        
        for item in tqdm(payload_data, desc="Ingesting payload data"):
            try:
                content = item.get('content', '')
                if not content.strip():
                    continue
                
                metadata = {
                    'type': 'security_payload',
                    'mitre_id': item.get('mitre_id', ''),
                    'attack_type': item.get('attack_type', ''),
                    'severity': item.get('severity', 'Medium'),
                    'payload': item.get('payload', ''),
                    'signature': item.get('signature', ''),
                    'label': item.get('label', ''),
                    'source': item.get('source', 'payload_dataset'),
                    'chunk_id': item.get('chunk_id', 0),
                    'total_chunks': item.get('total_chunks', 1),
                    'row_index': item.get('row_index', 0),
                    'mitre_techniques': json.dumps(item.get('mitre_techniques', []))
                }
                
                batch_documents.append(content)
                batch_metadata.append(metadata)
                count += 1
                
                if len(batch_documents) >= self.batch_size:
                    self.vector_db.add_documents(batch_documents, batch_metadata)
                    batch_documents = []
                    batch_metadata = []
                    
            except Exception as e:
                logging.warning(f"Error processing payload item: {e}")
                continue
        
        if batch_documents:
            self.vector_db.add_documents(batch_documents, batch_metadata)
        
        return count
    
    def _ingest_agent_knowledge(self, agent_knowledge: List[Dict[str, Any]]) -> int:
        count = 0
        batch_documents = []
        batch_metadata = []
        
        for item in tqdm(agent_knowledge, desc="Ingesting agent knowledge"):
            try:
                content = item.get('content', '')
                if not content.strip():
                    continue
                
                metadata = {
                    'type': 'agent_knowledge',
                    'agent_name': item.get('agent_name', ''),
                    'source': item.get('source', 'cyberagents'),
                    'file_path': item.get('file_path', ''),
                    'chunk_id': item.get('chunk_id', 0),
                    'total_chunks': item.get('total_chunks', 1)
                }
                
                batch_documents.append(content)
                batch_metadata.append(metadata)
                count += 1
                
                if len(batch_documents) >= self.batch_size:
                    self.vector_db.add_documents(batch_documents, batch_metadata)
                    batch_documents = []
                    batch_metadata = []
                    
            except Exception as e:
                logging.warning(f"Error processing agent knowledge item: {e}")
                continue
        
        if batch_documents:
            self.vector_db.add_documents(batch_documents, batch_metadata)
        
        return count
    
    def ingest_from_files(self, mitre_csv_path: str, payload_csv_path: str, 
                         cyberagents_path: str) -> Dict[str, int]:
        logging.info("Processing data from source files...")
        
        processed_data = self.data_processor.process_all_datasets(
            mitre_csv_path, payload_csv_path, cyberagents_path
        )
        
        return self.ingest_processed_data(processed_data)
    
    def incremental_ingestion(self, new_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
        logging.info("Performing incremental data ingestion...")
        return self.ingest_processed_data(new_data)
    
    def verify_ingestion(self) -> Dict[str, Any]:
        info = self.vector_db.get_collection_info()
        
        sample_queries = [
            "SQL injection attack",
            "MITRE ATT&CK T1110",
            "brute force authentication",
            "cross-site scripting XSS",
            "command injection"
        ]
        
        verification_results = {
            'collection_info': info,
            'sample_searches': {}
        }
        
        for query in sample_queries:
            try:
                results = self.vector_db.similarity_search(query, top_k=3, threshold=0.5)
                verification_results['sample_searches'][query] = {
                    'results_count': len(results),
                    'avg_similarity': sum(r['similarity'] for r in results) / len(results) if results else 0
                }
            except Exception as e:
                verification_results['sample_searches'][query] = {'error': str(e)}
        
        return verification_results

class IncrementalIngestionManager:
    def __init__(self, vector_db: Optional[CybersecurityVectorDB] = None):
        self.vector_db = vector_db or CybersecurityVectorDB()
        self.ingestion_pipeline = DataIngestionPipeline(self.vector_db)
        self.metadata_file = "ingestion_metadata.json"
        
    def save_ingestion_metadata(self, metadata: Dict[str, Any]) -> None:
        try:
            existing_metadata = self.load_ingestion_metadata()
            existing_metadata.update(metadata)
            existing_metadata['last_updated'] = time.time()
            
            with open(self.metadata_file, 'w') as f:
                json.dump(existing_metadata, f, indent=2)
                
            logging.info(f"Saved ingestion metadata to {self.metadata_file}")
        except Exception as e:
            logging.error(f"Failed to save ingestion metadata: {e}")
    
    def load_ingestion_metadata(self) -> Dict[str, Any]:
        try:
            if Path(self.metadata_file).exists():
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.warning(f"Failed to load ingestion metadata: {e}")
        
        return {
            'total_ingested': 0,
            'last_updated': 0,
            'file_hashes': {},
            'ingestion_history': []
        }
    
    def full_reingest(self, mitre_csv_path: str, payload_csv_path: str, 
                     cyberagents_path: str) -> Dict[str, int]:
        logging.info("Performing full reingestion - resetting vector database...")
        
        self.vector_db.reset_collection()
        
        stats = self.ingestion_pipeline.ingest_from_files(
            mitre_csv_path, payload_csv_path, cyberagents_path
        )
        
        metadata = {
            'full_reingest_stats': stats,
            'mitre_csv_path': mitre_csv_path,
            'payload_csv_path': payload_csv_path,
            'cyberagents_path': cyberagents_path
        }
        
        self.save_ingestion_metadata(metadata)
        
        return stats

class BatchIngestionOptimizer:
    def __init__(self, vector_db: Optional[CybersecurityVectorDB] = None):
        self.vector_db = vector_db or CybersecurityVectorDB()
        self.optimal_batch_sizes = {
            'mitre_data': 100,
            'payload_data': 150,
            'agent_knowledge': 50
        }
        
    def optimize_batch_ingestion(self, processed_data: Dict[str, List[Dict[str, Any]]], 
                               performance_target: float = 0.8) -> Dict[str, Any]:
        optimization_results = {}
        
        for data_type, data_list in processed_data.items():
            if not data_list:
                continue
                
            logging.info(f"Optimizing batch ingestion for {data_type}")
            
            batch_size = self.optimal_batch_sizes.get(data_type, 50)
            
            start_time = time.time()
            
            pipeline = DataIngestionPipeline(self.vector_db)
            pipeline.batch_size = batch_size
            
            if data_type == 'mitre_data':
                count = pipeline._ingest_mitre_data(data_list)
            elif data_type == 'payload_data':
                count = pipeline._ingest_payload_data(data_list)
            elif data_type == 'agent_knowledge':
                count = pipeline._ingest_agent_knowledge(data_list)
            else:
                continue
                
            end_time = time.time()
            duration = end_time - start_time
            throughput = count / duration if duration > 0 else 0
            
            optimization_results[data_type] = {
                'count': count,
                'duration': duration,
                'throughput': throughput,
                'batch_size': batch_size
            }
            
            logging.info(f"Ingested {count} items of {data_type} in {duration:.2f}s (throughput: {throughput:.2f} items/s)")
        
        return optimization_results
