#!/usr/bin/env python3

import sys
import os
import logging
from pathlib import Path

# Add the assr directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'assr'))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_payload_embedding():
    try:
        # Import the required modules
        from rag_pipeline.vector_db import CybersecurityVectorDB
        from rag_pipeline.ingestion import IncrementalIngestionManager
        
        logger.info("🚀 Starting payload embedding into ChromaDB...")
        
        # Initialize the vector database and ingestion manager
        vector_db_path = os.path.join(os.path.dirname(__file__), "assr/cybersecurity_vectordb")
        vector_db = CybersecurityVectorDB(vector_db_path)
        ingestion_manager = IncrementalIngestionManager(vector_db)
        
        # Set up file paths
        current_dir = os.path.dirname(__file__)
        mitre_csv_path = os.path.join(current_dir, "assr/mitre_attack_structured_dataset.csv")
        payload_csv_path = os.path.join(current_dir, "assr/payload_dataset.csv")
        cyberagents_path = os.path.join(current_dir, "assr/cyberagents")
        
        # Verify files exist
        for path, name in [(mitre_csv_path, "MITRE CSV"), (payload_csv_path, "Payload CSV"), (cyberagents_path, "CyberAgents")]:
            if not os.path.exists(path):
                logger.error(f"❌ {name} not found at: {path}")
                return False
            else:
                logger.info(f"✅ Found {name} at: {path}")
        
        # Check current database state
        db_info = vector_db.get_collection_info()
        logger.info(f"📊 Current database: {db_info['document_count']} documents")
        
        # Perform full reingest to embed payloads
        logger.info("🔄 Starting full reingest with fixed CSV parsers...")
        
        stats = ingestion_manager.full_reingest(
            mitre_csv_path=mitre_csv_path,
            payload_csv_path=payload_csv_path,
            cyberagents_path=cyberagents_path
        )
        
        logger.info("✅ Full reingest completed!")
        logger.info(f"📈 Ingestion stats: {stats}")
        
        # Check final database state
        final_db_info = vector_db.get_collection_info()
        logger.info(f"📊 Final database: {final_db_info['document_count']} documents")
        
        # Test payload searches
        logger.info("🔍 Testing payload searches...")
        
        test_queries = [
            "SQL injection",
            "XSS attack", 
            "brute force",
            "command injection",
            "directory traversal"
        ]
        
        for query in test_queries:
            results = vector_db.similarity_search(query, top_k=3, threshold=0.3)
            logger.info(f"'{query}': {len(results)} results")
            
            for i, result in enumerate(results[:2], 1):
                metadata = result.get('metadata', {})
                payload = metadata.get('payload', 'N/A')[:50]
                attack_type = metadata.get('attack_type', 'N/A')
                data_type = metadata.get('type', 'unknown')
                logger.info(f"  {i}. [{data_type}] {attack_type}: {payload}...")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_payload_embedding()
    if success:
        print("\n🎉 SUCCESS: Payload embedding completed!")
        print("✅ ChromaDB now contains payload vectors from your 33K+ payload dataset!")
    else:
        print("\n💥 FAILED: Payload embedding encountered errors!")
        sys.exit(1)