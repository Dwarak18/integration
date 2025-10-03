#!/usr/bin/env python3

import sys
import os
import logging

# Add the current directory to Python path
sys.path.append(os.path.dirname(__file__))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_payload_ingestion():
    try:
        # Import from the rag_pipeline
        from assr.rag_pipeline.main_pipeline import RAGPipelineOrchestrator, RAGPipelineConfig
        
        logger.info("🚀 Starting payload ingestion using RAG Pipeline...")
        
        # Configure paths
        config = RAGPipelineConfig()
        config.vector_db_path = "assr/cybersecurity_vectordb"
        
        # Initialize orchestrator
        orchestrator = RAGPipelineOrchestrator(config)
        
        # Set up data paths
        mitre_csv_path = "assr/mitre_attack_structured_dataset.csv"
        payload_csv_path = "assr/payload_dataset.csv" 
        cyberagents_path = "assr/cyberagents"
        
        logger.info("🔄 Initializing pipeline with force rebuild to include payloads...")
        
        # Initialize pipeline with force rebuild to ensure payload data is ingested
        result = orchestrator.initialize_pipeline(
            mitre_csv_path=mitre_csv_path,
            payload_csv_path=payload_csv_path,
            cyberagents_path=cyberagents_path,
            force_rebuild=True  # Force rebuild to re-ingest with fixed CSV parser
        )
        
        logger.info("✅ Pipeline initialization completed")
        logger.info(f"📊 Result: {result}")
        
        # Get final database info
        db_info = orchestrator.vector_db.get_collection_info()
        logger.info(f"📈 Database now contains {db_info['document_count']} documents")
        
        # Test payload search
        logger.info("🔍 Testing payload search...")
        test_queries = [
            "SQL injection attack",
            "XSS cross site scripting", 
            "brute force password",
            "command injection"
        ]
        
        for query in test_queries:
            results = orchestrator.vector_db.similarity_search(query, top_k=3, threshold=0.3)
            logger.info(f"Query '{query}': Found {len(results)} results")
            
            for i, result in enumerate(results[:2], 1):
                payload = result['metadata'].get('payload', 'N/A')
                attack_type = result['metadata'].get('attack_type', 'N/A')
                logger.info(f"  {i}. {attack_type}: {payload[:60]}...")
                
        return True
        
    except Exception as e:
        logger.error(f"❌ Error during payload ingestion: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_payload_ingestion()
    if success:
        print("\n🎉 Payload ingestion completed successfully!")
        print("✅ ChromaDB now contains payload vectors!")
    else:
        print("\n💥 Payload ingestion failed!")
        sys.exit(1)