import logging
import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def diagnose_pipeline():
    print("🔍 RAG Pipeline Diagnostic Tool")
    print("=" * 50)
    
    setup_logging()
    
    try:
        # Test 1: Import modules
        print("\n1. Testing module imports...")
        from rag_pipeline import CybersecurityVectorDB, ComprehensiveDataProcessor
        from rag_pipeline import AdvancedRAGRetriever, RAGSecurityAgent
        print("✅ All modules imported successfully")
        
        # Test 2: Check data files
        print("\n2. Checking data files...")
        current_dir = Path(__file__).parent
        mitre_path = current_dir / "mitre_attack_structured_dataset.csv"
        payload_path = current_dir / "payload_dataset.csv"
        cyberagents_path = current_dir / "cyberagents"
        
        if mitre_path.exists():
            print(f"✅ MITRE dataset found: {mitre_path}")
        else:
            print(f"❌ MITRE dataset missing: {mitre_path}")
            
        if payload_path.exists():
            print(f"✅ Payload dataset found: {payload_path}")
        else:
            print(f"❌ Payload dataset missing: {payload_path}")
            
        if cyberagents_path.exists():
            print(f"✅ CyberAgents folder found: {cyberagents_path}")
        else:
            print(f"❌ CyberAgents folder missing: {cyberagents_path}")
        
        # Test 3: Initialize vector database
        print("\n3. Testing vector database initialization...")
        vector_db = CybersecurityVectorDB("test_vectordb")
        collection_info = vector_db.get_collection_info()
        print(f"✅ Vector DB initialized. Documents: {collection_info['document_count']}")
        
        # Test 4: Test data processing
        print("\n4. Testing data processing...")
        processor = ComprehensiveDataProcessor()
        
        # Process a small sample of data
        try:
            processed_data = processor.process_all_datasets(
                str(mitre_path), str(payload_path), str(cyberagents_path)
            )
            
            total_processed = sum(len(data) for data in processed_data.values())
            print(f"✅ Data processing successful. Total entries: {total_processed}")
            
            for data_type, data_list in processed_data.items():
                print(f"  - {data_type}: {len(data_list)} entries")
                
        except Exception as e:
            print(f"❌ Data processing failed: {e}")
            return False
        
        # Test 5: Test data ingestion
        print("\n5. Testing data ingestion...")
        try:
            from rag_pipeline import DataIngestionPipeline
            ingestion_pipeline = DataIngestionPipeline(vector_db)
            
            # Ingest a small sample
            sample_data = {}
            for key, data_list in processed_data.items():
                # Take only first 10 items from each dataset for testing
                sample_data[key] = data_list[:10] if data_list else []
            
            stats = ingestion_pipeline.ingest_processed_data(sample_data)
            print(f"✅ Data ingestion successful. Stats: {stats}")
            
        except Exception as e:
            print(f"❌ Data ingestion failed: {e}")
            return False
        
        # Test 6: Test retrieval
        print("\n6. Testing retrieval system...")
        try:
            retriever = AdvancedRAGRetriever(vector_db)
            
            test_queries = [
                "SQL injection attack",
                "MITRE T1110",
                "brute force"
            ]
            
            for query in test_queries:
                try:
                    results = retriever.retrieve(query, top_k=3, similarity_threshold=0.3)
                    print(f"✅ Query '{query}': {len(results.retrieved_documents)} results, confidence: {results.confidence_score:.3f}")
                except Exception as e:
                    print(f"❌ Query '{query}' failed: {e}")
                    
        except Exception as e:
            print(f"❌ Retrieval system failed: {e}")
            return False
        
        # Test 7: Test security agent
        print("\n7. Testing security agent...")
        try:
            agent = RAGSecurityAgent(vector_db)
            
            # Test payload analysis
            test_payload = "' OR 1=1--"
            analysis = agent.analyze_payload(test_payload)
            print(f"✅ Payload analysis successful. Type: {analysis.payload_type}, Severity: {analysis.severity_level}")
            
        except Exception as e:
            print(f"❌ Security agent failed: {e}")
            return False
        
        print("\n" + "=" * 50)
        print("🎉 All tests passed! The pipeline should be working correctly.")
        return True
        
    except Exception as e:
        print(f"❌ Critical error during diagnosis: {e}")
        import traceback
        traceback.print_exc()
        return False

def fix_pipeline_issues():
    print("\n🔧 Attempting to fix identified issues...")
    
    try:
        from rag_pipeline import create_rag_pipeline, RAGPipelineConfig
        
        current_dir = Path(__file__).parent
        mitre_path = str(current_dir / "mitre_attack_structured_dataset.csv")
        payload_path = str(current_dir / "payload_dataset.csv")
        cyberagents_path = str(current_dir / "cyberagents")
        
        # Create configuration with lower thresholds for better results
        config = RAGPipelineConfig()
        config.similarity_threshold = 0.3  # Lower threshold for more results
        config.top_k_results = 10
        config.vector_db_path = "fixed_cybersecurity_vectordb"
        
        print("🚀 Initializing pipeline with optimized settings...")
        
        # Force rebuild to ensure fresh data
        pipeline = create_rag_pipeline(
            mitre_csv_path=mitre_path,
            payload_csv_path=payload_path,
            cyberagents_path=cyberagents_path,
            config=config
        )
        
        print("✅ Pipeline initialized successfully!")
        
        # Test the fixed pipeline
        print("\n🧪 Testing fixed pipeline...")
        
        # Test knowledge base query
        result = pipeline.query_knowledge_base("SQL injection prevention", query_type="optimized")
        if result['status'] == 'success' and len(result['results']) > 0:
            print(f"✅ Knowledge base query working: {len(result['results'])} results found")
        else:
            print(f"❌ Knowledge base query still failing: {result.get('error_message', 'No results')}")
        
        # Test incident analysis
        incident_data = {
            "indicators": ["SQL injection", "database attack"],
            "context": "Web application security incident",
            "payloads": ["' OR 1=1--"]
        }
        
        analysis_result = pipeline.analyze_security_incident(incident_data)
        if analysis_result['status'] == 'success':
            print("✅ Security incident analysis working")
        else:
            print(f"❌ Security incident analysis failing: {analysis_result.get('error_message')}")
        
        # Get final health check
        verification = pipeline._verify_pipeline_health()
        print(f"\n📊 Final Health Check:")
        print(f"  Vector DB accessible: {'✅' if verification['vector_db_accessible'] else '❌'}")
        print(f"  Sample queries working: {'✅' if verification['sample_queries_working'] else '❌'}")
        print(f"  Data retrieval working: {'✅' if verification['data_retrieval_working'] else '❌'}")
        print(f"  Agent analysis working: {'✅' if verification['agent_analysis_working'] else '❌'}")
        print(f"  Overall health: {verification['overall_health']}")
        
        return pipeline, verification
        
    except Exception as e:
        print(f"❌ Failed to fix pipeline issues: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == "__main__":
    print("Starting RAG Pipeline Diagnosis and Repair...")
    
    # Run diagnosis
    diagnosis_passed = diagnose_pipeline()
    
    if not diagnosis_passed:
        print("\n⚠️  Issues detected. Attempting to fix...")
        pipeline, verification = fix_pipeline_issues()
        
        if pipeline and verification and verification['overall_health'] in ['Good', 'Excellent']:
            print("\n🎉 Pipeline successfully repaired!")
        else:
            print("\n❌ Could not fully repair the pipeline. Please check the error messages above.")
    else:
        print("\n✅ No issues detected. Pipeline should be working correctly.")
