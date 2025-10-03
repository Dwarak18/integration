import logging
import json
import os
from pathlib import Path

from rag_pipeline import create_rag_pipeline, RAGPipelineConfig

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('rag_example.log')
        ]
    )

def main():
    print("=== Cybersecurity RAG Pipeline Demo ===\n")
    
    setup_logging()
    
    current_dir = Path(__file__).parent
    
    mitre_csv_path = str(current_dir / "mitre_attack_structured_dataset.csv")
    payload_csv_path = str(current_dir / "payload_dataset.csv") 
    cyberagents_path = str(current_dir / "cyberagents")
    
    print(f"Data paths:")
    print(f"  MITRE ATT&CK dataset: {mitre_csv_path}")
    print(f"  Payload dataset: {payload_csv_path}")
    print(f"  Cyber agents: {cyberagents_path}")
    print()
    
    try:
        print("🚀 Initializing RAG Pipeline...")
        
        config = RAGPipelineConfig()
        config.similarity_threshold = 0.6
        config.top_k_results = 8
        
        pipeline = create_rag_pipeline(
            mitre_csv_path=mitre_csv_path,
            payload_csv_path=payload_csv_path,
            cyberagents_path=cyberagents_path,
            config=config
        )
        
        print("✅ Pipeline initialized successfully!\n")
        
        print("📊 Pipeline Statistics:")
        stats = pipeline.get_pipeline_statistics()
        print(f"  Documents in vector database: {stats['collection_info']['document_count']}")
        print(f"  Vector database health: {stats['system_health'].get('vector_db_size', 'Unknown')}")
        print()
        
        print("🔍 Testing Knowledge Base Queries...")
        
        test_queries = [
            "SQL injection attack prevention",
            "MITRE ATT&CK T1110 brute force",
            "cross-site scripting XSS mitigation",
            "directory traversal vulnerability",
            "command injection protection"
        ]
        
        for query in test_queries:
            print(f"\nQuery: {query}")
            result = pipeline.query_knowledge_base(query, query_type="optimized")
            
            if result['status'] == 'success':
                print(f"  ✅ Query Type: {result['query_type']}")
                print(f"  ✅ Confidence: {result['confidence_score']:.3f}")
                print(f"  ✅ Results found: {len(result['results'])}")
                print(f"  ✅ Sources: {', '.join(result['sources'])}")
                
                if result['results']:
                    top_result = result['results'][0]
                    print(f"  📝 Top result preview: {top_result['content'][:100]}...")
            else:
                print(f"  ❌ Query failed: {result['error_message']}")
        
        print("\n" + "="*60)
        print("🛡️ Security Incident Analysis Demo")
        print("="*60)
        
        incident_examples = [
            {
                "name": "SQL Injection Attack",
                "data": {
                    "indicators": ["suspicious database queries", "union select statements", "SQL injection"],
                    "context": "Web application security incident",
                    "payloads": [
                        "' UNION SELECT username, password FROM users--",
                        "admin' OR '1'='1'--",
                        "'; DROP TABLE users; --"
                    ]
                }
            },
            {
                "name": "Cross-Site Scripting Attack",
                "data": {
                    "indicators": ["malicious JavaScript", "XSS payload", "script injection"],
                    "context": "Client-side security vulnerability",
                    "payloads": [
                        "<script>alert('XSS')</script>",
                        "javascript:alert(document.cookie)",
                        "<img src=x onerror=alert('XSS')>"
                    ]
                }
            },
            {
                "name": "Command Injection Attack", 
                "data": {
                    "indicators": ["system command execution", "shell injection", "remote code execution"],
                    "context": "Server-side command injection vulnerability",
                    "payloads": [
                        "; cat /etc/passwd",
                        "| whoami",
                        "&& rm -rf /"
                    ]
                }
            }
        ]
        
        for incident in incident_examples:
            print(f"\n🚨 Analyzing: {incident['name']}")
            print("-" * 40)
            
            analysis_result = pipeline.analyze_security_incident(incident['data'])
            
            if analysis_result['status'] == 'success':
                results = analysis_result['results']
                
                if 'threat_analysis' in results:
                    threat = results['threat_analysis']
                    print(f"  Threat Level: {threat['threat_level']} (Confidence: {threat['confidence_score']:.3f})")
                    print(f"  Attack Vectors: {', '.join(threat['attack_vectors'])}")
                    print(f"  MITRE Techniques: {', '.join(threat['mitre_techniques'][:3])}")
                    print(f"  Affected Systems: {', '.join(threat['affected_systems'])}")
                
                if 'payload_analyses' in results:
                    print(f"\n  📊 Payload Analysis Summary:")
                    for i, payload_analysis in enumerate(results['payload_analyses']):
                        print(f"    Payload {i+1}: {payload_analysis['payload_type']} "
                              f"(Severity: {payload_analysis['severity_level']})")
                
                if 'security_recommendations' in results:
                    print(f"\n  🔧 Top Security Recommendations:")
                    for i, rec in enumerate(results['security_recommendations'][:3]):
                        print(f"    {i+1}. {rec['action']} ({rec['priority']} priority)")
            else:
                print(f"  ❌ Analysis failed: {analysis_result['error_message']}")
        
        print("\n" + "="*60)
        print("📋 Batch Payload Analysis Demo")
        print("="*60)
        
        batch_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "; cat /etc/passwd",
            "../../../etc/passwd", 
            "eval($_POST['cmd'])",
            "{{7*7}}",
            "%0A%0D/bin/cat%20/etc/passwd",
            "javascript:alert('xss')"
        ]
        
        print(f"Analyzing batch of {len(batch_payloads)} payloads...")
        
        batch_result = pipeline.analyze_payload_batch(batch_payloads, "Security assessment")
        
        if batch_result['status'] == 'success':
            print(f"✅ Batch analysis completed in {batch_result['analysis_time']:.2f} seconds")
            
            summary = batch_result['summary_stats']
            print(f"\n📊 Summary Statistics:")
            print(f"  Total payloads: {summary['total_payloads']}")
            print(f"  Successful analyses: {summary['successful_analyses']}")
            
            if 'payload_type_distribution' in summary:
                print(f"\n  Payload Type Distribution:")
                for ptype, count in summary['payload_type_distribution'].items():
                    print(f"    {ptype}: {count}")
            
            if 'severity_distribution' in summary:
                print(f"\n  Severity Distribution:")
                for severity, count in summary['severity_distribution'].items():
                    print(f"    {severity}: {count}")
        else:
            print(f"❌ Batch analysis failed: {batch_result['error_message']}")
        
        print("\n" + "="*60)
        print("📈 Final Pipeline Statistics")
        print("="*60)
        
        final_stats = pipeline.get_pipeline_statistics()
        pipeline_stats = final_stats['pipeline_stats']
        
        print(f"Total documents processed: {pipeline_stats['total_documents_processed']}")
        print(f"Total queries processed: {pipeline_stats['total_queries_processed']}")
        print(f"Average query time: {pipeline_stats['average_query_time']:.3f} seconds")
        print(f"System health: {final_stats['system_health'].get('vector_db_size', 'Unknown')} documents")
        
        verification = pipeline._verify_pipeline_health()
        print(f"\nPipeline Health Check:")
        print(f"  Vector DB accessible: {'✅' if verification['vector_db_accessible'] else '❌'}")
        print(f"  Sample queries working: {'✅' if verification['sample_queries_working'] else '❌'}")
        print(f"  Data retrieval working: {'✅' if verification['data_retrieval_working'] else '❌'}")
        print(f"  Agent analysis working: {'✅' if verification['agent_analysis_working'] else '❌'}")
        print(f"  Overall health: {verification['overall_health']}")
        
        print("\n🎉 RAG Pipeline demonstration completed successfully!")
        print("\nThe pipeline is now ready for production use. You can:")
        print("1. Query the knowledge base for security information")
        print("2. Analyze security incidents and threats")
        print("3. Get payload analysis and recommendations")
        print("4. Investigate attack patterns and TTPs")
        print("5. Export analysis results for reporting")
        
    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
        logging.error(f"Pipeline demo failed: {e}", exc_info=True)

if __name__ == "__main__":
    main()
