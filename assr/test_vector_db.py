#!/usr/bin/env python3

from rag_pipeline.vector_db import CybersecurityVectorDB
import logging

logging.basicConfig(level=logging.INFO)

def test_vector_db():
    print("=== Testing Vector Database ===")
    
    # Initialize database
    db = CybersecurityVectorDB()
    info = db.get_collection_info()
    print(f"Database has {info['document_count']} documents")
    
    if info['document_count'] == 0:
        print("❌ Database is empty!")
        return
    
    # Test query with different thresholds
    query = 'SQL injection attack'
    print(f"\n🔍 Testing query: '{query}'")
    
    for threshold in [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0]:
        results = db.similarity_search(query, top_k=3, threshold=threshold)
        print(f"  Threshold {threshold}: {len(results)} results")
        
        if results:
            print(f"    ✅ Top similarity: {results[0]['similarity']:.3f}")
            print(f"    📄 Content preview: {results[0]['content'][:100]}...")
            print(f"    📊 Metadata: {results[0]['metadata']}")
            break
    
    # Test a simple query to see what kind of data we have
    print(f"\n🔍 Testing simple query: 'attack'")
    simple_results = db.similarity_search('attack', top_k=5, threshold=0.0)
    print(f"  Found {len(simple_results)} results for 'attack'")
    
    if simple_results:
        for i, result in enumerate(simple_results[:3]):
            print(f"  Result {i+1}:")
            print(f"    Similarity: {result['similarity']:.3f}")
            print(f"    Content: {result['content'][:150]}...")
            print(f"    Type: {result['metadata'].get('type', 'unknown')}")
            print()

if __name__ == "__main__":
    test_vector_db()
