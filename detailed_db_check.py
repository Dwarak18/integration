#!/usr/bin/env python3

import sqlite3
import json
import os

def detailed_chroma_analysis():
    db_path = "assr/cybersecurity_vectordb/chroma.sqlite3"
    
    if not os.path.exists(db_path):
        print("❌ ChromaDB database not found!")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 DETAILED CHROMADB ANALYSIS")
        print("="*50)
        
        # Get embeddings with metadata
        cursor.execute("""
            SELECT e.id, e.embedding_id, em.key, em.string_value, em.int_value
            FROM embeddings e
            LEFT JOIN embedding_metadata em ON e.id = em.id
            WHERE em.key IN ('type', 'payload', 'source', 'attack_type', 'severity')
            ORDER BY e.id, em.key
            LIMIT 50
        """)
        
        results = cursor.fetchall()
        
        current_embedding = None
        metadata = {}
        
        print("📊 EMBEDDING METADATA:")
        
        for row in results:
            embedding_id, embedding_uuid, key, string_value, int_value = row
            
            if current_embedding != embedding_id:
                if current_embedding is not None:
                    print(f"\nEmbedding {current_embedding}:")
                    for k, v in metadata.items():
                        if k == 'payload' and v:
                            print(f"  🎯 {k}: {v[:100]}...")
                        else:
                            print(f"  - {k}: {v}")
                
                current_embedding = embedding_id
                metadata = {}
            
            value = string_value if string_value else int_value
            metadata[key] = value
        
        # Print last embedding
        if current_embedding is not None:
            print(f"\nEmbedding {current_embedding}:")
            for k, v in metadata.items():
                if k == 'payload' and v:
                    print(f"  🎯 {k}: {v[:100]}...")
                else:
                    print(f"  - {k}: {v}")
        
        print("\n" + "="*50)
        
        # Check if there are any payload-related entries
        cursor.execute("""
            SELECT COUNT(*) 
            FROM embedding_metadata 
            WHERE key = 'payload' AND string_value IS NOT NULL AND string_value != ''
        """)
        payload_count = cursor.fetchone()[0]
        print(f"📈 Embeddings with non-empty payload metadata: {payload_count}")
        
        # Check data types
        cursor.execute("""
            SELECT em.key, COUNT(*) as count
            FROM embedding_metadata em
            GROUP BY em.key
            ORDER BY count DESC
        """)
        
        metadata_stats = cursor.fetchall()
        print("\n📊 Metadata key statistics:")
        for key, count in metadata_stats:
            print(f"  {key}: {count}")
        
        # Sample payload data
        print("\n🎯 SAMPLE PAYLOAD DATA:")
        cursor.execute("""
            SELECT e.embedding_id, em.string_value
            FROM embeddings e
            JOIN embedding_metadata em ON e.id = em.id
            WHERE em.key = 'payload' AND em.string_value IS NOT NULL AND em.string_value != ''
            LIMIT 5
        """)
        
        payload_samples = cursor.fetchall()
        for i, (emb_id, payload) in enumerate(payload_samples, 1):
            print(f"  {i}. {payload[:150]}...")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    detailed_chroma_analysis()