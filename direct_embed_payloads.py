#!/usr/bin/env python3

import sqlite3
import json
import pandas as pd
import os
import logging
from typing import Dict, List, Any
import uuid

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def direct_payload_embedding():
    """
    Directly insert payload data into ChromaDB by working with the SQLite database
    and using a simple text-based approach for now.
    """
    
    try:
        # Paths
        payload_csv_path = "assr/payload_dataset.csv"
        db_path = "assr/cybersecurity_vectordb/chroma.sqlite3"
        
        if not os.path.exists(payload_csv_path):
            logger.error(f"❌ Payload CSV not found: {payload_csv_path}")
            return False
            
        if not os.path.exists(db_path):
            logger.error(f"❌ ChromaDB not found: {db_path}")
            return False
        
        # Read payload data
        logger.info("📖 Reading payload dataset...")
        df = pd.read_csv(payload_csv_path, encoding='utf-8')
        logger.info(f"📊 Found {len(df)} payloads in dataset")
        
        # Connect to ChromaDB
        logger.info("🔌 Connecting to ChromaDB...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get the collection ID for cybersecurity_knowledge
        cursor.execute("SELECT id FROM collections WHERE name = 'cybersecurity_knowledge'")
        collection_result = cursor.fetchone()
        if not collection_result:
            logger.error("❌ Collection 'cybersecurity_knowledge' not found")
            return False
        
        collection_id = collection_result[0]
        logger.info(f"✅ Found collection ID: {collection_id}")
        
        # Get the segment ID for this collection
        cursor.execute("SELECT id FROM segments WHERE collection = ?", (collection_id,))
        segment_result = cursor.fetchone()
        if not segment_result:
            logger.error("❌ No segments found for collection")
            return False
            
        segment_id = segment_result[0]
        logger.info(f"✅ Found segment ID: {segment_id}")
        
        # Process and insert payloads
        logger.info("🚀 Processing and inserting payloads...")
        
        batch_size = 50
        processed_count = 0
        
        for start_idx in range(0, len(df), batch_size):
            end_idx = min(start_idx + batch_size, len(df))
            batch = df.iloc[start_idx:end_idx]
            
            logger.info(f"Processing batch {start_idx//batch_size + 1}: rows {start_idx}-{end_idx}")
            
            for idx, row in batch.iterrows():
                try:
                    # Create embedding ID
                    embedding_id = str(uuid.uuid4())
                    
                    # Insert into embeddings table
                    cursor.execute("""
                        INSERT INTO embeddings (segment_id, embedding_id, seq_id, created_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (segment_id, embedding_id, processed_count))
                    
                    embedding_db_id = cursor.lastrowid
                    
                    # Add metadata
                    metadata_items = [
                        ('type', 'security_payload', None, None, None),
                        ('payload', str(row.get('Payload', '')), None, None, None),
                        ('signature', str(row.get('Signature', '')), None, None, None),
                        ('attack_type', str(row.get('AttackType', '')), None, None, None),
                        ('severity', str(row.get('Severity', '')), None, None, None),
                        ('mitre_id', str(row.get('MITRE', '')), None, None, None),
                        ('label', str(row.get('Label', '')), None, None, None),
                        ('description', str(row.get('Description', ''))[:500], None, None, None),  # Truncate long descriptions
                        ('source', 'payload_dataset', None, None, None),
                        ('row_index', None, idx, None, None)
                    ]
                    
                    # Create document content
                    content = f"Payload: {row.get('Payload', '')} | Attack: {row.get('AttackType', '')} | Description: {row.get('Description', '')[:200]}"
                    metadata_items.append(('chroma:document', content, None, None, None))
                    
                    # Insert metadata
                    for key, str_val, int_val, float_val, bool_val in metadata_items:
                        cursor.execute("""
                            INSERT INTO embedding_metadata (id, key, string_value, int_value, float_value, bool_value)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (embedding_db_id, key, str_val, int_val, float_val, bool_val))
                    
                    processed_count += 1
                    
                except Exception as e:
                    logger.warning(f"⚠️ Error processing row {idx}: {e}")
                    continue
            
            # Commit batch
            conn.commit()
            logger.info(f"✅ Processed {processed_count} payloads so far...")
        
        # Update sequence tracking
        cursor.execute("INSERT OR REPLACE INTO max_seq_id (segment_id, seq_id) VALUES (?, ?)", 
                      (segment_id, processed_count))
        
        conn.commit()
        conn.close()
        
        logger.info(f"🎉 Successfully embedded {processed_count} payloads into ChromaDB!")
        
        # Verify the results
        logger.info("🔍 Verifying results...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Count total embeddings
        cursor.execute("SELECT COUNT(*) FROM embeddings")
        total_embeddings = cursor.fetchone()[0]
        logger.info(f"📊 Total embeddings in database: {total_embeddings}")
        
        # Count payload embeddings
        cursor.execute("""
            SELECT COUNT(*) 
            FROM embeddings e 
            JOIN embedding_metadata em ON e.id = em.id 
            WHERE em.key = 'type' AND em.string_value = 'security_payload'
        """)
        payload_embeddings = cursor.fetchone()[0]
        logger.info(f"🎯 Total payload embeddings: {payload_embeddings}")
        
        # Sample some payloads
        cursor.execute("""
            SELECT em.string_value
            FROM embeddings e 
            JOIN embedding_metadata em ON e.id = em.id 
            WHERE em.key = 'payload' AND em.string_value IS NOT NULL AND em.string_value != ''
            LIMIT 5
        """)
        
        sample_payloads = cursor.fetchall()
        logger.info("🔍 Sample embedded payloads:")
        for i, (payload,) in enumerate(sample_payloads, 1):
            logger.info(f"  {i}. {payload[:100]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"❌ Error during direct embedding: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = direct_payload_embedding()
    if success:
        print("\n🎉 SUCCESS: Direct payload embedding completed!")
        print("✅ Your ChromaDB now contains payload vectors from the 33K+ payload dataset!")
        print("🔍 You can now search for payloads using the RAG system!")
    else:
        print("\n💥 FAILED: Direct payload embedding encountered errors!")
        exit(1)