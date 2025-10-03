#!/usr/bin/env python3

import sqlite3
import json
import os

def check_chroma_db():
    # Check the main cybersecurity vector database
    db_path = "assr/cybersecurity_vectordb/chroma.sqlite3"
    
    if not os.path.exists(db_path):
        print("❌ ChromaDB database not found!")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("📊 Tables in database:")
        for table in tables:
            print(f"  - {table[0]}")
        
        print("\n" + "="*50)
        
        # Check embeddings table for documents
        try:
            cursor.execute("SELECT COUNT(*) FROM embeddings;")
            embedding_count = cursor.fetchone()[0]
            print(f"📈 Total embeddings: {embedding_count}")
            
            if embedding_count > 0:
                # Get sample embeddings with metadata
                cursor.execute("SELECT id, document, metadata FROM embeddings LIMIT 5;")
                samples = cursor.fetchall()
                
                print("\n🔍 Sample documents:")
                for i, (doc_id, document, metadata) in enumerate(samples, 1):
                    print(f"\n--- Sample {i} ---")
                    print(f"ID: {doc_id}")
                    print(f"Document: {document[:200]}...")
                    
                    if metadata:
                        try:
                            meta_dict = json.loads(metadata)
                            print("Metadata:")
                            for key, value in meta_dict.items():
                                if key == 'payload':
                                    print(f"  🎯 {key}: {str(value)[:100]}...")
                                else:
                                    print(f"  - {key}: {value}")
                        except:
                            print(f"Metadata (raw): {metadata[:100]}...")
        
        except sqlite3.OperationalError as e:
            print(f"Error querying embeddings: {e}")
            
            # Try to see what tables/columns exist
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table';")
            schemas = cursor.fetchall()
            print("\n📋 Table schemas:")
            for schema in schemas:
                print(f"  {schema[0]}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error accessing database: {e}")

def check_ingestion_metadata():
    metadata_path = "assr/ingestion_metadata.json"
    
    if os.path.exists(metadata_path):
        print("\n" + "="*50)
        print("📝 Ingestion Metadata:")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        print(f"  Total ingested: {metadata.get('total_ingested', 0)}")
        print(f"  Last updated: {metadata.get('last_updated', 'Unknown')}")
        
        if 'full_reingest_stats' in metadata:
            stats = metadata['full_reingest_stats']
            print("  Reingest stats:")
            print(f"    - MITRE data: {stats.get('mitre_data', 0)}")
            print(f"    - Payload data: {stats.get('payload_data', 0)}")
            print(f"    - Agent knowledge: {stats.get('agent_knowledge', 0)}")
            print(f"    - Total: {stats.get('total', 0)}")
            print(f"    - Errors: {stats.get('errors', 0)}")

def check_payload_dataset():
    payload_path = "assr/payload_dataset.csv"
    
    if os.path.exists(payload_path):
        print("\n" + "="*50)
        print("📁 Payload Dataset Info:")
        
        with open(payload_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        print(f"  Total lines: {len(lines)}")
        print(f"  Header: {lines[0].strip() if lines else 'Empty file'}")
        
        if len(lines) > 1:
            print("  Sample payloads:")
            for i in range(1, min(4, len(lines))):
                parts = lines[i].strip().split(',', 1)
                if parts:
                    payload = parts[0][:100]
                    print(f"    {i}: {payload}...")

if __name__ == "__main__":
    print("🔍 Checking Vector Database Content")
    print("="*50)
    
    check_chroma_db()
    check_ingestion_metadata()
    check_payload_dataset()