import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
import uuid
from typing import List, Dict, Any, Optional
import numpy as np
from sentence_transformers import SentenceTransformer
import logging

class VectorDatabase:
    def __init__(self, persist_directory: str = "rag_vectordb", collection_name: str = "cybersecurity_rag"):
        self.persist_directory = persist_directory
        self.collection_name = collection_name
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        self.client = chromadb.PersistentClient(path=persist_directory)
        
        self.embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        try:
            self.collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_function
            )
            logging.info(f"Loaded existing collection: {collection_name}")
        except:
            self.collection = self.client.create_collection(
                name=collection_name,
                embedding_function=self.embedding_function,
                metadata={"hnsw:space": "cosine"}
            )
            logging.info(f"Created new collection: {collection_name}")
    
    def add_documents(self, documents: List[str], metadatas: List[Dict[str, Any]], ids: Optional[List[str]] = None) -> None:
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in documents]
        
        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        logging.info(f"Added {len(documents)} documents to collection")
    
    def query(self, query_text: str, n_results: int = 5, where: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        results = self.collection.query(
            query_texts=[query_text],
            n_results=n_results,
            where=where
        )
        return results
    
    def similarity_search(self, query: str, top_k: int = 5, threshold: float = 0.7) -> List[Dict[str, Any]]:
        results = self.query(query, n_results=top_k)
        
        formatted_results = []
        if results['documents'] and results['documents'][0]:
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i] if results['metadatas'] and results['metadatas'][0] else {}
                distance = results['distances'][0][i] if results['distances'] and results['distances'][0] else 1.0
                similarity = 1 - distance
                
                if similarity >= threshold:
                    formatted_results.append({
                        'content': doc,
                        'metadata': metadata,
                        'similarity': similarity,
                        'distance': distance
                    })
        
        return sorted(formatted_results, key=lambda x: x['similarity'], reverse=True)
    
    def get_collection_info(self) -> Dict[str, Any]:
        count = self.collection.count()
        return {
            "collection_name": self.collection_name,
            "document_count": count,
            "embedding_model": "all-MiniLM-L6-v2"
        }
    
    def delete_collection(self) -> None:
        self.client.delete_collection(name=self.collection_name)
        logging.info(f"Deleted collection: {self.collection_name}")
    
    def reset_collection(self) -> None:
        try:
            self.delete_collection()
        except:
            pass
        
        self.collection = self.client.create_collection(
            name=self.collection_name,
            embedding_function=self.embedding_function,
            metadata={"hnsw:space": "cosine"}
        )
        logging.info(f"Reset collection: {self.collection_name}")

class CybersecurityVectorDB(VectorDatabase):
    def __init__(self, persist_directory: str = "cybersecurity_vectordb"):
        super().__init__(persist_directory, "cybersecurity_knowledge")
    
    def add_mitre_attack_data(self, payload: str, signature: str, attack_type: str, 
                             severity: str, mitre_id: str, description: str, 
                             additional_metadata: Optional[Dict[str, Any]] = None) -> None:
        
        combined_text = f"MITRE ATT&CK Technique: {mitre_id}\nAttack Type: {attack_type}\nSeverity: {severity}\nPayload: {payload}\nSignature: {signature}\nDescription: {description}"
        
        metadata = {
            "type": "mitre_attack",
            "mitre_id": mitre_id,
            "attack_type": attack_type,
            "severity": severity,
            "payload": payload,
            "signature": signature
        }
        
        if additional_metadata:
            metadata.update(additional_metadata)
        
        self.add_documents([combined_text], [metadata])
    
    def add_payload_data(self, payload: str, attack_type: str, severity: str, 
                        mitre_id: str, label: str, description: str,
                        additional_metadata: Optional[Dict[str, Any]] = None) -> None:
        
        combined_text = f"Security Payload: {payload}\nMITRE: {mitre_id}\nAttack Type: {attack_type}\nSeverity: {severity}\nLabel: {label}\nDescription: {description}"
        
        metadata = {
            "type": "security_payload",
            "mitre_id": mitre_id,
            "attack_type": attack_type,
            "severity": severity,
            "payload": payload,
            "label": label
        }
        
        if additional_metadata:
            metadata.update(additional_metadata)
        
        self.add_documents([combined_text], [metadata])
    
    def search_by_attack_type(self, attack_type: str, top_k: int = 5) -> List[Dict[str, Any]]:
        return self.similarity_search(f"attack type {attack_type}", top_k=top_k)
    
    def search_by_mitre_id(self, mitre_id: str, top_k: int = 5) -> List[Dict[str, Any]]:
        return self.similarity_search(f"MITRE {mitre_id}", top_k=top_k)
    
    def search_by_severity(self, severity: str, top_k: int = 5) -> List[Dict[str, Any]]:
        where_clause = {"severity": severity}
        results = self.query("cybersecurity threat", n_results=top_k, where=where_clause)
        
        formatted_results = []
        if results['documents'] and results['documents'][0]:
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i] if results['metadatas'] and results['metadatas'][0] else {}
                distance = results['distances'][0][i] if results['distances'] and results['distances'][0] else 1.0
                
                formatted_results.append({
                    'content': doc,
                    'metadata': metadata,
                    'similarity': 1 - distance,
                    'distance': distance
                })
        
        return formatted_results
    
    def get_attack_techniques_for_payload(self, payload: str, top_k: int = 3) -> List[Dict[str, Any]]:
        return self.similarity_search(payload, top_k=top_k)
