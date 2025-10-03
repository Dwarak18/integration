import json
import logging
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from dataclasses import dataclass
from enum import Enum
import re

from .vector_db import CybersecurityVectorDB

class QueryType(Enum):
    THREAT_ANALYSIS = "threat_analysis"
    PAYLOAD_IDENTIFICATION = "payload_identification"  
    MITIGATION_STRATEGY = "mitigation_strategy"
    ATTACK_PATTERN = "attack_pattern"
    GENERAL_SECURITY = "general_security"

@dataclass
class RetrievalResult:
    content: str
    metadata: Dict[str, Any]
    similarity_score: float
    relevance_score: float
    source_type: str
    mitre_techniques: List[str]

@dataclass
class RAGContext:
    query: str
    query_type: QueryType
    retrieved_documents: List[RetrievalResult]
    aggregated_context: str
    confidence_score: float
    sources: List[str]

class QueryClassifier:
    def __init__(self):
        self.threat_keywords = [
            'attack', 'threat', 'malware', 'vulnerability', 'exploit', 'breach',
            'intrusion', 'malicious', 'suspicious', 'compromise', 'infection'
        ]
        
        self.payload_keywords = [
            'payload', 'injection', 'script', 'command', 'code', 'execute',
            'sql', 'xss', 'csrf', 'traversal', 'overflow'
        ]
        
        self.mitigation_keywords = [
            'prevent', 'protect', 'defend', 'mitigate', 'remediate', 'fix',
            'patch', 'secure', 'harden', 'block', 'filter'
        ]
        
        self.pattern_keywords = [
            'pattern', 'technique', 'tactic', 'procedure', 'method', 'approach',
            'behavior', 'signature', 'indicator', 'ttp'
        ]
    
    def classify_query(self, query: str) -> QueryType:
        query_lower = query.lower()
        
        threat_score = sum(1 for keyword in self.threat_keywords if keyword in query_lower)
        payload_score = sum(1 for keyword in self.payload_keywords if keyword in query_lower)
        mitigation_score = sum(1 for keyword in self.mitigation_keywords if keyword in query_lower)
        pattern_score = sum(1 for keyword in self.pattern_keywords if keyword in query_lower)
        
        scores = {
            QueryType.THREAT_ANALYSIS: threat_score,
            QueryType.PAYLOAD_IDENTIFICATION: payload_score,
            QueryType.MITIGATION_STRATEGY: mitigation_score,
            QueryType.ATTACK_PATTERN: pattern_score
        }
        
        max_score = max(scores.values())
        if max_score == 0:
            return QueryType.GENERAL_SECURITY
        
        return max(scores, key=scores.get)

class RelevanceScorer:
    def __init__(self):
        self.mitre_weight = 0.3
        self.severity_weight = 0.25
        self.content_weight = 0.35
        self.source_weight = 0.1
        
        self.severity_scores = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.6,
            'Low': 0.4
        }
        
        self.source_scores = {
            'mitre_attack_dataset': 0.9,
            'payload_dataset': 0.8,
            'cyberagents': 0.7
        }
    
    def calculate_relevance_score(self, result: Dict[str, Any], query: str, 
                                query_type: QueryType) -> float:
        
        similarity = result.get('similarity', 0.0)
        metadata = result.get('metadata', {})
        
        mitre_score = self._calculate_mitre_score(metadata, query)
        severity_score = self._calculate_severity_score(metadata)
        source_score = self._calculate_source_score(metadata)
        
        type_bonus = self._calculate_type_bonus(metadata, query_type)
        
        relevance = (
            similarity * self.content_weight +
            mitre_score * self.mitre_weight +
            severity_score * self.severity_weight +
            source_score * self.source_weight +
            type_bonus
        )
        
        return min(relevance, 1.0)
    
    def _calculate_mitre_score(self, metadata: Dict[str, Any], query: str) -> float:
        mitre_techniques_str = metadata.get('mitre_techniques', '[]')
        try:
            mitre_techniques = json.loads(mitre_techniques_str) if mitre_techniques_str else []
        except:
            mitre_techniques = []
        
        mitre_id = metadata.get('mitre_id', '')
        
        query_mitre = re.findall(r'T\d{4}(?:\.\d{3})?', query.upper())
        
        if query_mitre:
            if mitre_id in query_mitre or any(tech in query_mitre for tech in mitre_techniques):
                return 1.0
            return 0.5 if mitre_techniques else 0.2
        
        return 0.7 if mitre_techniques else 0.5
    
    def _calculate_severity_score(self, metadata: Dict[str, Any]) -> float:
        severity = metadata.get('severity', 'Medium')
        return self.severity_scores.get(severity, 0.5)
    
    def _calculate_source_score(self, metadata: Dict[str, Any]) -> float:
        source = metadata.get('source', 'unknown')
        return self.source_scores.get(source, 0.5)
    
    def _calculate_type_bonus(self, metadata: Dict[str, Any], query_type: QueryType) -> float:
        if query_type == QueryType.PAYLOAD_IDENTIFICATION:
            if metadata.get('type') == 'security_payload':
                return 0.1
        elif query_type == QueryType.THREAT_ANALYSIS:
            if metadata.get('type') == 'mitre_attack':
                return 0.1
        elif query_type == QueryType.MITIGATION_STRATEGY:
            if metadata.get('source') == 'cyberagents':
                return 0.1
        
        return 0.0

class ContextAggregator:
    def __init__(self, max_context_length: int = 2000):
        self.max_context_length = max_context_length
        
    def aggregate_context(self, results: List[RetrievalResult], query: str,
                         query_type: QueryType) -> Tuple[str, float]:
        
        if not results:
            return "", 0.0
        
        sorted_results = sorted(results, key=lambda x: x.relevance_score, reverse=True)
        
        context_parts = []
        current_length = 0
        confidence_scores = []
        
        for result in sorted_results:
            if current_length >= self.max_context_length:
                break
                
            content = result.content
            if len(content) + current_length > self.max_context_length:
                remaining_length = self.max_context_length - current_length
                content = content[:remaining_length] + "..."
            
            context_part = self._format_context_part(result, query_type)
            context_parts.append(context_part)
            current_length += len(context_part)
            confidence_scores.append(result.relevance_score)
        
        aggregated_context = "\n\n".join(context_parts)
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        confidence_score = self._calculate_aggregated_confidence(confidence_scores, len(results))
        
        return aggregated_context, confidence_score
    
    def _format_context_part(self, result: RetrievalResult, query_type: QueryType) -> str:
        header = f"[{result.source_type.upper()}]"
        
        if result.mitre_techniques:
            techniques_str = ", ".join(result.mitre_techniques)
            header += f" MITRE: {techniques_str}"
        
        if result.metadata.get('severity'):
            header += f" | Severity: {result.metadata['severity']}"
        
        content = f"{header}\n{result.content}"
        
        if result.metadata.get('attack_type'):
            content += f"\nAttack Type: {result.metadata['attack_type']}"
        
        return content
    
    def _calculate_aggregated_confidence(self, scores: List[float], total_results: int) -> float:
        if not scores:
            return 0.0
        
        avg_score = sum(scores) / len(scores)
        
        # Coverage factor: how many results we have (more results = higher confidence)
        coverage_factor = min(len(scores) / 3.0, 1.0)
        
        # Consistency factor: less harsh penalty for score variance
        if len(scores) > 1:
            score_variance = np.var(scores)
            # Use a gentler penalty for variance - only penalize high variance
            consistency_factor = max(0.3, 1.0 - min(score_variance * 2, 0.7))
        else:
            consistency_factor = 1.0
        
        # Quality boost: if average score is high, boost confidence
        quality_factor = 1.0 + (avg_score * 0.5)  # Up to 50% boost for high-quality results
        
        confidence = avg_score * coverage_factor * consistency_factor * quality_factor
        
        # Ensure minimum confidence if we have reasonable results
        if avg_score > 0.3 and len(scores) > 0:
            confidence = max(confidence, 0.2)  # Minimum 20% confidence for decent results
        
        return min(confidence, 1.0)

class AdvancedRAGRetriever:
    def __init__(self, vector_db: Optional[CybersecurityVectorDB] = None):
        self.vector_db = vector_db or CybersecurityVectorDB()
        self.query_classifier = QueryClassifier()
        self.relevance_scorer = RelevanceScorer()
        self.context_aggregator = ContextAggregator()
        
    def retrieve(self, query: str, top_k: int = 10, 
                similarity_threshold: float = 0.6) -> RAGContext:
        
        query_type = self.query_classifier.classify_query(query)
        
        logging.info(f"Processing query: '{query}' as {query_type.value}")
        
        raw_results = self.vector_db.similarity_search(query, top_k=top_k * 2, 
                                                      threshold=similarity_threshold)
        
        enhanced_results = []
        for result in raw_results:
            relevance_score = self.relevance_scorer.calculate_relevance_score(
                result, query, query_type
            )
            
            mitre_techniques_str = result['metadata'].get('mitre_techniques', '[]')
            try:
                mitre_techniques = json.loads(mitre_techniques_str) if mitre_techniques_str else []
            except:
                mitre_techniques = []
            
            retrieval_result = RetrievalResult(
                content=result['content'],
                metadata=result['metadata'],
                similarity_score=result['similarity'],
                relevance_score=relevance_score,
                source_type=result['metadata'].get('source', 'unknown'),
                mitre_techniques=mitre_techniques
            )
            enhanced_results.append(retrieval_result)
        
        enhanced_results = sorted(enhanced_results, key=lambda x: x.relevance_score, reverse=True)
        top_results = enhanced_results[:top_k]
        
        aggregated_context, confidence_score = self.context_aggregator.aggregate_context(
            top_results, query, query_type
        )
        
        sources = list(set(result.source_type for result in top_results))
        
        return RAGContext(
            query=query,
            query_type=query_type,
            retrieved_documents=top_results,
            aggregated_context=aggregated_context,
            confidence_score=confidence_score,
            sources=sources
        )
    
    def retrieve_by_mitre_technique(self, mitre_id: str, top_k: int = 5) -> List[RetrievalResult]:
        query = f"MITRE {mitre_id}"
        results = self.vector_db.search_by_mitre_id(mitre_id, top_k=top_k)
        
        enhanced_results = []
        for result in results:
            mitre_techniques_str = result['metadata'].get('mitre_techniques', '[]')
            try:
                mitre_techniques = json.loads(mitre_techniques_str) if mitre_techniques_str else []
            except:
                mitre_techniques = []
            
            retrieval_result = RetrievalResult(
                content=result['content'],
                metadata=result['metadata'],
                similarity_score=result['similarity'],
                relevance_score=result['similarity'],
                source_type=result['metadata'].get('source', 'unknown'),
                mitre_techniques=mitre_techniques
            )
            enhanced_results.append(retrieval_result)
        
        return enhanced_results
    
    def retrieve_by_attack_type(self, attack_type: str, top_k: int = 5) -> List[RetrievalResult]:
        results = self.vector_db.search_by_attack_type(attack_type, top_k=top_k)
        
        enhanced_results = []
        for result in results:
            mitre_techniques_str = result['metadata'].get('mitre_techniques', '[]')
            try:
                mitre_techniques = json.loads(mitre_techniques_str) if mitre_techniques_str else []
            except:
                mitre_techniques = []
            
            retrieval_result = RetrievalResult(
                content=result['content'],
                metadata=result['metadata'],
                similarity_score=result['similarity'],
                relevance_score=result['similarity'],
                source_type=result['metadata'].get('source', 'unknown'),
                mitre_techniques=mitre_techniques
            )
            enhanced_results.append(retrieval_result)
        
        return enhanced_results
    
    def multi_modal_retrieve(self, queries: List[str], weights: Optional[List[float]] = None,
                           top_k: int = 10) -> RAGContext:
        
        if weights is None:
            weights = [1.0] * len(queries)
        
        all_results = {}
        
        for query, weight in zip(queries, weights):
            context = self.retrieve(query, top_k=top_k)
            
            for result in context.retrieved_documents:
                doc_id = result.content[:50]
                
                if doc_id in all_results:
                    all_results[doc_id].relevance_score += result.relevance_score * weight
                else:
                    result.relevance_score *= weight
                    all_results[doc_id] = result
        
        combined_results = sorted(all_results.values(), key=lambda x: x.relevance_score, reverse=True)
        top_results = combined_results[:top_k]
        
        combined_query = " | ".join(queries)
        query_type = self.query_classifier.classify_query(combined_query)
        
        aggregated_context, confidence_score = self.context_aggregator.aggregate_context(
            top_results, combined_query, query_type
        )
        
        sources = list(set(result.source_type for result in top_results))
        
        return RAGContext(
            query=combined_query,
            query_type=query_type,
            retrieved_documents=top_results,
            aggregated_context=aggregated_context,
            confidence_score=confidence_score,
            sources=sources
        )

class RAGQueryOptimizer:
    def __init__(self, retriever: AdvancedRAGRetriever):
        self.retriever = retriever
        
    def expand_query(self, query: str) -> List[str]:
        query_expansions = [query]
        
        mitre_techniques = re.findall(r'T\d{4}(?:\.\d{3})?', query.upper())
        for technique in mitre_techniques:
            expanded_query = query.replace(technique, f"{technique} technique attack")
            query_expansions.append(expanded_query)
        
        security_terms = {
            'injection': ['code injection', 'sql injection', 'command injection'],
            'xss': ['cross-site scripting', 'reflected xss', 'stored xss'],
            'csrf': ['cross-site request forgery', 'session riding'],
            'traversal': ['directory traversal', 'path traversal', 'file inclusion']
        }
        
        query_lower = query.lower()
        for term, expansions in security_terms.items():
            if term in query_lower:
                for expansion in expansions:
                    query_expansions.append(query.replace(term, expansion, 1))
        
        return list(set(query_expansions))
    
    def optimize_retrieval(self, query: str, top_k: int = 10) -> RAGContext:
        expanded_queries = self.expand_query(query)
        
        if len(expanded_queries) == 1:
            return self.retriever.retrieve(query, top_k=top_k)
        
        weights = [1.0] + [0.7] * (len(expanded_queries) - 1)
        
        return self.retriever.multi_modal_retrieve(expanded_queries, weights, top_k=top_k)
