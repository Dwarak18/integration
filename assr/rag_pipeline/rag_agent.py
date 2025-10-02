import logging
from typing import List, Dict, Any, Optional, Tuple
import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime

from .retrieval import AdvancedRAGRetriever, RAGQueryOptimizer, RAGContext, QueryType
from .vector_db import CybersecurityVectorDB

@dataclass
class ThreatAnalysisResult:
    threat_level: str
    confidence_score: float
    attack_vectors: List[str]
    mitre_techniques: List[str]
    affected_systems: List[str]
    recommendations: List[str]
    evidence: List[Dict[str, Any]]
    analysis_summary: str
    timestamp: str

@dataclass
class PayloadAnalysisResult:
    payload_type: str
    attack_classification: str
    severity_level: str
    exploitation_method: str
    target_systems: List[str]
    mitigation_strategies: List[str]
    similar_attacks: List[Dict[str, Any]]
    technical_details: Dict[str, Any]
    risk_assessment: str

@dataclass
class SecurityRecommendation:
    priority: str
    category: str
    action: str
    description: str
    implementation_steps: List[str]
    resources_required: List[str]
    timeline: str
    effectiveness_rating: float

class RAGSecurityAgent:
    def __init__(self, vector_db: Optional[CybersecurityVectorDB] = None):
        self.vector_db = vector_db or CybersecurityVectorDB()
        self.retriever = AdvancedRAGRetriever(self.vector_db)
        self.optimizer = RAGQueryOptimizer(self.retriever)
        
        self.threat_level_mapping = {
            'critical': ['critical', 'severe', 'high-risk', 'dangerous'],
            'high': ['high', 'significant', 'important', 'major'],
            'medium': ['medium', 'moderate', 'standard', 'normal'],
            'low': ['low', 'minor', 'minimal', 'negligible']
        }
        
    def analyze_threat(self, threat_indicators: List[str], context: str = "") -> ThreatAnalysisResult:
        logging.info(f"Analyzing threat with {len(threat_indicators)} indicators")
        
        combined_query = f"{context} {' '.join(threat_indicators)}".strip()
        
        rag_context = self.optimizer.optimize_retrieval(combined_query, top_k=15)
        
        threat_level = self._determine_threat_level(rag_context)
        attack_vectors = self._extract_attack_vectors(rag_context)
        mitre_techniques = self._extract_mitre_techniques(rag_context)
        affected_systems = self._identify_affected_systems(threat_indicators, rag_context)
        recommendations = self._generate_threat_recommendations(rag_context, threat_level)
        analysis_summary = self._generate_threat_summary(rag_context, threat_level)
        
        evidence = []
        for doc in rag_context.retrieved_documents[:5]:
            evidence.append({
                'source': doc.source_type,
                'content': doc.content[:200] + "..." if len(doc.content) > 200 else doc.content,
                'relevance_score': doc.relevance_score,
                'mitre_techniques': doc.mitre_techniques
            })
        
        return ThreatAnalysisResult(
            threat_level=threat_level,
            confidence_score=rag_context.confidence_score,
            attack_vectors=attack_vectors,
            mitre_techniques=mitre_techniques,
            affected_systems=affected_systems,
            recommendations=recommendations,
            evidence=evidence,
            analysis_summary=analysis_summary,
            timestamp=datetime.now().isoformat()
        )
    
    def analyze_payload(self, payload: str, additional_context: str = "") -> PayloadAnalysisResult:
        logging.info(f"Analyzing payload: {payload[:50]}...")
        
        query = f"analyze payload {payload} {additional_context}".strip()
        
        rag_context = self.retriever.retrieve(query, top_k=12)
        
        payload_type = self._classify_payload_type(payload, rag_context)
        attack_classification = self._classify_attack_type(rag_context)
        severity_level = self._determine_payload_severity(payload, rag_context)
        exploitation_method = self._identify_exploitation_method(payload, rag_context)
        target_systems = self._identify_target_systems(payload, rag_context)
        mitigation_strategies = self._generate_mitigation_strategies(rag_context)
        similar_attacks = self._find_similar_attacks(rag_context)
        technical_details = self._extract_technical_details(payload, rag_context)
        risk_assessment = self._assess_payload_risk(payload, rag_context)
        
        return PayloadAnalysisResult(
            payload_type=payload_type,
            attack_classification=attack_classification,
            severity_level=severity_level,
            exploitation_method=exploitation_method,
            target_systems=target_systems,
            mitigation_strategies=mitigation_strategies,
            similar_attacks=similar_attacks,
            technical_details=technical_details,
            risk_assessment=risk_assessment
        )
    
    def get_security_recommendations(self, security_context: str, priority_level: str = "high") -> List[SecurityRecommendation]:
        logging.info(f"Generating security recommendations for: {security_context}")
        
        mitigation_query = f"prevent protect mitigate {security_context}"
        rag_context = self.retriever.retrieve(mitigation_query, top_k=10)
        
        recommendations = []
        
        seen_recommendations = set()
        
        for doc in rag_context.retrieved_documents:
            if doc.source_type == 'cyberagents':
                continue
                
            rec_text = self._extract_recommendation_from_content(doc.content)
            if rec_text and rec_text not in seen_recommendations:
                seen_recommendations.add(rec_text)
                
                category = self._categorize_recommendation(rec_text, doc.metadata)
                priority = self._determine_recommendation_priority(doc, priority_level)
                implementation_steps = self._generate_implementation_steps(rec_text)
                resources_required = self._identify_required_resources(rec_text)
                timeline = self._estimate_implementation_timeline(rec_text, priority)
                effectiveness = self._rate_effectiveness(doc.relevance_score)
                
                recommendation = SecurityRecommendation(
                    priority=priority,
                    category=category,
                    action=rec_text,
                    description=doc.content[:300] + "..." if len(doc.content) > 300 else doc.content,
                    implementation_steps=implementation_steps,
                    resources_required=resources_required,
                    timeline=timeline,
                    effectiveness_rating=effectiveness
                )
                recommendations.append(recommendation)
        
        return sorted(recommendations, key=lambda x: (x.priority == 'Critical', x.effectiveness_rating), reverse=True)
    
    def investigate_attack_pattern(self, attack_indicators: List[str]) -> Dict[str, Any]:
        logging.info(f"Investigating attack pattern with {len(attack_indicators)} indicators")
        
        pattern_query = " ".join(attack_indicators) + " attack pattern technique"
        rag_context = self.retriever.retrieve(pattern_query, top_k=15)
        
        investigation_result = {
            'attack_pattern': self._identify_attack_pattern(rag_context),
            'ttp_analysis': self._analyze_ttps(rag_context),
            'attribution_hints': self._extract_attribution_hints(rag_context),
            'timeline_reconstruction': self._reconstruct_attack_timeline(attack_indicators, rag_context),
            'related_campaigns': self._find_related_campaigns(rag_context),
            'defensive_gaps': self._identify_defensive_gaps(rag_context),
            'hunting_queries': self._generate_hunting_queries(attack_indicators, rag_context),
            'confidence_assessment': rag_context.confidence_score
        }
        
        return investigation_result
    
    def _determine_threat_level(self, rag_context: RAGContext) -> str:
        severity_scores = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        weighted_score = 0
        total_weight = 0
        
        for doc in rag_context.retrieved_documents:
            severity = doc.metadata.get('severity', 'Medium')
            weight = doc.relevance_score
            
            score = severity_scores.get(severity, 2)
            weighted_score += score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 'Medium'
        
        avg_score = weighted_score / total_weight
        
        if avg_score >= 3.5:
            return 'Critical'
        elif avg_score >= 2.5:
            return 'High'
        elif avg_score >= 1.5:
            return 'Medium'
        else:
            return 'Low'
    
    def _extract_attack_vectors(self, rag_context: RAGContext) -> List[str]:
        attack_vectors = set()
        
        for doc in rag_context.retrieved_documents:
            attack_type = doc.metadata.get('attack_type', '').lower()
            if attack_type:
                attack_vectors.add(attack_type)
            
            content_lower = doc.content.lower()
            
            if 'web application' in content_lower or 'http' in content_lower:
                attack_vectors.add('Web Application')
            if 'network' in content_lower or 'tcp' in content_lower or 'udp' in content_lower:
                attack_vectors.add('Network')
            if 'email' in content_lower or 'phishing' in content_lower:
                attack_vectors.add('Email')
            if 'social engineering' in content_lower:
                attack_vectors.add('Social Engineering')
            if 'malware' in content_lower or 'trojan' in content_lower:
                attack_vectors.add('Malware')
        
        return list(attack_vectors)
    
    def _extract_mitre_techniques(self, rag_context: RAGContext) -> List[str]:
        techniques = set()
        
        for doc in rag_context.retrieved_documents:
            techniques.update(doc.mitre_techniques)
            
            mitre_id = doc.metadata.get('mitre_id', '')
            if mitre_id and mitre_id.startswith('T'):
                techniques.add(mitre_id)
        
        return list(techniques)
    
    def _identify_affected_systems(self, indicators: List[str], rag_context: RAGContext) -> List[str]:
        systems = set()
        
        system_patterns = {
            'Windows': ['windows', 'win32', 'ntfs', 'registry', 'powershell'],
            'Linux': ['linux', 'unix', 'bash', 'shell', '/etc/', '/var/'],
            'Web Server': ['apache', 'nginx', 'iis', 'tomcat', 'http'],
            'Database': ['mysql', 'postgresql', 'oracle', 'mssql', 'database'],
            'Network Infrastructure': ['router', 'switch', 'firewall', 'dns', 'dhcp'],
            'Cloud Services': ['aws', 'azure', 'gcp', 'cloud', 's3']
        }
        
        all_content = ' '.join(indicators + [doc.content.lower() for doc in rag_context.retrieved_documents])
        
        for system, patterns in system_patterns.items():
            if any(pattern in all_content for pattern in patterns):
                systems.add(system)
        
        return list(systems) if systems else ['Unknown']
    
    def _generate_threat_recommendations(self, rag_context: RAGContext, threat_level: str) -> List[str]:
        recommendations = []
        
        base_recommendations = {
            'Critical': [
                'Implement immediate incident response procedures',
                'Isolate affected systems from the network',
                'Engage external security experts if needed',
                'Notify relevant stakeholders and authorities'
            ],
            'High': [
                'Activate security monitoring protocols',
                'Apply security patches immediately',
                'Review and strengthen access controls',
                'Conduct thorough security assessment'
            ],
            'Medium': [
                'Monitor systems for suspicious activity',
                'Review security configurations',
                'Update security policies and procedures',
                'Schedule security training for staff'
            ],
            'Low': [
                'Document findings for future reference',
                'Continue regular security monitoring',
                'Consider preventive security measures',
                'Review security awareness programs'
            ]
        }
        
        recommendations.extend(base_recommendations.get(threat_level, base_recommendations['Medium']))
        
        for doc in rag_context.retrieved_documents[:3]:
            if 'mitigate' in doc.content.lower() or 'prevent' in doc.content.lower():
                extracted_rec = self._extract_recommendation_from_content(doc.content)
                if extracted_rec:
                    recommendations.append(extracted_rec)
        
        return recommendations[:6]
    
    def _generate_threat_summary(self, rag_context: RAGContext, threat_level: str) -> str:
        mitre_techniques = self._extract_mitre_techniques(rag_context)
        attack_vectors = self._extract_attack_vectors(rag_context)
        
        summary = f"Threat Level: {threat_level}. "
        
        if mitre_techniques:
            summary += f"Associated MITRE techniques: {', '.join(mitre_techniques[:3])}. "
        
        if attack_vectors:
            summary += f"Primary attack vectors: {', '.join(attack_vectors[:3])}. "
        
        summary += f"Analysis confidence: {rag_context.confidence_score:.2f}. "
        
        top_doc = rag_context.retrieved_documents[0] if rag_context.retrieved_documents else None
        if top_doc:
            summary += f"Key finding: {top_doc.content[:150]}..."
        
        return summary
    
    def _classify_payload_type(self, payload: str, rag_context: RAGContext) -> str:
        payload_lower = payload.lower()
        
        payload_types = {
            'SQL Injection': ['select', 'union', 'drop', 'insert', 'update', 'delete', "'", '"'],
            'Cross-Site Scripting': ['<script>', 'javascript:', 'alert(', 'document.', 'window.'],
            'Command Injection': ['exec', 'system', 'eval', '`', '$(', '&&', '||'],
            'Directory Traversal': ['../', '..\\', '%2e%2e', 'etc/passwd', 'windows/system32'],
            'Server-Side Request Forgery': ['http://', 'https://', 'file://', 'gopher://'],
            'Template Injection': ['{{', '}}', '${', '}', 'jinja', 'freemarker'],
            'Buffer Overflow': ['%n', '%x', 'AAAA', '\\x90', 'shellcode'],
            'Authentication Bypass': ['admin', 'password', 'bypass', 'login', 'auth']
        }
        
        scores = {}
        for payload_type, indicators in payload_types.items():
            score = sum(1 for indicator in indicators if indicator in payload_lower)
            scores[payload_type] = score
        
        max_score = max(scores.values()) if scores else 0
        if max_score > 0:
            return max(scores, key=scores.get)
        
        for doc in rag_context.retrieved_documents:
            attack_type = doc.metadata.get('attack_type', '')
            if attack_type:
                return attack_type
        
        return 'Unknown'
    
    def _classify_attack_type(self, rag_context: RAGContext) -> str:
        attack_types = {}
        
        for doc in rag_context.retrieved_documents:
            attack_type = doc.metadata.get('attack_type', 'Unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + doc.relevance_score
        
        if attack_types:
            return max(attack_types, key=attack_types.get)
        
        return 'Unknown'
    
    def _determine_payload_severity(self, payload: str, rag_context: RAGContext) -> str:
        severity_scores = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for doc in rag_context.retrieved_documents:
            severity = doc.metadata.get('severity', 'Medium')
            severity_scores[severity] += doc.relevance_score
        
        return max(severity_scores, key=severity_scores.get) if any(severity_scores.values()) else 'Medium'
    
    def _identify_exploitation_method(self, payload: str, rag_context: RAGContext) -> str:
        methods = []
        
        if 'inject' in payload.lower():
            methods.append('Code Injection')
        if any(char in payload for char in ['<', '>', 'script']):
            methods.append('Client-Side Injection')
        if any(sql_kw in payload.lower() for sql_kw in ['select', 'union', 'drop']):
            methods.append('SQL Manipulation')
        if any(file_kw in payload for file_kw in ['../', '..\\']):
            methods.append('File System Traversal')
        
        for doc in rag_context.retrieved_documents:
            content_lower = doc.content.lower()
            if 'remote code execution' in content_lower:
                methods.append('Remote Code Execution')
            if 'privilege escalation' in content_lower:
                methods.append('Privilege Escalation')
        
        return ', '.join(set(methods)) if methods else 'Unknown'
    
    def _identify_target_systems(self, payload: str, rag_context: RAGContext) -> List[str]:
        targets = set()
        
        target_indicators = {
            'Web Applications': ['http', 'web', 'browser', 'html', 'php', 'asp'],
            'Databases': ['sql', 'mysql', 'postgresql', 'oracle', 'database'],
            'Operating Systems': ['system', 'os', 'windows', 'linux', 'unix'],
            'Network Services': ['network', 'service', 'port', 'tcp', 'udp'],
            'Cloud Infrastructure': ['cloud', 'aws', 'azure', 'gcp', 's3']
        }
        
        combined_text = payload.lower() + ' ' + ' '.join([doc.content.lower() for doc in rag_context.retrieved_documents[:3]])
        
        for target, indicators in target_indicators.items():
            if any(indicator in combined_text for indicator in indicators):
                targets.add(target)
        
        return list(targets) if targets else ['General Systems']
    
    def _generate_mitigation_strategies(self, rag_context: RAGContext) -> List[str]:
        strategies = []
        
        mitigation_keywords = ['prevent', 'protect', 'defend', 'mitigate', 'block', 'filter', 'sanitize', 'validate']
        
        for doc in rag_context.retrieved_documents:
            content_lower = doc.content.lower()
            
            for keyword in mitigation_keywords:
                if keyword in content_lower:
                    sentences = doc.content.split('.')
                    for sentence in sentences:
                        if keyword in sentence.lower() and len(sentence.strip()) > 20:
                            strategies.append(sentence.strip())
                            break
        
        general_strategies = [
            'Implement input validation and sanitization',
            'Deploy Web Application Firewall (WAF)',
            'Apply principle of least privilege',
            'Enable comprehensive logging and monitoring',
            'Keep systems and software updated',
            'Implement network segmentation'
        ]
        
        strategies.extend(general_strategies)
        
        return list(set(strategies))[:8]
    
    def _find_similar_attacks(self, rag_context: RAGContext) -> List[Dict[str, Any]]:
        similar_attacks = []
        
        for doc in rag_context.retrieved_documents[:5]:
            if doc.similarity_score > 0.8:
                attack_info = {
                    'attack_type': doc.metadata.get('attack_type', 'Unknown'),
                    'mitre_technique': doc.metadata.get('mitre_id', ''),
                    'severity': doc.metadata.get('severity', 'Medium'),
                    'description': doc.content[:200] + "..." if len(doc.content) > 200 else doc.content,
                    'similarity_score': doc.similarity_score
                }
                similar_attacks.append(attack_info)
        
        return similar_attacks
    
    def _extract_technical_details(self, payload: str, rag_context: RAGContext) -> Dict[str, Any]:
        details = {
            'payload_length': len(payload),
            'character_analysis': self._analyze_payload_characters(payload),
            'encoding_detection': self._detect_encoding(payload),
            'obfuscation_techniques': self._detect_obfuscation(payload),
            'execution_context': self._determine_execution_context(payload, rag_context)
        }
        
        return details
    
    def _assess_payload_risk(self, payload: str, rag_context: RAGContext) -> str:
        risk_factors = []
        
        if len(payload) > 500:
            risk_factors.append("Large payload size indicates complex attack")
        
        dangerous_functions = ['eval', 'exec', 'system', 'shell_exec', 'passthru']
        if any(func in payload.lower() for func in dangerous_functions):
            risk_factors.append("Contains dangerous function calls")
        
        if re.search(r'[<>"\']', payload):
            risk_factors.append("Contains special characters often used in attacks")
        
        high_severity_count = sum(1 for doc in rag_context.retrieved_documents if doc.metadata.get('severity') in ['Critical', 'High'])
        if high_severity_count > 3:
            risk_factors.append("Matches multiple high-severity attack patterns")
        
        if len(risk_factors) >= 3:
            risk_level = "High Risk"
        elif len(risk_factors) >= 1:
            risk_level = "Medium Risk"
        else:
            risk_level = "Low Risk"
        
        assessment = f"{risk_level}: " + "; ".join(risk_factors) if risk_factors else "Low Risk: No significant risk factors identified"
        
        return assessment
    
    def _extract_recommendation_from_content(self, content: str) -> str:
        mitigation_patterns = [
            r'[Pp]revent.*?by (.+?)[\.\n]',
            r'[Mm]itigate.*?through (.+?)[\.\n]',
            r'[Pp]rotect.*?using (.+?)[\.\n]',
            r'[Ii]mplement (.+?) to prevent',
            r'[Uu]se (.+?) to defend'
        ]
        
        for pattern in mitigation_patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1).strip()
        
        sentences = content.split('.')
        for sentence in sentences:
            if any(word in sentence.lower() for word in ['prevent', 'protect', 'defend', 'mitigate']):
                if len(sentence.strip()) > 20:
                    return sentence.strip()
        
        return ""
    
    def _categorize_recommendation(self, rec_text: str, metadata: Dict[str, Any]) -> str:
        categories = {
            'Network Security': ['firewall', 'network', 'traffic', 'ports', 'protocols'],
            'Access Control': ['authentication', 'authorization', 'access', 'privileges', 'permissions'],
            'Data Protection': ['encryption', 'data', 'backup', 'privacy', 'confidentiality'],
            'System Hardening': ['configuration', 'hardening', 'secure', 'settings', 'policies'],
            'Monitoring': ['monitoring', 'logging', 'detection', 'alerts', 'surveillance'],
            'Incident Response': ['response', 'incident', 'recovery', 'forensics', 'investigation']
        }
        
        rec_lower = rec_text.lower()
        for category, keywords in categories.items():
            if any(keyword in rec_lower for keyword in keywords):
                return category
        
        return 'General Security'
    
    def _determine_recommendation_priority(self, doc, priority_level: str) -> str:
        severity = doc.metadata.get('severity', 'Medium')
        relevance = doc.relevance_score
        
        if severity == 'Critical' or relevance > 0.9:
            return 'Critical'
        elif severity == 'High' or relevance > 0.7:
            return 'High'
        elif severity == 'Medium' or relevance > 0.5:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_implementation_steps(self, rec_text: str) -> List[str]:
        generic_steps = [
            "Assess current security posture",
            "Plan implementation approach",
            "Allocate necessary resources",
            "Execute implementation",
            "Test and validate effectiveness",
            "Monitor and maintain"
        ]
        
        return generic_steps
    
    def _identify_required_resources(self, rec_text: str) -> List[str]:
        resources = ['Security personnel', 'Technical documentation', 'Implementation time']
        
        if 'software' in rec_text.lower() or 'tool' in rec_text.lower():
            resources.append('Security software/tools')
        if 'hardware' in rec_text.lower() or 'device' in rec_text.lower():
            resources.append('Hardware equipment')
        if 'train' in rec_text.lower() or 'education' in rec_text.lower():
            resources.append('Training materials')
        
        return resources
    
    def _estimate_implementation_timeline(self, rec_text: str, priority: str) -> str:
        if priority == 'Critical':
            return 'Immediate (24-48 hours)'
        elif priority == 'High':
            return 'Short-term (1-2 weeks)'
        elif priority == 'Medium':
            return 'Medium-term (2-4 weeks)'
        else:
            return 'Long-term (1-3 months)'
    
    def _rate_effectiveness(self, relevance_score: float) -> float:
        return min(relevance_score * 1.2, 1.0)
    
    def _identify_attack_pattern(self, rag_context: RAGContext) -> str:
        patterns = {}
        
        for doc in rag_context.retrieved_documents:
            attack_type = doc.metadata.get('attack_type', 'Unknown')
            patterns[attack_type] = patterns.get(attack_type, 0) + doc.relevance_score
        
        if patterns:
            return max(patterns, key=patterns.get)
        
        return 'Unknown Pattern'
    
    def _analyze_ttps(self, rag_context: RAGContext) -> Dict[str, List[str]]:
        ttps = {'tactics': [], 'techniques': [], 'procedures': []}
        
        for doc in rag_context.retrieved_documents:
            if doc.mitre_techniques:
                ttps['techniques'].extend(doc.mitre_techniques)
        
        ttps['techniques'] = list(set(ttps['techniques']))
        
        return ttps
    
    def _extract_attribution_hints(self, rag_context: RAGContext) -> List[str]:
        return ["Attribution analysis requires additional threat intelligence"]
    
    def _reconstruct_attack_timeline(self, indicators: List[str], rag_context: RAGContext) -> List[str]:
        return ["Timeline reconstruction requires temporal analysis of indicators"]
    
    def _find_related_campaigns(self, rag_context: RAGContext) -> List[str]:
        return ["Related campaign analysis requires threat intelligence correlation"]
    
    def _identify_defensive_gaps(self, rag_context: RAGContext) -> List[str]:
        gaps = []
        
        for doc in rag_context.retrieved_documents:
            if 'bypass' in doc.content.lower():
                gaps.append("Security controls may be bypassable")
            if 'undetected' in doc.content.lower():
                gaps.append("Detection capabilities may be insufficient")
        
        return gaps if gaps else ["No specific defensive gaps identified"]
    
    def _generate_hunting_queries(self, indicators: List[str], rag_context: RAGContext) -> List[str]:
        queries = []
        
        for indicator in indicators[:3]:
            if len(indicator.strip()) > 5:
                queries.append(f"Search for: {indicator}")
        
        return queries
    
    def _analyze_payload_characters(self, payload: str) -> Dict[str, Any]:
        return {
            'special_chars': len([c for c in payload if not c.isalnum() and not c.isspace()]),
            'uppercase_ratio': sum(1 for c in payload if c.isupper()) / len(payload) if payload else 0,
            'numeric_ratio': sum(1 for c in payload if c.isdigit()) / len(payload) if payload else 0
        }
    
    def _detect_encoding(self, payload: str) -> List[str]:
        encodings = []
        
        if '%' in payload and any(c.isdigit() or c in 'abcdefABCDEF' for c in payload.replace('%', '')):
            encodings.append('URL Encoding')
        if '\\x' in payload:
            encodings.append('Hex Encoding')
        if payload != payload.encode().decode('utf-8', errors='ignore'):
            encodings.append('UTF-8 Encoding')
        
        return encodings if encodings else ['Plain Text']
    
    def _detect_obfuscation(self, payload: str) -> List[str]:
        obfuscations = []
        
        if len(set(payload)) < len(payload) * 0.3:
            obfuscations.append('Character Repetition')
        if any(len(word) > 50 for word in payload.split()):
            obfuscations.append('Long Strings')
        if payload.count('\\') > len(payload) * 0.1:
            obfuscations.append('Escape Sequences')
        
        return obfuscations if obfuscations else ['No Obfuscation Detected']
    
    def _determine_execution_context(self, payload: str, rag_context: RAGContext) -> str:
        contexts = []
        
        if any(web_indicator in payload.lower() for web_indicator in ['http', 'html', 'javascript', 'php']):
            contexts.append('Web Application')
        if any(sys_indicator in payload.lower() for sys_indicator in ['system', 'exec', 'shell', 'cmd']):
            contexts.append('System Command')
        if any(db_indicator in payload.lower() for db_indicator in ['select', 'insert', 'update', 'delete']):
            contexts.append('Database Query')
        
        return ', '.join(contexts) if contexts else 'Unknown Context'
