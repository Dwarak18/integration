import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple, Optional
import re
import logging
from pathlib import Path
import json
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class DataPreprocessor:
    def __init__(self):
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
    def clean_text(self, text: str) -> str:
        if pd.isna(text) or not isinstance(text, str):
            return ""
        
        text = re.sub(r'[^\w\s\-\.\,\:\;\(\)\[\]\{\}\'\"\/\\]', '', text)
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        return text
    
    def normalize_severity(self, severity: str) -> str:
        if pd.isna(severity):
            return "Medium"
        
        severity = severity.lower().strip()
        severity_mapping = {
            'critical': 'Critical',
            'high': 'High', 
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Low',
            'information': 'Low'
        }
        
        return severity_mapping.get(severity, 'Medium')
    
    def extract_mitre_techniques(self, text: str) -> List[str]:
        if pd.isna(text) or not isinstance(text, str):
            return []
        
        mitre_pattern = r'T\d{4}(?:\.\d{3})?'
        techniques = re.findall(mitre_pattern, text)
        return list(set(techniques))
    
    def chunk_long_text(self, text: str, max_length: int = 512, overlap: int = 50) -> List[str]:
        if len(text) <= max_length:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = min(start + max_length, len(text))
            
            if end < len(text):
                last_space = text.rfind(' ', start, end)
                if last_space > start:
                    end = last_space
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            start = max(end - overlap, start + 1)
            
        return chunks
    
    def generate_embeddings(self, texts: List[str]) -> np.ndarray:
        return self.embedding_model.encode(texts, convert_to_tensor=False)
    
    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        embeddings = self.generate_embeddings([text1, text2])
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        return float(similarity)

class MitreAttackProcessor(DataPreprocessor):
    def __init__(self):
        super().__init__()
        
    def process_mitre_dataset(self, csv_path: str) -> List[Dict[str, Any]]:
        try:
            # Custom parser for pipe-delimited CSV with multiline descriptions
            processed_data = []
            
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Skip empty lines and get header
            header_line = lines[0].strip()
            if '|' in header_line:
                headers = [h.strip() for h in header_line.split('|')]
            else:
                logging.error("Invalid header format in MITRE dataset")
                return []
            
            current_row = []
            in_description = False
            description_buffer = ""
            
            for i, line in enumerate(lines[1:], 1):
                line = line.strip()
                
                if not line:  # Skip empty lines
                    if in_description:
                        description_buffer += "\n"
                    continue
                
                # Check if this is a new row (starts with a payload)
                if line.count('|') >= 6 and not in_description:
                    # Process previous row if exists
                    if current_row:
                        self._process_mitre_row(current_row, headers, processed_data)
                    
                    # Start new row
                    current_row = [part.strip() for part in line.split('|')]
                    if len(current_row) > 6 and current_row[6]:  # Has description
                        in_description = True
                        description_buffer = current_row[6]
                    else:
                        in_description = False
                        
                elif in_description:
                    # Continue building description
                    description_buffer += " " + line
                    if current_row and len(current_row) > 6:
                        current_row[6] = description_buffer
                    
                    # Check if this might be the end of description
                    if line.endswith('"') and line.count('"') % 2 == 1:
                        in_description = False
            
            # Process last row
            if current_row:
                self._process_mitre_row(current_row, headers, processed_data)
                
        except Exception as e:
            logging.error(f"Error processing MITRE dataset: {e}")
            return []
        
        return processed_data
    
    def _process_mitre_row(self, row_data: List[str], headers: List[str], processed_data: List[Dict[str, Any]]):
        """Process a single MITRE dataset row"""
        try:
            if len(row_data) < len(headers):
                # Pad with empty strings if row is shorter than headers
                row_data.extend([''] * (len(headers) - len(row_data)))
            
            # Create row dictionary
            row_dict = {}
            for i, header in enumerate(headers):
                row_dict[header] = row_data[i] if i < len(row_data) else ''
            
            # Process the row similar to original logic
            payload = self.clean_text(str(row_dict.get('Payload', '')))
            signature = self.clean_text(str(row_dict.get('Signature', '')))
            attack_type = self.clean_text(str(row_dict.get('AttackType', '')))
            severity = self.normalize_severity(str(row_dict.get('Severity', '')))
            mitre_id = self.clean_text(str(row_dict.get('MITRE', '')))
            label = self.clean_text(str(row_dict.get('Label', '')))
            description = self.clean_text(str(row_dict.get('Description', '')))
            
            if not payload and not description:
                return
            
            mitre_techniques = self.extract_mitre_techniques(mitre_id)
            if not mitre_techniques:
                mitre_techniques = self.extract_mitre_techniques(description)
            
            main_content = f"{payload} {description}".strip()
            chunks = self.chunk_long_text(main_content, max_length=400)
            
            for i, chunk in enumerate(chunks):
                processed_entry = {
                    'content': chunk,
                    'payload': payload,
                    'signature': signature,
                    'attack_type': attack_type,
                    'severity': severity,
                    'mitre_id': mitre_id,
                    'mitre_techniques': mitre_techniques,
                    'label': label,
                    'description': description,
                    'chunk_id': i,
                    'total_chunks': len(chunks),
                    'source': 'mitre_attack_dataset',
                    'row_index': len(processed_data)
                }
                processed_data.append(processed_entry)
                
        except Exception as e:
            logging.warning(f"Error processing MITRE row: {e}")

        logging.info(f"Processed {len(processed_data)} entries from MITRE ATT&CK dataset")

class PayloadProcessor(DataPreprocessor):
    def __init__(self):
        super().__init__()
        
    def process_payload_dataset(self, csv_path: str) -> List[Dict[str, Any]]:
        try:
            # Custom parser for pipe-delimited CSV
            processed_data = []
            
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Skip empty lines and get header
            header_line = lines[0].strip()
            if '|' in header_line:
                headers = [h.strip() for h in header_line.split('|')]
            else:
                logging.error("Invalid header format in payload dataset")
                return []
            
            current_row = []
            in_description = False
            description_buffer = ""
            
            for i, line in enumerate(lines[1:], 1):
                line = line.strip()
                
                if not line:  # Skip empty lines
                    if in_description:
                        description_buffer += "\n"
                    continue
                
                # Check if this is a new row (starts with a payload)
                if line.count('|') >= 6 and not in_description:
                    # Process previous row if exists
                    if current_row:
                        self._process_payload_row(current_row, headers, processed_data)
                    
                    # Start new row
                    current_row = [part.strip() for part in line.split('|')]
                    if len(current_row) > 6 and current_row[6]:  # Has description
                        in_description = True
                        description_buffer = current_row[6]
                    else:
                        in_description = False
                        
                elif in_description:
                    # Continue building description
                    description_buffer += " " + line
                    if current_row and len(current_row) > 6:
                        current_row[6] = description_buffer
                    
                    # Check if this might be the end of description
                    if line.endswith('"') and line.count('"') % 2 == 1:
                        in_description = False
            
            # Process last row
            if current_row:
                self._process_payload_row(current_row, headers, processed_data)
                
        except Exception as e:
            logging.error(f"Error processing payload dataset: {e}")
            return []
        
        logging.info(f"Processed {len(processed_data)} entries from payload dataset")
        return processed_data
    
    def _process_payload_row(self, row_data: List[str], headers: List[str], processed_data: List[Dict[str, Any]]):
        """Process a single payload dataset row"""
        try:
            if len(row_data) < len(headers):
                # Pad with empty strings if row is shorter than headers
                row_data.extend([''] * (len(headers) - len(row_data)))
            
            # Create row dictionary
            row_dict = {}
            for i, header in enumerate(headers):
                row_dict[header] = row_data[i] if i < len(row_data) else ''
            
            # Process the row similar to original logic
            payload = self.clean_text(str(row_dict.get('Payload', '')))
            signature = self.clean_text(str(row_dict.get('Signature', '')))
            attack_type = self.clean_text(str(row_dict.get('AttackType', '')))
            severity = self.normalize_severity(str(row_dict.get('Severity', '')))
            mitre_id = self.clean_text(str(row_dict.get('MITRE', '')))
            label = self.clean_text(str(row_dict.get('Label', '')))
            description = self.clean_text(str(row_dict.get('Description', '')))
            
            if not payload and not description:
                return
            
            mitre_techniques = self.extract_mitre_techniques(mitre_id)
            if not mitre_techniques:
                mitre_techniques = self.extract_mitre_techniques(description)
            
            main_content = f"{payload} {description}".strip()
            chunks = self.chunk_long_text(main_content, max_length=400)
            
            for i, chunk in enumerate(chunks):
                processed_entry = {
                    'content': chunk,
                    'payload': payload,
                    'signature': signature,
                    'attack_type': attack_type,
                    'severity': severity,
                    'mitre_id': mitre_id,
                    'mitre_techniques': mitre_techniques,
                    'label': label,
                    'description': description,
                    'chunk_id': i,
                    'total_chunks': len(chunks),
                    'source': 'payload_dataset',
                    'row_index': len(processed_data)
                }
                processed_data.append(processed_entry)
                
        except Exception as e:
            logging.warning(f"Error processing payload row: {e}")
            
            for idx, row in df.iterrows():
                try:
                    payload = self.clean_text(str(row.get('Payload', '')))
                    signature = self.clean_text(str(row.get('Signature', '')))
                    attack_type = self.clean_text(str(row.get('AttackType', '')))
                    severity = self.normalize_severity(str(row.get('Severity', '')))
                    mitre_id = self.clean_text(str(row.get('MITRE', '')))
                    label = self.clean_text(str(row.get('Label', '')))
                    description = self.clean_text(str(row.get('Description', '')))
                    
                    if not payload and not description:
                        continue
                    
                    mitre_techniques = self.extract_mitre_techniques(mitre_id)
                    if not mitre_techniques:
                        mitre_techniques = self.extract_mitre_techniques(description)
                    
                    main_content = f"{payload} {description}".strip()
                    chunks = self.chunk_long_text(main_content, max_length=400)
                    
                    for i, chunk in enumerate(chunks):
                        processed_entry = {
                            'content': chunk,
                            'payload': payload,
                            'signature': signature,
                            'attack_type': attack_type,
                            'severity': severity,
                            'mitre_id': mitre_id,
                            'mitre_techniques': mitre_techniques,
                            'label': label,
                            'description': description,
                            'chunk_id': i,
                            'total_chunks': len(chunks),
                            'source': 'payload_dataset',
                            'row_index': idx
                        }
                        processed_data.append(processed_entry)
                        
                except Exception as e:
                    logging.warning(f"Error processing row {idx}: {e}")
                    continue
            
            logging.info(f"Processed {len(processed_data)} entries from payload dataset")
            return processed_data
            
        except Exception as e:
            logging.error(f"Error processing payload dataset: {e}")
            return []

class CyberAgentDataProcessor(DataPreprocessor):
    def __init__(self):
        super().__init__()
        
    def extract_agent_knowledge(self, cyberagents_path: str) -> List[Dict[str, Any]]:
        knowledge_base = []
        
        agents_path = Path(cyberagents_path) / "agents"
        
        if not agents_path.exists():
            logging.warning(f"Agents path not found: {agents_path}")
            return []
        
        for py_file in agents_path.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                agent_name = py_file.stem
                
                docstrings = re.findall(r'"""(.*?)"""', content, re.DOTALL)
                comments = re.findall(r'#\s*(.*)', content)
                
                knowledge_text = f"Agent: {agent_name}\n"
                
                if docstrings:
                    knowledge_text += "Documentation:\n" + "\n".join(docstrings) + "\n"
                
                if comments:
                    relevant_comments = [c.strip() for c in comments if len(c.strip()) > 10]
                    if relevant_comments:
                        knowledge_text += "Implementation Notes:\n" + "\n".join(relevant_comments[:5])
                
                chunks = self.chunk_long_text(knowledge_text, max_length=300)
                
                for i, chunk in enumerate(chunks):
                    knowledge_entry = {
                        'content': chunk,
                        'agent_name': agent_name,
                        'source': 'cyberagents',
                        'file_path': str(py_file),
                        'chunk_id': i,
                        'total_chunks': len(chunks),
                        'type': 'agent_knowledge'
                    }
                    knowledge_base.append(knowledge_entry)
                    
            except Exception as e:
                logging.warning(f"Error processing agent file {py_file}: {e}")
                continue
        
        logging.info(f"Extracted knowledge from {len(knowledge_base)} agent chunks")
        return knowledge_base

class ComprehensiveDataProcessor:
    def __init__(self):
        self.mitre_processor = MitreAttackProcessor()
        self.payload_processor = PayloadProcessor()
        self.agent_processor = CyberAgentDataProcessor()
        
    def process_all_datasets(self, mitre_csv_path: str, payload_csv_path: str, 
                           cyberagents_path: str) -> Dict[str, List[Dict[str, Any]]]:
        
        logging.info("Starting comprehensive data processing...")
        
        results = {
            'mitre_data': [],
            'payload_data': [],
            'agent_knowledge': []
        }
        
        try:
            results['mitre_data'] = self.mitre_processor.process_mitre_dataset(mitre_csv_path)
        except Exception as e:
            logging.error(f"Failed to process MITRE dataset: {e}")
            
        try:
            results['payload_data'] = self.payload_processor.process_payload_dataset(payload_csv_path)
        except Exception as e:
            logging.error(f"Failed to process payload dataset: {e}")
            
        try:
            results['agent_knowledge'] = self.agent_processor.extract_agent_knowledge(cyberagents_path)
        except Exception as e:
            logging.error(f"Failed to process agent knowledge: {e}")
        
        total_processed = sum(len(data) for data in results.values())
        logging.info(f"Completed processing. Total entries: {total_processed}")
        
        return results
    
    def save_processed_data(self, processed_data: Dict[str, List[Dict[str, Any]]], 
                          output_path: str) -> None:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(processed_data, f, ensure_ascii=False, indent=2)
            logging.info(f"Saved processed data to {output_path}")
        except Exception as e:
            logging.error(f"Failed to save processed data: {e}")
    
    def load_processed_data(self, input_path: str) -> Dict[str, List[Dict[str, Any]]]:
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logging.info(f"Loaded processed data from {input_path}")
            return data
        except Exception as e:
            logging.error(f"Failed to load processed data: {e}")
            return {'mitre_data': [], 'payload_data': [], 'agent_knowledge': []}
