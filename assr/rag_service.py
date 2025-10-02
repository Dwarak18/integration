from fastapi import FastAPI, Request
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import Filter, FieldCondition, MatchValue
import os

app = FastAPI()

QDRANT_HOST = 'localhost'
QDRANT_PORT = 6333
EMBEDDING_MODEL = 'all-MiniLM-L6-v2'

model = SentenceTransformer(EMBEDDING_MODEL)
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

class PayloadRequest(BaseModel):
    payload: str

@app.post('/check_payload')
async def check_payload(req: PayloadRequest):
    embedding = model.encode(req.payload)
    threshold = 0.8  # Similarity threshold
    verdict = None
    best_score = 0.0
    best_label = None
    results = {}
    for collection in ['malicious', 'legit']:
        search_result = client.search(collection_name=collection, query_vector=embedding.tolist(), limit=1)
        results[collection] = search_result
        if search_result:
            score = search_result[0].score if hasattr(search_result[0], 'score') else 0.0
            if score > best_score:
                best_score = score
                best_label = collection
    if best_score >= threshold:
        verdict = 'malicious' if best_label == 'malicious' else 'legit'
    else:
        # Fallback to Gemini API (mocked)
        verdict = await call_gemini_api(req.payload)
        # Insert new result into Qdrant
        metadata = {'Payload': req.payload, 'verdict': verdict}
        collection = 'malicious' if verdict == 'malicious' else 'legit'
        from qdrant_client.http.models import PointStruct
        point = PointStruct(id=os.urandom(8).hex(), vector=embedding.tolist(), payload=metadata)
        client.upsert(collection_name=collection, points=[point])
    # Logging malicious verdicts
    if verdict == 'malicious':
        log_malicious(req.payload, best_score)
    return {'verdict': verdict, 'score': best_score, 'results': results}
# Logging function
def log_malicious(payload, score):
    with open('malicious_verdicts.log', 'a', encoding='utf-8') as f:
        f.write(f"{payload}\t{score}\n")

@app.post('/ingest_example')
async def ingest_example(req: PayloadRequest):
    embedding = model.encode(req.payload)
    # Default to legit, can be extended
    metadata = {'Payload': req.payload, 'verdict': 'legit'}
    from qdrant_client.http.models import PointStruct
    point = PointStruct(id=os.urandom(8).hex(), vector=embedding.tolist(), payload=metadata)
    client.upsert(collection_name='legit', points=[point])
    return {'status': 'inserted'}
# Gemini API mock function
import asyncio
async def call_gemini_api(payload: str) -> str:
    # Simulate Gemini verdict: return 'malicious' if 'password' in payload else 'legit'
    await asyncio.sleep(1)
    return 'malicious' if 'password' in payload else 'legit'

@app.post('/retrain')
async def retrain():
    # Rebuild Qdrant index from updated dataset
    import pandas as pd
    CSV_PATH = 'payload_dataset.csv'
    if not os.path.exists(CSV_PATH):
        return {'status': 'payload_dataset.csv not found'}
    df = pd.read_csv(CSV_PATH)
    for collection in ['malicious', 'legit']:
        client.recreate_collection(
            collection_name=collection,
            vectors_config=client.get_collection(collection_name=collection).config.params
        )
    for idx, row in df.iterrows():
        payload = str(row['Payload'])
        label = row['Label'] if 'Label' in row else 'legit'
        metadata = {
            'Signature': row['Signature'] if 'Signature' in row else '',
            'AttackType': row['AttackType'] if 'AttackType' in row else '',
            'Severity': row['Severity'] if 'Severity' in row else '',
            'MITRE': row['MITRE'] if 'MITRE' in row else '',
            'Description': row['Description'] if 'Description' in row else '',
            'Payload': payload
        }
        embedding = model.encode(payload)
        collection = 'malicious' if label.lower() == 'malicious' else 'legit'
        from qdrant_client.http.models import PointStruct
        point = PointStruct(id=idx, vector=embedding.tolist(), payload=metadata)
        client.upsert(collection_name=collection, points=[point])
    return {'status': 'retrained'}

@app.get('/stats')
async def stats():
    # TODO: Return stats about collections
    return {'status': 'not implemented'}
