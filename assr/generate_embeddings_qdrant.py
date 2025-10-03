import pandas as pd
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import PointStruct, Distance, VectorParams
import os

CSV_PATH = 'payload_dataset.csv'
QDRANT_HOST = 'localhost'
QDRANT_PORT = 6333
EMBEDDING_MODEL = 'all-MiniLM-L6-v2'

# Load payloads
df = pd.read_csv(CSV_PATH)
model = SentenceTransformer(EMBEDDING_MODEL)

client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

# Create collections
for collection in ['malicious', 'legit']:
    client.recreate_collection(
        collection_name=collection,
        vectors_config=VectorParams(size=model.get_sentence_embedding_dimension(), distance=Distance.COSINE)
    )

for idx, row in df.iterrows():
    payload = str(row['Payload'])
    label = row['Label']
    severity = row['Severity']
    metadata = {
        'Signature': row['Signature'],
        'AttackType': row['AttackType'],
        'Severity': severity,
        'MITRE': row['MITRE'],
        'Description': row['Description'],
        'Payload': payload
    }
    embedding = model.encode(payload)
    collection = 'malicious' if label.lower() == 'malicious' else 'legit'
    point = PointStruct(id=idx, vector=embedding.tolist(), payload=metadata)
    client.upsert(collection_name=collection, points=[point])

print('Embeddings uploaded to Qdrant collections: malicious and legit.')
