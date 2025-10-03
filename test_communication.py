#!/usr/bin/env python3
"""
Test script to verify communication between API Gateway and RAG service
"""

import requests
import json
import time

def test_rag_service():
    """Test RAG service directly"""
    print("=" * 50)
    print("Testing RAG Service (Direct)")
    print("=" * 50)
    
    try:
        # Test health endpoint
        response = requests.get("http://localhost:8000/health", timeout=5)
        print(f"Health Check: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Test payload analysis
        payload_data = {"payload": "SELECT * FROM users WHERE id=1 OR 1=1"}
        response = requests.post("http://localhost:8000/check_payload", 
                               json=payload_data, 
                               timeout=10)
        print(f"\nPayload Analysis: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        return True
        
    except Exception as e:
        print(f"RAG Service Error: {e}")
        return False

def test_api_gateway():
    """Test API Gateway"""
    print("\n" + "=" * 50)
    print("Testing API Gateway")
    print("=" * 50)
    
    try:
        # Test health endpoint
        response = requests.get("http://127.0.0.1:8080/health", timeout=5)
        print(f"Health Check: {response.status_code}")
        print(f"Response: {response.json()}")
        
        return True
        
    except Exception as e:
        print(f"API Gateway Error: {e}")
        return False

def test_full_integration():
    """Test full integration through API Gateway"""
    print("\n" + "=" * 50)
    print("Testing Full Integration (API Gateway -> RAG)")
    print("=" * 50)
    
    # The API gateway processes requests and forwards them through RAG analysis
    # Let's try a malicious-looking request that should trigger RAG
    try:
        # This should trigger the RAG analysis in the middleware
        response = requests.post("http://127.0.0.1:8080/api/test", 
                               json={"data": "script:alert('xss')"}, 
                               timeout=10)
        print(f"Integration Test: {response.status_code}")
        print(f"Response: {response.text}")
        
        return True
        
    except Exception as e:
        print(f"Integration Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing RAG and Backend Communication")
    print("Make sure both services are running:")
    print("1. RAG Service: http://localhost:8000")
    print("2. API Gateway: http://127.0.0.1:8080")
    print()
    
    # Test services individually first
    rag_ok = test_rag_service()
    api_ok = test_api_gateway()
    
    # If both are working, test integration
    if rag_ok and api_ok:
        test_full_integration()
    else:
        print("\n❌ One or both services are not responding. Check that they are running.")
        
    print("\n✅ Communication test complete!")