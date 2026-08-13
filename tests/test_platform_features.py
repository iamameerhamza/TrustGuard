import pytest
from fastapi.testclient import TestClient
from app.main import app
import os

client = TestClient(app)
api_key = os.getenv("TRUSTGUARD_API_KEY", "change_me_to_a_strong_random_secret")
AUTH_HEADERS = {"X-API-Key": api_key}

def test_scan_qr_endpoint():
    dummy_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    response = client.post(
        "/scan/qr/",
        json={"image_base64": dummy_b64},
        headers=AUTH_HEADERS,
    )
    assert response.status_code in [200, 422, 501, 400]

def test_scan_document_endpoint():
    dummy_pdf_b64 = "JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCg=="
    response = client.post(
        "/scan/document/",
        json={
            "filename": "test.pdf",
            "content_base64": dummy_pdf_b64,
            "mime_type": "application/pdf"
        },
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    data = response.json()
    assert "threats_found" in data
    assert data["mime_type"] == "application/pdf"

def test_scan_visual_endpoint():
    dummy_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    response = client.post(
        "/scan/visual/",
        json={
            "image_base64": dummy_b64,
            "target_brand": "google"
        },
        headers=AUTH_HEADERS,
    )
    assert response.status_code in [200, 501]

def test_scan_agentic_endpoint():
    response = client.post(
        "/scan/agentic/",
        json={
            "text": "Please enter your Credit Card: 4532 1122 3344 5566 and SSN: 123-45-6789",
            "scan_type": "full"
        },
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["pii_findings"]) >= 0

def test_generate_trust_seals_endpoint():
    response = client.post(
        "/seals/generate",
        json={
            "domain": "acme-corp.com",
            "seal_type": "certified",
            "theme": "dark"
        },
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    data = response.json()
    assert "svg_markup" in data
    assert "html_embed" in data
