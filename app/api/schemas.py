from pydantic import BaseModel
from typing import Dict, Any

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    domain: str
    tld: str
    path: str
    query: str
    scheme: str
    features: Dict[str, Any]
