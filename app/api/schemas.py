from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    domain: str
    tld: str
    path: str
    query: str
    scheme: str
