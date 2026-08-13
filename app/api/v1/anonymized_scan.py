"""
TrustGuard API - Privacy-Preserving k-Anonymity Threat Lookup Route
Receives 5-character SHA-256 hash prefix and returns range of matching hashes + decoy hashes to preserve client anonymity.
"""
from __future__ import annotations
import hashlib
import random
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/lookup", tags=["k-Anonymity"])


class PrefixMatchItem(BaseModel):
    hashSuffix: str
    riskScore: float
    verdictLabel: str


class KAnonymityResponse(BaseModel):
    prefix: str
    matches: list[PrefixMatchItem]


# Mock threat database for k-Anonymity prefix lookups
KNOWN_THREAT_HASHES: dict[str, dict] = {
    # Pre-computed SHA-256 hashes of sample malicious domains
    hashlib.sha256(b"phishing-example.com").hexdigest(): {"risk_score": 95.0, "label": "phishing"},
    hashlib.sha256(b"login-verify-account.xyz").hexdigest(): {"risk_score": 90.0, "label": "phishing"},
    hashlib.sha256(b"secure-paypal-update.tk").hexdigest(): {"risk_score": 88.0, "label": "phishing"},
}


@router.get("/prefix/{hash_prefix}", response_model=KAnonymityResponse)
async def lookup_by_prefix(
    hash_prefix: str = Path(..., min_length=5, max_length=16, description="5 to 16 hex character SHA-256 hash prefix")
) -> KAnonymityResponse:
    """
    K-Anonymity threat lookup endpoint.
    Client sends truncated hash prefix. Server returns set of suffixes matching prefix, plus noise decoy entries.
    Zero disclosure of full domain or URL to the server.
    """
    clean_prefix = hash_prefix.lower().strip()
    if not all(c in "0123456789abcdef" for c in clean_prefix):
        raise HTTPException(status_code=400, detail="Invalid hexadecimal hash prefix format")

    matches: list[PrefixMatchItem] = []

    # 1. Match real known threat hashes matching the prefix
    for full_hash, info in KNOWN_THREAT_HASHES.items():
        if full_hash.startswith(clean_prefix):
            matches.append(
                PrefixMatchItem(
                    hashSuffix=full_hash[len(clean_prefix):],
                    riskScore=info["risk_score"],
                    verdictLabel=info["label"],
                )
            )

    # 2. Add randomized decoy items to ensure minimum k-anonymity set size (k >= 5)
    desired_k = max(5, len(matches) + 3)
    remaining_len = 64 - len(clean_prefix)

    while len(matches) < desired_k:
        random_suffix = "".join(random.choices("0123456789abcdef", k=remaining_len))
        matches.append(
            PrefixMatchItem(
                hashSuffix=random_suffix,
                riskScore=round(random.uniform(70.0, 99.0), 1),
                verdictLabel="phishing"
            )
        )

    # Shuffle match list so true target position is hidden
    random.shuffle(matches)

    return KAnonymityResponse(
        prefix=clean_prefix,
        matches=matches
    )
