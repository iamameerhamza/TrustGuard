import re
from typing import Any
from app.api.schemas import PiiFinding

CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
SSN_RE = re.compile(r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b")
API_KEY_RE = re.compile(r"\b(?:api[_-]?key|token|secret)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

def luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def redact_snippet(snippet: str, visible_chars: int = 4) -> str:
    inner = max(len(snippet) - visible_chars * 2, 0)
    if inner > 0:
        return snippet[:visible_chars] + "*" * inner + snippet[-visible_chars:]
    return "*" * len(snippet)

def scan_pii(text: str) -> list[PiiFinding]:
    findings = []
    seen = set()
    
    for match in CREDIT_CARD_RE.finditer(text):
        snippet = match.group(0)
        if snippet in seen:
            continue
        clean = snippet.replace(" ", "").replace("-", "")
        if luhn_check(clean):
            seen.add(snippet)
            findings.append(PiiFinding(
                type="credit_card",
                position=match.start(),
                snippet=snippet,
                redacted=redact_snippet(clean)
            ))
            
    for match in SSN_RE.finditer(text):
        snippet = match.group(0)
        if snippet in seen:
            continue
        seen.add(snippet)
        findings.append(PiiFinding(
            type="ssn",
            position=match.start(),
            snippet=snippet,
            redacted="***-**-" + snippet[-4:] if len(snippet) >= 4 else "****"
        ))
        
    for match in API_KEY_RE.finditer(text):
        snippet = match.group(1) or match.group(0)
        if snippet in seen:
            continue
        seen.add(snippet)
        findings.append(PiiFinding(
            type="api_key",
            position=match.start(),
            snippet=match.group(0),
            redacted=redact_snippet(snippet, visible_chars=6)
        ))
        
    for match in EMAIL_RE.finditer(text):
        snippet = match.group(0)
        if snippet in seen:
            continue
        seen.add(snippet)
        findings.append(PiiFinding(
            type="email",
            position=match.start(),
            snippet=snippet,
            redacted=snippet.split("@")[0][:2] + "***@" + snippet.split("@")[1] if "@" in snippet else snippet
        ))
        
    for match in PHONE_RE.finditer(text):
        snippet = match.group(0)
        if snippet in seen:
            continue
        seen.add(snippet)
        findings.append(PiiFinding(
            type="phone",
            position=match.start(),
            snippet=snippet,
            redacted="(###) ###-" + snippet[-4:] if len(snippet) >= 4 else "####"
        ))
        
    return findings

def sanitize_text(text: str, findings: list[PiiFinding]) -> str:
    sanitized = text
    for finding in sorted(findings, key=lambda x: x.position, reverse=True):
        sanitized = sanitized[:finding.position] + f"[REDACTED:{finding.type}]" + sanitized[finding.position + len(finding.snippet):]
    return sanitized
