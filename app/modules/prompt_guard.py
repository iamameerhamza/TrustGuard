import re
from typing import Any

INJECTION_PATTERNS = [
    (r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions?", "ignore_instructions"),
    (r"forget\s+(?:everything\s+)?(?:you\s+)?(?:were\s+)?told", "forget_context"),
    (r"you\s+are\s+now\s+(?:a\s+)?\w+", "role_override"),
    (r"disregard\s+(?:the\s+)?(?:above|previous)", "disregard"),
    (r"system\s*:\s*new\s+instruction", "system_override"),
    (r"<\|im_start\|>", "chatml_injection"),
    (r"user\s*:\s*.*assistant\s*:\s*", "chatlog_injection"),
    (r"DAN\s*\(Do\s+Anything\s+Now\)", "dan_mode"),
    (r"jailbreak", "jailbreak_keyword"),
    (r"\"\"\"\s*System\s*:", "quoted_system"),
]

def detect_prompt_injection(text: str) -> dict[str, Any]:
    text_lower = text.lower()
    matches = []
    
    for pattern, label in INJECTION_PATTERNS:
        for match in re.finditer(pattern, text_lower, re.IGNORECASE):
            matches.append({
                "pattern": label,
                "matched_text": text[match.start():match.end()],
                "position": match.start()
            })
            
    confidence = min(len(matches) * 0.15, 1.0)
    if any(m["pattern"] in ("system_override", "chatml_injection", "quoted_system") for m in matches):
        confidence = max(confidence, 0.9)
        
    return {
        "detected": len(matches) > 0,
        "confidence": round(confidence, 4),
        "matches": matches
    }
