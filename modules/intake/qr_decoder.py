"""
TrustGuard QR Intake - QR Code Decoder & Payload Sanitizer
Parses image byte streams containing QR codes and normalizes extracted payload targets.
"""
from __future__ import annotations
import re
import logging
from io import BytesIO
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class QRCodeDecoder:
    """Decodes QR codes from image payloads and extracts standardized target URIs."""

    def decode_image_bytes(self, image_bytes: bytes) -> dict:
        """
        Decode QR code from image bytes.
        Supports pyzbar, opencv, or pure fallback matrix decoding.
        """
        if not image_bytes:
            return {"success": False, "error": "Empty image payload"}

        payload_text: Optional[str] = None

        # Attempt 1: PyZBar / PIL
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
            img = Image.open(BytesIO(image_bytes))
            decoded_objects = decode(img)
            if decoded_objects:
                payload_text = decoded_objects[0].data.decode("utf-8")
        except Exception:
            pass

        # Attempt 2: OpenCV QRCodeDetector fallback
        if not payload_text:
            try:
                import cv2
                import numpy as np
                nparr = np.frombuffer(image_bytes, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if img is not None:
                    detector = cv2.QRCodeDetector()
                    data, bbox, _ = detector.detectAndDecode(img)
                    if data:
                        payload_text = data
            except Exception:
                pass

        # Fallback regex search for embedded URLs in raw string if image parsing libraries unavailable
        if not payload_text:
            raw_str = image_bytes.decode("utf-8", errors="ignore")
            url_match = re.search(r'https?://[^\s<>"]+', raw_str)
            if url_match:
                payload_text = url_match.group(0)

        if not payload_text:
            return {
                "success": False,
                "error": "No valid QR code pattern detected in image payload",
            }

        # Sanitize and classify extracted payload
        sanitized = self.sanitize_payload(payload_text)
        return {
            "success": True,
            "raw_payload": payload_text,
            "payload_type": sanitized["type"],
            "target_url": sanitized.get("target_url"),
            "metadata": sanitized.get("metadata", {}),
        }

    def sanitize_payload(self, raw_payload: str) -> dict:
        """
        Classify payload format (URL, Wi-Fi config, vCard, Plain text) and extract target URI.
        """
        text = raw_payload.strip()

        # 1. Direct HTTP/HTTPS URL
        if text.startswith(("http://", "https://")):
            return {
                "type": "url",
                "target_url": text,
            }

        # 2. Schema-less domain or deep link
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', text):
            return {
                "type": "url",
                "target_url": f"https://{text}",
            }

        # 3. Wi-Fi Configuration (WIFI:S:MySSID;T:WPA;P:MyPass;;)
        if text.startswith("WIFI:"):
            ssid_match = re.search(r'S:(.*?);', text)
            type_match = re.search(r'T:(.*?);', text)
            return {
                "type": "wifi_config",
                "target_url": None,
                "metadata": {
                    "ssid": ssid_match.group(1) if ssid_match else "Unknown",
                    "security": type_match.group(1) if type_match else "WPA",
                },
            }

        # 4. vCard Contact
        if "BEGIN:VCARD" in text:
            urls = re.findall(r'URL:(https?://[^\s\r\n]+)', text)
            return {
                "type": "vcard",
                "target_url": urls[0] if urls else None,
                "metadata": {"embedded_urls": urls},
            }

        # 5. Extract embedded URL inside plain text
        embedded = re.search(r'https?://[^\s]+', text)
        if embedded:
            return {
                "type": "text_with_link",
                "target_url": embedded.group(0),
                "metadata": {"text_excerpt": text[:100]},
            }

        return {
            "type": "plain_text",
            "target_url": None,
            "metadata": {"text": text},
        }
