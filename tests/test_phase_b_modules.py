"""
Standalone unit tests for Phase B Micro-Modules (MM-2.1, MM-2.2, MM-2.3, MM-2.4)
"""
import unittest
from modules.extractors.visual.brand_matcher import PerceptualHashMatcher
from modules.intake.qr_decoder import QRCodeDecoder
from modules.extractors.documents.pdf_parser import PDFDocumentParser
from modules.extractors.documents.doc_inspector import DocumentSecurityInspector
from modules.extractors.media.audio_cues import AudioVishingCueExtractor


class TestPhaseBModules(unittest.TestCase):
    def test_phash_brand_matcher(self):
        matcher = PerceptualHashMatcher()
        # Compute phash for dummy image bytes
        phash = matcher.compute_phash_from_bytes(b"dummy_image_content_12345")
        self.assertEqual(len(phash), 16)

        # Test Hamming distance
        dist = matcher.hamming_distance("a1f0c2e3f8901234", "a1f0c2e3f8901234")
        self.assertEqual(dist, 0)

        dist_diff = matcher.hamming_distance("ffffffffffffffff", "0000000000000000")
        self.assertEqual(dist_diff, 64)

    def test_qr_decoder_payload_sanitizer(self):
        decoder = QRCodeDecoder()

        res1 = decoder.sanitize_payload("https://phishing-site.xyz/login")
        self.assertEqual(res1["type"], "url")
        self.assertEqual(res1["target_url"], "https://phishing-site.xyz/login")

        res2 = decoder.sanitize_payload("WIFI:S:HomeNet;T:WPA;P:secret123;;")
        self.assertEqual(res2["type"], "wifi_config")
        self.assertEqual(res2["metadata"]["ssid"], "HomeNet")

        res3 = decoder.sanitize_payload("Please verify your account at https://bank-update.com immediately")
        self.assertEqual(res3["type"], "text_with_link")
        self.assertEqual(res3["target_url"], "https://bank-update.com")

    def test_pdf_parser(self):
        parser = PDFDocumentParser()
        sample_pdf_bytes = b"%PDF-1.4 /URI (https://malicious-target.com/phish) /JavaScript (app.alert('xss'));"
        res = parser.parse_pdf_bytes(sample_pdf_bytes)

        self.assertTrue(res["has_javascript"])
        self.assertIn("https://malicious-target.com/phish", res["links"])

    def test_doc_inspector(self):
        inspector = DocumentSecurityInspector()
        sample_pdf_bytes = b"%PDF-1.4 /URI (https://malicious-target.com/phish) /JavaScript (app.alert('xss'));"
        res = inspector.inspect_document(sample_pdf_bytes, "test.pdf")

        self.assertEqual(res["format"], "PDF")
        self.assertTrue(res["has_javascript"])
        self.assertGreaterEqual(res["document_risk_score"], 45.0)

    def test_audio_vishing_cue_extractor(self):
        extractor = AudioVishingCueExtractor()
        transcript = "This is the bank security team. Your account has been suspended. Please provide your 2FA OTP code and transfer funds via wire transfer immediately."
        res = extractor.analyze_audio_transcript(transcript)

        self.assertGreaterEqual(res["vishing_risk_score"], 65.0)
        self.assertEqual(res["verdict"], "vishing_phishing")
        self.assertIn("bank", res["urgency_keywords_found"])


if __name__ == "__main__":
    unittest.main()
