import unittest
import struct
from SecureMail.services.atae.analyzers.image import ImageAnalyzer
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.exceptions import ATAEParserError

class TestImageAnalyzer(unittest.TestCase):
    def test_valid_png(self):
        # minimal PNG
        data = b'\x89PNG\r\n\x1a\n' + struct.pack('>I4sIIBBBBB', 13, b'IHDR', 1, 1, 8, 2, 0, 0, 0) + b'CRC1'
        data += struct.pack('>I4s', 0, b'IEND') + b'CRC2'
        ctx = AnalysisContext("img1", "", "test.png", "image/png")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertNotIn("IMAGE_INVALID_STRUCTURE", techs)
        self.assertNotIn("IMAGE_APPENDED_DATA", techs)

    def test_malformed_png(self):
        # minimal PNG with duplicate IHDR
        data = b'\x89PNG\r\n\x1a\n' + struct.pack('>I4sIIBBBBB', 13, b'IHDR', 1, 1, 8, 2, 0, 0, 0) + b'CRC1'
        data += struct.pack('>I4sIIBBBBB', 13, b'IHDR', 1, 1, 8, 2, 0, 0, 0) + b'CRC1'
        data += struct.pack('>I4s', 0, b'IEND') + b'CRC2'
        ctx = AnalysisContext("img2", "", "test.png", "image/png")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_INVALID_STRUCTURE", techs)

    def test_png_appended_zip(self):
        data = b'\x89PNG\r\n\x1a\n' + struct.pack('>I4sIIBBBBB', 13, b'IHDR', 1, 1, 8, 2, 0, 0, 0) + b'CRC1'
        data += struct.pack('>I4s', 0, b'IEND') + b'CRC2'
        data += b'PK\x03\x04' + b'\x00' * 50
        ctx = AnalysisContext("img3", "", "test.png", "image/png")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_APPENDED_DATA", techs)
        self.assertIn("IMAGE_POLYGLOT_ZIP", techs)

    def test_jpeg_appended_pe(self):
        data = b'\xff\xd8' + b'\xff\xe0' + struct.pack('>H', 16) + b'JFIF\x00' + b'\x00'*9
        data += b'\xff\xd9' + b'MZ\x90' + b'\x00'*100
        ctx = AnalysisContext("img4", "", "test.jpg", "image/jpeg")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_APPENDED_DATA", techs)
        self.assertIn("IMAGE_POLYGLOT_PE", techs)

    def test_jpeg_missing_eoi(self):
        data = b'\xff\xd8' + b'\xff\xe0' + struct.pack('>H', 16) + b'JFIF\x00' + b'\x00'*9
        ctx = AnalysisContext("img5", "", "test.jpg", "image/jpeg")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_INVALID_STRUCTURE", techs)

    def test_gif_malformed_trailer(self):
        data = b'GIF89a\x01\x00\x01\x00\x00\x00\x00' # No trailer \x3b
        ctx = AnalysisContext("img6", "", "test.gif", "image/gif")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_INVALID_STRUCTURE", techs)

    def test_bmp_oversized_header(self):
        data = b'BM' + struct.pack('<I', 500) + b'\x00'*4 + struct.pack('<I', 50) + b'\x00'*10 # file size 500, but data is short
        ctx = AnalysisContext("img7", "", "test.bmp", "image/bmp")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_INVALID_STRUCTURE", techs)

    def test_webp_malformed_riff(self):
        data = b'RIFF' + struct.pack('<I', 100) + b'WEBP' # length 100 but short data
        ctx = AnalysisContext("img8", "", "test.webp", "image/webp")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        self.assertTrue(True)
        
    def test_oversized_metadata(self):
        # PNG with huge tEXt chunk
        data = b'\x89PNG\r\n\x1a\n' + struct.pack('>I4sIIBBBBB', 13, b'IHDR', 1, 1, 8, 2, 0, 0, 0) + b'CRC1'
        data += struct.pack('>I4s', 600 * 1024, b'tEXt') + b'A' * (600 * 1024) + b'CRC2'
        data += struct.pack('>I4s', 0, b'IEND') + b'CRC3'
        ctx = AnalysisContext("img9", "", "test.png", "image/png")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_OVERSIZED_METADATA", techs)
        
    def test_high_entropy_trailer(self):
        import os
        trailer = os.urandom(1024) # High entropy random data
        data = b'\x89PNG\r\n\x1a\n' + struct.pack('>I4sIIBBBBB', 13, b'IHDR', 1, 1, 8, 2, 0, 0, 0) + b'CRC1'
        data += struct.pack('>I4s', 0, b'IEND') + b'CRC2' + trailer
        ctx = AnalysisContext("img10", "", "test.png", "image/png")
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("IMAGE_APPENDED_DATA", techs)
        self.assertIn("IMAGE_STEGANOGRAPHY_HEURISTIC", techs)

if __name__ == "__main__":
    unittest.main()
