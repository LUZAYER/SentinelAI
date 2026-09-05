"""
Document Forgery Detector

Analyzes documents (PDFs, images of documents, scanned documents) for
manipulation indicators using:
- OCR (pytesseract) for text extraction
- Error Level Analysis (ELA) for manipulation detection
- Metadata extraction and anomaly detection
- Font consistency analysis
- Layout analysis (line spacing, alignment)
- Compression inconsistency detection
- Copy-paste artifact detection
- Text pattern analysis

IMPORTANT: This detector identifies possible evidence of manipulation.
It does NOT claim legal authenticity or definitively determine whether
an official document is genuine.

Reports clearly distinguish "detected evidence of possible manipulation"
from "this document is officially forged."
"""

import logging
import os
import re
from io import BytesIO

import cv2
import numpy as np
from PIL import Image, ImageChops

from backend.app.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DocumentDetector(BaseDetector):
    """Document forgery and manipulation detection."""

    def supported_input_types(self) -> list[str]:
        return ["image", "document"]

    def analyze(self, file_path: str | None = None, **kwargs) -> dict:
        """Analyze a document for manipulation indicators."""
        if not file_path or not os.path.exists(file_path):
            return self._empty_result("document", ["No file provided or file not found"])

        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext in (".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"):
                return self._analyze_document_image(file_path)
            elif ext == ".pdf":
                return self._analyze_pdf(file_path)
            else:
                return self._empty_result("document", [f"Unsupported document format: {ext}"])
        except Exception as e:
            logger.error(f"Document analysis failed: {e}", exc_info=True)
            return self._empty_result("document", [f"Analysis error: {str(e)}"])

    def _analyze_document_image(self, file_path: str) -> dict:
        """Analyze a document image for forgery indicators."""
        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = []
        risk_factors = []

        try:
            img = Image.open(file_path)
            img_cv = cv2.imread(file_path)
        except Exception as e:
            return self._empty_result("document", [f"Failed to load image: {str(e)}"])

        # --- 1. OCR Text Extraction ---
        ocr_result = self._extract_text_ocr(file_path)
        technical_details["ocr"] = ocr_result
        evidence["extracted_text_length"] = len(ocr_result.get("text", ""))
        if ocr_result.get("text"):
            evidence["text_preview"] = ocr_result["text"][:500]

        # --- 2. ELA Analysis ---
        ela_result = self._ela_analysis(img, file_path)
        technical_details["ela"] = ela_result["stats"]
        if ela_result["suspicious"]:
            indicators["ela_manipulation"] = ela_result["details"]
            risk_factors.append(("ela", ela_result["risk_contribution"]))

        # --- 3. Metadata Analysis ---
        metadata = self._extract_metadata(img, file_path)
        technical_details["metadata"] = metadata["data"]
        if metadata["anomalies"]:
            indicators["metadata_anomalies"] = metadata["anomalies"]
            risk_factors.append(("metadata", len(metadata["anomalies"]) * 5))

        # --- 4. Layout Analysis ---
        layout_result = self._analyze_layout(img_cv)
        technical_details["layout"] = layout_result
        if layout_result.get("anomalies"):
            indicators["layout_anomalies"] = layout_result["anomalies"]
            risk_factors.append(("layout", layout_result.get("risk_contribution", 10)))

        # --- 5. Font Consistency ---
        font_result = self._analyze_font_consistency(img_cv)
        technical_details["font_analysis"] = font_result
        if font_result.get("inconsistencies"):
            indicators["font_inconsistencies"] = font_result["inconsistencies"]
            risk_factors.append(("font", font_result.get("risk_contribution", 10)))

        # --- 6. Copy-Paste Detection ---
        cp_result = self._detect_copy_paste(img_cv)
        technical_details["copy_paste"] = cp_result
        if cp_result.get("suspicious"):
            indicators["copy_paste_artifacts"] = cp_result["details"]
            risk_factors.append(("copy_paste", cp_result.get("risk_contribution", 15)))

        # --- 7. Text Pattern Analysis ---
        if ocr_result.get("text"):
            text_result = self._analyze_text_patterns(ocr_result["text"])
            technical_details["text_analysis"] = text_result
            if text_result.get("anomalies"):
                indicators["text_anomalies"] = text_result["anomalies"]
                risk_factors.append(("text_patterns", text_result.get("risk_contribution", 5)))

        # Calculate risk
        total_risk = sum(r[1] for r in risk_factors)
        risk_score = min(100, total_risk)
        confidence = min(0.8, 0.25 + len(risk_factors) * 0.1)

        if risk_score < 20:
            status = "clean"
        elif risk_score < 50:
            status = "suspicious"
        else:
            status = "suspicious" if risk_score < 75 else "malicious"

        evidence["risk_factors"] = [
            {"source": name, "contribution": score} for name, score in risk_factors
        ]

        limitations.append("This analysis identifies possible indicators of manipulation, not definitive proof of forgery")
        limitations.append("OCR accuracy depends on document quality and language")
        limitations.append("Heuristic analysis without a trained document authentication model")

        return {
            "analysis_type": "document",
            "status": status,
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 4),
            "indicators": indicators,
            "evidence": evidence,
            "technical_details": technical_details,
            "limitations": limitations,
        }

    def _extract_text_ocr(self, file_path: str) -> dict:
        """Extract text from document image using OCR."""
        try:
            import pytesseract
            img = Image.open(file_path)

            # Preprocess for better OCR
            img_gray = img.convert("L")
            text = pytesseract.image_to_string(img_gray)

            # Get detailed OCR data
            ocr_data = pytesseract.image_to_data(img_gray, output_type=pytesseract.Output.DICT)

            # Calculate confidence
            confidences = [int(c) for c in ocr_data["conf"] if c != "-1" and int(c) > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0

            return {
                "text": text.strip(),
                "word_count": len(text.split()),
                "average_confidence": round(avg_confidence, 2),
                "total_words_detected": len(confidences),
            }
        except ImportError:
            return {"text": "", "error": "pytesseract not available"}
        except Exception as e:
            return {"text": "", "error": str(e)}

    def _ela_analysis(self, img: Image.Image, file_path: str) -> dict:
        """Error Level Analysis for document manipulation detection."""
        quality = 90
        stats = {}
        suspicious = False
        details = []
        risk_contribution = 0

        try:
            buffer = BytesIO()
            img_rgb = img.convert("RGB")
            img_rgb.save(buffer, "JPEG", quality=quality)
            buffer.seek(0)
            resaved = Image.open(buffer)

            diff = ImageChops.difference(img_rgb, resaved)
            diff_array = np.array(diff, dtype=np.float64)

            mean_diff = float(np.mean(diff_array))
            std_diff = float(np.std(diff_array))

            stats = {
                "mean_error_level": round(mean_diff, 4),
                "std_error_level": round(std_diff, 4),
            }

            # For documents, even moderate ELA variance is suspicious
            if std_diff > 12:
                suspicious = True
                details.append(f"ELA variance ({std_diff:.2f}) suggests possible image editing")
                risk_contribution = 20

            # Check block-level variance
            h, w = diff_array.shape[:2]
            block_size = max(h, w) // 6 or 1
            block_means = []
            for y in range(0, h - block_size, block_size):
                for x in range(0, w - block_size, block_size):
                    block = diff_array[y:y+block_size, x:x+block_size]
                    block_means.append(float(np.mean(block)))

            if block_means:
                block_std = float(np.std(block_means))
                stats["block_variance"] = round(block_std, 4)
                if block_std > 8:
                    suspicious = True
                    details.append("Localized ELA differences suggest region-specific editing")
                    risk_contribution += 15

        except Exception as e:
            stats["error"] = str(e)

        return {
            "stats": stats,
            "suspicious": suspicious,
            "details": details,
            "risk_contribution": risk_contribution,
        }

    def _extract_metadata(self, img: Image.Image, file_path: str) -> dict:
        """Extract image metadata and check for anomalies."""
        from PIL import ExifTags
        data = {}
        anomalies = []

        try:
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    try:
                        data[tag_name] = str(value) if not isinstance(value, bytes) else f"<binary {len(value)}b>"
                    except Exception:
                        pass

                software = data.get("Software", "").lower()
                if any(t in software for t in ["photoshop", "gimp", "paint"]):
                    anomalies.append(f"Image editing software detected: {data.get('Software')}")
            else:
                data["exif_present"] = False
        except Exception:
            data["exif_present"] = False

        data["file_size"] = os.path.getsize(file_path)
        data["dimensions"] = f"{img.width}x{img.height}"
        data["format"] = img.format

        return {"data": data, "anomalies": anomalies}

    def _analyze_layout(self, img_cv: np.ndarray) -> dict:
        """Analyze document layout for alignment and spacing anomalies."""
        result = {"anomalies": [], "risk_contribution": 0}

        if img_cv is None:
            return result

        try:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

            # Edge detection to find text lines
            edges = cv2.Canny(gray, 50, 150)

            # Detect lines using Hough transform
            lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=100,
                                     minLineLength=50, maxLineGap=10)

            if lines is not None:
                angles = []
                for line in lines:
                    x1, y1, x2, y2 = line[0]
                    angle = np.degrees(np.arctan2(y2 - y1, x2 - x1))
                    angles.append(angle)

                result["detected_lines"] = len(lines)

                # Check for non-horizontal/non-vertical lines (misalignment)
                near_horizontal = [a for a in angles if abs(a) < 5 or abs(abs(a) - 180) < 5]
                near_vertical = [a for a in angles if abs(abs(a) - 90) < 5]
                skewed = len(angles) - len(near_horizontal) - len(near_vertical)

                result["aligned_lines"] = len(near_horizontal) + len(near_vertical)
                result["skewed_lines"] = skewed

                if skewed > len(angles) * 0.3 and len(angles) > 5:
                    result["anomalies"].append(
                        f"Significant line misalignment detected ({skewed}/{len(angles)} lines skewed)"
                    )
                    result["risk_contribution"] = 10
            else:
                result["detected_lines"] = 0

        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_font_consistency(self, img_cv: np.ndarray) -> dict:
        """Analyze font consistency across the document."""
        result = {"inconsistencies": [], "risk_contribution": 0}

        if img_cv is None:
            return result

        try:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

            # Divide into horizontal strips and compare character density
            h, w = gray.shape
            strip_height = h // 10 or 1
            strip_densities = []

            for y in range(0, h - strip_height, strip_height):
                strip = gray[y:y+strip_height, :]
                _, binary = cv2.threshold(strip, 128, 255, cv2.THRESH_BINARY_INV)
                density = float(np.sum(binary > 0)) / (strip.shape[0] * strip.shape[1])
                strip_densities.append(density)

            if strip_densities:
                # Check for sudden changes in text density (possible inserted text)
                density_diffs = [abs(strip_densities[i+1] - strip_densities[i])
                                for i in range(len(strip_densities) - 1)]
                if density_diffs:
                    max_diff = max(density_diffs)
                    result["max_density_change"] = round(max_diff, 4)

                    if max_diff > 0.3:
                        result["inconsistencies"].append(
                            "Abrupt text density change detected — possible text insertion or deletion"
                        )
                        result["risk_contribution"] = 10

        except Exception as e:
            result["error"] = str(e)

        return result

    def _detect_copy_paste(self, img_cv: np.ndarray) -> dict:
        """Detect copy-paste artifacts using feature matching."""
        result = {"suspicious": False, "details": [], "risk_contribution": 0}

        if img_cv is None:
            return result

        try:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

            # Use ORB features (patent-free) for copy-paste detection
            orb = cv2.ORB_create(nfeatures=500)
            keypoints, descriptors = orb.detectAndCompute(gray, None)

            if descriptors is not None and len(descriptors) > 10:
                # Match features against themselves to find duplicates
                bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
                matches = bf.knnMatch(descriptors, descriptors, k=2)

                # Filter self-matches and near-duplicate regions
                suspicious_matches = 0
                for m_pair in matches:
                    if len(m_pair) < 2:
                        continue
                    m, n = m_pair
                    if m.queryIdx != m.trainIdx:
                        # Similar features at different locations
                        pt1 = keypoints[m.queryIdx].pt
                        pt2 = keypoints[m.trainIdx].pt
                        dist = np.sqrt((pt1[0] - pt2[0])**2 + (pt1[1] - pt2[1])**2)

                        # Features that are similar but far apart may indicate copy-paste
                        if m.distance < 30 and dist > 50:
                            suspicious_matches += 1

                result["similar_features_found"] = suspicious_matches

                if suspicious_matches > 10:
                    result["suspicious"] = True
                    result["details"].append(
                        f"Found {suspicious_matches} similar feature pairs at different locations — "
                        "possible copy-paste region"
                    )
                    result["risk_contribution"] = 15

        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_text_patterns(self, text: str) -> dict:
        """Analyze OCR-extracted text for anomalies."""
        result = {"anomalies": [], "risk_contribution": 0}

        if not text:
            return result

        # Check for mixed character encodings
        ascii_count = sum(1 for c in text if ord(c) < 128)
        non_ascii_count = len(text) - ascii_count
        if non_ascii_count > 0 and ascii_count > 0:
            ratio = non_ascii_count / len(text)
            if 0.01 < ratio < 0.1:
                result["anomalies"].append(
                    "Mixed character encoding detected — possible homoglyph substitution"
                )
                result["risk_contribution"] += 5

        # Check for inconsistent number formats
        numbers = re.findall(r'\d+', text)
        if numbers:
            result["numbers_found"] = len(numbers)

        # Check for common forgery indicators in text
        suspicious_patterns = [
            (r'(?i)specimen', "Word 'SPECIMEN' found in document"),
            (r'(?i)sample\s*only', "'Sample only' text found"),
            (r'(?i)not\s*valid', "'Not valid' text found"),
        ]
        for pattern, description in suspicious_patterns:
            if re.search(pattern, text):
                result["anomalies"].append(description)
                result["risk_contribution"] += 3

        return result

    def _analyze_pdf(self, file_path: str) -> dict:
        """Analyze PDF document for manipulation indicators."""
        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = ["PDF analysis is limited to metadata and structure checks"]
        risk_factors = []

        try:
            # Basic PDF metadata extraction
            with open(file_path, "rb") as f:
                content = f.read(4096)

            technical_details["file_size"] = os.path.getsize(file_path)

            # Check PDF header
            if not content.startswith(b"%PDF"):
                indicators["invalid_pdf_header"] = "File does not start with %PDF header"
                risk_factors.append(("invalid_header", 20))

            # Check for JavaScript (potential malicious content)
            full_content = open(file_path, "rb").read()
            if b"/JavaScript" in full_content or b"/JS" in full_content:
                indicators["embedded_javascript"] = "PDF contains embedded JavaScript"
                risk_factors.append(("javascript", 30))

            # Check for embedded files
            if b"/EmbeddedFile" in full_content:
                indicators["embedded_files"] = "PDF contains embedded files"
                risk_factors.append(("embedded_files", 15))

            # Check for form actions
            if b"/SubmitForm" in full_content or b"/URI" in full_content:
                indicators["form_actions"] = "PDF contains form submission or URI actions"
                risk_factors.append(("form_actions", 10))

            # Try to extract text and analyze
            # For image-based PDFs, note the limitation
            evidence["pdf_analyzed"] = True

            total_risk = sum(r[1] for r in risk_factors)
            risk_score = min(100, total_risk)
            confidence = min(0.7, 0.3 + len(risk_factors) * 0.1)
            status = "clean" if risk_score < 20 else "suspicious" if risk_score < 75 else "malicious"

            return {
                "analysis_type": "document",
                "status": status,
                "risk_score": round(risk_score, 2),
                "confidence": round(confidence, 4),
                "indicators": indicators,
                "evidence": evidence,
                "technical_details": technical_details,
                "limitations": limitations,
            }

        except Exception as e:
            logger.error(f"PDF analysis failed: {e}", exc_info=True)
            return self._empty_result("document", [f"PDF analysis error: {str(e)}"])
