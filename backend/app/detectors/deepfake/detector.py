"""
Deepfake Detector

Performs actual image/video/audio analysis for deepfake detection using:
- Error Level Analysis (ELA) for manipulation detection
- EXIF metadata extraction and anomaly detection
- Face detection using OpenCV DNN/Haar cascades
- Frequency domain analysis (DCT) for AI-generation indicators
- Compression artifact analysis
- Video frame extraction and temporal consistency checking
- Audio spectral analysis for synthetic voice indicators

This is a baseline detector using computer vision heuristics and signal
processing. The model interface is designed to be replaceable with a
trained deep learning model (e.g., fine-tuned EfficientNet or XceptionNet).

Limitation: Without a trained classification model, this detector relies
on statistical and forensic heuristics. It provides genuine evidence but
may have lower accuracy than a purpose-trained model.
"""

import logging
import os
import hashlib
import struct
from io import BytesIO

import cv2
import numpy as np
from PIL import Image, ImageChops, ExifTags

from backend.app.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DeepfakeDetector(BaseDetector):
    """Multi-modal deepfake detection using forensic analysis techniques."""

    def supported_input_types(self) -> list[str]:
        return ["image", "video", "audio"]

    def analyze(self, file_path: str | None = None, **kwargs) -> dict:
        """Analyze a file for deepfake indicators."""
        if not file_path or not os.path.exists(file_path):
            return self._empty_result("deepfake", ["No file provided or file not found"])

        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext in (".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp", ".gif"):
                return self._analyze_image(file_path)
            elif ext in (".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv"):
                return self._analyze_video(file_path)
            elif ext in (".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"):
                return self._analyze_audio(file_path)
            else:
                return self._empty_result("deepfake", [f"Unsupported file type: {ext}"])
        except Exception as e:
            logger.error(f"Deepfake analysis failed: {e}", exc_info=True)
            return self._empty_result("deepfake", [f"Analysis error: {str(e)}"])

    def _analyze_image(self, file_path: str) -> dict:
        """Full image deepfake analysis pipeline."""
        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = []
        risk_factors = []

        try:
            img = Image.open(file_path)
            img_cv = cv2.imread(file_path)
        except Exception as e:
            return self._empty_result("deepfake", [f"Failed to load image: {str(e)}"])

        # --- 1. Metadata Analysis ---
        metadata_result = self._extract_metadata(img, file_path)
        technical_details["metadata"] = metadata_result["data"]
        if metadata_result["anomalies"]:
            indicators["metadata_anomalies"] = metadata_result["anomalies"]
            risk_factors.append(("metadata", len(metadata_result["anomalies"]) * 8))

        # --- 2. Error Level Analysis (ELA) ---
        ela_result = self._error_level_analysis(img, file_path)
        technical_details["ela"] = ela_result["stats"]
        evidence["ela_analysis"] = ela_result["summary"]
        if ela_result["suspicious"]:
            indicators["ela_manipulation_indicators"] = ela_result["details"]
            risk_factors.append(("ela", ela_result["risk_contribution"]))

        # --- 3. Face Detection ---
        face_result = self._detect_faces(img_cv)
        technical_details["face_detection"] = face_result
        evidence["faces_detected"] = face_result["count"]
        if face_result["count"] > 0:
            indicators["face_regions"] = face_result["regions"]

        # --- 4. Compression Analysis ---
        compression_result = self._analyze_compression(img, file_path)
        technical_details["compression"] = compression_result
        if compression_result.get("anomalies"):
            indicators["compression_anomalies"] = compression_result["anomalies"]
            risk_factors.append(("compression", compression_result.get("risk_contribution", 5)))

        # --- 5. Frequency Domain Analysis ---
        freq_result = self._frequency_analysis(img_cv)
        technical_details["frequency_analysis"] = freq_result["stats"]
        if freq_result["suspicious"]:
            indicators["frequency_anomalies"] = freq_result["details"]
            risk_factors.append(("frequency", freq_result["risk_contribution"]))

        # --- 6. Statistical Analysis ---
        stats_result = self._statistical_analysis(img_cv)
        technical_details["image_statistics"] = stats_result

        # --- 7. Noise Analysis ---
        noise_result = self._noise_analysis(img_cv)
        technical_details["noise_analysis"] = noise_result["stats"]
        if noise_result["suspicious"]:
            indicators["noise_inconsistencies"] = noise_result["details"]
            risk_factors.append(("noise", noise_result["risk_contribution"]))

        # --- Calculate Risk Score ---
        total_risk = sum(r[1] for r in risk_factors)
        risk_score = min(100, total_risk)
        confidence = min(0.85, 0.3 + len(risk_factors) * 0.1)  # Higher with more evidence

        if risk_score < 20:
            status = "clean"
        elif risk_score < 50:
            status = "suspicious"
        else:
            status = "suspicious" if risk_score < 75 else "malicious"

        evidence["risk_factors"] = [
            {"source": name, "contribution": score} for name, score in risk_factors
        ]

        limitations.append("Heuristic analysis without a trained deepfake classification model")
        limitations.append("ELA effectiveness varies with JPEG quality and re-compression")
        if face_result["count"] == 0:
            limitations.append("No faces detected — face-specific analysis was not performed")

        return {
            "analysis_type": "deepfake",
            "status": status,
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 4),
            "indicators": indicators,
            "evidence": evidence,
            "technical_details": technical_details,
            "limitations": limitations,
        }

    def _extract_metadata(self, img: Image.Image, file_path: str) -> dict:
        """Extract and analyze EXIF metadata for anomalies."""
        data = {}
        anomalies = []

        try:
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    try:
                        if isinstance(value, bytes):
                            data[tag_name] = f"<binary {len(value)} bytes>"
                        else:
                            data[tag_name] = str(value)
                    except Exception:
                        data[tag_name] = "<unreadable>"

                # Check for editing software indicators
                software = data.get("Software", "").lower()
                editing_tools = ["photoshop", "gimp", "lightroom", "affinity", "paint.net",
                                "pixlr", "canva", "snapseed", "facetune", "faceapp"]
                for tool in editing_tools:
                    if tool in software:
                        anomalies.append(f"Editing software detected: {data.get('Software')}")
                        break

                # Check for missing expected metadata
                if not data.get("Make") and not data.get("Model"):
                    anomalies.append("No camera make/model in EXIF — may indicate synthetic origin")

                # Check for date inconsistencies
                date_original = data.get("DateTimeOriginal")
                date_digitized = data.get("DateTimeDigitized")
                date_modified = data.get("DateTime")
                if date_original and date_modified and date_original != date_modified:
                    anomalies.append("Date modified differs from date taken — possible editing")
            else:
                anomalies.append("No EXIF data found — may indicate processing or synthetic origin")
                data["exif_present"] = False
        except Exception as e:
            data["exif_error"] = str(e)

        # File-level metadata
        stat = os.stat(file_path)
        data["file_size_bytes"] = stat.st_size
        data["image_dimensions"] = f"{img.width}x{img.height}"
        data["image_mode"] = img.mode
        data["image_format"] = img.format

        return {"data": data, "anomalies": anomalies}

    def _error_level_analysis(self, img: Image.Image, file_path: str) -> dict:
        """Perform Error Level Analysis (ELA).

        ELA works by re-saving the image at a known quality level and comparing
        the re-saved version to the original. Areas that have been manipulated
        will show different error levels compared to the rest of the image.
        """
        quality = 90
        stats = {}
        summary = ""
        suspicious = False
        details = []
        risk_contribution = 0

        try:
            # Re-save at known quality
            buffer = BytesIO()
            img_rgb = img.convert("RGB")
            img_rgb.save(buffer, "JPEG", quality=quality)
            buffer.seek(0)
            resaved = Image.open(buffer)

            # Compute difference
            diff = ImageChops.difference(img_rgb, resaved)
            diff_array = np.array(diff, dtype=np.float64)

            # Enhance for visibility
            extrema = diff.getextrema()
            max_diff = max(max(ch) for ch in extrema)

            if max_diff > 0:
                scale = 255.0 / max_diff
            else:
                scale = 1

            # Statistics
            mean_diff = np.mean(diff_array)
            std_diff = np.std(diff_array)
            max_val = np.max(diff_array)

            stats = {
                "mean_error_level": round(float(mean_diff), 4),
                "std_error_level": round(float(std_diff), 4),
                "max_error_level": round(float(max_val), 4),
                "quality_used": quality,
            }

            # Analyze for manipulation indicators
            # High std deviation suggests inconsistent compression = possible manipulation
            if std_diff > 15:
                suspicious = True
                details.append(f"High ELA variance (std={std_diff:.2f}) suggests inconsistent compression")
                risk_contribution += 20

            # Check for localized high-error regions (blocks significantly different)
            h, w = diff_array.shape[:2]
            block_size = max(h, w) // 8 or 1
            block_means = []
            for y in range(0, h - block_size, block_size):
                for x in range(0, w - block_size, block_size):
                    block = diff_array[y:y+block_size, x:x+block_size]
                    block_means.append(np.mean(block))

            if block_means:
                block_std = np.std(block_means)
                block_max = np.max(block_means)
                stats["block_variance"] = round(float(block_std), 4)
                stats["max_block_error"] = round(float(block_max), 4)

                if block_std > 10:
                    suspicious = True
                    details.append(f"Localized high-error regions detected (block_std={block_std:.2f})")
                    risk_contribution += 15

            summary = (
                f"ELA analysis complete. Mean error: {mean_diff:.2f}, "
                f"Std: {std_diff:.2f}. "
                + ("Potential manipulation indicators found." if suspicious else "No obvious manipulation detected.")
            )

        except Exception as e:
            stats["error"] = str(e)
            summary = f"ELA analysis failed: {str(e)}"

        return {
            "stats": stats,
            "summary": summary,
            "suspicious": suspicious,
            "details": details,
            "risk_contribution": risk_contribution,
        }

    def _detect_faces(self, img_cv: np.ndarray) -> dict:
        """Detect faces using OpenCV's DNN or Haar cascade."""
        result = {"count": 0, "regions": [], "method": "haar_cascade"}

        if img_cv is None:
            return result

        try:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

            # Use Haar cascade (available everywhere)
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            face_cascade = cv2.CascadeClassifier(cascade_path)

            faces = face_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
            )

            result["count"] = len(faces)
            for i, (x, y, w, h) in enumerate(faces):
                result["regions"].append({
                    "face_id": i + 1,
                    "x": int(x), "y": int(y),
                    "width": int(w), "height": int(h),
                    "area_ratio": round(float(w * h) / (img_cv.shape[0] * img_cv.shape[1]), 4),
                })

        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_compression(self, img: Image.Image, file_path: str) -> dict:
        """Analyze JPEG compression artifacts and quality."""
        result = {"format": img.format, "anomalies": [], "risk_contribution": 0}

        try:
            if img.format == "JPEG":
                # Estimate JPEG quality
                file_size = os.path.getsize(file_path)
                pixel_count = img.width * img.height
                bpp = (file_size * 8) / pixel_count if pixel_count > 0 else 0
                result["bits_per_pixel"] = round(bpp, 4)
                result["estimated_quality"] = "high" if bpp > 3 else "medium" if bpp > 1 else "low"

                # Very low quality can indicate re-compression
                if bpp < 0.5:
                    result["anomalies"].append("Very low bits-per-pixel suggests heavy re-compression")
                    result["risk_contribution"] = 10

                # Check for double JPEG compression artifacts
                # (Simplified: check if quantization tables suggest re-compression)
                with open(file_path, "rb") as f:
                    data = f.read(4096)
                    dqt_count = data.count(b"\xff\xdb")
                    result["quantization_tables_found"] = dqt_count
                    if dqt_count > 2:
                        result["anomalies"].append(
                            f"Multiple quantization tables ({dqt_count}) may indicate re-compression"
                        )
                        result["risk_contribution"] += 8

            elif img.format == "PNG":
                result["lossless"] = True
                # PNG images converted from JPEG may retain artifacts
                file_size = os.path.getsize(file_path)
                pixel_count = img.width * img.height
                bpp = (file_size * 8) / pixel_count if pixel_count > 0 else 0
                result["bits_per_pixel"] = round(bpp, 4)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _frequency_analysis(self, img_cv: np.ndarray) -> dict:
        """Frequency domain analysis using DCT/FFT.

        AI-generated images often show distinct patterns in the frequency domain
        (e.g., unusual spectral peaks or missing high-frequency detail).
        """
        stats = {}
        suspicious = False
        details = []
        risk_contribution = 0

        if img_cv is None:
            return {"stats": stats, "suspicious": False, "details": [], "risk_contribution": 0}

        try:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY).astype(np.float32)

            # FFT analysis
            f_transform = np.fft.fft2(gray)
            f_shift = np.fft.fftshift(f_transform)
            magnitude = np.log1p(np.abs(f_shift))

            stats["fft_mean_magnitude"] = round(float(np.mean(magnitude)), 4)
            stats["fft_std_magnitude"] = round(float(np.std(magnitude)), 4)
            stats["fft_max_magnitude"] = round(float(np.max(magnitude)), 4)

            # Check for unusual spectral patterns
            # AI-generated images often have less high-frequency content
            h, w = magnitude.shape
            center_h, center_w = h // 2, w // 2

            # Low-frequency energy (center 25%)
            low_freq = magnitude[
                center_h - h//8:center_h + h//8,
                center_w - w//8:center_w + w//8
            ]
            # High-frequency energy (outer 25%)
            high_freq_mask = np.ones_like(magnitude, dtype=bool)
            high_freq_mask[
                center_h - h//4:center_h + h//4,
                center_w - w//4:center_w + w//4
            ] = False
            high_freq = magnitude[high_freq_mask]

            low_energy = float(np.mean(low_freq))
            high_energy = float(np.mean(high_freq))
            ratio = low_energy / high_energy if high_energy > 0 else 0

            stats["low_freq_energy"] = round(low_energy, 4)
            stats["high_freq_energy"] = round(high_energy, 4)
            stats["low_high_ratio"] = round(ratio, 4)

            # Unusually high ratio can indicate AI-generated or heavily processed images
            if ratio > 4.0:
                suspicious = True
                details.append(
                    f"Unusual frequency distribution (low/high ratio={ratio:.2f}): "
                    "may indicate AI generation or heavy processing"
                )
                risk_contribution = 15

        except Exception as e:
            stats["error"] = str(e)

        return {
            "stats": stats,
            "suspicious": suspicious,
            "details": details,
            "risk_contribution": risk_contribution,
        }

    def _statistical_analysis(self, img_cv: np.ndarray) -> dict:
        """Basic statistical analysis of image pixel values."""
        stats = {}

        if img_cv is None:
            return stats

        try:
            for i, channel in enumerate(["blue", "green", "red"]):
                ch = img_cv[:, :, i].astype(np.float64)
                stats[f"{channel}_mean"] = round(float(np.mean(ch)), 4)
                stats[f"{channel}_std"] = round(float(np.std(ch)), 4)
                stats[f"{channel}_skew"] = round(float(
                    np.mean(((ch - np.mean(ch)) / (np.std(ch) + 1e-7)) ** 3)
                ), 4)

            stats["overall_mean"] = round(float(np.mean(img_cv)), 4)
            stats["overall_std"] = round(float(np.std(img_cv)), 4)
            stats["dimensions"] = f"{img_cv.shape[1]}x{img_cv.shape[0]}"
            stats["channels"] = img_cv.shape[2] if len(img_cv.shape) > 2 else 1

        except Exception as e:
            stats["error"] = str(e)

        return stats

    def _noise_analysis(self, img_cv: np.ndarray) -> dict:
        """Analyze noise patterns for inconsistencies.

        Different regions of a manipulated image may have different noise levels
        if parts were spliced from different sources.
        """
        stats = {}
        suspicious = False
        details = []
        risk_contribution = 0

        if img_cv is None:
            return {"stats": stats, "suspicious": False, "details": [], "risk_contribution": 0}

        try:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY).astype(np.float64)

            # Estimate noise using Laplacian
            laplacian = cv2.Laplacian(gray, cv2.CV_64F)
            noise_level = float(laplacian.var())
            stats["laplacian_variance"] = round(noise_level, 4)

            # Divide into blocks and check noise consistency
            h, w = gray.shape
            block_size = max(h, w) // 4 or 1
            block_noises = []

            for y in range(0, h - block_size, block_size):
                for x in range(0, w - block_size, block_size):
                    block = gray[y:y+block_size, x:x+block_size]
                    block_lap = cv2.Laplacian(block, cv2.CV_64F)
                    block_noises.append(float(block_lap.var()))

            if block_noises:
                noise_std = float(np.std(block_noises))
                noise_mean = float(np.mean(block_noises))
                stats["block_noise_mean"] = round(noise_mean, 4)
                stats["block_noise_std"] = round(noise_std, 4)

                # High variation in block noise levels suggests splicing
                cv = noise_std / noise_mean if noise_mean > 0 else 0
                stats["noise_coefficient_of_variation"] = round(cv, 4)

                if cv > 1.5:
                    suspicious = True
                    details.append(
                        f"Inconsistent noise levels across image regions (CV={cv:.2f}): "
                        "may indicate splicing or compositing"
                    )
                    risk_contribution = 15

        except Exception as e:
            stats["error"] = str(e)

        return {
            "stats": stats,
            "suspicious": suspicious,
            "details": details,
            "risk_contribution": risk_contribution,
        }

    def _analyze_video(self, file_path: str) -> dict:
        """Analyze video for deepfake indicators by extracting and analyzing frames."""
        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = ["Video analysis uses sampled frames, not every frame"]
        risk_factors = []

        try:
            cap = cv2.VideoCapture(file_path)
            if not cap.isOpened():
                return self._empty_result("deepfake", ["Failed to open video file"])

            # Video metadata
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            duration = frame_count / fps if fps > 0 else 0

            technical_details["video_info"] = {
                "fps": round(fps, 2),
                "total_frames": frame_count,
                "resolution": f"{width}x{height}",
                "duration_seconds": round(duration, 2),
            }

            # Sample frames for analysis (max 10 frames evenly distributed)
            max_samples = min(10, frame_count)
            sample_indices = np.linspace(0, frame_count - 1, max_samples, dtype=int)

            frame_results = []
            face_counts = []
            noise_levels = []

            for idx in sample_indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
                ret, frame = cap.read()
                if not ret:
                    continue

                # Face detection on each frame
                face_result = self._detect_faces(frame)
                face_counts.append(face_result["count"])

                # Noise analysis on each frame
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float64)
                laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
                noise_levels.append(laplacian_var)

                frame_results.append({
                    "frame_index": int(idx),
                    "faces_detected": face_result["count"],
                    "noise_level": round(laplacian_var, 4),
                })

            cap.release()

            technical_details["frame_analysis"] = frame_results
            evidence["frames_analyzed"] = len(frame_results)

            # Temporal consistency checks
            if len(face_counts) > 1:
                face_consistency = np.std(face_counts)
                technical_details["face_consistency_std"] = round(float(face_consistency), 4)
                if face_consistency > 0.5:
                    indicators["temporal_face_inconsistency"] = (
                        "Face count varies significantly across frames"
                    )
                    risk_factors.append(("temporal_faces", 20))

            if len(noise_levels) > 1:
                noise_cv = float(np.std(noise_levels)) / (float(np.mean(noise_levels)) + 1e-7)
                technical_details["noise_temporal_cv"] = round(noise_cv, 4)
                if noise_cv > 1.0:
                    indicators["temporal_noise_inconsistency"] = (
                        "Noise levels vary significantly across frames"
                    )
                    risk_factors.append(("temporal_noise", 15))

            # Calculate risk
            total_risk = sum(r[1] for r in risk_factors)
            risk_score = min(100, total_risk)
            confidence = min(0.75, 0.25 + len(risk_factors) * 0.1)

            status = "clean" if risk_score < 20 else "suspicious" if risk_score < 75 else "malicious"

            limitations.append("Baseline heuristic analysis without a trained video deepfake model")

            return {
                "analysis_type": "deepfake",
                "status": status,
                "risk_score": round(risk_score, 2),
                "confidence": round(confidence, 4),
                "indicators": indicators,
                "evidence": evidence,
                "technical_details": technical_details,
                "limitations": limitations,
            }

        except Exception as e:
            logger.error(f"Video analysis failed: {e}", exc_info=True)
            return self._empty_result("deepfake", [f"Video analysis error: {str(e)}"])

    def _analyze_audio(self, file_path: str) -> dict:
        """Analyze audio for synthetic/AI-generated voice indicators."""
        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = ["Audio deepfake detection relies on spectral heuristics"]
        risk_factors = []

        try:
            import librosa

            y, sr = librosa.load(file_path, sr=None, duration=60)  # Load up to 60s

            technical_details["audio_info"] = {
                "sample_rate": int(sr),
                "duration_seconds": round(float(len(y) / sr), 2),
                "samples": len(y),
            }

            # Spectral features
            spectral_centroid = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
            spectral_rolloff = librosa.feature.spectral_rolloff(y=y, sr=sr)[0]
            zero_crossing_rate = librosa.feature.zero_crossing_rate(y)[0]
            mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)

            technical_details["spectral_features"] = {
                "centroid_mean": round(float(np.mean(spectral_centroid)), 2),
                "centroid_std": round(float(np.std(spectral_centroid)), 2),
                "rolloff_mean": round(float(np.mean(spectral_rolloff)), 2),
                "zcr_mean": round(float(np.mean(zero_crossing_rate)), 6),
                "mfcc_means": [round(float(m), 4) for m in np.mean(mfccs, axis=1)],
            }

            # Check for unusual spectral patterns
            centroid_cv = float(np.std(spectral_centroid)) / (float(np.mean(spectral_centroid)) + 1e-7)
            if centroid_cv < 0.1:
                indicators["unusually_stable_spectrum"] = (
                    "Spectral centroid is unusually stable — may indicate synthetic audio"
                )
                risk_factors.append(("spectral_stability", 20))

            evidence["spectral_analysis"] = "completed"
            limitations.append("No trained audio deepfake classifier available — using spectral heuristics")

            total_risk = sum(r[1] for r in risk_factors)
            risk_score = min(100, total_risk)
            confidence = min(0.6, 0.2 + len(risk_factors) * 0.1)
            status = "clean" if risk_score < 20 else "suspicious"

            return {
                "analysis_type": "deepfake",
                "status": status,
                "risk_score": round(risk_score, 2),
                "confidence": round(confidence, 4),
                "indicators": indicators,
                "evidence": evidence,
                "technical_details": technical_details,
                "limitations": limitations,
            }

        except ImportError:
            return self._empty_result("deepfake", ["librosa not available for audio analysis"])
        except Exception as e:
            logger.error(f"Audio analysis failed: {e}", exc_info=True)
            return self._empty_result("deepfake", [f"Audio analysis error: {str(e)}"])
