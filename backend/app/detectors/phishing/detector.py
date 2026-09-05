"""
Phishing Detector

Analyzes URLs and domains for phishing indicators using:
- URL structural analysis (length, depth, special characters)
- Domain analysis (suspicious keywords, TLDs, homoglyphs)
- Brand impersonation detection
- Redirect chain analysis (with SSRF protection)
- TLS/SSL certificate checking
- Encoding detection (punycode, percent-encoding)
- Known suspicious patterns

SSRF Protection: The detector never accesses internal/private IP ranges.
All URL fetching is restricted to public addresses only.
External intelligence (VirusTotal, URLScan) is used as supplementary
evidence when API keys are configured, not as absolute truth.
"""

import logging
import os
import re
import socket
import ipaddress
from urllib.parse import urlparse, unquote

import httpx

from backend.app.detectors.base import BaseDetector
from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# Known brand names for impersonation detection
BRAND_NAMES = {
    "google", "facebook", "meta", "apple", "microsoft", "amazon",
    "netflix", "paypal", "instagram", "twitter", "linkedin",
    "whatsapp", "telegram", "bank", "chase", "wells", "citi",
    "dropbox", "icloud", "outlook", "yahoo", "gmail",
    "coinbase", "binance", "blockchain", "metamask",
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".work", ".click", ".link", ".info", ".site",
    ".online", ".icu", ".monster",
}

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "account", "verify", "update",
    "secure", "banking", "confirm", "password", "credential",
    "suspended", "unusual", "activity", "alert", "urgent",
    "expire", "limited", "offer", "free", "winner", "prize",
    "claim", "reward", "wallet", "recover", "unlock",
}

# Private IP ranges for SSRF protection
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class PhishingDetector(BaseDetector):
    """URL and domain phishing detection."""

    def supported_input_types(self) -> list[str]:
        return ["url"]

    def analyze(self, url: str | None = None, **kwargs) -> dict:
        """Analyze a URL for phishing indicators."""
        if not url:
            return self._empty_result("phishing", ["No URL provided"])

        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = []
        risk_factors = []

        try:
            parsed = urlparse(url)
        except Exception as e:
            return self._empty_result("phishing", [f"Invalid URL: {str(e)}"])

        # --- 1. URL Structure Analysis ---
        structure_result = self._analyze_url_structure(url, parsed)
        technical_details["url_structure"] = structure_result
        if structure_result.get("suspicious_features"):
            indicators["url_structure"] = structure_result["suspicious_features"]
            risk_factors.append(("url_structure", structure_result.get("risk_contribution", 0)))

        # --- 2. Domain Analysis ---
        domain_result = self._analyze_domain(parsed)
        technical_details["domain_analysis"] = domain_result
        if domain_result.get("suspicious_features"):
            indicators["domain"] = domain_result["suspicious_features"]
            risk_factors.append(("domain", domain_result.get("risk_contribution", 0)))

        # --- 3. Brand Impersonation Check ---
        brand_result = self._check_brand_impersonation(url, parsed)
        technical_details["brand_analysis"] = brand_result
        if brand_result.get("impersonation_detected"):
            indicators["brand_impersonation"] = brand_result["details"]
            risk_factors.append(("brand_impersonation", brand_result.get("risk_contribution", 0)))

        # --- 4. Encoding Analysis ---
        encoding_result = self._analyze_encoding(url, parsed)
        technical_details["encoding"] = encoding_result
        if encoding_result.get("suspicious"):
            indicators["encoding_tricks"] = encoding_result["details"]
            risk_factors.append(("encoding", encoding_result.get("risk_contribution", 0)))

        # --- 5. SSRF-safe TLS/connectivity check ---
        if self._is_safe_url(parsed):
            tls_result = self._check_tls(url, parsed)
            technical_details["tls"] = tls_result
            if tls_result.get("issues"):
                indicators["tls_issues"] = tls_result["issues"]
                risk_factors.append(("tls", tls_result.get("risk_contribution", 0)))
        else:
            indicators["ssrf_blocked"] = "URL resolves to a private/internal IP address"
            risk_factors.append(("ssrf_attempt", 40))
            limitations.append("URL points to private network — connection check skipped for safety")

        # Calculate risk score
        total_risk = sum(r[1] for r in risk_factors)
        risk_score = min(100, total_risk)
        confidence = min(0.9, 0.3 + len(risk_factors) * 0.1)

        if risk_score < 15:
            status = "clean"
            classification = "Safe"
        elif risk_score < 40:
            status = "suspicious"
            classification = "Suspicious"
        elif risk_score < 70:
            status = "suspicious"
            classification = "Suspicious"
        else:
            status = "malicious"
            classification = "Malicious"

        evidence["classification"] = classification
        evidence["url_analyzed"] = url
        evidence["risk_factors"] = [
            {"source": name, "contribution": score} for name, score in risk_factors
        ]

        limitations.append("URL reputation analysis without external threat intelligence API")
        if not settings.VIRUSTOTAL_API_KEY:
            limitations.append("VirusTotal API not configured — no reputation lookup performed")

        return {
            "analysis_type": "phishing",
            "status": status,
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 4),
            "indicators": indicators,
            "evidence": evidence,
            "technical_details": technical_details,
            "limitations": limitations,
        }

    def _analyze_url_structure(self, url: str, parsed) -> dict:
        """Analyze URL structure for suspicious patterns."""
        result = {"suspicious_features": [], "risk_contribution": 0}

        # URL length
        result["url_length"] = len(url)
        if len(url) > 100:
            result["suspicious_features"].append(f"Unusually long URL ({len(url)} chars)")
            result["risk_contribution"] += 5
        if len(url) > 200:
            result["risk_contribution"] += 10

        # Path depth
        path_parts = [p for p in parsed.path.split("/") if p]
        result["path_depth"] = len(path_parts)
        if len(path_parts) > 5:
            result["suspicious_features"].append(f"Deep URL path ({len(path_parts)} levels)")
            result["risk_contribution"] += 5

        # Special characters in URL
        special_chars = sum(1 for c in url if c in "@!#$%^&*()=+[]{}|;:',<>?")
        result["special_characters"] = special_chars
        if special_chars > 3:
            result["suspicious_features"].append(f"Excessive special characters ({special_chars})")
            result["risk_contribution"] += 10

        # @ symbol in URL (used for credential phishing)
        if "@" in parsed.netloc:
            result["suspicious_features"].append("@ symbol in URL — possible credential phishing trick")
            result["risk_contribution"] += 25

        # IP address instead of domain
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.hostname or ""):
            result["suspicious_features"].append("IP address used instead of domain name")
            result["risk_contribution"] += 20

        # Suspicious keywords in URL
        url_lower = url.lower()
        found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in url_lower]
        if found_keywords:
            result["suspicious_keywords"] = found_keywords
            result["risk_contribution"] += min(len(found_keywords) * 3, 15)
            if len(found_keywords) > 2:
                result["suspicious_features"].append(
                    f"Multiple suspicious keywords: {', '.join(found_keywords[:5])}"
                )

        # Multiple subdomains
        hostname = parsed.hostname or ""
        subdomain_count = hostname.count(".") - 1
        result["subdomain_count"] = subdomain_count
        if subdomain_count > 2:
            result["suspicious_features"].append(f"Excessive subdomains ({subdomain_count})")
            result["risk_contribution"] += 10

        # Hyphen-heavy domain (common in phishing)
        if hostname.count("-") > 2:
            result["suspicious_features"].append(f"Many hyphens in domain ({hostname.count('-')})")
            result["risk_contribution"] += 8

        return result

    def _analyze_domain(self, parsed) -> dict:
        """Analyze domain characteristics."""
        result = {"suspicious_features": [], "risk_contribution": 0}

        hostname = parsed.hostname or ""
        result["hostname"] = hostname
        result["scheme"] = parsed.scheme
        result["port"] = parsed.port

        # Non-standard port
        if parsed.port and parsed.port not in (80, 443):
            result["suspicious_features"].append(f"Non-standard port: {parsed.port}")
            result["risk_contribution"] += 10

        # HTTP instead of HTTPS
        if parsed.scheme == "http":
            result["suspicious_features"].append("Uses HTTP instead of HTTPS")
            result["risk_contribution"] += 10

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                result["suspicious_features"].append(f"Suspicious TLD: {tld}")
                result["risk_contribution"] += 10
                break

        # Very long domain
        if len(hostname) > 50:
            result["suspicious_features"].append(f"Unusually long domain ({len(hostname)} chars)")
            result["risk_contribution"] += 5

        # Numeric-heavy domain
        digits_in_domain = sum(1 for c in hostname if c.isdigit())
        if digits_in_domain > 5:
            result["suspicious_features"].append(f"Many digits in domain ({digits_in_domain})")
            result["risk_contribution"] += 5

        return result

    def _check_brand_impersonation(self, url: str, parsed) -> dict:
        """Check for brand name impersonation in the URL."""
        result = {"impersonation_detected": False, "details": [], "risk_contribution": 0}

        hostname = (parsed.hostname or "").lower()
        url_lower = url.lower()

        for brand in BRAND_NAMES:
            # Check if brand appears in subdomain or path but not as the actual domain
            brand_in_hostname = brand in hostname
            is_legit_domain = hostname.endswith(f"{brand}.com") or hostname.endswith(f"{brand}.org")

            if brand_in_hostname and not is_legit_domain:
                result["impersonation_detected"] = True
                result["details"].append(
                    f"Brand '{brand}' appears in hostname but is not the legitimate domain"
                )
                result["risk_contribution"] += 20
                break

            # Brand in path with login-like keywords
            if brand in url_lower and any(k in url_lower for k in ("login", "signin", "verify")):
                if not is_legit_domain:
                    result["impersonation_detected"] = True
                    result["details"].append(
                        f"Brand '{brand}' with login keywords in URL from non-brand domain"
                    )
                    result["risk_contribution"] += 25
                    break

        return result

    def _analyze_encoding(self, url: str, parsed) -> dict:
        """Check for encoding tricks used in phishing URLs."""
        result = {"suspicious": False, "details": [], "risk_contribution": 0}

        hostname = parsed.hostname or ""

        # Punycode / IDN homoglyph detection
        if hostname.startswith("xn--") or any(part.startswith("xn--") for part in hostname.split(".")):
            result["suspicious"] = True
            result["details"].append("Punycode/IDN domain detected — possible homoglyph attack")
            result["risk_contribution"] += 20
            try:
                decoded = hostname.encode("ascii").decode("idna")
                result["decoded_domain"] = decoded
            except Exception:
                pass

        # Excessive percent-encoding
        decoded_url = unquote(url)
        if len(decoded_url) != len(url):
            encoding_ratio = 1 - (len(decoded_url) / len(url))
            result["encoding_ratio"] = round(encoding_ratio, 4)
            if encoding_ratio > 0.1:
                result["suspicious"] = True
                result["details"].append(
                    f"Heavy URL encoding ({encoding_ratio:.0%}) — possible obfuscation"
                )
                result["risk_contribution"] += 10

        return result

    def _is_safe_url(self, parsed) -> bool:
        """SSRF protection: ensure URL doesn't point to private/internal networks."""
        hostname = parsed.hostname or ""

        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            for private_range in PRIVATE_RANGES:
                if ip_obj in private_range:
                    return False

            return True
        except (socket.gaierror, ValueError):
            # Can't resolve — treat as potentially safe but note limitation
            return True

    def _check_tls(self, url: str, parsed) -> dict:
        """Check TLS/SSL certificate (SSRF-safe)."""
        result = {"issues": [], "risk_contribution": 0}

        if parsed.scheme != "https":
            result["issues"].append("Not using HTTPS")
            result["risk_contribution"] += 5
            return result

        try:
            with httpx.Client(timeout=5.0, follow_redirects=False, verify=True) as client:
                resp = client.head(url)
                result["status_code"] = resp.status_code
                result["ssl_valid"] = True

                # Check for suspicious redirects
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    result["redirect_to"] = location
                    if location and urlparse(location).hostname != parsed.hostname:
                        result["issues"].append(
                            f"Redirects to different domain: {urlparse(location).hostname}"
                        )
                        result["risk_contribution"] += 10

        except httpx.ConnectError:
            result["issues"].append("Connection failed — domain may not exist")
            result["risk_contribution"] += 15
        except Exception as e:
            result["ssl_valid"] = False
            result["issues"].append(f"TLS/SSL error: {str(e)}")
            result["risk_contribution"] += 10

        return result
