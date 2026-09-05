"""
Scam / Social Engineering Detector

Analyzes text messages (SMS, email, chat, social media) for scam indicators using:
- NLP pattern matching for urgency, threats, financial requests
- Keyword analysis for common scam categories
- Suspicious link extraction and analysis
- Emotional manipulation indicator detection
- Credential/sensitive information request detection
- Impersonation pattern detection

Scam Categories:
  - Financial scam (investment, lottery, prize)
  - Phishing (credential theft)
  - Romance scam
  - Tech support scam
  - Government impersonation
  - Job/employment scam
  - Advance fee fraud
  - Generic social engineering
"""

import logging
import re
from collections import Counter

from backend.app.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

# Urgency indicators
URGENCY_PATTERNS = [
    (r"(?i)\b(urgent|immediately|right\s+now|asap|hurry|quick|fast)\b", "urgency"),
    (r"(?i)\b(last\s+chance|final\s+warning|expires?\s+today|time\s+limited)\b", "urgency"),
    (r"(?i)\b(act\s+now|don'?t\s+delay|limited\s+time|deadline)\b", "urgency"),
    (r"(?i)\b(within\s+\d+\s+hours?|within\s+\d+\s+minutes?)\b", "urgency"),
]

# Threat patterns
THREAT_PATTERNS = [
    (r"(?i)\b(suspended|terminated|closed|locked|blocked|disabled)\b.*\b(account|access)\b", "threat"),
    (r"(?i)\b(account)\b.*\b(suspended|terminated|closed|locked|blocked)\b", "threat"),
    (r"(?i)\b(legal\s+action|prosecution|arrest|warrant|lawsuit)\b", "threat"),
    (r"(?i)\b(unauthorized\s+access|suspicious\s+activity|security\s+breach)\b", "threat"),
    (r"(?i)\b(fail(ure)?\s+to\s+comply|consequences)\b", "threat"),
]

# Financial request patterns
FINANCIAL_PATTERNS = [
    (r"(?i)\b(send|transfer|wire|deposit)\b.*\b(money|funds|payment|bitcoin|crypto)\b", "financial"),
    (r"(?i)\b(bank\s+account|routing\s+number|swift\s+code)\b", "financial"),
    (r"(?i)\b(gift\s+card|itunes\s+card|google\s+play\s+card|steam\s+card)\b", "financial"),
    (r"(?i)\b(bitcoin|btc|ethereum|eth|crypto\s*currency|wallet\s+address)\b", "financial"),
    (r"(?i)\b(processing\s+fee|handling\s+fee|administration\s+fee|advance\s+fee)\b", "financial"),
    (r"(?i)\$\s*\d{3,}", "financial"),
]

# Credential request patterns
CREDENTIAL_PATTERNS = [
    (r"(?i)\b(password|passcode|pin|ssn|social\s+security)\b", "credential"),
    (r"(?i)\b(credit\s+card|debit\s+card|card\s+number|cvv|expir)\b", "credential"),
    (r"(?i)\b(verify\s+your\s+(identity|account|email|phone))\b", "credential"),
    (r"(?i)\b(confirm\s+your\s+(details|information|credentials))\b", "credential"),
    (r"(?i)\b(log\s*in|sign\s*in)\s+(here|now|below|to\s+verify)\b", "credential"),
]

# Impersonation patterns
IMPERSONATION_PATTERNS = [
    (r"(?i)\b(irs|fbi|cia|dea|customs|immigration|tax\s+authority)\b", "government_impersonation"),
    (r"(?i)\b(microsoft|apple|google|amazon|facebook|meta)\s+(support|team|security)\b", "tech_impersonation"),
    (r"(?i)\b(dear\s+(customer|user|member|sir|madam|valued))\b", "generic_greeting"),
    (r"(?i)\b(your\s+(bank|financial\s+institution|service\s+provider))\b", "vague_organization"),
]

# Prize/lottery patterns
PRIZE_PATTERNS = [
    (r"(?i)\b(congratulations|you'?ve?\s+won|you\s+are\s+selected|winner)\b", "prize"),
    (r"(?i)\b(lottery|sweepstakes|jackpot|grand\s+prize|million\s+dollars?)\b", "lottery"),
    (r"(?i)\b(claim\s+your\s+(prize|reward|winnings)|collect\s+your)\b", "prize"),
    (r"(?i)\b(free\s+(iphone|macbook|laptop|gift|money|vacation))\b", "free_offer"),
]

# Emotional manipulation
EMOTIONAL_PATTERNS = [
    (r"(?i)\b(please\s+help|i\s+need\s+your\s+help|desperate|stranded)\b", "emotional"),
    (r"(?i)\b(dying|hospital|accident|emergency|sick|cancer)\b", "emotional"),
    (r"(?i)\b(love|miss\s+you|thinking\s+of\s+you|soulmate|destiny)\b", "romance"),
    (r"(?i)\b(god|blessing|blessed|prayer|miracle|faith)\b", "religious"),
]

# Investment scam patterns
INVESTMENT_PATTERNS = [
    (r"(?i)\b(guaranteed\s+(returns?|profit|income)|risk\s*-?\s*free)\b", "investment"),
    (r"(?i)\b(double\s+your\s+(money|investment)|100%\s+return)\b", "investment"),
    (r"(?i)\b(exclusive\s+(opportunity|deal|offer|investment))\b", "investment"),
    (r"(?i)\b(insider\s+(tip|information|trading))\b", "investment"),
]


class ScamDetector(BaseDetector):
    """Text-based scam and social engineering detection."""

    def supported_input_types(self) -> list[str]:
        return ["text"]

    def analyze(self, text_content: str | None = None, **kwargs) -> dict:
        """Analyze text for scam and social engineering indicators."""
        if not text_content or not text_content.strip():
            return self._empty_result("scam", ["No text content provided"])

        text = text_content.strip()

        indicators = {}
        evidence = {}
        technical_details = {}
        limitations = []
        risk_factors = []
        category_scores = Counter()

        # --- 1. Pattern Matching ---
        all_patterns = [
            ("urgency", URGENCY_PATTERNS),
            ("threats", THREAT_PATTERNS),
            ("financial_requests", FINANCIAL_PATTERNS),
            ("credential_requests", CREDENTIAL_PATTERNS),
            ("impersonation", IMPERSONATION_PATTERNS),
            ("prize_lottery", PRIZE_PATTERNS),
            ("emotional_manipulation", EMOTIONAL_PATTERNS),
            ("investment_scam", INVESTMENT_PATTERNS),
        ]

        pattern_matches = {}
        for category, patterns in all_patterns:
            matches = []
            for pattern, sub_category in patterns:
                found = re.findall(pattern, text)
                if found:
                    matches.extend(found if isinstance(found[0], str) else [f[0] for f in found])
                    category_scores[category] += len(found)

            if matches:
                pattern_matches[category] = {
                    "count": len(matches),
                    "examples": matches[:5],  # Limit examples
                }

        if pattern_matches:
            indicators["pattern_matches"] = pattern_matches
            total_pattern_hits = sum(v["count"] for v in pattern_matches.values())
            risk_factors.append(("patterns", min(total_pattern_hits * 5, 40)))

        # --- 2. Suspicious Link Detection ---
        links = re.findall(
            r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
            text
        )
        if links:
            indicators["suspicious_links"] = {
                "count": len(links),
                "urls": links[:10],
            }
            risk_factors.append(("links", min(len(links) * 5, 15)))

        # Shortened URLs
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd"]
        shortened = [l for l in links if any(s in l.lower() for s in shorteners)]
        if shortened:
            indicators["shortened_urls"] = shortened
            risk_factors.append(("shortened_urls", 10))

        # --- 3. Text Statistics ---
        technical_details["text_stats"] = {
            "character_count": len(text),
            "word_count": len(text.split()),
            "line_count": text.count("\n") + 1,
            "uppercase_ratio": round(
                sum(1 for c in text if c.isupper()) / max(len(text), 1), 4
            ),
            "exclamation_count": text.count("!"),
            "question_count": text.count("?"),
        }

        # Excessive capitalization
        uppercase_ratio = technical_details["text_stats"]["uppercase_ratio"]
        if uppercase_ratio > 0.3 and len(text) > 20:
            indicators["excessive_capitals"] = f"Uppercase ratio: {uppercase_ratio:.0%}"
            risk_factors.append(("capitals", 5))

        # Excessive exclamation marks
        if text.count("!") > 3:
            indicators["excessive_exclamation"] = f"Exclamation marks: {text.count('!')}"
            risk_factors.append(("exclamation", 3))

        # --- 4. Categorize Scam Type ---
        scam_category = "generic_social_engineering"
        if category_scores:
            top_category = category_scores.most_common(1)[0][0]
            category_map = {
                "financial_requests": "financial_scam",
                "credential_requests": "phishing",
                "prize_lottery": "lottery_scam",
                "investment_scam": "investment_scam",
                "emotional_manipulation": "romance_scam" if "romance" in str(pattern_matches.get("emotional_manipulation", {})) else "emotional_manipulation",
                "impersonation": "impersonation_scam",
                "urgency": "urgency_based_scam",
                "threats": "threat_based_scam",
            }
            scam_category = category_map.get(top_category, "generic_social_engineering")

        evidence["scam_category"] = scam_category
        evidence["category_scores"] = dict(category_scores)
        technical_details["pattern_categories"] = dict(category_scores)

        # --- 5. Calculate Risk Score ---
        # Base risk from pattern matches
        total_risk = sum(r[1] for r in risk_factors)

        # Bonus risk for multiple categories of indicators
        active_categories = len([c for c, s in category_scores.items() if s > 0])
        if active_categories >= 3:
            total_risk += 15  # Multiple scam indicators from different categories
            evidence["multi_category_warning"] = f"Indicators from {active_categories} different scam categories"

        risk_score = min(100, total_risk)
        confidence = min(0.85, 0.2 + active_categories * 0.1 + len(risk_factors) * 0.05)

        if risk_score < 15:
            status = "clean"
        elif risk_score < 45:
            status = "suspicious"
        else:
            status = "suspicious" if risk_score < 70 else "malicious"

        evidence["risk_factors"] = [
            {"source": name, "contribution": score} for name, score in risk_factors
        ]

        limitations.append("Pattern-based analysis — sophisticated scams may use novel language")
        limitations.append("Text analysis only — does not verify claims or identities")

        return {
            "analysis_type": "scam",
            "status": status,
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 4),
            "indicators": indicators,
            "evidence": evidence,
            "technical_details": technical_details,
            "limitations": limitations,
        }
