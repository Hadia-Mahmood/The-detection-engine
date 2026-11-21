"""
sqli_detector.py — Multi-signal SQL injection detector.

Normalizes input (URL-decode, case-fold, strip comments), then evaluates
categorized regex signatures and assigns a confidence score.
"""
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Signature catalog — grouped by attack class
# ---------------------------------------------------------------------------
SIGNATURES = {
    "union_based": [
        r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b",
        r"(?i)\bUNION\s+SELECT\s+NULL",
        r"(?i)\bUNION\s+SELECT\s+[\d,'\"]",
    ],
    "boolean_based": [
        r"(?i)(?:'\s*)?\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)\bAND\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)\bOR\b\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+['\"]",
        r"(?i)['\"]\s*(?:OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    ],
    "time_based": [
        r"(?i)\bSLEEP\s*\(\s*\d+\s*\)",
        r"(?i)\bBENCHMARK\s*\(\s*\d+\s*,",
        r"(?i)\bPG_SLEEP\s*\(\s*\d+\s*\)",
        r"(?i)\bWAITFOR\s+DELAY\b",
    ],
    "error_based": [
        r"(?i)\bEXTRACTVALUE\s*\(",
        r"(?i)\bUPDATEXML\s*\(",
        r"(?i)\bFLOOR\s*\(\s*RAND\s*\(",
        r"(?i)\bCONVERT\s*\(.*\bINT\b",
    ],
    "stacked_queries": [
        r"(?i);\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b",
        r"(?i);\s*EXEC(?:UTE)?\b",
        r"(?i);\s*SHUTDOWN\b",
    ],
    "file_access": [
        r"(?i)\bLOAD_FILE\s*\(",
        r"(?i)\bINTO\s+(?:OUT|DUMP)FILE\b",
        r"(?i)\bxp_cmdshell\b",
    ],
    "schema_enumeration": [
        r"(?i)\binformation_schema\b",
        r"(?i)\bsysdatabases\b",
        r"(?i)\bsysusers\b",
        r"(?i)\bpg_catalog\b",
    ],
    "comment_obfuscation": [
        r"(?i)/\*.*?\*/",                    # inline comment
        r"(?i)--\s*$",                       # line comment at end
        r"(?i)#\s*$",                        # MySQL line comment
        r"(?i)/\*!\d+",                      # MySQL versioned comment
    ],
    "encoding_evasion": [
        r"(?i)%27",                          # URL-encoded single quote
        r"(?i)%22",                          # URL-encoded double quote
        r"(?i)%3D",                          # URL-encoded =
        r"(?i)%2D%2D",                       # URL-encoded --
    ],
}

# Pre-compile for speed
_COMPILED: dict[str, list[re.Pattern]] = {
    cat: [re.compile(p) for p in pats] for cat, pats in SIGNATURES.items()
}


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------
@dataclass
class SQLiResult:
    detected: bool
    score: float                          # 0.0 – 1.0
    categories: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    normalized_input: str = ""
    raw_input: str = ""


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------
def normalize(value: str, max_depth: int = 3) -> str:
    """URL-decode repeatedly, then case-fold."""
    current = value or ""
    for _ in range(max_depth):
        decoded = urllib.parse.unquote_plus(current)
        if decoded == current:
            break
        current = decoded
    return current.strip()


def strip_sql_comments(text: str) -> str:
    """Remove SQL comments to reveal payloads hidden behind them."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"--[^\n]*", " ", text)
    text = re.sub(r"#[^\n]*", " ", text)
    return text


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------
class SQLiDetector:
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def analyze(self, value: str) -> SQLiResult:
        if not value or not value.strip():
            return SQLiResult(False, 0.0, raw_input=value or "")

        # Layer 1 — normalize
        normalized = normalize(value)

        # Layer 2 — also check comment-stripped variant
        stripped = strip_sql_comments(normalized)

        candidates = [normalized]
        if stripped != normalized:
            candidates.append(stripped)

        categories = set()
        matched = []

        for text in candidates:
            for category, patterns in _COMPILED.items():
                for pattern in patterns:
                    if pattern.search(text):
                        categories.add(category)
                        matched.append(pattern.pattern)

        # Layer 3 — scoring
        #   - Any single high-signal category (union, time, stacked, file) = 0.9
        #   - Multiple medium categories stack up
        high_signal = {"union_based", "time_based", "stacked_queries",
                       "file_access", "error_based"}
        medium_signal = {"boolean_based", "schema_enumeration",
                         "encoding_evasion"}

        if categories & high_signal:
            score = 0.9 + min(0.1, 0.03 * len(categories))
        elif len(categories & medium_signal) >= 2:
            score = 0.75
        elif categories & medium_signal:
            score = 0.55
        elif "comment_obfuscation" in categories:
            score = 0.35    # comment alone is not conclusive
        else:
            score = 0.0

        detected = score >= self.threshold

        return SQLiResult(
            detected=detected,
            score=round(min(score, 1.0), 2),
            categories=sorted(categories),
            matched_patterns=matched[:8],          # cap for logging
            normalized_input=normalized[:500],
            raw_input=value[:500],
        )


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------
_default_detector = SQLiDetector()

def is_sqli(value: str, threshold: float = 0.5) -> bool:
    return SQLiDetector(threshold).analyze(value).detected

def detect_sqli(value: str, threshold: float = 0.5) -> SQLiResult:
    return SQLiDetector(threshold).analyze(value)
