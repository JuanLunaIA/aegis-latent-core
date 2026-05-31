"""
aegis.core.taint_analysis — Dynamic Taint Analysis for LLM Request Pipelines.
Tracks the flow of untrusted user input to prevent injection and data exfiltration.
"""
import re
import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

class TaintEngine:
    """
    Implements a light-weight, regex-based dynamic taint engine.
    Marks untrusted user input as 'tainted' and tracks its propagation.
    """
    
    def __init__(self):
        # Patterns for common injection vectors
        self._injection_patterns = {
            "SQLi": re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)", re.IGNORECASE),
            "XSS": re.compile(r"(<script.*?>|javascript:|on\w+\s*=)", re.IGNORECASE),
            "CMD_INJ": re.compile(r"(\b(ls|cat|rm|chmod|sudo|sh|bash|curl|wget)\b)", re.IGNORECASE),
            "PATH_TRAV": re.compile(r"(\.\.\/|\.\.\\)", re.IGNORECASE),
        }
        self._tainted_sources: Set[str] = set()

    def taint(self, payload: str, origin: str) -> "TaintedValue":
        """
        Marks a string as tainted with a specific origin.
        """
        logger.debug(f"Tainting payload from origin: {origin}")
        return TaintedValue(payload, origin)

    def sanitize_value(self, tainted_val: "TaintedValue", context: str) -> "TaintedValue":
        """
        Applies context-aware sanitization to a tainted value.
        """
        sanitized = tainted_val.value
        
        # Simple sanitization rules
        if context == "ENTROPY_WAF_PIPELINE":
            # Strip control characters and potential injection artifacts
            sanitized = re.sub(r"[\x00-\x1F\x7F]", "", sanitized)
            sanitized = re.sub(r"[<>]", "", sanitized) # Basic XSS prevention
            
        return TaintedValue(sanitized, f"{tainted_val.origin} -> {context}")

class TaintedValue:
    """
    A wrapper for strings that carries taint metadata.
    """
    def __init__(self, value: str, origin: str):
        self.value = value
        self.origin = origin

    def __repr__(self) -> str:
        return f"TaintedValue(value='{self.value}', origin='{self.origin}')"

    def __str__(self) -> str:
        return self.value

    def __bool__(self) -> bool:
        return bool(self.value)
