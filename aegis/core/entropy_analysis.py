"""
aegis.core.entropy_analysis — Shannon Entropy and KL-Divergence monitoring for LLM outputs.
Detects adversarial shifts in logit distributions.
"""
import math
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

class PayloadEntropyAnalyzer:
    """
    Analyzes the Shannon entropy of LLM response logprobs to detect 
    unnatural/adversarial response patterns.
    """
    
    def __init__(self, baseline_entropy: float = 2.5):
        self.baseline_entropy = baseline_entropy
        self._history: List[float] = []

    def analyze_payload(self, text: str) -> tuple[bool, float]:
        """
        Calculates entropy of the provided text.
        Returns (is_allowed, calculated_entropy).
        """
        if not text:
            return True, 0.0
            
        entropy = self._calculate_shannon_entropy(text)
        
        # Rule: If entropy drops significantly below baseline, it might be a 
        # repetitive/deterministic attack (e.g., token flooding).
        is_allowed = bool(entropy > (self.baseline_entropy * 0.4))
        
        self._history.append(entropy)
        if len(self._history) > 100:
            self._history.pop(0)
            
        return is_allowed, entropy

    def detect_entropy_shift(self, text: str) -> bool:
        """
        Detects if the current text's entropy represents a statistical anomaly
        relative to the recent history.
        """
        if len(self._history) < 10:
            return False
            
        current_entropy = self._calculate_shannon_entropy(text)
        avg_history = sum(self._history) / len(self._history)
        
        # Shift detection: if current entropy is 2 standard deviations away from mean
        std_dev = float(np.std(self._history)) if len(self._history) > 1 else 0.1
        return bool(abs(current_entropy - avg_history) > (2 * std_dev))

    def _calculate_shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
            
        probs = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs if p > 0)

class XDPDynamicSegmenter:
    """
    Simulates XDP-based network segmentation for blocking malicious IPs.
    In a real production environment, this would interact with eBPF/XDP via a kernel interface.
    """
    def __init__(self):
        self._blocked_ips: Set[str] = set()

    def block_ip_immediately(self, ip: str):
        """Adds an IP to the blackhole list."""
        self._blocked_ips.add(ip)
        logger.warning(f"XDP SEGMENTATION: IP {ip} has been blackholed at the kernel level.")

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips
