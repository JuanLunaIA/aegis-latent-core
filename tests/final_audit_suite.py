
import requests
import time
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FinalAudit")

BASE_URL = "http://127.0.0.1:8000"

def test_case(name, payload, expected_status, description):
    print(f"Testing {name}...", end=" ")
    try:
        response = requests.post(f"{BASE_URL}/v1/chat/completions", json=payload, timeout=2)
        status = response.status_code
        success = (status == expected_status)
        print(f"Result: {status} | {'PASS' if success else 'FAIL'} ({description})")
        return success
    except Exception as e:
        print(f"Error: {e}")
        return False

# Attack Matrix
attacks = [
    # A. Schema & Type Attacks
    ("Schema-Bypass", {"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}], "extra": "attack"}, 422, "Forbid extra fields"),
    ("Type-Confusion", {"model": "gpt-4", "messages": "this should be a list"}, 422, "Invalid message type"),
    
    # B. Input Obfuscation (L7)
    ("Unicode-Smuggling", {"model": "gpt-4", "messages": [{"role": "user", "content": "H\u200Bello"}]}, 200, "Normalize and allow"),
    ("Control-Char-Inject", {"model": "gpt-4", "messages": [{"role": "user", "content": "Hello\x00World"}]}, 200, "Strip control chars"),
    
    # C. Adversarial Payloads (Entropy/Taint)
    ("High-Entropy-Polyglot", {"model": "gpt-4", "messages": [{"role": "user", "content": "A" * 100 + "B" * 100 + "C" * 100}]}, 403, "Block via EntropyAnalyzer"),
    ("Entropy-Shift-Injection", {"model": "gpt-4", "messages": [{"role": "user", "content": "Normal text here " + "!" * 100}]}, 403, "Block via Shift Detection"),
    ("Data-Leak-Symmetry", {"model": "gpt-4", "messages": [{"role": "user", "content": "SECRET_KEY: " + "a" * 64}]}, 403, "Block via LeakDetector"),
    
    # D. Request Smuggling (L4/L7)
    # This requires raw socket manipulation, handled separately in the proxy logic
]

print("\n--- STARTING FINAL ADVERSARIAL AUDIT ---")
results = []
for name, payload, expected, desc in attacks:
    results.append(test_case(name, payload, expected, desc))
    time.sleep(0.1)

pass_rate = (sum(results) / len(results)) * 100
print(f"\nFINAL AUDIT PASS RATE: {pass_rate:.2f}%")
