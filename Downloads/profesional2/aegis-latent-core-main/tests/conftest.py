import asyncio

# Monkeypatch asyncio.get_event_loop so legacy tests calling
# asyncio.get_event_loop().run_until_complete() behave on newer Pythons.
_orig_get_event_loop = asyncio.get_event_loop


def _safe_get_event_loop():
    try:
        return _orig_get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

# Replace the function globally for test runtime
asyncio.get_event_loop = _safe_get_event_loop


def pytest_configure():
    # Ensure a loop exists at pytest startup as a fallback
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
