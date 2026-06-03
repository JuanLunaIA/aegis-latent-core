import asyncio

# Ensure asyncio.get_event_loop() returns a loop on Python versions where
# no default event loop is present by default (compat shim for test suite).
# This keeps legacy tests that call asyncio.get_event_loop().run_until_complete
# working in newer Python interpreters.

def pytest_configure():
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
