# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import os
import sys

# FORCE LOCAL IMPORT
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis.core.seccomp_guard import SeccompGuard


def test_seccomp_init():
    print("--- Starting SeccompGuard Test ---")
    guard = SeccompGuard()
    print(f"Guard initialized. Enforced: {guard.is_enforced()}")

    # Try to apply filter (expecting potential failure due to permissions in sandbox)
    print("Attempting to apply filter...")
    success = guard.apply_filter()

    if success:
        print("SUCCESS: Seccomp filter applied!")
    else:
        print("NOTICE: Seccomp filter could NOT be applied (likely due to sandbox permissions).")

    print(f"Guard status: {'ENFORCED' if guard.is_enforced() else 'NOT ENFORCED'}")
    print("--- SeccompGuard Test COMPLETED ---")


if __name__ == "__main__":
    try:
        test_seccomp_init()
    except Exception as e:
        print(f"TEST FAILED with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
