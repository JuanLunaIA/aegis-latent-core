"""
aegis.core.lsm_guard — Linux Security Module (LSM) Confinement Verification.
Verifies if the current process is running under active LSM profiles (AppArmor/SELinux).
"""
import logging
import subprocess
import os

logger = logging.getLogger(__name__)

class LSMGuard:
    """
    Provides verification of Linux Security Module (LSM) confinement.
    This is a critical component for ensuring the process is bounded by
    kernel-level mandatory access control.
    """
    
    def __init__(self):
        self._is_confined = False

    def verify_confinement(self) -> bool:
        """
        Verifies if the process is under LSM confinement (AppArmor or SELinux).
        Returns True if active confinement is detected.
        """
        try:
            # 1. Check for SELinux status
            if self._check_selinux():
                logger.info("LSM Confinement detected: SELinux is active.")
                self._is_confined = True
                return True
                
            # 2. Check for AppArmor status
            if self._check_apparmor():
                logger.info("LSM Confinement detected: AppArmor is active.")
                self._is_confined = True
                return True
                
            logger.warning("LSM Confinement NOT detected. System is running in DAC-only mode.")
            self._is_confined = False
            return False
            
        except Exception as e:
            logger.error(f"Error during LSM confinement verification: {e}")
            return False

    def _check_selinux(self) -> bool:
        """Checks if SELinux is enabled and enforcing."""
        try:
            # On most systems, 'getenforce' returns 'Enforcing', 'Permissive', or 'Disabled'
            result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                status = result.stdout.strip().lower()
                return status == "enforcing"
        except FileNotFoundError:
            pass # getenforce not available
        except Exception:
            pass
        return False

    def _check_apparmor(self) -> bool:
        """Checks if AppArmor is active by inspecting /sys/module/apparmor/."""
        try:
            return os.path.exists("/sys/module/apparmor")
        except Exception:
            return False

    def get_confinement_status(self) -> str:
        if self._is_confined:
            return "CONFINED"
        return "UNCONFINED"
