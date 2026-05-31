import os
import subprocess
import logging
import sys
from typing import Optional, Dict

logger = logging.getLogger("aegis.sandbox")

class NamespaceSandbox:
    """
    L2 Sandbox implementing Linux Namespaces for total process isolation.
    Isolates: User, Network, and Mount namespaces.
    """
    def __init__(self):
        self.enabled = False
        # Check if we have the necessary privileges to use unshare
        try:
            subprocess.run(["unshare", "--version"], check=True, capture_output=True)
            self.enabled = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error(" 'unshare' utility not found. Sandbox L2 is DISABLED.")

    def wrap_execution(self, command: list[str], env: Optional[Dict[str, str]] = None):
        """
        Wraps a command execution inside a set of isolated namespaces.
        """
        if not self.enabled:
            logger.warning("L2 Sandbox disabled. Executing command in host namespace.")
            return subprocess.run(command, env=env)

        # Construct the unshare command for total isolation:
        # -U: User namespace (maps current user to root inside)
        # -N: Network namespace (no network access by default)
        # -M: Mount namespace (private mount points)
        # -P: PID namespace (isolated process IDs)
        # -f: Fork to ensure the new process is the first in the new PID namespace
        
        unshare_cmd = [
            "unshare", 
            "--user", "--net", "--mount", "--pid", "--fork",
            "--map-root-user"
        ] + command

        logger.info("Executing process in L2 Isolated Namespaces (User, Net, Mount, PID)...")
        return subprocess.run(unshare_cmd, env=env)

sandbox_l2 = NamespaceSandbox()
