from __future__ import annotations

import shutil
import subprocess
from typing import Sequence


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(command: Sequence[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
