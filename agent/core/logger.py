from __future__ import annotations

import logging
from pathlib import Path


def setup_logger(name: str = "ai_security_analyst", log_file: str = "logs/agent.log") -> logging.Logger:
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(file_handler)

    try:
        from rich.logging import RichHandler

        console_handler = RichHandler(rich_tracebacks=True, markup=False)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    except Exception:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logger.addHandler(console_handler)
    return logger
