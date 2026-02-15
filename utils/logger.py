
import logging
import sys
from typing import Optional, List


# -------------------------
# Logging
# -------------------------
def setup_logging(level: str, log_file: Optional[str] = None) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )

