"""
Helper class for using logging as trace file object
"""
from __future__ import annotations

import logging

class logging_file_class:

    def __init__(self, logging_level: int) -> None:
        self._logging_level = logging_level

    def write(self, msg: str) -> None:
        logging.log(self._logging_level, msg[:-1])

    def flush(self) -> None:
        return

logging_file_obj = logging_file_class(logging.DEBUG)
