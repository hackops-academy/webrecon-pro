#!/usr/bin/env python3
"""Logging setup for WebRecon Pro."""
import logging

def setup_logger(level: int = logging.WARNING):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("webrecon")
    return logger
