"""
Core module - addon and configuration for Glance.
"""

__all__ = [
    "EXPORT_FOLDER",
    "STRICT_MODE",
    "PATTERNS",
    "SUSPICIOUS_URLS",
    "IGNORE_HOSTS",
]

from .config import EXPORT_FOLDER, STRICT_MODE, PATTERNS, SUSPICIOUS_URLS, IGNORE_HOSTS
