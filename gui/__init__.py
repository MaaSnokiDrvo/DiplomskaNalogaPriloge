"""
NetSentinel IDS GUI Package
Nadzorna plošča za zaznavanje groženj v realnem času.
"""

__version__ = "2.0.0"
__author__ = "NetSentinel"
__description__ = "PyQt5 Dashboard for NetSentinel IDS"

from .api_client import APIClient
from .main import NetSentinelMainWindow

__all__ = ["APIClient", "NetSentinelMainWindow"]
