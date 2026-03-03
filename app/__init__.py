"""
LogSentinel — Mini SOC Log Analyzer & Alert Dashboard.

A FastAPI-based security operations dashboard that ingests Linux auth.log
and nginx access logs, parses them into structured events, and runs
detection rules to surface actionable alerts.
"""

__version__ = "1.0.0"
