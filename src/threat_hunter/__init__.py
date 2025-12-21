"""
Autonomous Threat-Hunting AI Agent

A self-directed security investigation system that continuously monitors,
analyzes, and responds to threats across AI agent deployments.
"""

__version__ = "0.1.0"
__author__ = "AI Agent Security Platform"

from .detector import ThreatDetector
from .investigator import ThreatInvestigator
from .responder import ThreatResponder

__all__ = ["ThreatDetector", "ThreatInvestigator", "ThreatResponder"]
