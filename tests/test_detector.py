"""
Tests for ThreatDetector
"""

import pytest
from datetime import datetime
from src.threat_hunter.detector import ThreatDetector, ThreatEvent


def test_detector_initialization():
    """Test detector initialization"""
    detector = ThreatDetector()
    assert detector is not None
    assert detector.running == False


def test_baseline_establishment():
    """Test baseline establishment"""
    detector = ThreatDetector()
    historical_data = [
        {"api_calls": 10, "data_access": []},
        {"api_calls": 12, "data_access": []},
    ]
    detector.establish_baseline("agent-1", historical_data)
    assert "agent-1" in detector.baselines


def test_anomaly_detection():
    """Test anomaly detection"""
    detector = ThreatDetector()
    detector.establish_baseline("agent-1", [{"api_calls": 10}])
    
    # Normal activity
    normal_activity = {"unusual_api_calls": 0, "data_access_spike": False}
    threat = detector.detect_anomaly("agent-1", normal_activity)
    assert threat is None
    
    # Suspicious activity
    suspicious_activity = {"unusual_api_calls": 50, "data_access_spike": True}
    threat = detector.detect_anomaly("agent-1", suspicious_activity)
    assert threat is not None
    assert threat.risk_score > 0.7


def test_severity_determination():
    """Test severity determination"""
    detector = ThreatDetector()
    assert detector._determine_severity(0.95) == "critical"
    assert detector._determine_severity(0.75) == "high"
    assert detector._determine_severity(0.55) == "medium"
    assert detector._determine_severity(0.3) == "low"
