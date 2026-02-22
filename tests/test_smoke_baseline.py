from src.threat_hunter.detector import ThreatDetector


def test_detector_detects_suspicious_activity():
    detector = ThreatDetector()
    detector.establish_baseline('a1', [{'api_calls': 2}])
    event = detector.detect_anomaly('a1', {'unusual_api_calls': 20, 'data_access_spike': True})
    assert event is not None
    assert event.severity in {'high', 'critical'}
