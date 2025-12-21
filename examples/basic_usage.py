"""
Basic usage example for Autonomous Threat-Hunter
"""

import asyncio
from src.threat_hunter import ThreatDetector, ThreatInvestigator, ThreatResponder


async def main():
    # Initialize components
    detector = ThreatDetector()
    investigator = ThreatInvestigator()
    responder = ThreatResponder()
    
    # Establish baseline for an agent
    historical_data = [
        {"api_calls": 10, "data_access": ["user_data"], "action": "process_request"},
        {"api_calls": 12, "data_access": ["user_data"], "action": "process_request"},
        {"api_calls": 11, "data_access": ["user_data"], "action": "process_request"},
    ]
    detector.establish_baseline("agent-123", historical_data)
    
    # Simulate suspicious activity
    suspicious_activity = {
        "unusual_api_calls": 50,
        "data_access_spike": True,
        "privilege_escalation": False
    }
    
    # Detect threat
    threat = detector.detect_anomaly("agent-123", suspicious_activity)
    
    if threat:
        print(f"Threat detected: {threat.threat_type} (Severity: {threat.severity})")
        
        # Investigate
        investigation = await investigator.investigate(threat)
        print(f"Root cause: {investigation.root_cause}")
        
        # Respond
        responses = await responder.respond(threat, investigation)
        for response in responses:
            print(f"Response: {response.action.value} - {response.message}")


if __name__ == "__main__":
    asyncio.run(main())
