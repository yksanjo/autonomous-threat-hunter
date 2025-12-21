"""
Threat Investigation Engine

Self-directed investigation system that automatically investigates
detected threats and determines root cause.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass

from .detector import ThreatEvent

logger = logging.getLogger(__name__)


@dataclass
class InvestigationReport:
    """Investigation report with findings"""
    threat_event: ThreatEvent
    root_cause: str
    evidence: List[Dict]
    timeline: List[Dict]
    recommendations: List[str]
    investigation_time: float


class ThreatInvestigator:
    """Autonomous threat investigation engine"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.playbooks = self._load_playbooks()
        
    def _load_playbooks(self) -> Dict:
        """Load investigation playbooks"""
        return {
            "behavioral_anomaly": self._investigate_behavioral_anomaly,
            "privilege_escalation": self._investigate_privilege_escalation,
            "data_exfiltration": self._investigate_data_exfiltration,
            "model_poisoning": self._investigate_model_poisoning,
        }
        
    async def investigate(self, threat_event: ThreatEvent) -> InvestigationReport:
        """
        Automatically investigate a threat event
        
        Args:
            threat_event: The threat event to investigate
            
        Returns:
            InvestigationReport with findings
        """
        logger.info(f"Starting investigation for threat: {threat_event.threat_type}")
        start_time = datetime.now()
        
        # Select appropriate playbook
        playbook = self.playbooks.get(threat_event.threat_type, self._investigate_generic)
        
        # Execute investigation
        root_cause, evidence, timeline = await playbook(threat_event)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_event, root_cause)
        
        investigation_time = (datetime.now() - start_time).total_seconds()
        
        return InvestigationReport(
            threat_event=threat_event,
            root_cause=root_cause,
            evidence=evidence,
            timeline=timeline,
            recommendations=recommendations,
            investigation_time=investigation_time
        )
        
    async def _investigate_behavioral_anomaly(self, event: ThreatEvent) -> tuple:
        """Investigate behavioral anomaly"""
        evidence = [
            {"type": "activity_log", "data": event.details},
            {"type": "baseline_comparison", "data": "Deviation detected"}
        ]
        timeline = [
            {"time": event.timestamp, "event": "Anomaly detected"},
            {"time": datetime.now(), "event": "Investigation started"}
        ]
        root_cause = "Agent behavior deviated from established baseline"
        return root_cause, evidence, timeline
        
    async def _investigate_privilege_escalation(self, event: ThreatEvent) -> tuple:
        """Investigate privilege escalation attempt"""
        evidence = [
            {"type": "permission_changes", "data": event.details.get("permissions", [])},
            {"type": "access_logs", "data": "Unauthorized access attempts"}
        ]
        timeline = [
            {"time": event.timestamp, "event": "Privilege escalation detected"},
        ]
        root_cause = "Agent attempted to access resources beyond normal scope"
        return root_cause, evidence, timeline
        
    async def _investigate_data_exfiltration(self, event: ThreatEvent) -> tuple:
        """Investigate data exfiltration"""
        evidence = [
            {"type": "data_transfer_logs", "data": event.details.get("transfers", [])},
            {"type": "network_logs", "data": "Unusual outbound connections"}
        ]
        timeline = [
            {"time": event.timestamp, "event": "Data exfiltration detected"},
        ]
        root_cause = "Unusual data transfer patterns detected"
        return root_cause, evidence, timeline
        
    async def _investigate_model_poisoning(self, event: ThreatEvent) -> tuple:
        """Investigate model poisoning"""
        evidence = [
            {"type": "model_changes", "data": event.details.get("model_updates", [])},
            {"type": "training_data", "data": "Suspicious training data detected"}
        ]
        timeline = [
            {"time": event.timestamp, "event": "Model poisoning detected"},
        ]
        root_cause = "Model behavior changed unexpectedly"
        return root_cause, evidence, timeline
        
    async def _investigate_generic(self, event: ThreatEvent) -> tuple:
        """Generic investigation playbook"""
        evidence = [{"type": "event_data", "data": event.details}]
        timeline = [{"time": event.timestamp, "event": "Threat detected"}]
        root_cause = "Unknown threat type - requires manual investigation"
        return root_cause, evidence, timeline
        
    def _generate_recommendations(self, event: ThreatEvent, root_cause: str) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if event.severity == "critical":
            recommendations.append("Immediately isolate the affected agent")
            recommendations.append("Revoke all agent credentials")
        elif event.severity == "high":
            recommendations.append("Rate limit agent activity")
            recommendations.append("Review agent permissions")
            
        recommendations.append(f"Address root cause: {root_cause}")
        recommendations.append("Update behavioral baseline after remediation")
        
        return recommendations
