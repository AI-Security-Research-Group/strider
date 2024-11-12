# services/knowledge_base/service.py

import logging
from typing import Dict, List, Optional, Any
from .database import KnowledgeBaseDB
from .models import Component, ComponentThreat, ComponentType

logger = logging.getLogger(__name__)

class KnowledgeBaseService:
    def __init__(self):
        self.db = KnowledgeBaseDB()
        logger.info("Knowledge base service initialized")

    def get_component_threats(self, 
                            component_type: str,
                            context: Optional[Dict[str, Any]] = None) -> List[ComponentThreat]:
        """Get threats for a component with context-aware filtering"""
        try:
            threats = self.db.get_component_threats(component_type)
            if context:
                threats = self._filter_threats_by_context(threats, context)
            logger.info(f"Retrieved {len(threats)} threats for {component_type}")
            return threats
        except Exception as e:
            logger.error(f"Error retrieving threats: {str(e)}")
            return []

    def _filter_threats_by_context(self,
                                 threats: List[ComponentThreat],
                                 context: Dict[str, Any]) -> List[ComponentThreat]:
        """Filter threats based on context"""
        filtered_threats = []
        for threat in threats:
            if self._is_threat_applicable(threat, context):
                filtered_threats.append(threat)
        return filtered_threats

    def _is_threat_applicable(self,
                            threat: ComponentThreat,
                            context: Dict[str, Any]) -> bool:
        """Check if threat applies to given context"""
        return True  # Placeholder for threat applicability logic