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

    def _is_threat_applicable(self, threat: ComponentThreat, context: Dict[str, Any]) -> bool:
        """
        Determine if a threat is applicable based on the given context
        
        Args:
            threat: The threat to evaluate
            context: Context dictionary containing application details
            
        Returns:
            bool: True if threat is applicable, False otherwise
        """
        try:
            logger.info(f"Evaluating applicability of threat: {threat.id}")
            
            # Initialize score tracking
            applicability_scores = []
            
            # 1. Check Component Match
            if context.get("name"):
                component_match = any(
                    comp.lower() in context["name"].lower() 
                    for comp in [threat.component_name] + threat.affected_components
                )
                applicability_scores.append(1.0 if component_match else 0.0)
                logger.debug(f"Component match score: {1.0 if component_match else 0.0}")

            # 2. Check Technology Stack
            if context.get("tech_stack"):
                tech_relevance = self._evaluate_tech_stack_relevance(
                    threat, 
                    context["tech_stack"]
                )
                applicability_scores.append(tech_relevance)
                logger.debug(f"Technology relevance score: {tech_relevance}")

            # 3. Check Data Sensitivity
            if context.get("sensitivity"):
                sensitivity_match = self._evaluate_sensitivity_match(
                    threat, 
                    context["sensitivity"]
                )
                applicability_scores.append(sensitivity_match)
                logger.debug(f"Sensitivity match score: {sensitivity_match}")

            # 4. Check Prerequisites
            if threat.prerequisites:
                prereq_match = self._evaluate_prerequisites(
                    threat.prerequisites, 
                    context
                )
                applicability_scores.append(prereq_match)
                logger.debug(f"Prerequisites match score: {prereq_match}")

            # 5. Calculate final applicability
            if applicability_scores:
                final_score = sum(applicability_scores) / len(applicability_scores)
                is_applicable = final_score >= 0.5  # Threshold for applicability
                
                logger.info(f"Threat {threat.id} applicability score: {final_score:.2f}")
                logger.info(f"Threat {threat.id} is {'applicable' if is_applicable else 'not applicable'}")
                
                return is_applicable
            
            # Default to True if no evaluation criteria available
            logger.warning(f"No evaluation criteria available for threat {threat.id}, defaulting to applicable")
            return True

        except Exception as e:
            logger.error(f"Error evaluating threat applicability: {str(e)}")
            # Default to True in case of error to avoid missing potential threats
            return True

    def _evaluate_tech_stack_relevance(self, 
                                     threat: ComponentThreat, 
                                     tech_stack: List[str]) -> float:
        """Evaluate how relevant a threat is to the given technology stack"""
        try:
            # Define technology-threat mappings
            tech_threat_mappings = {
                "sql": ["sql injection", "database", "data leak"],
                "nosql": ["injection", "database", "data leak"],
                "azure": ["cloud", "storage", "identity"],
                "aws": ["cloud", "s3", "iam"],
                "oauth": ["authentication", "token", "identity"],
                "jwt": ["token", "authentication"],
                "api": ["rest", "endpoint", "service"],
                "web": ["xss", "csrf", "frontend"]
            }

            relevant_techs = 0
            total_techs = len(tech_stack)

            for tech in tech_stack:
                tech_lower = tech.lower()
                # Check if technology keywords match threat description or category
                for key, threats in tech_threat_mappings.items():
                    if key in tech_lower and any(
                        t in threat.description.lower() or 
                        t in threat.category.lower() 
                        for t in threats
                    ):
                        relevant_techs += 1
                        break

            return relevant_techs / total_techs if total_techs > 0 else 0.0

        except Exception as e:
            logger.error(f"Error evaluating tech stack relevance: {str(e)}")
            return 0.0

    def _evaluate_sensitivity_match(self, 
                                  threat: ComponentThreat, 
                                  sensitivity: str) -> float:
        """Evaluate if threat severity matches data sensitivity"""
        try:
            # Define sensitivity levels and corresponding threat severity requirements
            sensitivity_levels = {
                "Top Secret": ["high"],
                "Secret": ["high", "medium"],
                "Confidential": ["high", "medium"],
                "Restricted": ["high", "medium", "low"],
                "Unclassified": ["medium", "low"],
                "None": ["low"]
            }

            if sensitivity in sensitivity_levels:
                return 1.0 if threat.severity.lower() in sensitivity_levels[sensitivity] else 0.0
            return 0.5  # Default middle score if sensitivity level unknown

        except Exception as e:
            logger.error(f"Error evaluating sensitivity match: {str(e)}")
            return 0.5

    def _evaluate_prerequisites(self, 
                              prerequisites: List[str], 
                              context: Dict[str, Any]) -> float:
        """Evaluate if threat prerequisites are met in the given context"""
        try:
            # Define common prerequisite indicators
            prerequisite_indicators = {
                "internet_facing": {
                    "keywords": ["internet", "external", "public", "exposed"],
                    "context_key": "internet_facing"
                },
                "authentication": {
                    "keywords": ["auth", "login", "credential", "user"],
                    "context_key": "authentication"
                },
                "data_storage": {
                    "keywords": ["database", "storage", "data", "store"],
                    "context_key": "has_database"
                }
            }

            met_prerequisites = 0
            total_prerequisites = len(prerequisites)

            for prereq in prerequisites:
                prereq_lower = prereq.lower()
                for indicator in prerequisite_indicators.values():
                    # Check if prerequisite matches any indicators
                    if any(keyword in prereq_lower for keyword in indicator["keywords"]):
                        # Check if context satisfies the prerequisite
                        if context.get(indicator["context_key"]):
                            met_prerequisites += 1
                            break

            return met_prerequisites / total_prerequisites if total_prerequisites > 0 else 0.0

        except Exception as e:
            logger.error(f"Error evaluating prerequisites: {str(e)}")
            return 0.0