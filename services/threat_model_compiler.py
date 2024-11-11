# services/threat_model_compiler.py

import logging
from typing import Dict, List, Any, Optional
import streamlit as st
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CriticalityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ComponentThreat:
    """Structure for component-specific threats"""
    threat_id: str
    threat_type: str
    component_name: str
    component_type: str
    scenario: str
    attack_vectors: List[str]
    affected_components: List[str]
    impact: str
    base_score: float
    criticality_score: float
    mitigations: List[str]

class ThreatModelCompiler:
    """Enhanced Threat Model Compiler with component context"""

    def __init__(self):
        logger.info("Initializing ThreatModelCompiler")
        self.component_weights = {
            'authentication_service': 1.5,
            'api_gateway': 1.4,
            'database': 1.3,
            'backend': 1.2,
            'frontend': 1.0,
            'cache': 0.9,
            'static_content': 0.8
        }

    def compile_threat_model(self,
                           agent_analyses: List[tuple],
                           arch_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile threat model with component context
        
        Args:
            agent_analyses: List of (agent_name, analysis) tuples
            arch_analysis: Architecture analysis results
            
        Returns:
            Compiled threat model with component mapping
        """
        try:
            logger.info("Starting threat model compilation")
            
            # Extract and organize component-specific threats
            component_threats = self._extract_component_threats(agent_analyses)
            
            # Calculate criticality scores
            scored_threats = self._calculate_criticality_scores(
                component_threats,
                arch_analysis
            )
            
            # Generate component-threat mapping
            threat_mapping = self._generate_threat_mapping(scored_threats)
            
            # Compile final threat model
            compiled_model = self._compile_final_model(
                scored_threats,
                threat_mapping,
                arch_analysis
            )
            
            logger.info("Successfully compiled threat model")
            return compiled_model
            
        except Exception as e:
            logger.error(f"Error compiling threat model: {str(e)}", exc_info=True)
            return self._get_empty_model()

    def _extract_component_threats(self,
                                 agent_analyses: List[tuple]) -> List[ComponentThreat]:
        """Extract and normalize component-specific threats"""
        logger.info("Extracting component-specific threats")
        threats = []
        threat_counter = 1

        try:
            for agent_name, analysis in agent_analyses:
                if not analysis or agent_name == "ThreatModelCompiler":
                    continue

                for threat in analysis.get("threats", []):
                    threat_id = f"THREAT-{threat_counter:03d}"
                    threats.append(
                        ComponentThreat(
                            threat_id=threat_id,
                            threat_type=threat.get("Threat Type", "Unknown"),
                            component_name=threat.get("component_name", "System"),
                            component_type=threat.get("component_type", "Unknown"),
                            scenario=threat.get("Scenario", ""),
                            attack_vectors=threat.get("attack_vectors", []),
                            affected_components=threat.get("affected_components", []),
                            impact=threat.get("Potential Impact", ""),
                            base_score=float(threat.get("risk_score", 5.0)),
                            criticality_score=0.0,  # Will be calculated later
                            mitigations=[]  # Will be populated later
                        )
                    )
                    threat_counter += 1

            logger.info(f"Extracted {len(threats)} component-specific threats")
            return threats

        except Exception as e:
            logger.error(f"Error extracting threats: {str(e)}", exc_info=True)
            return []

    def _calculate_criticality_scores(self,
                                    threats: List[ComponentThreat],
                                    arch_analysis: Dict[str, Any]) -> List[ComponentThreat]:
        """Calculate criticality scores for threats"""
        logger.info("Calculating threat criticality scores")

        try:
            for threat in threats:
                # Base criticality factors
                component_weight = self._get_component_weight(threat.component_type)
                connectivity_score = self._calculate_connectivity_score(
                    threat.component_name,
                    arch_analysis
                )
                data_sensitivity = self._assess_data_sensitivity(
                    threat.component_name,
                    arch_analysis
                )
                
                # Calculate final criticality score
                threat.criticality_score = self._compute_final_score(
                    threat.base_score,
                    component_weight,
                    connectivity_score,
                    data_sensitivity
                )

            # Sort threats by criticality score
            return sorted(
                threats,
                key=lambda x: x.criticality_score,
                reverse=True
            )

        except Exception as e:
            logger.error(f"Error calculating criticality scores: {str(e)}", exc_info=True)
            return threats

    def _get_component_weight(self, component_type: str) -> float:
        """Get weight factor for component type"""
        return self.component_weights.get(component_type.lower(), 1.0)

    def _calculate_connectivity_score(self,
                                   component_name: str,
                                   arch_analysis: Dict[str, Any]) -> float:
        """Calculate connectivity score based on component relationships"""
        try:
            relationships = arch_analysis.get("relationships", [])
            connected_components = set()
            
            for rel in relationships:
                if rel.get("source") == component_name:
                    connected_components.add(rel.get("target"))
                if rel.get("target") == component_name:
                    connected_components.add(rel.get("source"))
            
            # More connections = higher risk
            return min(1.5, 0.8 + (len(connected_components) * 0.1))

        except Exception as e:
            logger.warning(f"Error calculating connectivity score: {str(e)}")
            return 1.0

    def _assess_data_sensitivity(self,
                               component_name: str,
                               arch_analysis: Dict[str, Any]) -> float:
        """Assess data sensitivity for a component"""
        try:
            component = next(
                (c for c in arch_analysis.get("components", [])
                 if c.get("name") == component_name),
                {}
            )
            
            # Check for sensitive data indicators
            sensitivity_indicators = [
                "pii", "personal", "sensitive", "credential", "payment",
                "financial", "health", "password", "secret", "key"
            ]
            
            description = (
                component.get("description", "").lower() +
                str(component.get("data_type", "")).lower()
            )
            
            matches = sum(1 for indicator in sensitivity_indicators
                         if indicator in description)
            
            return min(2.0, 1.0 + (matches * 0.2))

        except Exception as e:
            logger.warning(f"Error assessing data sensitivity: {str(e)}")
            return 1.0

    def _compute_final_score(self,
                           base_score: float,
                           component_weight: float,
                           connectivity_score: float,
                           data_sensitivity: float) -> float:
        """Compute final criticality score"""
        return round(
            base_score * component_weight * connectivity_score * data_sensitivity,
            2
        )

    def _generate_threat_mapping(self,
                               threats: List[ComponentThreat]) -> Dict[str, List[str]]:
        """Generate component to threat mapping"""
        mapping = {}
        
        for threat in threats:
            # Map primary component
            if threat.component_name not in mapping:
                mapping[threat.component_name] = []
            mapping[threat.component_name].append(threat.threat_id)
            
            # Map affected components
            for component in threat.affected_components:
                if component not in mapping:
                    mapping[component] = []
                mapping[component].append(threat.threat_id)
        
        return mapping

    def _compile_final_model(self,
                           threats: List[ComponentThreat],
                           threat_mapping: Dict[str, List[str]],
                           arch_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Compile final threat model with component context"""
        return {
            "threat_model": [self._threat_to_dict(t) for t in threats],
            "component_mapping": threat_mapping,
            "component_risk_levels": self._calculate_component_risk_levels(threats),
            "critical_paths": self._identify_critical_paths(threats, arch_analysis),
            "improvement_suggestions": self._generate_improvements(threats, arch_analysis),
            "risk_summary": self._generate_risk_summary(threats)
        }

    def _threat_to_dict(self, threat: ComponentThreat) -> Dict[str, Any]:
        """Convert threat to dictionary format"""
        return {
            "threat_id": threat.threat_id,
            "Threat Type": threat.threat_type,
            "component_name": threat.component_name,
            "component_type": threat.component_type,
            "Scenario": threat.scenario,
            "attack_vectors": threat.attack_vectors,
            "affected_components": threat.affected_components,
            "Potential Impact": threat.impact,
            "criticality_score": threat.criticality_score,
            "criticality_level": self._get_criticality_level(threat.criticality_score)
        }

    def _calculate_component_risk_levels(self,
                                      threats: List[ComponentThreat]) -> Dict[str, Dict[str, Any]]:
        """Calculate risk levels for each component"""
        component_risks = {}
        
        for threat in threats:
            if threat.component_name not in component_risks:
                component_risks[threat.component_name] = {
                    "highest_criticality": 0.0,
                    "threat_count": 0,
                    "threat_types": set()
                }
            
            current = component_risks[threat.component_name]
            current["highest_criticality"] = max(
                current["highest_criticality"],
                threat.criticality_score
            )
            current["threat_count"] += 1
            current["threat_types"].add(threat.threat_type)
        
        # Convert sets to lists for JSON serialization
        for component in component_risks.values():
            component["threat_types"] = list(component["threat_types"])
        
        return component_risks

    def _get_criticality_level(self, score: float) -> str:
        """Convert criticality score to level"""
        if score >= 8.0:
            return CriticalityLevel.CRITICAL.name
        elif score >= 6.0:
            return CriticalityLevel.HIGH.name
        elif score >= 4.0:
            return CriticalityLevel.MEDIUM.name
        return CriticalityLevel.LOW.name

    def _get_empty_model(self) -> Dict[str, Any]:
        """Return empty model structure"""
        return {
            "threat_model": [],
            "component_mapping": {},
            "component_risk_levels": {},
            "critical_paths": [],
            "improvement_suggestions": [],
            "risk_summary": {}
        }

    def _identify_critical_paths(self, threats: List[ComponentThreat], 
                            arch_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify critical attack paths through the system"""
        logger.info("Identifying critical attack paths")
        critical_paths = []
        
        try:
            # Get relationships from architecture analysis
            relationships = arch_analysis.get("relationships", [])
            
            # Group threats by component
            component_threats = {}
            for threat in threats:
                if threat.component_name not in component_threats:
                    component_threats[threat.component_name] = []
                component_threats[threat.component_name].append(threat)

            # Identify paths with high criticality scores
            for rel in relationships:
                source = rel.get("source", "")
                target = rel.get("target", "")
                
                source_threats = component_threats.get(source, [])
                target_threats = component_threats.get(target, [])
                
                # Check if this path has high criticality threats
                path_criticality = max(
                    ([t.criticality_score for t in source_threats] + 
                    [t.criticality_score for t in target_threats] + 
                    [0.0])
                )
                
                if path_criticality >= 7.0:  # High criticality threshold
                    critical_paths.append({
                        "path": [source, target],
                        "risk_level": self._get_criticality_level(path_criticality),
                        "description": f"Critical path between {source} and {target} " \
                                    f"with risk score {path_criticality:.1f}"
                    })

            logger.info(f"Identified {len(critical_paths)} critical paths")
            return critical_paths
            
        except Exception as e:
            logger.error(f"Error identifying critical paths: {str(e)}", exc_info=True)
            return []        

    def _generate_improvements(self, 
                            threats: List[ComponentThreat],
                            arch_analysis: Dict[str, Any]) -> List[str]:
        """Generate improvement suggestions based on threats and architecture"""
        logger.info("Generating improvement suggestions")
        improvements = set()  # Using set to avoid duplicates
        
        try:
            # Component-specific improvements
            component_improvements = self._generate_component_improvements(threats, arch_analysis)
            improvements.update(component_improvements)
            
            # Architecture-level improvements
            arch_improvements = self._generate_architecture_improvements(threats, arch_analysis)
            improvements.update(arch_improvements)
            
            # Technology-specific improvements
            tech_improvements = self._generate_technology_improvements(arch_analysis)
            improvements.update(tech_improvements)
            
            logger.info(f"Generated {len(improvements)} improvement suggestions")
            return list(improvements)
            
        except Exception as e:
            logger.error(f"Error generating improvements: {str(e)}", exc_info=True)
            return []

    def _generate_component_improvements(self, 
                                    threats: List[ComponentThreat],
                                    arch_analysis: Dict[str, Any]) -> List[str]:
        """Generate component-specific improvements"""
        improvements = set()
        
        # Group threats by component
        component_threats = {}
        for threat in threats:
            if threat.component_name not in component_threats:
                component_threats[threat.component_name] = []
            component_threats[threat.component_name].append(threat)
        
        # Generate improvements for each component
        for component, threats in component_threats.items():
            high_risk_threats = [t for t in threats if t.criticality_score >= 7.0]
            if high_risk_threats:
                improvements.add(
                    f"Prioritize security hardening for {component} due to "
                    f"{len(high_risk_threats)} high-risk threats"
                )
        
        return list(improvements)

    def _generate_architecture_improvements(self,
                                        threats: List[ComponentThreat],
                                        arch_analysis: Dict[str, Any]) -> List[str]:
        """Generate architecture-level improvements"""
        improvements = set()
        
        # Analyze relationships for security concerns
        relationships = arch_analysis.get("relationships", [])
        for rel in relationships:
            source = rel.get("source", "")
            target = rel.get("target", "")
            data_flow = rel.get("data_flow", "")
            
            # Check for sensitive data flows
            if any(term in data_flow.lower() for term in ["sensitive", "credential", "token"]):
                improvements.add(
                    f"Implement encrypted communication channel between {source} and {target}"
                )
        
        # Check for missing security components
        components = [c.get("name", "").lower() for c in arch_analysis.get("components", [])]
        if not any("waf" in c for c in components):
            improvements.add("Consider implementing a Web Application Firewall (WAF)")
        if not any("gateway" in c for c in components):
            improvements.add("Consider implementing an API Gateway for centralized security controls")
        
        return list(improvements)

    def _generate_technology_improvements(self, arch_analysis: Dict[str, Any]) -> List[str]:
        """Generate technology-specific improvements"""
        improvements = set()
        
        # Check each component's technology stack
        for component in arch_analysis.get("components", []):
            for tech in component.get("technologies", []):
                tech_name = tech.get("name", "").lower()
                
                # Database-specific improvements
                if tech_name in ["mysql", "postgresql", "mongodb"]:
                    improvements.add(
                        f"Implement database encryption at rest for {component.get('name', '')}"
                    )
                
                # Cache-specific improvements
                if tech_name in ["redis", "memcached"]:
                    improvements.add(
                        f"Implement cache entry encryption for {component.get('name', '')}"
                    )
                
                # Authentication-specific improvements
                if "oauth" in tech_name or "auth" in tech_name:
                    improvements.add("Implement OAuth 2.0 with PKCE for secure authentication")
        
        return list(improvements)

    def _generate_risk_summary(self, threats: List[ComponentThreat]) -> Dict[str, Any]:
        """Generate overall risk summary"""
        logger.info("Generating risk summary")
        
        try:
            # Initialize counters
            risk_levels = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
            
            threat_types = {}
            affected_components = set()
            
            # Analyze threats
            for threat in threats:
                # Count risk levels
                criticality_level = self._get_criticality_level(threat.criticality_score)
                risk_levels[criticality_level.lower()] += 1
                
                # Count threat types
                threat_type = threat.threat_type
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                
                # Track affected components
                affected_components.add(threat.component_name)
                affected_components.update(threat.affected_components)
            
            # Generate summary
            return {
                "risk_distribution": risk_levels,
                "threat_distribution": threat_types,
                "total_threats": len(threats),
                "affected_components": len(affected_components),
                "highest_risks": [
                    {
                        "component": t.component_name,
                        "score": t.criticality_score,
                        "threat_type": t.threat_type
                    }
                    for t in sorted(threats, key=lambda x: x.criticality_score, reverse=True)[:5]
                ],
                "most_affected_components": [
                    {
                        "component": comp,
                        "threat_count": sum(1 for t in threats 
                                        if comp in [t.component_name] + t.affected_components)
                    }
                    for comp in sorted(affected_components)
                ]
            }
            
        except Exception as e:
            logger.error(f"Error generating risk summary: {str(e)}", exc_info=True)
            return {
                "risk_distribution": {},
                "threat_distribution": {},
                "total_threats": 0,
                "affected_components": 0,
                "highest_risks": [],
                "most_affected_components": []
            }