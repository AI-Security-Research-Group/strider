# services/input_processor/processor.py

import logging
from typing import Dict, Any, List
import json
from openai import OpenAI
import requests
import streamlit as st

from .data_flow_analyzer import DataFlowAnalyzer
from .trust_boundary_detector import TrustBoundaryDetector
from .tech_stack_analyzer import EnhancedTechnologyStackAnalyzer

logger = logging.getLogger(__name__)

class InputContextProcessor:
    """Main processor for input context analysis"""

    def __init__(self):
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.trust_boundary_detector = TrustBoundaryDetector()
        self.tech_stack_analyzer = EnhancedTechnologyStackAnalyzer()
        logger.info("Input context processor initialized")

    def process_context(self, app_description: str, model_config: Dict[str, Any]) -> Dict[str, Any]:
        """Process input context through all analyzers"""
        try:
            logger.info(f"Starting context pre-processing using {model_config['provider']}")
            logger.info(f"Selected model: {model_config['model_name']}")
            
            # Run all analyses in sequence
            data_flows = self.data_flow_analyzer.analyze_flows(
                app_description, 
                model_config
            )
            logger.info("Data flow analysis completed")
            logger.debug("Data flow results: %s", json.dumps(data_flows, indent=2))

            trust_boundaries = self.trust_boundary_detector.detect_boundaries(
                app_description,
                model_config
            )
            logger.info("Trust boundary detection completed")
            logger.debug("Trust boundary results: %s", json.dumps(trust_boundaries, indent=2))

            tech_stack = self.tech_stack_analyzer.analyze_stack(
                app_description,
                model_config
            )
            logger.info("Technology stack analysis completed")
            logger.debug("Tech stack results: %s", json.dumps(tech_stack, indent=2))

            # Combine all analyses
            enhanced_context = self._combine_analyses(
                app_description,
                data_flows,
                trust_boundaries,
                tech_stack
            )

            logger.info("Context pre-processing completed successfully")
            logger.debug("Final enhanced context: %s", json.dumps(enhanced_context, indent=2))
            
            return enhanced_context

        except Exception as e:
            logger.error(f"Error in context processing: {str(e)}")
            logger.error("Full error:", exc_info=True)
            return {
                "error": str(e),
                "original_context": app_description,
                "analyses": {
                    "data_flows": {},
                    "trust_boundaries": {},
                    "tech_stack": {}
                },
                "summary": {
                    "data_flows_count": 0,
                    "trust_zones_count": 0,
                    "technologies_count": 0,
                    "security_mechanisms_count": 0,
                    "high_sensitivity_flows": 0,
                    "external_interfaces": 0,
                    "trust_boundaries_count": 0,
                    "integration_points_count": 0
                }
            }

    def _generate_summary(self,
                            data_flows: Dict,
                            trust_boundaries: Dict,
                            tech_stack: Dict) -> Dict[str, Any]:
            """Generate a summary of all analyses"""
            return {
                "data_flows_count": len(data_flows.get("data_flows", [])),
                "trust_zones_count": len(trust_boundaries.get("trust_zones", [])),
                "technologies_count": len(tech_stack.get("technologies", [])),
                "security_mechanisms_count": len(tech_stack.get("security_mechanisms", [])),
                "high_sensitivity_flows": self._count_sensitive_flows(data_flows),
                "external_interfaces": len(data_flows.get("external_interfaces", [])),
                "trust_boundaries_count": len(trust_boundaries.get("trust_boundaries", [])),
                "integration_points_count": len(tech_stack.get("integration_points", []))
            }
    def _combine_analyses(self,
                         original_context: str,
                         data_flows: Dict,
                         trust_boundaries: Dict,
                         tech_stack: Dict) -> Dict[str, Any]:
        """Combine all analyses into a structured format"""
        try:
            # Create summary
            summary = {
                "data_flows_count": len(data_flows.get("data_flows", [])),
                "trust_zones_count": len(trust_boundaries.get("trust_zones", [])),
                "technologies_count": len(tech_stack.get("technologies", [])),
                "security_mechanisms_count": len(tech_stack.get("security_mechanisms", [])),
                "high_sensitivity_flows": self._count_sensitive_flows(data_flows),
                "external_interfaces": len(data_flows.get("external_interfaces", [])),
                "trust_boundaries_count": len(trust_boundaries.get("trust_boundaries", [])),
                "integration_points_count": len(tech_stack.get("integration_points", []))
            }

            return {
                "original_context": original_context,
                "analyses": {
                    "data_flows": data_flows,
                    "trust_boundaries": trust_boundaries,
                    "tech_stack": tech_stack
                },
                "summary": summary
            }
        except Exception as e:
            logger.error(f"Error combining analyses: {str(e)}")
            return {
                "original_context": original_context,
                "analyses": {
                    "data_flows": {},
                    "trust_boundaries": {},
                    "tech_stack": {}
                },
                "summary": {
                    "data_flows_count": 0,
                    "trust_zones_count": 0,
                    "technologies_count": 0,
                    "security_mechanisms_count": 0,
                    "high_sensitivity_flows": 0,
                    "external_interfaces": 0,
                    "trust_boundaries_count": 0,
                    "integration_points_count": 0
                }
            }

    def _count_sensitive_flows(self, data_flows: Dict) -> int:
        """Count number of high sensitivity data flows"""
        try:
            flows = data_flows.get("data_flows", [])
            return sum(1 for flow in flows if flow.get("sensitivity") == "high")
        except Exception:
            return 0

    def format_enhanced_context(self, analysis_results: Dict) -> str:
        """Format the analysis results into a readable text format"""
        try:
            formatted_text = [
#                "Enhanced Application Context",
#                "=========================="
#                "",
#                "Original Description:",
                analysis_results["original_context"],
                "",
                "Data Flow Analysis:",
                "-------------------"
            ]

            # Add Data Flows
            data_flows = analysis_results["analyses"]["data_flows"].get("data_flows", [])
            for flow in data_flows:
                formatted_text.append(
                    f"- {flow.get('source', '')} → {flow.get('destination', '')}: "
                    f"{flow.get('data_type', '')} ({flow.get('sensitivity', '')} sensitivity)"
                )

            # Add Trust Boundaries
            formatted_text.extend([
                "",
                "Trust Boundaries:",
                "----------------"
            ])
            trust_zones = analysis_results["analyses"]["trust_boundaries"].get("trust_zones", [])
            for zone in trust_zones:
                formatted_text.append(
                    f"- {zone.get('name', '')} ({zone.get('type', '')}): "
                    f"Security Level: {zone.get('security_level', '')}"
                )

            # Add Technology Stack
            formatted_text.extend([
                "",
                "Technology Stack:",
                "----------------"
            ])
            technologies = analysis_results["analyses"]["tech_stack"].get("technologies", [])
            for tech in technologies:
                formatted_text.append(
                    f"- {tech.get('name', '')} ({tech.get('category', '')}): {tech.get('purpose', '')}"
                )

            # Add Summary
            summary = analysis_results.get("summary", {})
            formatted_text.extend([
                "",
                "Analysis Summary:",
                "----------------",
                f"- Data Flows: {summary.get('data_flows_count', 0)}",
                f"- Trust Zones: {summary.get('trust_zones_count', 0)}",
                f"- Technologies: {summary.get('technologies_count', 0)}",
                f"- Security Mechanisms: {summary.get('security_mechanisms_count', 0)}",
                f"- High Sensitivity Flows: {summary.get('high_sensitivity_flows', 0)}",
                f"- Integration Points: {summary.get('integration_points_count', 0)}"
            ])

            return "\n".join(formatted_text)

        except Exception as e:
            logger.error(f"Error formatting enhanced context: {str(e)}")
            return "Error formatting analysis results"

    def get_markdown_report(self, analysis_results: Dict) -> str:
        """Generate a markdown report of the analysis results"""
        try:
            markdown = [
                "# Application Context Analysis Report\n",
                "## Original Description\n",
                analysis_results["original_context"],
                "\n## Data Flow Analysis\n",
                "| Source | Destination | Data Type | Sensitivity | Protocol |",
                "|--------|-------------|------------|-------------|-----------|"
            ]

            # Add Data Flows
            for flow in analysis_results["analyses"]["data_flows"].get("data_flows", []):
                markdown.append(
                    f"| {flow.get('source', '')} | {flow.get('destination', '')} | "
                    f"{flow.get('data_type', '')} | {flow.get('sensitivity', '')} | "
                    f"{flow.get('protocol', '')} |"
                )

            # Add Trust Boundaries
            markdown.extend([
                "\n## Trust Boundaries\n",
                "| Zone Name | Type | Security Level | Components |",
                "|-----------|------|----------------|------------|"
            ])
            
            for zone in analysis_results["analyses"]["trust_boundaries"].get("trust_zones", []):
                markdown.append(
                    f"| {zone.get('name', '')} | {zone.get('type', '')} | "
                    f"{zone.get('security_level', '')} | "
                    f"{', '.join(zone.get('components', []))} |"
                )

            # Add summary section
            summary = analysis_results.get("summary", {})
            markdown.extend([
                "\n## Analysis Summary\n",
                f"- **Data Flows**: {summary.get('data_flows_count', 0)}",
                f"- **Trust Zones**: {summary.get('trust_zones_count', 0)}",
                f"- **Technologies**: {summary.get('technologies_count', 0)}",
                f"- **Security Mechanisms**: {summary.get('security_mechanisms_count', 0)}",
                f"- **High Sensitivity Flows**: {summary.get('high_sensitivity_flows', 0)}",
                f"- **Integration Points**: {summary.get('integration_points_count', 0)}"
            ])

            return "\n".join(markdown)

        except Exception as e:
            logger.error(f"Error generating markdown report: {str(e)}")
            return "Error generating analysis report"