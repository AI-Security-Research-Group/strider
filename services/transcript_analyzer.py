# transcript_analyzer.py
import json
from typing import Dict, Any
import streamlit as st
from openai import OpenAI
import requests

class TranscriptAnalyzer:
    def __init__(self):
        self.system_prompt = """You are an expert technical data analyst tasked with analyzing application-related discussions and extracting key technical and architectural details from the transcripts. Focus on identifying:

1. Application type and purpose
2. Technical architecture components
3. Data flows and integrations
4. Security mechanisms
5. User interactions and authentication
6. Data storage and processing
7. External dependencies and third-party integrations
8. Deployment environment details

Format the output as a JSON object with these sections. Only include information explicitly mentioned in the transcript."""

    def create_analysis_prompt(self, transcript: str) -> str:
        return f"""Analyze the following transcript and extract relevant application details:

{transcript}

Structure your response as a JSON object with the following keys:
{{
    "application_overview": {{
        "type": "string",
        "purpose": "string",
        "primary_users": "string"
    }},
    "technical_architecture": {{
        "components": ["string"],
        "integrations": ["string"],
        "data_flows": ["string"]
    }},
    "security_details": {{
        "authentication": ["string"],
        "authorization": ["string"],
        "data_protection": ["string"]
    }},
    "data_handling": {{
        "storage": ["string"],
        "processing": ["string"],
        "sensitivity": "string"
    }},
    "deployment": {{
        "environment": "string",
        "infrastructure": ["string"]
    }},
    "additional_context": ["string"]
}}

Include only information that is explicitly mentioned in the transcript."""

    def analyze_with_openai(self, api_key: str, model_name: str, transcript: str) -> Dict[str, Any]:
        """Analyze transcript using OpenAI API"""
        try:
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model_name,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": self.create_analysis_prompt(transcript)}
                ]
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            st.error(f"Error analyzing transcript with OpenAI: {str(e)}")
            return {}

    def analyze_with_ollama(self, model_name: str, transcript: str) -> Dict[str, Any]:
        """Analyze transcript using Ollama"""
        try:
            url = "http://localhost:11434/api/chat"
            data = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": self.create_analysis_prompt(transcript)}
                ],
                "format": "json",
                "stream": False
            }
            response = requests.post(url, json=data)
            return json.loads(response.json()["message"]["content"])
        except Exception as e:
            st.error(f"Error analyzing transcript with Ollama: {str(e)}")
            return {}

    def format_analysis_output(self, analysis: Dict[str, Any]) -> str:
        """Format the analysis results as markdown"""
        markdown = "## Application Analysis from Transcript\n\n"
        
        # Application Overview
        markdown += "### Application Overview\n"
        overview = analysis.get("application_overview", {})
        markdown += f"- **Type:** {overview.get('type', 'Not specified')}\n"
        markdown += f"- **Purpose:** {overview.get('purpose', 'Not specified')}\n"
        markdown += f"- **Primary Users:** {overview.get('primary_users', 'Not specified')}\n\n"
        
        # Technical Architecture
        markdown += "### Technical Architecture\n"
        tech = analysis.get("technical_architecture", {})
        if tech.get("components"):
            markdown += "**Components:**\n"
            for component in tech["components"]:
                markdown += f"- {component}\n"
        if tech.get("integrations"):
            markdown += "\n**Integrations:**\n"
            for integration in tech["integrations"]:
                markdown += f"- {integration}\n"
        if tech.get("data_flows"):
            markdown += "\n**Data Flows:**\n"
            for flow in tech["data_flows"]:
                markdown += f"- {flow}\n"
        markdown += "\n"
        
        # Security Details
        markdown += "### Security Details\n"
        security = analysis.get("security_details", {})
        if security.get("authentication"):
            markdown += "**Authentication Methods:**\n"
            for auth in security["authentication"]:
                markdown += f"- {auth}\n"
        if security.get("authorization"):
            markdown += "\n**Authorization Controls:**\n"
            for authz in security["authorization"]:
                markdown += f"- {authz}\n"
        if security.get("data_protection"):
            markdown += "\n**Data Protection Measures:**\n"
            for protection in security["data_protection"]:
                markdown += f"- {protection}\n"
        markdown += "\n"
        
        # Data Handling
        markdown += "### Data Handling\n"
        data = analysis.get("data_handling", {})
        if data.get("storage"):
            markdown += "**Storage:**\n"
            for storage in data["storage"]:
                markdown += f"- {storage}\n"
        if data.get("processing"):
            markdown += "\n**Processing:**\n"
            for process in data["processing"]:
                markdown += f"- {process}\n"
        markdown += f"\n**Data Sensitivity:** {data.get('sensitivity', 'Not specified')}\n\n"
        
        # Deployment
        markdown += "### Deployment Information\n"
        deploy = analysis.get("deployment", {})
        markdown += f"**Environment:** {deploy.get('environment', 'Not specified')}\n"
        if deploy.get("infrastructure"):
            markdown += "\n**Infrastructure:**\n"
            for infra in deploy["infrastructure"]:
                markdown += f"- {infra}\n"
        
        # Additional Context
        if analysis.get("additional_context"):
            markdown += "\n### Additional Context\n"
            for context in analysis["additional_context"]:
                markdown += f"- {context}\n"
        
        return markdown