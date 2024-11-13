# services/input_processor/tech_stack_analyzer.py

import logging
from typing import Dict, Any, List
import json
from openai import OpenAI
import requests
import re
import streamlit as st

logger = logging.getLogger(__name__)

class EnhancedTechnologyStackAnalyzer:
    """Enhanced technology stack analysis using LLM"""

    def __init__(self):
        self.system_prompt = """You are a technical architect specializing in technology stack analysis.
        Analyze the application description and provide your response in STRICT JSON format.
        Do not include any explanation or markdown formatting. Only output the JSON object.
        
        Required JSON structure:
        {
            "technologies": [
                {
                    "name": "technology name",
                    "category": "framework/database/infrastructure/etc",
                    "purpose": "description",
                    "security_implications": ["implication1", "implication2"]
                }
            ],
            "security_mechanisms": [
                {
                    "type": "mechanism type",
                    "implementation": "description",
                    "components": ["component1", "component2"],
                    "effectiveness": "high/medium/low"
                }
            ],
            "infrastructure": [
                {
                    "component": "component name",
                    "type": "cloud/on-premise/hybrid",
                    "provider": "provider name",
                    "security_features": ["feature1", "feature2"]
                }
            ],
            "integration_points": [
                {
                    "name": "integration name",
                    "type": "api/service/database",
                    "technologies": ["tech1", "tech2"],
                    "security_considerations": ["consideration1", "consideration2"]
                }
            ]
        }"""

    def analyze_stack(self, description: str, model_config: Dict) -> Dict[str, Any]:
        """Analyze technology stack using specified LLM"""
        try:
            logger.info("Starting enhanced technology stack analysis")
            prompt = self._create_analysis_prompt(description)

            if model_config["provider"] == "OpenAI API":
                return self._analyze_with_openai(prompt, model_config)
            else:
                return self._analyze_with_ollama(prompt, model_config)

        except Exception as e:
            logger.error(f"Error in technology stack analysis: {str(e)}")
            return self._get_empty_response()

    def _create_analysis_prompt(self, description: str) -> str:
        return f"""Analyze the following application description and identify the complete technology stack:

Application Description:
{description}

Focus on identifying:
- Core technologies and frameworks
- Infrastructure components
- Security mechanisms
- Integration points
- Development tools and practices

Do not assume anything, write only fact which is given in description. If you are unable to find tech stack in description just return empty response in json in given format.

Provide a structured analysis in the specified JSON format."""

    def _analyze_with_openai(self, prompt: str, model_config: Dict) -> Dict[str, Any]:
        """Analyze using OpenAI API"""
        try:
            client = OpenAI(api_key=model_config["api_key"])
            response = client.chat.completions.create(
                model=model_config["model_name"],
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ]
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"OpenAI analysis error: {str(e)}")
            return self._get_empty_response()

    def _analyze_with_ollama(self, prompt: str, model_config: Dict) -> Dict[str, Any]:
        """Analyze using Ollama with robust parsing"""
        try:
            logger.info("Sending request to Ollama for tech stack analysis")
            
            request_data = {
                "model": model_config["model_name"],
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "stream": False,
                "options": {
                    "temperature": 0.7
                }
            }
            
            logger.debug("Sending request to Ollama:")
            logger.debug(json.dumps(request_data, indent=2))
            
            response = requests.post(
                "http://localhost:11434/api/chat",
                json=request_data
            )
            
            # Log raw response
            raw_response = response.text
            logger.debug("Raw response from Ollama:")
            logger.debug(raw_response)
            
            response_data = response.json()
            
            logger.debug("Parsed response data:")
            logger.debug(json.dumps(response_data, indent=2))
            
            content = response_data.get("message", {}).get("content", "")
            logger.info(f"Response content length: {len(content)}")
            logger.debug("Response content:")
            logger.debug(content)
            
            # Extract JSON from response
            try:
                # Method 1: Look for JSON code block
                json_match = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1).strip()
                    logger.info("Found JSON in code block")
                else:
                    # Method 2: Look for anything between first { and last }
                    start_idx = content.find('{')
                    end_idx = content.rfind('}') + 1
                    if start_idx != -1 and end_idx > start_idx:
                        json_str = content[start_idx:end_idx]
                        logger.info("Found JSON using brackets")
                    else:
                        # Method 3: Try to clean content
                        cleaned_content = re.sub(r'[^{}[\],":\s\w-]', '', content)
                        match = re.search(r'\{.*\}', cleaned_content, re.DOTALL)
                        if match:
                            json_str = match.group(0)
                            logger.info("Found JSON after cleaning content")
                        else:
                            logger.error("No JSON found in response")
                            return self._get_empty_response()
                
                logger.debug(f"Extracted JSON string: {json_str}")
                
                # Parse JSON
                parsed_data = json.loads(json_str)
                logger.info("Successfully parsed JSON response")
                logger.debug("Parsed data:")
                logger.debug(json.dumps(parsed_data, indent=2))
                
                # Validate response structure
                required_keys = ["technologies", "security_mechanisms", "infrastructure", "integration_points"]
                if not all(key in parsed_data for key in required_keys):
                    logger.warning("Response missing required keys")
                    for key in required_keys:
                        if key not in parsed_data:
                            parsed_data[key] = []
                
                return parsed_data
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error: {str(e)}")
                logger.error("Failed JSON content:")
                logger.error(json_str if 'json_str' in locals() else 'No JSON found')
                return self._get_empty_response()
                
        except Exception as e:
            logger.error(f"Ollama analysis error: {str(e)}")
            logger.error("Full error:", exc_info=True)
            return self._get_empty_response()

    def _get_empty_response(self) -> Dict[str, Any]:
        """Return empty response structure for technology stack analysis"""
        return {
            "technologies": [],
            "security_mechanisms": [], 
            "infrastructure": [],
            "integration_points": []
        }