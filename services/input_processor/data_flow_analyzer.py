# services/input_processor/data_flow_analyzer.py

import logging
import json
import re
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)

class DataFlowAnalyzer:
    def __init__(self):
        # Define the system prompt
        self.system_prompt = """You are a security-focused solution architect specializing in data flow analysis.
        Analyze the application description and provide your response in STRICT JSON format.
        Do not include any explanation or markdown formatting. Only output the JSON object.
        
        Required JSON structure:
        {
            "data_flows": [
                {
                    "source": "component_name",
                    "destination": "component_name",
                    "data_type": "description of data",
                    "direction": "inbound/outbound/bidirectional",
                    "protocol": "protocol used",
                    "sensitivity": "high/medium/low"
                }
            ],
            "storage_points": [
                {
                    "component": "name",
                    "data_types": ["type1", "type2"],
                    "persistence": "temporary/permanent"
                }
            ],
            "external_interfaces": [
                {
                    "name": "interface name",
                    "type": "api/file/stream/etc",
                    "direction": "inbound/outbound",
                    "connected_systems": ["system1", "system2"]
                }
            ]
        }"""

    # Analyze data flows using specified LLM
    def analyze_flows(self, description: str, model_config: Dict) -> Dict[str, Any]:
        """Analyze data flows using specified LLM"""
        try:
            logger.info("Starting data flow analysis")
            prompt = self._create_analysis_prompt(description)

            if model_config["provider"] == "OpenAI API":
                return self._analyze_with_openai(prompt, model_config)
            else:
                return self._analyze_with_ollama(prompt, model_config)

        except Exception as e:
            logger.error(f"Error in data flow analysis: {str(e)}")
            return self._get_empty_response()

    def _create_analysis_prompt(self, description: str) -> str:
        return f"""Analyze the following application description and provide a comprehensive data flow analysis in JSON format:

Application Description:
{description}

Double check and make sure you are not missing any flow from given description

Provide ONLY the JSON response, no additional text or formatting."""

    def _analyze_with_ollama(self, prompt: str, model_config: Dict) -> Dict[str, Any]:
        """Analyze using Ollama with robust parsing"""
        try:
            logger.info("Sending request to Ollama for data flow analysis")
            
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
                required_keys = ["data_flows", "storage_points", "external_interfaces"]
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
        """Return empty response structure"""
        return {
            "data_flows": [],
            "storage_points": [],
            "external_interfaces": []
        }

