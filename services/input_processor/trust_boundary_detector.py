# services/input_processor/trust_boundary_detector.py

import logging
import json
import re
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)

class TrustBoundaryDetector:
    def __init__(self):
        self.system_prompt = """You are a security architect specializing in trust boundary analysis.
        Analyze the application description and provide your response in STRICT JSON format.
        Do not include any explanation or markdown formatting. Only output the JSON object.
        
        Required JSON structure:
        {
            "trust_zones": [
                {
                    "name": "zone name",
                    "type": "public/private/dmz",
                    "components": ["component1", "component2"],
                    "security_level": "high/medium/low"
                }
            ],
            "trust_boundaries": [
                {
                    "id": "boundary id",
                    "type": "authentication/authorization/network",
                    "location": "description",
                    "connected_zones": ["zone1", "zone2"],
                    "security_controls": ["control1", "control2"]
                }
            ],
            "sensitive_data_zones": [
                {
                    "zone": "zone name",
                    "data_types": ["type1", "type2"],
                    "required_controls": ["control1", "control2"]
                }
            ]
        }"""

    def detect_boundaries(self, description: str, model_config: Dict[str, Any]) -> Dict[str, Any]:
        """Detect trust boundaries using specified LLM"""
        try:
            logger.info("Starting trust boundary detection")
            prompt = self._create_detection_prompt(description)

            if model_config["provider"] == "OpenAI API":
                return self._detect_with_openai(prompt, model_config)
            else:
                return self._detect_with_ollama(prompt, model_config)

        except Exception as e:
            logger.error(f"Error in trust boundary detection: {str(e)}")
            return self._get_empty_response()

    def _create_detection_prompt(self, description: str) -> str:
        return f"""Analyze the following application description and identify trust boundaries:

Application Description:
{description}

Provide ONLY the JSON response, no additional text or formatting."""

    def _detect_with_ollama(self, prompt: str, model_config: Dict) -> Dict[str, Any]:
        """Detect using Ollama with enhanced logging"""
        try:
            logger.info("Sending request to Ollama for trust boundary detection")
            
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
            
            # Log raw response for debugging
            raw_response = response.text
            logger.debug("Raw response from Ollama:")
            logger.debug(raw_response)
            
            response_data = response.json()
            
            # Log parsed response
            logger.debug("Parsed response data:")
            logger.debug(json.dumps(response_data, indent=2))
            
            content = response_data.get("message", {}).get("content", "")
            logger.info(f"Response content length: {len(content)}")
            logger.debug("Response content:")
            logger.debug(content)
            
            # Extract JSON from response
            try:
                # Try multiple methods to extract JSON
                
                # Method 1: Look for JSON code block
                json_match = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1).strip()
                    logger.info("Found JSON in code block")
                    logger.debug(f"Extracted JSON from code block: {json_str}")
                else:
                    # Method 2: Look for anything between first { and last }
                    start_idx = content.find('{')
                    end_idx = content.rfind('}') + 1
                    if start_idx != -1 and end_idx > start_idx:
                        json_str = content[start_idx:end_idx]
                        logger.info("Found JSON using brackets")
                        logger.debug(f"Extracted JSON using brackets: {json_str}")
                    else:
                        # Method 3: Try to remove any markdown or text formatting
                        cleaned_content = re.sub(r'[^{}[\],":\s\w-]', '', content)
                        match = re.search(r'\{.*\}', cleaned_content, re.DOTALL)
                        if match:
                            json_str = match.group(0)
                            logger.info("Found JSON after cleaning content")
                            logger.debug(f"Extracted JSON after cleaning: {json_str}")
                        else:
                            logger.error("No JSON found in response")
                            return self._get_empty_response()

                # Parse the extracted JSON
                parsed_data = json.loads(json_str)
                logger.info("Successfully parsed JSON response")
                logger.debug("Parsed data:")
                logger.debug(json.dumps(parsed_data, indent=2))
                
                # Validate response structure
                required_keys = ["trust_zones", "trust_boundaries", "sensitive_data_zones"]
                if not all(key in parsed_data for key in required_keys):
                    logger.warning("Response missing required keys")
                    # Add missing keys with empty lists
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
            logger.error(f"Ollama detection error: {str(e)}")
            logger.error("Full error:", exc_info=True)
            return self._get_empty_response()

    def _get_empty_response(self) -> Dict[str, Any]:
        """Return empty response structure"""
        return {
            "trust_zones": [],
            "trust_boundaries": [],
            "sensitive_data_zones": []
        }