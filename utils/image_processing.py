# utils/image_processing.py
import base64
import requests
import logging
from typing import Optional, Dict, Any
import streamlit as st

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComponentAnalyzer:
    """Handles component analysis from architecture diagrams"""
    
    @staticmethod
    def categorize_component(component_info: str) -> Dict[str, Any]:
        """Categorizes a component based on its description"""
        component_types = {
            'api': 'api_gateway',
            'gateway': 'api_gateway',
            'database': 'database',
            'db': 'database',
            'cache': 'cache',
            'redis': 'cache',
            'cdn': 'cdn',
            'frontend': 'frontend',
            'ui': 'frontend',
            'backend': 'backend',
            'service': 'backend',
            'auth': 'authentication_service',
            'queue': 'message_queue',
            'load': 'load_balancer'
        }
        
        component_info = component_info.lower()
        
        # Determine component type
        identified_type = 'custom'
        for key, value in component_types.items():
            if key in component_info:
                identified_type = value
                break
        
        return {
            "type": identified_type,
            "description": component_info
        }

def analyze_image_ollama(
    image_data: bytes,
    prompt: str,
    model: str = "llama3.2-vision:latest"
) -> Optional[Dict[str, Any]]:
    """
    Analyze an image using Ollama's Llava model with basic prompt
    """
    try:
        logger.info("Starting image analysis with Ollama")
        
        # Convert image to base64
        base64_image = base64.b64encode(image_data).decode('utf-8')
        
        # Basic system prompt
        system_prompt = """
You are a Solution Architect analyzing an architecture diagram.
Describe the key components, their interactions, and any security-relevant aspects visible in the diagram.
Focus on:
1. Key components and their roles
2. How components interact
3. External interfaces
4. Security-relevant aspects

Provide a clear, structured explanation.
Do not make assumptions about unseen components.
"""
        
        # Check Ollama availability
        try:
            logger.info("Checking Ollama availability")
            response = requests.get("http://localhost:11434/api/tags")
            available_models = [m["name"] for m in response.json().get("models", [])]
            
            if "llama3.2-vision:latest" not in available_models:
                logger.warning("Llava model not found. Attempting installation...")
                st.warning("Installing llama3.2-vision:latest model...")
                
                install_response = requests.post(
                    "http://localhost:11434/api/pull",
                    json={"name": "llama3.2-vision:latest"}
                )
                
                if install_response.status_code != 200:
                    raise Exception("Failed to install llama3.2-vision:latest model")
                    
                logger.info("Successfully installed llama3.2-vision:latest model")
                st.success("Successfully installed llama3.2-vision:latest model")
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Error checking/installing Llava model: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        
        # Make API request
        url = "http://localhost:11434/api/chat"
        payload = {
            "model": "llama3.2-vision:latest",
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": prompt,
                    "images": [base64_image]
                }
            ],
            "stream": False
        }

        logger.info("Sending analysis request to Ollama")
        response = requests.post(url, json=payload)
        response.raise_for_status()
        
        # Process response
        result = response.json()
        content = result.get("message", {}).get("content")
        
        if content:
            logger.info("Successfully analyzed architecture diagram")
            return {"analysis": content}
        
        return None
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Error communicating with Ollama: {str(e)}"
        logger.error(error_msg)
        st.error(error_msg)
        return None
    except Exception as e:
        error_msg = f"Error processing image: {str(e)}"
        logger.error(error_msg)
        st.error(error_msg)
        return None