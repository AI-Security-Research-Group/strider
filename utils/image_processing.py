# utils/image_processing.py
import base64
import requests
from typing import Optional
import streamlit as st

def analyze_image_ollama(image_data: bytes, prompt: str, model: str = "llava:latest") -> Optional[str]:
    """
    Analyze an image using Ollama's Llava model
    
    Args:
        image_data: Raw image bytes
        prompt: The prompt for image analysis
        model: The model name (default: llava)
        
    Returns:
        str: Analysis result or None if failed
    """
    try:
        # Convert image to base64
        base64_image = base64.b64encode(image_data).decode('utf-8')
        
        # Define the system and user prompts
        system_prompt = """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to 
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key 
         components, their interactions, and any technologies used.
      3. Include how data is flowing between all the components.
    
    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional 
    discussion.
    
    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.
        """
        
        # Prepare the API request
        url = "http://localhost:11434/api/chat"
        payload = {
            "model": model,
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

        # Make the API request
        response = requests.post(url, json=payload)
        response.raise_for_status()
        
        # Parse the response
        result = response.json()
        return result.get("message", {}).get("content")
        
    except requests.exceptions.RequestException as e:
        st.error(f"Error communicating with Ollama: {str(e)}")
        return None
    except Exception as e:
        st.error(f"Error processing image: {str(e)}")
        return None