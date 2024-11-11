# services/test_cases.py

import requests
from openai import OpenAI
import logging
import streamlit as st
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_test_cases_prompt(threats):
    """Enhanced prompt creation with better threat model handling"""
    logger.info("Creating test cases prompt")
    
    # Handle different threat model formats
    if isinstance(threats, dict):
        # Extract threats from dictionary format
        if 'threat_model' in threats:
            threats_list = threats['threat_model']
        else:
            threats_list = [threats]  # Single threat case
    elif isinstance(threats, str):
        # Try to parse JSON string
        try:
            threats_data = json.loads(threats)
            threats_list = threats_data.get('threat_model', [threats_data])
        except json.JSONDecodeError:
            threats_list = [threats]  # Treat as raw text
    else:
        threats_list = threats  # Assume it's already a list

    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology. 
Your task is to provide Gherkin test cases for the threats identified in a threat model. It is very important that 
your responses are tailored to reflect the details of the threats. 

Below is the list of identified threats:
{json.dumps(threats_list, indent=2)}

For each threat, create specific test cases that:
1. Verify the vulnerability exists
2. Test the attack vector
3. Validate mitigation effectiveness

Use the threat descriptions in the 'Given' steps so that the test cases are specific to the threats identified.
Format test cases in Gherkin syntax within triple backticks (```). Add a title for each test case.

YOUR RESPONSE (provide only the Gherkin test cases):
"""
    logger.debug(f"Generated prompt with {len(threats_list)} threats")
    return prompt

def get_test_cases(api_key: str, model_name: str, prompt: str) -> str:
    """Generate test cases using OpenAI with enhanced error handling"""
    logger.info("Generating test cases with OpenAI")
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a security testing expert that provides Gherkin test cases in Markdown format."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ]
        )
        
        test_cases = response.choices[0].message.content
        logger.info("Successfully generated test cases")
        return test_cases
        
    except Exception as e:
        logger.error(f"Error generating test cases with OpenAI: {str(e)}")
        return "Error generating test cases. Please try again."

def get_test_cases_ollama(ollama_model: str, prompt: str) -> str:
    """Generate test cases using Ollama with enhanced error handling"""
    logger.info("Generating test cases with Ollama")
    try:
        url = "http://localhost:11434/api/chat"
        data = {
            "model": ollama_model,
            "stream": False,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a security testing expert that provides Gherkin test cases in Markdown format."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        outer_json = response.json()
        test_cases = outer_json["message"]["content"]
        logger.info("Successfully generated test cases")
        return test_cases
        
    except Exception as e:
        logger.error(f"Error generating test cases with Ollama: {str(e)}")
        return "Error generating test cases. Please try again."

def validate_threat_model_state() -> bool:
    """Validate threat model data in session state"""
    logger.info("Validating threat model state")
    
    # Check for threat model in different possible locations
    threat_model_exists = any([
        'threat_model' in st.session_state,
        'agent_analyses' in st.session_state,
        bool(st.session_state.get('current_model_id'))
    ])
    
    if not threat_model_exists:
        logger.warning("No threat model found in session state")
        return False
        
    logger.info("Threat model validation successful")
    return True

def get_current_threat_model() -> dict:
    """Get current threat model from session state"""
    logger.info("Retrieving current threat model")
    
    # Try to get threat model from agent analyses first
    if 'agent_analyses' in st.session_state:
        for agent_name, result in st.session_state['agent_analyses']:
            if agent_name == "ThreatModelCompiler":
                logger.info("Found threat model in agent analyses")
                return result
    
    # Try to get from direct threat model storage
    if 'threat_model' in st.session_state:
        logger.info("Found threat model in session state")
        return st.session_state['threat_model']
    
    # Try to get from database if we have a model ID
    if 'current_model_id' in st.session_state:
        from utils.database import DatabaseManager
        db_manager = DatabaseManager()
        model = db_manager.get_threat_model(st.session_state['current_model_id'])
        if model and model.threat_model_output:
            logger.info("Found threat model in database")
            return model.threat_model_output
    
    logger.warning("No threat model found")
    return {}