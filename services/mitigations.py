# services/mitigations.py

import requests
from openai import OpenAI
import streamlit as st
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_mitigations_prompt(threats):
    """Enhanced prompt creation with better threat model handling"""
    logger.info("Creating mitigations prompt")
    
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
Your task is to provide potential mitigations for the threats identified in the threat model. 
It is very important that your responses are tailored to reflect the details of the threats.

Below is the list of identified threats:
{json.dumps(threats_list, indent=2)}

Your output MUST be in the form of a markdown table with exactly these three columns:
| Threat Type | Threat Scenario | Suggested Mitigation |

For each threat:
1. Keep the original threat type
2. Use the original scenario description
3. Provide specific, actionable mitigation strategies

Format the response as a clean markdown table without any additional text or explanations.
"""
    logger.debug(f"Generated prompt with {len(threats_list)} threats")
    return prompt

def get_mitigations(api_key: str, model_name: str, prompt: str) -> str:
    """Generate mitigations using OpenAI with enhanced error handling"""
    logger.info("Generating mitigations with OpenAI")
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a security expert that provides mitigation strategies in markdown table format."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ]
        )
        
        mitigations = response.choices[0].message.content
        logger.info("Successfully generated mitigations")
        
        # Ensure proper table format
        if not mitigations.startswith("|"):
            mitigations = format_mitigation_table(mitigations)
        
        return mitigations
        
    except Exception as e:
        logger.error(f"Error generating mitigations with OpenAI: {str(e)}")
        return "Error generating mitigations. Please try again."

def get_mitigations_ollama(ollama_model: str, prompt: str) -> str:
    """Generate mitigations using Ollama with enhanced error handling"""
    logger.info("Generating mitigations with Ollama")
    try:
        url = "http://localhost:11434/api/chat"
        data = {
            "model": ollama_model,
            "stream": False,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a security expert that provides mitigation strategies in markdown table format."
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
        mitigations = outer_json["message"]["content"]
        logger.info("Successfully generated mitigations")
        
        # Ensure proper table format
        if not mitigations.startswith("|"):
            mitigations = format_mitigation_table(mitigations)
            
        return mitigations
        
    except Exception as e:
        logger.error(f"Error generating mitigations with Ollama: {str(e)}")
        return "Error generating mitigations. Please try again."

def format_mitigation_table(content: str) -> str:
    """Ensure content is properly formatted as a markdown table"""
    lines = content.strip().split('\n')
    formatted_lines = []
    
    # Add header
    formatted_lines.append("| Threat Type | Threat Scenario | Suggested Mitigation |")
    formatted_lines.append("|------------|-----------------|---------------------|")
    
    # Process content
    for line in lines:
        if '|' not in line:  # Skip non-table lines
            continue
        # Clean up and standardize the line
        cells = [cell.strip() for cell in line.split('|')]
        if len(cells) >= 3:  # Ensure we have all required columns
            formatted_lines.append(f"| {cells[1]} | {cells[2]} | {cells[3]} |")
    
    return '\n'.join(formatted_lines)

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