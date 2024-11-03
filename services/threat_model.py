import json
import requests
from typing import Optional, Dict, Any
from openai import OpenAI
import streamlit as st
import base64  # Add this for image processing

# Function to convert JSON to Markdown for display.    
def json_to_markdown(threat_model, improvement_suggestions, open_questions):
    markdown_output = "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
    
    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"
        
    markdown_output += "\n\n## Open Questions\n\n"
    for question in open_questions:
        markdown_output += f"- {question}\n"
    
    return markdown_output

# Function to create a prompt for generating a threat model
def create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to analyze the provided summary, content, and application description to produce a list of specific threats for the application.

For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list multiple (3 or 4) credible threats if applicable. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

When providing the threat model, use a JSON formatted response with the keys "threat_model", "improvement_suggestions", and "open_questions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact". 

Under "improvement_suggestions", include an array of strings with suggestions on how the developers can improve their code or application description to enhance security.

Under "open_questions", include an array of strings with critical questions that need to be answered to better understand the security context of the application.

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
SUMMARY, ARCHITECTURE ANALYSIS, AND APPLICATION DESCRIPTION:
{app_input}

Example of expected JSON response format:
  
    {{
      "threat_model": [
        {{
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario ",
          "Potential Impact": "Example Potential Impact "
        }},
        {{
          "Threat Type": "Tampering",
          "Scenario": "Example Scenario ",
          "Potential Impact": "Example Potential Impact "
        }}
      ],
      "improvement_suggestions": [
        "Example improvement suggestion 1.",
        "Example improvement suggestion 2."
        ...provide more improvement suggestions...
      ],
      "open_questions": [
        "What authentication mechanism is used for external users?",
        "How is sensitive data encrypted at rest?"
        ...ask more open questions if you have...
      ]
    }}
"""
    return prompt

def create_image_analysis_prompt():
    prompt = """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to 
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key 
         components, their interactions, and any technologies used.
    
    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional 
    discussion.
    
    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.
    """
    return prompt

# Function to get analyse uploaded architecture diagrams.
def get_image_analysis(api_key: str, model_name: str, prompt: str, image_data: bytes, provider: str = "openai") -> Optional[dict]:
    """
    Analyze an image using either OpenAI's vision models or Ollama's Llava
    
    Args:
        api_key: API key (for OpenAI)
        model_name: Name of the model to use
        prompt: Analysis prompt
        image_data: Raw image bytes
        provider: 'openai' or 'ollama'
        
    Returns:
        dict: Analysis results or None if failed
    """
    try:
        if provider == "openai":
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }

            base64_image = base64.b64encode(image_data).decode('utf-8')
            
            messages = [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt
                        },
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                        }
                    ]
                }
            ]

            payload = {
                "model": model_name,
                "messages": messages,
                "max_tokens": 4000
            }

            response = requests.post(
                "https://api.openai.com/v1/chat/completions", 
                headers=headers, 
                json=payload
            )
            response.raise_for_status()
            return response.json()
            
        elif provider == "ollama":
            # Import the Ollama image analysis function
            from utils.image_processing import analyze_image_ollama
            
            # Call Ollama's Llava model
            result = analyze_image_ollama(image_data, prompt, model_name)
            if result:
                return {"choices": [{"message": {"content": result}}]}
            return None
            
    except Exception as e:
        st.error(f"Error analyzing image: {str(e)}")
        return None


# Function to get threat model from the GPT response.
def get_threat_model(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content


# Function to get threat model from Ollama hosted LLM.
def get_threat_model_ollama(ollama_model, prompt):

    url = "http://localhost:11434/api/generate"

    data = {
        "model": ollama_model,
        "prompt": prompt,
        "format": "json",
        "stream": False
    }

    response = requests.post(url, json=data)

    outer_json = response.json()

    inner_json = json.loads(outer_json['response'])

    return inner_json