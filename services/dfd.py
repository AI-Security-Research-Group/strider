import re
import requests
from openai import OpenAI
import logging

def create_dfd_prompt(app_input):
    prompt = f"""
Your task is to analyze the application details provided and create a comprehensive yet simple data flow diagram using correct Mermaid flowchart syntax.

Important: Double check and make sure syntaxt is supported by renderer.

APPLICATION DESCRIPTION: {app_input}

You MUST only respond with the Mermaid code block.
"""
    return prompt

def get_data_flow_diagram(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": """
You are a flow diagram expert who creates data flow diagrams using Mermaid syntax. Respond only Mermaid code block.
"""
            },
            {"role": "user", "content": prompt}
        ]
    )

    dfd_code = response.choices[0].message.content
    
    # Remove Markdown code block delimiters
    dfd_code = re.sub(r'^```mermaid\s*|\s*```$', '', dfd_code, flags=re.MULTILINE)

    return dfd_code

# Ollama implementation
def get_data_flow_diagram_ollama(ollama_model, prompt):
    url = "http://localhost:11434/api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system", 
                "content": """
You are a mermaid diagram expert who creates data flow diagrams using Mermaid syntax.
Always use flowchart TD directive and ensure proper Mermaid syntax.
Include all major components, data flows, and trust boundaries.
Highlight sensitive data flows in red using appropriate syntax.
"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
    
    response = requests.post(url, json=data)
    outer_json = response.json()
    
    dfd_code = outer_json["message"]["content"]
    
    # Remove Markdown code block delimiters
    dfd_code = re.sub(r'^```mermaid\s*|\s*```$', '', dfd_code, flags=re.MULTILINE)

    return dfd_code