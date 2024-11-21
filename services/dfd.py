import re
import requests
from openai import OpenAI
import logging

def create_dfd_prompt(app_input):
    prompt = f"""
You are an expert in creating data flow diagrams using Mermaid syntax. Your task is to analyze an application description and create a comprehensive yet simple data flow diagram based solely on the information provided.

Here is the application description you need to analyze:

<app_description>
{app_input}
</app_description>

Please follow these steps to create an accurate and informative data flow diagram:

1. Carefully analyze the application description provided above.
2. Use the Mermaid flowchart syntax to create a data flow diagram.
3. Include all major components, data flows, and trust boundaries mentioned in the description.
4. Highlight sensitive data flows in red using appropriate Mermaid syntax.
5. Ensure you're using the 'flowchart TD' directive for top-down flow.
6. Double-check that all Mermaid syntax is correct and supported by standard renderers.

It's OK for this section to be quite long.

Example structure of a Mermaid flowchart (this is just a generic example, your actual diagram will be based on the specific application description):

```mermaid
flowchart TD
    A[Component A] -->|Data Flow 1| B[Component B]
    B -->|Data Flow 2| C[Component C]
    C -->|Sensitive Data| D[Component D]
    style C fill:#f9f,stroke:#333,stroke-width:4px
    linkStyle 2 stroke:#ff3,stroke-width:4px;
```

Please provide only the Mermaid code block for the data flow diagram based on the given application description in response. no other data than Mermaid code block.


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