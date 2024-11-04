import re
import requests
from openai import OpenAI

def create_dfd_prompt(app_input):
    prompt = f"""
Act as a flow diagram expert skilled in creating data flow diagrams. Your task is to analyze the application details provided and create a comprehensive data flow diagram using Mermaid flowchart syntax.

APPLICATION DESCRIPTION: {app_input}

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

Make sure the mermaid syntax is correct. Refer the below example:

```mermaid
graph TD
    A[Enter Chart Definition] --> B(Preview)
    B --> C{{decide}}
    C --> D["Keep"]
    C --> E["Edit Definition (Edit)"]
    E --> B
    D --> F["Save Image and Code"]
    F --> B
```

Double check and make sure the mermaid syntax is correct and in sctrictly follows above given format only.

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"], Don't do simply like [Example Node Label (ENL)]
"""
    return prompt

def get_data_flow_diagram(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": """
You are a flow diagram expert who creates data flow diagrams using Mermaid syntax.
Always use flowchart TD directive and ensure proper Mermaid syntax.
Include all major components, data flows, and trust boundaries.
Highlight sensitive data flows in red using appropriate syntax.
Use subgraphs for trust boundaries and proper node shapes for different components:
- External entities: rectangles [Entity]
- Processes: rounded rectangles (Process)
- Data stores: cylinder [(Store)]
"""
            },
            {"role": "user", "content": prompt}
        ]
    )

    dfd_code = response.choices[0].message.content
    
    # Remove Markdown code block delimiters
    dfd_code = re.sub(r'^```mermaid\s*|\s*```$', '', dfd_code, flags=re.MULTILINE)

    return dfd_code

def get_data_flow_diagram_ollama(ollama_model, prompt):
    url = "http://localhost:11434/api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system", 
                "content": """
You are a security expert who creates data flow diagrams using Mermaid syntax.
Always use flowchart TD directive and ensure proper Mermaid syntax.
Include all major components, data flows, and trust boundaries.
Highlight sensitive data flows in red using appropriate syntax.
Use subgraphs for trust boundaries and proper node shapes for different components:
- External entities: rectangles [Entity]
- Processes: rounded rectangles (Process)
- Data stores: cylinder [(Store)]
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