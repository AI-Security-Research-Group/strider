import re
import requests
import streamlit as st
from openai import OpenAI

# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""
    return prompt
    print(prompt)

# Function to get attack tree from the GPT response.
def get_attack_tree(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": """
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax. The attack tree should reflect the potential threats for the application based on the details given.

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

Make sure the mermaid syntax is correct.

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

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].
"""},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the 'content' attribute of the 'message' object directly
    attack_tree_code = response.choices[0].message.content
    
    # Remove Markdown code block delimiters using regular expression
    attack_tree_code = re.sub(r'^```mermaid\s*|\s*```$', '', attack_tree_code, flags=re.MULTILINE)

    return attack_tree_code


# Function to get attack tree from Ollama hosted LLM.
def get_attack_tree_ollama(ollama_model, prompt):
    
    url = "http://localhost:11434/api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system", 
                "content": """
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax. The attack tree should reflect the potential threats for the application based on the details given.

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

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

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes.

Never include parentheses ( ) and braces { } inside square brackets [ ] like in 

example: B --> C[some text (CSJS)]
example: C --> E[{Unsuccessful Auth}]


 Correct synatx would be For example, ["Example Node Label (ENL)"].

"""},
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
    response = requests.post(url, json=data)

    outer_json = response.json()
    
    # Access the 'content' attribute of the 'message' dictionary
    attack_tree_code = outer_json["message"]["content"]

    # Remove Markdown code block delimiters using regular expression
    attack_tree_code = re.sub(r'^```mermaid\s*|\s*```$', '', attack_tree_code, flags=re.MULTILINE)

    return attack_tree_code