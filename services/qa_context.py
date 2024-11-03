from typing import Dict, List, Any
import streamlit as st
from openai import OpenAI
import requests

def create_question_generation_prompt(app_type: str, authentication: List[str], 
                                   internet_facing: str, sensitive_data: str, 
                                   app_input: str) -> str:
    """Create prompt for generating contextual questions"""
    return f"""
As a security architect with expertise in threat modeling, analyze the following application context and generate
specific questions to gather additional security-relevant information. Focus on areas that would impact the threat model.

APPLICATION CONTEXT:
- Type: {app_type}
- Authentication: {', '.join(authentication)}
- Internet Facing: {internet_facing}
- Data Sensitivity: {sensitive_data}
- Description: {app_input}

Generate 5-7 specific questions that would help gather important security context missing from the above description.
The questions should:
1. Be specific to the application type and context provided
2. Focus on security-relevant architectural details
3. Help identify potential threat vectors
4. Cover relevant compliance and regulatory requirements based on data sensitivity
5. Address integration and dependency security concerns

Format the response as a JSON array of questions only. Example:
{{"questions": [
    "What authentication flows and session management mechanisms are implemented?",
    "How is sensitive data encrypted at rest and in transit?"
]}}"""

def create_context_analysis_prompt(questions_and_answers: Dict[str, str]) -> str:
    """Create prompt for analyzing Q&A context"""
    qa_formatted = "\n".join([f"Q: {q}\nA: {a}" for q, a in questions_and_answers.items()])
    
    return f"""
Analyze the following Q&A session and extract key security-relevant information for threat modeling.
Synthesize the information into a clear, structured summary.

Q&A SESSION:
{qa_formatted}

Format the response as a JSON object with these sections:
{{
    "security_components": [],    // Key security mechanisms identified
    "threat_vectors": [],        // Potential threat vectors revealed
    "sensitive_assets": [],      // Critical assets requiring protection
    "dependencies": [],          // External dependencies and integrations
    "constraints": []            // Security constraints and requirements
}}"""

def get_contextual_questions(api_key: str, model_name: str, prompt: str) -> List[str]:
    """Get contextual questions using OpenAI API"""
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a security architect generating questions for threat modeling."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        st.error(f"Error generating questions: {str(e)}")
        return {"questions": []}

def get_contextual_questions_ollama(model_name: str, prompt: str) -> List[str]:
    """Get contextual questions using Ollama"""
    try:
        url = "http://localhost:11434/api/chat"
        data = {
            "model": model_name,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a security architect generating questions for threat modeling."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "format": "json",
            "stream": False
        }
        response = requests.post(url, json=data)
        return response.json()["message"]["content"]
    except Exception as e:
        st.error(f"Error generating questions with Ollama: {str(e)}")
        return {"questions": []}

def analyze_qa_context(api_key: str, model_name: str, prompt: str) -> Dict[str, Any]:
    """Analyze Q&A context using OpenAI API"""
    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a security architect analyzing threat modeling context."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        st.error(f"Error analyzing context: {str(e)}")
        return {}

def analyze_qa_context_ollama(model_name: str, prompt: str) -> Dict[str, Any]:
    """Analyze Q&A context using Ollama"""
    try:
        url = "http://localhost:11434/api/chat"
        data = {
            "model": model_name,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a security architect analyzing threat modeling context."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "format": "json",
            "stream": False
        }
        response = requests.post(url, json=data)
        return response.json()["message"]["content"]
    except Exception as e:
        st.error(f"Error analyzing context with Ollama: {str(e)}")
        return {}