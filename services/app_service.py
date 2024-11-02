import streamlit as st
from typing import Dict, Any, Tuple
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_ollama
from dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_ollama, dread_json_to_markdown
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_ollama
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_ollama
from threat_model import (
    create_threat_model_prompt, get_threat_model, get_threat_model_ollama,
    json_to_markdown, create_image_analysis_prompt, get_image_analysis
)
from utils.file_processing import process_uploaded_file
from utils.image_processing import analyze_image_ollama

class AppService:
    def process_file(self, uploaded_file) -> Tuple[str, bool]:
        """Process uploaded PDF or TXT file"""
        return process_uploaded_file(uploaded_file)

    def analyze_image(self, 
                        image_data: bytes, 
                        model_provider: str, 
                        api_key: str = None, 
                        model_name: str = None) -> Dict[str, Any]:
            """Analyze uploaded architecture diagram"""
            prompt = create_image_analysis_prompt()
            
            if model_provider == "Ollama":
                try:
                    analysis_result = analyze_image_ollama(image_data, prompt, model_name)
                    if analysis_result:
                        return {
                            "choices": [{
                                "message": {
                                    "content": analysis_result
                                }
                            }]
                        }
                    return None
                except Exception as e:
                    st.error(f"Error analyzing image with Ollama: {str(e)}")
                    return None
            else:
                return get_image_analysis(api_key, model_name, prompt, image_data, provider="openai")

    def generate_threat_model(self, 
                            inputs: Dict[str, Any], 
                            model_config: Dict[str, str]) -> Dict[str, Any]:
        """Generate threat model based on inputs"""
        prompt = create_threat_model_prompt(
            inputs["app_type"],
            inputs["authentication"],
            inputs["internet_facing"],
            inputs["sensitive_data"],
            inputs["app_input"]
        )
        
        if model_config["provider"] == "OpenAI API":
            return get_threat_model(model_config["api_key"], model_config["model_name"], prompt)
        elif model_config["provider"] == "Ollama":
            return get_threat_model_ollama(model_config["model_name"], prompt)

    def generate_attack_tree(self,
                           inputs: Dict[str, Any],
                           model_config: Dict[str, str]) -> str:
        """Generate attack tree based on inputs"""
        prompt = create_attack_tree_prompt(
            inputs["app_type"],
            inputs["authentication"],
            inputs["internet_facing"],
            inputs["sensitive_data"],
            inputs["app_input"]
        )
        
        if model_config["provider"] == "OpenAI API":
            return get_attack_tree(model_config["api_key"], model_config["model_name"], prompt)
        elif model_config["provider"] == "Ollama":
            return get_attack_tree_ollama(model_config["model_name"], prompt)

    def generate_mitigations(self,
                           threats_markdown: str,
                           model_config: Dict[str, str]) -> str:
        """Generate mitigations based on threats"""
        prompt = create_mitigations_prompt(threats_markdown)
        
        if model_config["provider"] == "OpenAI API":
            return get_mitigations(model_config["api_key"], model_config["model_name"], prompt)
        elif model_config["provider"] == "Ollama":
            return get_mitigations_ollama(model_config["model_name"], prompt)

    def generate_dread_assessment(self,
                                threats_markdown: str,
                                model_config: Dict[str, str]) -> Dict[str, Any]:
        """Generate DREAD risk assessment"""
        prompt = create_dread_assessment_prompt(threats_markdown)
        
        if model_config["provider"] == "OpenAI API":
            return get_dread_assessment(model_config["api_key"], model_config["model_name"], prompt)
        elif model_config["provider"] == "Ollama":
            return get_dread_assessment_ollama(model_config["model_name"], prompt)

    def generate_test_cases(self,
                          threats_markdown: str,
                          model_config: Dict[str, str]) -> str:
        """Generate test cases based on threats"""
        prompt = create_test_cases_prompt(threats_markdown)
        
        if model_config["provider"] == "OpenAI API":
            return get_test_cases(model_config["api_key"], model_config["model_name"], prompt)
        elif model_config["provider"] == "Ollama":
            return get_test_cases_ollama(model_config["model_name"], prompt)

    def format_threat_model_output(self, model_output: Dict[str, Any]) -> str:
        """Format threat model output to markdown"""
        threat_model = model_output.get("threat_model", [])
        improvement_suggestions = model_output.get("improvement_suggestions", [])
        open_questions = model_output.get("open_questions",[])
        return json_to_markdown(threat_model, improvement_suggestions, open_questions)

    def format_dread_output(self, dread_assessment: Dict[str, Any]) -> str:
        """Format DREAD assessment output to markdown"""
        return dread_json_to_markdown(dread_assessment)