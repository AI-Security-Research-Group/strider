# services/app_service.py

from typing import Dict, Any, Tuple, List
import streamlit as st
import pandas as pd
import json
from services.attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_ollama
from services.dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_ollama, dread_json_to_markdown
from services.mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_ollama
from services.test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_ollama
from services.knowledge_base.service import KnowledgeBaseService
from services.agents.agent_factory import SecurityAgentFactory
from services.threat_model import (
    create_threat_model_prompt, get_threat_model, get_threat_model_ollama,
    json_to_markdown, create_image_analysis_prompt, get_image_analysis
)
from services.technology_analyzer import TechnologyStackAnalyzer, IntegrationAnalyzer, analyze_architecture
from utils.file_processing import process_uploaded_file
from utils.image_processing import analyze_image_ollama
from utils.database import DatabaseManager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AppService:
    def __init__(self):
        self.tech_analyzer = TechnologyStackAnalyzer()
        self.integration_analyzer = IntegrationAnalyzer()
        self.kb_service = KnowledgeBaseService()
        self.db_manager = DatabaseManager() 
        logger.info("AppService initialized with technology analyzers")

    def process_file(self, uploaded_file) -> Tuple[str, bool]:
        """Process uploaded PDF or TXT file"""
        return process_uploaded_file(uploaded_file)

    def analyze_image(self, 
                    image_data: bytes, 
                    model_provider: str, 
                    api_key: str = None, 
                    model_name: str = None) -> Dict[str, Any]:
        """Simplified image analysis with basic prompt"""
        try:
            logger.info(f"Starting basic image analysis with provider: {model_provider}")
            
            # Get basic analysis
            if model_provider == "Ollama":
                logger.info("Using Ollama for image analysis")
                analysis_result = analyze_image_ollama(image_data, create_image_analysis_prompt(), model_name)
            else:
                logger.info("Using OpenAI for image analysis")
                analysis_result = get_image_analysis(api_key, model_name, create_image_analysis_prompt(), image_data)

            if not analysis_result:
                logger.error("Image analysis failed")
                return None

            logger.info("Successfully completed image analysis")
            return analysis_result

        except Exception as e:
            logger.error(f"Error in image analysis: {str(e)}", exc_info=True)
            st.error(f"Error analyzing image: {str(e)}")
            return None

    def generate_threat_model(self, inputs: Dict[str, Any], model_config: Dict[str, str]) -> Dict[str, Any]:
        """Generate threat model based on inputs with enhanced component context"""
        try:
            logger.info("Starting enhanced threat model generation")
            
            # Create enhanced context with component and tech stack
            enhanced_context = {
                "components": inputs.get("components", []),
                "tech_stack": inputs.get("tech_stack", []),
                "app_type": inputs["app_type"],
                "authentication": inputs["authentication"],
                "internet_facing": inputs["internet_facing"],
                "sensitive_data": inputs["sensitive_data"],
                "use_agents": inputs.get("use_agents", False)
            }
            
            # Log analysis context
            logger.info("\n=== Analysis Context ===")
            logger.info(f"Components: {enhanced_context['components']}")
            logger.info(f"Tech Stack: {enhanced_context['tech_stack']}")
            logger.info(f"App Type: {enhanced_context['app_type']}")
            logger.info(f"Authentication: {enhanced_context['authentication']}")
            logger.info(f"Internet Facing: {enhanced_context['internet_facing']}")
            logger.info(f"Data Sensitivity: {enhanced_context['sensitive_data']}")
            logger.info(f"Using Agents: {enhanced_context['use_agents']}")

            try:
                # Generate base prompt
                prompt = create_threat_model_prompt(
                    inputs["app_type"],
                    inputs["authentication"],
                    inputs["internet_facing"],
                    inputs["sensitive_data"],
                    inputs["app_input"]
                )

                # Add component and tech stack context to prompt
                component_context = "\nComponents in scope:\n"
                for component in enhanced_context['components']:
                    component_context += f"- {component}\n"
                
                tech_context = "\nTechnology Stack:\n"
                for tech in enhanced_context['tech_stack']:
                    tech_context += f"- {tech}\n"

                enhanced_prompt = f"{prompt}\n{component_context}{tech_context}"
                
                # Log enhanced prompt
                logger.info("\n=== Enhanced Prompt ===")
                logger.info(enhanced_prompt)

                # Generate threat model based on provider
                if model_config["provider"] == "OpenAI API":
                    if not model_config["api_key"]:
                        logger.error("No OpenAI API key provided")
                        st.error("Please provide an OpenAI API key to proceed.")
                        return {}
                        
                    logger.info("\n=== Using OpenAI API ===")
                    use_agents = inputs.get("use_agents", False)
                    logger.info(f"Agent-based analysis: {use_agents}")
                    
                    result = get_threat_model(
                        model_config["api_key"], 
                        model_config["model_name"], 
                        enhanced_prompt,
                        use_agents
                    )
                    
                elif model_config["provider"] == "Ollama":
                    try:
                        logger.info("\n=== Using Ollama ===")
                        result = get_threat_model_ollama(
                            model_config["model_name"], 
                            enhanced_prompt,
                            inputs.get("use_agents", False)
                        )
                    except Exception as e:
                        logger.error(f"Error connecting to Ollama: {str(e)}")
                        st.info("Please ensure Ollama is running locally.")
                        return {}
                else:
                    logger.error(f"Unsupported model provider: {model_config['provider']}")
                    st.error("Unsupported model provider")
                    return {}

                # Process results
                if result:
                    # Log result statistics
                    logger.info("\n=== Analysis Results ===")
                    logger.info(f"Threats found: {len(result.get('threat_model', []))}")
                    logger.info(f"Improvements: {len(result.get('improvement_suggestions', []))}")
                    logger.info(f"Questions: {len(result.get('open_questions', []))}")

                    # Add component and tech stack context to results
                    result['analysis_context'] = {
                        'components': enhanced_context['components'],
                        'tech_stack': enhanced_context['tech_stack']
                    }

                    # Add KB-based threats for each component
                    kb_threats = []
                    for component in enhanced_context['components']:
                        # Get threats from knowledge base
                        component_threats = self.kb_service.get_component_threats(
                            component_type=component,
                            context={"name": component}
                        )
                        if component_threats:
                            logger.info(f"Found {len(component_threats)} KB threats for {component}")
                            kb_threats.extend(component_threats)

                    # Add KB threats to result
                    if kb_threats:
                        logger.info(f"Adding {len(kb_threats)} KB-based threats")
                        result['threat_model'].extend(kb_threats)

                    return result
                else:
                    logger.error("No result received from threat model generation")
                    return {
                        "threat_model": [],
                        "improvement_suggestions": [],
                        "open_questions": []
                    }

            except Exception as e:
                logger.error(f"Error in threat model generation: {str(e)}")
                logger.exception("Full traceback:")
                return {
                    "threat_model": [],
                    "improvement_suggestions": [],
                    "open_questions": []
                }
                
        except Exception as e:
            logger.error(f"Error in generate_threat_model: {str(e)}")
            logger.exception("Full traceback:")
            return {
                "threat_model": [],
                "improvement_suggestions": [],
                "open_questions": []
            }

    def generate_attack_tree(self, inputs: Dict[str, Any], model_config: Dict[str, str]) -> str:
        """Generate attack tree based on inputs"""
        logger.info("Generating attack tree")
        prompt = create_attack_tree_prompt(
            inputs["app_type"],
            inputs["authentication"],
            inputs["internet_facing"],
            inputs["sensitive_data"],
            inputs["app_input"]
        )
        
        if model_config["provider"] == "OpenAI API":
            return get_attack_tree(model_config["api_key"], model_config["model_name"], prompt)
        else:
            return get_attack_tree_ollama(model_config["model_name"], prompt)

    def generate_mitigations(self, threats_markdown: str, model_config: Dict[str, str]) -> str:
        """Generate mitigations based on threats"""
        logger.info("Generating mitigations")
        prompt = create_mitigations_prompt(threats_markdown)
        
        if model_config["provider"] == "OpenAI API":
            return get_mitigations(model_config["api_key"], model_config["model_name"], prompt)
        else:
            return get_mitigations_ollama(model_config["model_name"], prompt)

    def generate_dread_assessment(self, threats_markdown: str, model_config: Dict[str, str]) -> Dict[str, Any]:
        """Generate DREAD risk assessment"""
        logger.info("Generating DREAD assessment")
        prompt = create_dread_assessment_prompt(threats_markdown)
        
        if model_config["provider"] == "OpenAI API":
            return get_dread_assessment(model_config["api_key"], model_config["model_name"], prompt)
        else:
            return get_dread_assessment_ollama(model_config["model_name"], prompt)

    def generate_test_cases(self, threats_markdown: str, model_config: Dict[str, str]) -> str:
        """Generate test cases based on threats"""
        logger.info("Generating test cases")
        prompt = create_test_cases_prompt(threats_markdown)
        
        try:
            if model_config["provider"] == "OpenAI API":
                test_cases = get_test_cases(model_config["api_key"], model_config["model_name"], prompt)
            else:
                test_cases = get_test_cases_ollama(model_config["model_name"], prompt)
                
            # Save to database if we have a current model ID
            if 'current_model_id' in st.session_state and test_cases:
                try:
                    self.db_manager.update_threat_model(
                        st.session_state['current_model_id'],
                        test_cases=test_cases
                    )
                    logger.info("Successfully saved test cases to database")
                except Exception as e:
                    logger.error(f"Error saving test cases to database: {str(e)}")
                
            return test_cases
            
        except Exception as e:
            logger.error(f"Error generating test cases: {str(e)}")
            return f"Error generating test cases: {str(e)}"

    def _enhance_threat_context(self, inputs: Dict[str, Any], arch_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance the threat analysis context with technology information"""
        enhanced_inputs = inputs.copy()
        
        # Add technology context to application input
        tech_context = "\n\nTechnology Stack Analysis:\n"
        for component in arch_analysis.get('components', []):
            tech_context += f"\n{component.get('name', 'Unknown Component')}:\n"
            for tech in component.get('technologies', []):
                tech_context += f"- {tech.get('name', 'Unknown')} ({tech.get('category', 'Unknown')})\n"
                for impl in tech.get('security_implications', []):
                    tech_context += f"  * {impl}\n"

        # Add integration context
        tech_context += "\nIntegration Patterns:\n"
        for rel in arch_analysis.get('relationships', []):
            if rel.get('security_considerations'):
                tech_context += f"\n{rel.get('source', '')} → {rel.get('target', '')}:\n"
                for consid in rel['security_considerations']:
                    tech_context += f"- {consid['pattern']}\n"
                    for risk in consid.get('risks', []):
                        tech_context += f"  * {risk}\n"

        enhanced_inputs['app_input'] = inputs['app_input'] + tech_context
        return enhanced_inputs

    def _generate_technology_threats(self, arch_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate technology-specific threats"""
        tech_threats = []
        
        # Component-specific threats
        for component in arch_analysis.get('components', []):
            comp_name = component.get('name', 'Unknown Component')
            for tech in component.get('technologies', []):
                tech_name = tech.get('name', 'Unknown Technology')
                for impl in tech.get('security_implications', []):
                    tech_threats.append({
                        "Threat Type": self._categorize_tech_threat(impl),
                        "Scenario": f"Technology-specific threat in {comp_name} using {tech_name}: {impl}",
                        "Potential Impact": "Varies based on exploitation success"
                    })

        # Integration-specific threats
        for rel in arch_analysis.get('relationships', []):
            for consid in rel.get('security_considerations', []):
                for risk in consid.get('risks', []):
                    tech_threats.append({
                        "Threat Type": self._categorize_tech_threat(risk),
                        "Scenario": f"Integration threat between {rel.get('source', '')} and {rel.get('target', '')}: {risk}",
                        "Potential Impact": "Potential service disruption or data compromise"
                    })

        return tech_threats

    def _categorize_tech_threat(self, threat_desc: str) -> str:
        """Categorize technology threats into STRIDE"""
        threat_desc = threat_desc.lower()
        
        # STRIDE categorization mapping
        stride_categories = {
            'Spoofing': ['authentication', 'fake', 'impersonation', 'identity'],
            'Tampering': ['integrity', 'modify', 'injection', 'alter'],
            'Repudiation': ['logging', 'audit', 'track', 'deny'],
            'Information Disclosure': ['leak', 'disclosure', 'exposure', 'confidential'],
            'Denial of Service': ['dos', 'denial', 'availability', 'flood'],
            'Elevation of Privilege': ['privilege', 'escalation', 'permission', 'admin']
        }

        for category, keywords in stride_categories.items():
            if any(keyword in threat_desc for keyword in keywords):
                return category
                
        return "Information Disclosure"  # Default category

    def format_threat_model_output(self, model_output: Dict[str, Any]) -> str:
        """Format threat model output to markdown"""
        return json_to_markdown(
            model_output.get("threat_model", []),
            model_output.get("improvement_suggestions", []),
            model_output.get("open_questions", [])
        )

    def format_dread_output(self, dread_assessment: Dict[str, Any]) -> str:
        """Format DREAD assessment output to markdown"""
        return dread_json_to_markdown(dread_assessment)