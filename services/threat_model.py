import json
import requests
from typing import Optional, Dict, Any, List
from openai import OpenAI
import streamlit as st
import base64
import logging
from services.agents.agent_factory import SecurityAgentFactory
from .threat_model_compiler import ThreatModelCompiler
import logging

logger = logging.getLogger(__name__)

BASE_THREAT_FORMAT = """
{
    "threat_model": [
        {
            "Threat Type": "<STRIDE category>",
            "component_name": "<affected component>",
            "component_type": "<component type>",
            "technology": "<specific technology if applicable>",
            "Scenario": "<detailed attack scenario>",
            "Potential Impact": "<impact description>",
            "attack_vectors": ["vector1", "vector2"],
            "affected_components": ["component1", "component2"],
            "risk_score": "<1-10>"
        }
    ],
    "improvement_suggestions": [
        "<specific suggestions for security improvements>"
    ],
    "open_questions": [
        "<critical questions that need answers>"
    ],
    "analysis_details": "<comprehensive analysis>",
    "confidence_level": "<1-10 rating with explanation>"
}
"""

def json_to_markdown(threat_model: List[Dict[str, Any]], 
                    improvement_suggestions: List[str], 
                    open_questions: List[str]) -> str:
    """Convert STRIDE analyses to detailed markdown with enhanced layout"""
    
    # Update the STRIDE agents list to include Information Disclosure
    stride_results = {}
    if 'agent_analyses' in st.session_state:
        for agent_name, result in st.session_state['agent_analyses']:
            if agent_name in ["SpoofingExpert", "TamperingExpert", "RepudiationExpert", 
                            "DosExpert", "ElevationExpert", "InformationDisclosureExpert"]:
                stride_results[agent_name] = result

    # Add debug logging
    logger.info("Processing threat model for display")
    logger.info(f"Total STRIDE results: {len(stride_results)}")

    if not stride_results:
        return "No threat analysis available."

    st.markdown("# 🛡️ Security Analysis Dashboard")

    # Collect all threats from STRIDE results and identify KB threats
    all_threats = []
    kb_threats = []
    for agent_name, result in stride_results.items():
        agent_threats = result.get('threats', [])
        logger.info(f"Agent {agent_name} has {len(agent_threats)} threats")
        
        for threat in agent_threats:
            if threat.get('source') == 'Knowledge Base':
                kb_threats.append(threat)
            all_threats.append(threat)

    # Log threat counts
    logger.info(f"Total threats: {len(all_threats)}")
    logger.info(f"KB threats: {len(kb_threats)}")

    # Overall metrics at the top
    total_threats = len(all_threats)
    total_high_risks = sum(
        1 for threat in all_threats 
        if float(threat.get('risk_score', 0)) >= 7
    )

    # Create metric columns with KB info
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Threats", total_threats)
    with col2:
        st.metric("High Risk Threats", total_high_risks)
    with col3:
        st.metric("KB Threats", len(kb_threats))
    with col4:
        st.metric("STRIDE Categories", len(stride_results))

    # Display KB threats if present
    if kb_threats:
        st.markdown("## 📚 Knowledge Base Verified Threats")
        for threat in kb_threats:
            with st.expander(f"🔒 {threat.get('name', 'KB Threat')} - {threat.get('Threat Type', 'Unknown')}"):
                col1, col2 = st.columns([2,1])
                
                with col1:
                    st.markdown(f"""
                    **Description:**  
                    {threat.get('Scenario', 'No description provided')}
                    
                    **Component:** {threat.get('component_name', 'N/A')}  
                    **Category:** {threat.get('Threat Type', 'N/A')}
                    """)
                    
                    if threat.get('attack_vectors'):
                        st.markdown("**Attack Vectors:**")
                        for vector in threat['attack_vectors']:
                            st.markdown(f"🔶 {vector}")

                with col2:
                    severity = threat.get('severity', 'medium').lower()
                    severity_colors = {
                        'high': '#dc3545',
                        'medium': '#ffc107',
                        'low': '#28a745'
                    }
                    st.markdown(f"""
                    <div style='background-color: {severity_colors.get(severity, '#6c757d')}; 
                         color: white; padding: 15px; border-radius: 10px; text-align: center;'>
                        <h3 style='margin: 0;'>{severity.upper()}</h3>
                        <p style='margin: 0;'>Severity Level</p>
                    </div>
                    """, unsafe_allow_html=True)

                if threat.get('mitigations'):
                    st.markdown("**Recommended Mitigations:**")
                    for mitigation in threat['mitigations']:
                        st.markdown(f"✓ {mitigation}")

        st.markdown("---")

    # Display open questions if present
    if open_questions:
        st.markdown("## ❓ Open Questions")
        for question in open_questions:
            st.info(f"🤔 {question}")
        st.markdown("---")

    # Main content in tabs (existing STRIDE analysis)
    tabs = st.tabs([name.replace('Expert', '').upper() for name in stride_results.keys()])
    
    for tab, (agent_name, result) in zip(tabs, stride_results.items()):
        with tab:
            # Rest of your existing tab content...
            st.markdown(f"""
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <h2>{agent_name.replace('Expert', '')} Analysis</h2>
                <div style='background-color: #f0f2f6; padding: 8px 15px; border-radius: 15px;'>
                    Confidence: {result.get('confidence_level', 'N/A')}/10
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Threats section
            if result.get('threats'):
                for threat in result['threats']:
                    # Skip KB threats as they're already displayed
                    if threat.get('source') == 'Knowledge Base':
                        continue
                        
                    risk_score = float(threat.get('risk_score', 0))
                    risk_color = ("🔴" if risk_score >= 7 else 
                                "🟡" if risk_score >= 4 else "🟢")
                    
                    with st.container():
                        # Your existing threat display code...
                        st.markdown(f"""
                        <div style='border-left: 4px solid {"red" if risk_score >= 7 else "orange" if risk_score >= 4 else "green"}; 
                                    padding: 10px; margin: 10px 0; background-color: #f8f9fa;'>
                            <h3 style='margin: 0;'>{risk_color} {threat.get('Threat Type')}</h3>
                            <p style='margin: 5px 0; font-size: 1.1em;'>{threat.get('Scenario')}</p>
                        </div>
                        """, unsafe_allow_html=True)

                        # Rest of your existing threat display code...
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            st.markdown("**Details**")
                            st.markdown(f"""
                            - **Component:** {threat.get('component_name', 'N/A')}
                            - **Impact:** {threat.get('Potential Impact', 'N/A')}
                            """)

                            if threat.get('attack_vectors'):
                                st.markdown("**Attack Vectors:**")
                                for vector in threat['attack_vectors']:
                                    st.markdown(f"🔶 {vector}")

                            if threat.get('affected_components'):
                                st.markdown("**Affected Components:**")
                                for comp in threat['affected_components']:
                                    st.markdown(f"⚡ {comp}")

                        with col2:
                            st.markdown(f"""
                            <div style='background-color: {"#dc3545" if risk_score >= 7 else "#ffc107" if risk_score >= 4 else "#28a745"}; 
                                      color: white; padding: 20px; border-radius: 10px; text-align: center;'>
                                <h2 style='margin: 0;'>{risk_score}/10</h2>
                                <p style='margin: 0;'>Risk Score</p>
                            </div>
                            """, unsafe_allow_html=True)

            # Rest of your existing code for recommendations and questions...
            col1, col2 = st.columns(2)
            with col1:
                with st.expander("💡 Improvement Suggestions", expanded=True):
                    for sugg in result.get('improvement_suggestions', []):
                        st.markdown(f"- {sugg}")
            
            with col2:
                with st.expander("❓ Open Questions", expanded=True):
                    for q in result.get('open_questions', []):
                        st.markdown(f"- {q}")

            if result.get('analysis_details'):
                with st.expander("📋 Full Analysis Details"):
                    st.markdown(result['analysis_details'])

    return ""  # Return empty string as we're using direct st.markdown


def format_agent_analysis(agent_analyses: List[tuple]) -> str:
    """Format the agent analysis results into Markdown format"""
    markdown = "# Detailed Security Analysis\n\n"
    
    # Process each agent's analysis
    for agent_name, solution in agent_analyses:
        if not solution:  # Skip if no solution
            continue
            
        markdown += f"## {agent_name}\n\n"
        
        if isinstance(solution, dict):
            # Handle threats
            if "threats" in solution:
                markdown += "### Identified Threats\n\n"
                markdown += "| Threat Type | Scenario | Potential Impact |\n"
                markdown += "|-------------|----------|------------------|\n"
                
                for threat in solution["threats"]:
                    threat_type = threat.get("Threat Type", "Unknown")
                    scenario = threat.get("Scenario", "Not specified")
                    impact = threat.get("Potential Impact", "Not specified")
                    markdown += f"| {threat_type} | {scenario} | {impact} |\n"
                
                markdown += "\n"
            
            # Handle analysis details
            if "analysis_details" in solution:
                markdown += f"### Analysis Details\n{solution['analysis_details']}\n\n"
            
            # Handle confidence level
            if "confidence_level" in solution:
                markdown += f"### Confidence Level\n{solution['confidence_level']}\n\n"
            
            # Only show improvement suggestions and open questions for ThreatModelCompiler
            if agent_name == "ThreatModelCompiler":
                if "improvement_suggestions" in solution:
                    markdown += "### Improvement Suggestions\n\n"
                    for suggestion in solution["improvement_suggestions"]:
                        markdown += f"- {suggestion}\n"
                    markdown += "\n"
                
                if "open_questions" in solution:
                    markdown += "### Open Questions\n\n"
                    for question in solution["open_questions"]:
                        markdown += f"- {question}\n"
                    markdown += "\n"
            
        elif isinstance(solution, str):
            # Handle raw string output
            markdown += f"{solution}\n\n"
        
        markdown += "---\n\n"

    return markdown

def create_threat_model_prompt(app_type: str, authentication: List[str], 
                             internet_facing: str, sensitive_data: str, 
                             app_input: str) -> str:
    """Create prompt for threat model generation"""
    return f"""

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION:
{app_input}

Provide response in this JSON format:
{BASE_THREAT_FORMAT}
"""

def create_image_analysis_prompt() -> str:
    """Create prompt for analyzing architecture diagrams"""
    return """
You are a Senior Solution Architect analyzing an architecture diagram for security threat modeling.
Focus on:
1. Key components and their interactions
2. Data flows and trust boundaries
3. External interfaces and integration points
4. Security-relevant technologies and protocols

Provide a clear, structured explanation suitable for security analysis.
Do not include phrases like "The image shows..." - focus directly on the architectural details.
Only include information visible in the diagram - do not make assumptions about unseen components.
"""

def analyze_with_agents(prompt: str, model_config: Dict[str, str]) -> Dict[str, Any]:
    """Analyze system using specialized security agents with enhanced compilation"""
    try:
        factory = SecurityAgentFactory()
        agents = factory.create_agents()
        compiler = ThreatModelCompiler()
        
        previous_solution = None
        all_solutions = []
        
        with st.spinner("Analyzing with specialized security agents..."):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for idx, agent in enumerate(agents):
                progress = (idx + 1) / len(agents)
                progress_bar.progress(progress)
                status_text.text(f"Agent {agent.name} analyzing... ({int(progress * 100)}%)")
                
                # Get architecture analysis from session state
                arch_analysis = st.session_state.get('architecture_analysis', {})
                
                # Pass architecture analysis to agent
                solution = agent.get_solution(prompt, previous_solution, arch_analysis)
                all_solutions.append((agent.name, solution))
                
                if solution and isinstance(solution, (dict, str)):
                    previous_solution = solution
                
            progress_bar.empty()
            status_text.empty()
        
        # Store all solutions for reference
        st.session_state['agent_analyses'] = all_solutions
        
        # Use new compiler to create final threat model
        logger.info("Compiling final threat model with component context")
        arch_analysis = st.session_state.get('architecture_analysis', {})
        final_model = compiler.compile_threat_model(all_solutions, arch_analysis)
        
        return final_model
        
    except Exception as e:
        logger.error(f"Agent-based analysis failed: {str(e)}", exc_info=True)
        return {
            "threat_model": [],
            "improvement_suggestions": [],
            "open_questions": []
        }


def get_image_analysis(api_key: str, model_name: str, prompt: str, 
                      image_data: bytes, provider: str = "openai") -> Optional[Dict]:
    """Analyze architecture diagram"""
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
                        {"type": "text", "text": prompt},
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
            
    except Exception as e:
        logger.error(f"Error analyzing image: {str(e)}")
        return None

def get_threat_model(api_key: str, model_name: str, prompt: str, use_agents: bool = True) -> Dict[str, Any]:
    """Get threat model using OpenAI"""
    try:
        model_config = {
            "provider": "OpenAI API",
            "api_key": api_key,
            "model_name": model_name
        }
        return analyze_with_agents(prompt, model_config)
    except Exception as e:
        st.error(f"Error in OpenAI analysis: {str(e)}")
        return {
            "threat_model": [],
            "improvement_suggestions": [],
            "open_questions": []
        }

def get_threat_model_ollama(ollama_model: str, prompt: str, use_agents: bool = True) -> Dict[str, Any]:
    """Get threat model using Ollama"""
    try:
        model_config = {
            "provider": "Ollama",
            "model_name": ollama_model
        }
        return analyze_with_agents(prompt, model_config)
    except Exception as e:
        st.error(f"Error in Ollama analysis: {str(e)}")
        return {
            "threat_model": [],
            "improvement_suggestions": [],
            "open_questions": []
        }

def combine_threat_analyses(analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine multiple threat analyses into a single model"""
    combined = {
        "threat_model": [],
        "improvement_suggestions": set(),
        "open_questions": set()
    }
    
    seen_scenarios = set()
    
    for analysis in analyses:
        if not isinstance(analysis, dict):
            continue
            
        # Process threats
        for threat in analysis.get("threat_model", []):
            # Create a unique key for the scenario
            scenario_key = f"{threat['Threat Type']}:{threat['Scenario']}"
            if scenario_key not in seen_scenarios:
                seen_scenarios.add(scenario_key)
                combined["threat_model"].append(threat)
        
        # Process improvement suggestions and questions
        combined["improvement_suggestions"].update(analysis.get("improvement_suggestions", []))
        combined["open_questions"].update(analysis.get("open_questions", []))
    
    # Convert sets back to lists for JSON serialization
    return {
        "threat_model": combined["threat_model"],
        "improvement_suggestions": list(combined["improvement_suggestions"]),
        "open_questions": list(combined["open_questions"])
    }