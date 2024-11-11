import streamlit as st
import streamlit.components.v1 as components
import requests
from typing import Dict, List, Any, Tuple
from services.app_service import AppService
from services.technology_analyzer import TechnologyStackAnalyzer, IntegrationAnalyzer
import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

class AppUI:
    def __init__(self):
        self.service = AppService()
        self.tech_analyzer = TechnologyStackAnalyzer()
        self.integration_analyzer = IntegrationAnalyzer()
        self.setup_page_config()
        self.load_env_variables()

    def render_technology_analysis(self, analysis: Dict[str, Any]) -> None:
        """Render technology stack analysis results"""
        if not analysis:
            return

        st.markdown("## Technology Stack Analysis")
        
        # Create tabs for different views
        tech_tab, integr_tab, sec_tab = st.tabs([
            "Technology Stack", "Integration Patterns", "Security Summary"
        ])

        with tech_tab:
            self._render_technology_stack(analysis.get('components', []))

        with integr_tab:
            self._render_integration_patterns(analysis.get('relationships', []))

        with sec_tab:
            self._render_security_summary(analysis.get('security_summary', {}))

    def _render_technology_stack(self, components: list[Dict[str, Any]]) -> None:
        """Render technology stack details"""
        for component in components:
            with st.expander(f"🔹 {component['name']} ({component['type']})"):
                # Technologies used
                if component.get('technologies'):
                    st.markdown("**Technologies:**")
                    for tech in component['technologies']:
                        st.markdown(f"- **{tech['name']}** ({tech['category']})")
                        with st.expander("Security Implications"):
                            for impl in tech.get('security_implications', []):
                                st.markdown(f"- {impl}")

    def _render_integration_patterns(self, relationships: list[Dict[str, Any]]) -> None:
        """Render integration pattern details"""
        for rel in relationships:
            if rel.get('security_considerations'):
                with st.expander(f"🔗 {rel.get('source', '')} → {rel.get('target', '')}"):
                    # Display relationship details
                    st.markdown(f"**Data Flow:** {rel.get('data_flow', 'N/A')}")
                    if rel.get('requires_encryption'):
                        st.warning("⚠️ Requires Encryption")

                    # Security considerations
                    st.markdown("**Security Considerations:**")
                    for consid in rel['security_considerations']:
                        st.markdown(f"- **{consid['pattern']}**")
                        for risk in consid['risks']:
                            st.markdown(f"  - {risk}")

    def _render_security_summary(self, summary: Dict[str, Any]) -> None:
        """Render security summary"""
        # Critical Components
        if summary.get('critical_components'):
            st.error("⚠️ Critical Components Identified")
            for comp in summary['critical_components']:
                st.markdown(f"- {comp}")

        # Sensitive Data Flows
        if summary.get('sensitive_data_flows'):
            st.warning("🔒 Sensitive Data Flows")
            for flow in summary['sensitive_data_flows']:
                st.markdown(f"- {flow.get('source', '')} → {flow.get('target', '')}")

        # High Risk Technologies
        if summary.get('high_risk_technologies'):
            st.warning("⚠️ High Risk Technologies")
            for tech in summary['high_risk_technologies']:
                st.markdown(f"- {tech}")
        
    def setup_page_config(self):
        """Configure the Streamlit page"""
        st.set_page_config(
            page_title="STRIDER",
            page_icon=":shield:",
            layout="wide",
            initial_sidebar_state="expanded"
        )

    def load_env_variables(self):
        """Load environment variables"""
        if os.path.exists('.env'):
            load_dotenv('.env')
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if openai_api_key:
            st.session_state['openai_api_key'] = openai_api_key

    def render_sidebar(self) -> Tuple[str, str, str]:
        """Render sidebar and return model configuration"""
        st.markdown(
    """
    <h1 font-family: Arial, sans-serif; font-weight: bold;'>
        STRIDER
    </h1>
    """,
    unsafe_allow_html=True
)

        # Additional description below the logo
        st.write(
            """
            **🤖 Automated Self-Serve Threat Modeling Assistant for Engineering Teams**
            
            """
            
            )

        st.sidebar.header("How to use STRIDER")
        
        
        model_provider = st.sidebar.selectbox(
            "Select your preferred model provider:",
            ["Ollama", "OpenAI API"],
            key="model_provider",
            help="Select the model provider you would like to use. Ollama is recommended for local processing."
        )
        
        api_key = None
        model_name = None
        
        if model_provider == "Ollama":
            st.sidebar.markdown("""
            1. Ensure Ollama is running locally 🚀
            2. For image analysis, ensure you have the Llava model installed
            3. Provide details of the application that you would like to threat model 📝
            """)
            
            try:
                response = requests.get("http://localhost:11434/api/tags")
                data = response.json()
                available_models = [model["name"] for model in data["models"]]
                model_name = st.sidebar.selectbox(
                    "Select the model you would like to use:",
                    available_models,
                    index=available_models.index("llama3.1:latest") if "llama3.1:latest" in available_models else 0,
                    key="selected_model",
                )
            except requests.exceptions.RequestException:
                st.sidebar.error("Could not connect to Ollama. Please ensure the Ollama server is running.")
                
        elif model_provider == "OpenAI API":
            st.sidebar.markdown("""
            1. Enter your OpenAI API key and chosen model below 🔑
            2. Provide details of the application that you would like to threat model 📝
            3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
            """)
            
            api_key = st.sidebar.text_input(
                "Enter your OpenAI API key:",
                value=st.session_state.get('openai_api_key', ''),
                type="password",
            )
            if api_key:
                st.session_state['openai_api_key'] = api_key
                
            model_name = st.sidebar.selectbox(
                "Select the model you would like to use:",
                ["gpt-4", "gpt-4-turbo"],
                key="selected_model",
            )

        # Add analysis type selection here, after model selection
        st.sidebar.markdown("---")
        st.sidebar.markdown("### Analysis Configuration")
        analysis_type = st.sidebar.radio(
            "Select Analysis Type",
            ["Standard Analysis", "Agent-based Analysis"],
            help="""
            Choose the analysis method:
            - Standard Analysis: Single-pass threat analysis
            - Agent-based Analysis: Multiple specialized security experts analyze the system
            """
        )
        st.session_state['use_agents'] = analysis_type == "Agent-based Analysis"
            
        return model_provider, api_key, model_name

    def render_input_section(self) -> Dict[str, Any]:
        """Render input section with proper state management"""
        col1, col2 = st.columns([1, 1])
        
        with col1:
            # Initialize session states if not exist
            if 'app_input' not in st.session_state:
                st.session_state['app_input'] = ''
            if 'doc_content' not in st.session_state:
                st.session_state['doc_content'] = ''
            if 'image_analysis' not in st.session_state:
                st.session_state['image_analysis'] = ''

            # File upload section
            uploaded_doc = st.file_uploader(
                "Upload a PDF or TXT file",
                type=['pdf', 'txt'],
                key="doc_uploader",
                help="Upload a PDF or TXT file containing your application details."
            )
            
            if uploaded_doc and uploaded_doc != st.session_state.get('last_uploaded_doc', ''):
                with st.spinner('Processing uploaded file...'):
                    file_content, success = self.service.process_file(uploaded_doc)
                    if success:
                        st.session_state['last_uploaded_doc'] = uploaded_doc
                        st.session_state['doc_content'] = file_content
                        # Combine document content with existing image analysis
                        combined_content = self._combine_content()
                        st.session_state['app_input'] = combined_content
                        st.success(f"Successfully processed {uploaded_doc.name}")
                    else:
                        st.error("Failed to process the uploaded file.")

            # Image upload section
            uploaded_image = st.file_uploader(
                "Upload architecture diagram (optional)",
                type=["jpg", "jpeg", "png"],
                key="image_uploader",
                help="Upload an architecture diagram for analysis."
            )

            if uploaded_image:
                self.handle_image_upload(uploaded_image)
                
            # Text area with combined content
            input_text = st.text_area(
                label="Describe the application to be modelled",
                value=st.session_state['app_input'],
                placeholder="Enter your application details...",
                height=300,
                key="app_desc"
            )
            # Update session state when text changes manually
            if input_text != st.session_state['app_input']:
                st.session_state['app_input'] = input_text
                    
        with col2:
            # Application details
            st.markdown("### Application Details")
            app_type = st.selectbox(
                label="Select the application type",
                options=[
                    "Web application",
                    "Mobile application",
                    "Desktop application",
                    "Cloud application",
                    "IoT application",
                    "Other",
                ],
            )
            
            # New Component Configuration Section
            st.markdown("### Component Configuration")
            
            # Component Selection
            components = st.multiselect(
                "Select Components",
                options=[
                    "Azure Storage",
                    "Application Insights",
                    "Azure Cognitive Service",
                    "API Gateway",
                    "Load Balancer",
                    "Web Frontend",
                    "Backend Service",
                    "Database",
                    "Cache",
                    "Message Queue",
                    "Authentication Service",
                    "Custom"
                ],
                help="Select the components used in your application"
            )

            # If Custom is selected, allow custom component input
            if "Custom" in components:
                custom_component = st.text_input(
                    "Custom Component Name",
                    help="Enter the name of your custom component"
                )
                if custom_component:
                    components = [c if c != "Custom" else custom_component for c in components]

            # Technology Stack Selection
            tech_stack = st.multiselect(
                "Select Technology Stack",
                options=[
                    "Azure Cloud",
                    "AWS Cloud",
                    "GCP Cloud",
                    "Node.js",
                    "Python",
                    "Java",
                    "React",
                    "Angular",
                    "Vue.js",
                    "PostgreSQL",
                    "MongoDB",
                    "Redis",
                    "RabbitMQ",
                    "Kafka",
                    "Docker",
                    "Kubernetes",
                    "Custom"
                ],
                help="Select the technologies used in your application"
            )

            # If Custom is selected in tech stack
            if "Custom" in tech_stack:
                custom_tech = st.text_input(
                    "Custom Technology",
                    help="Enter the name of your custom technology"
                )
                if custom_tech:
                    tech_stack = [t if t != "Custom" else custom_tech for t in tech_stack]
            
            # Existing fields...
            sensitive_data = st.selectbox(
                label="What is the highest sensitivity level of the data processed by the application?",
                options=[
                    "Top Secret",
                    "Secret",
                    "Confidential",
                    "Restricted",
                    "Unclassified",
                    "None",
                ],
            )
            
            internet_facing = st.selectbox(
                label="Is the application internet-facing?",
                options=["Yes", "No"],
            )
            
            authentication = st.multiselect(
                "What authentication methods are supported by the application?",
                ["SSO", "MFA", "OAUTH2", "Basic", "None","SSO","Access Token"],
            )
        
        # Include component and tech stack in return value
        return {
            "app_input": input_text,
            "app_type": app_type,
            "sensitive_data": sensitive_data,
            "internet_facing": internet_facing,
            "authentication": authentication,
            "components": components,
            "tech_stack": tech_stack,
            "use_agents": st.session_state.get('use_agents', False)
        }

    def _combine_content(self) -> str:
        """Combine image analysis and document content"""
        combined = []
        
        # Add image analysis if exists
        if st.session_state.get('image_analysis'):
            combined.append("Architecture Analysis:")
            combined.append(st.session_state['image_analysis'])
            
        # Add document content if exists
        if st.session_state.get('doc_content'):
            combined.append(st.session_state['doc_content'])
            
        return "\n\n".join(filter(None, combined))

    def generate_threat_model(self, inputs: Dict[str, Any], model_config: Dict[str, str]) -> Dict[str, Any]:
        """
        Generate threat model based on inputs with enhanced logging
        """
        try:
            # Log initial configuration
            st.write("Configuration:")
            st.write(f"- Analysis Type: {'Agent-based' if inputs.get('use_agents') else 'Standard'}")
            st.write(f"- Model Provider: {model_config['provider']}")
            st.write(f"- Model Name: {model_config['model_name']}")
            
            # Create the analysis prompt
            prompt = create_threat_model_prompt(
                inputs["app_type"],
                inputs["authentication"],
                inputs["internet_facing"],
                inputs["sensitive_data"],
                inputs["app_input"]
            )
            
            use_agents = inputs.get("use_agents", False)
            st.session_state['debug_use_agents'] = use_agents  # Store for debugging
            
            # Debug information
            with st.expander("Debug Information", expanded=False):
                st.write("Analysis Configuration:")
                st.write(inputs)
                st.write("\nModel Configuration:")
                st.write({k: v for k, v in model_config.items() if k != 'api_key'})
                
            if use_agents:
                st.write("🤖 Starting agent-based security analysis...")
                st.info("Agent Pipeline: Spoofing → Tampering → Repudiation → DoS → Elevation → Compiler")
            else:
                st.write("🔍 Starting standard security analysis...")
                
            # Generate threat model based on provider
            if model_config["provider"] == "OpenAI API":
                if not model_config["api_key"]:
                    st.error("Please provide an OpenAI API key to proceed.")
                    return {}
                    
                try:
                    st.write(f"Initiating {'agent-based' if use_agents else 'standard'} analysis with OpenAI...")
                    result = get_threat_model(
                        model_config["api_key"], 
                        model_config["model_name"], 
                        prompt,
                        use_agents
                    )
                    st.write("✅ Analysis completed")
                    
                    # Log result structure
                    with st.expander("Response Structure", expanded=False):
                        st.write({
                            "keys_present": list(result.keys()) if isinstance(result, dict) else "Not a dictionary",
                            "threats_count": len(result.get("threat_model", [])) if isinstance(result, dict) else 0,
                            "agent_analyses_present": 'agent_analyses' in st.session_state
                        })
                    
                except Exception as e:
                    st.error(f"OpenAI analysis failed: {str(e)}")
                    return {}
                    
            elif model_config["provider"] == "Ollama":
                try:
                    # Check Ollama connection
                    response = requests.get("http://localhost:11434/api/tags")
                    if response.status_code != 200:
                        st.error("Could not connect to Ollama server")
                        return {}
                        
                    st.write(f"Initiating {'agent-based' if use_agents else 'standard'} analysis with Ollama...")
                    result = get_threat_model_ollama(
                        model_config["model_name"], 
                        prompt,
                        use_agents
                    )
                    st.write("✅ Analysis completed")
                    
                    # Log result structure
                    with st.expander("Response Structure", expanded=False):
                        st.write({
                            "keys_present": list(result.keys()) if isinstance(result, dict) else "Not a dictionary",
                            "threats_count": len(result.get("threat_model", [])) if isinstance(result, dict) else 0,
                            "agent_analyses_present": 'agent_analyses' in st.session_state
                        })
                    
                except Exception as e:
                    st.error(f"Error connecting to Ollama: {str(e)}")
                    st.info("Please ensure Ollama is running locally.")
                    return {}
            else:
                st.error("Unsupported model provider")
                return {}
                
            # Display agent analyses if available
            if use_agents and 'agent_analyses' in st.session_state:
                st.write("📊 Displaying detailed agent analyses...")
                with st.expander("Detailed Agent Analyses", expanded=True):
                    st.markdown(format_agent_analysis(st.session_state['agent_analyses']))
            elif use_agents:
                st.warning("Agent analyses were expected but not found in results")
                
            return result
            
        except Exception as e:
            st.error(f"Error generating threat model: {str(e)}")
            st.write("Debug traceback:")
            st.exception(e)
            return {
                "threat_model": [],
                "improvement_suggestions": [],
                "open_questions": []
            }
            
        except Exception as e:
            st.error(f"Error generating threat model: {str(e)}")
            return {
                "threat_model": [],
                "improvement_suggestions": [],
                "open_questions": []
            }

    def handle_image_upload(self, uploaded_image):
        """Handle image upload and analysis"""
        if uploaded_image is not None:
            model_provider = st.session_state.get('model_provider')
            if model_provider == "OpenAI API":
                api_key = st.session_state.get('openai_api_key')
                if not api_key:
                    st.error("Please enter your OpenAI API key to analyse the image.")
                else:
                    self._process_image_analysis(uploaded_image, model_provider, api_key)
            elif model_provider == "Ollama":
                self._check_llava_and_process_image(uploaded_image)

    def _process_image_analysis(self, uploaded_image, model_provider, api_key=None):
        """Process image analysis with proper state management"""
        if 'uploaded_image' not in st.session_state or st.session_state.uploaded_image != uploaded_image:
            st.session_state.uploaded_image = uploaded_image
            with st.spinner("Analysing the uploaded image..."):
                try:
                    model_name = st.session_state.get('selected_model')
                    image_data = uploaded_image.read()
                    image_analysis_output = self.service.analyze_image(
                        image_data, 
                        model_provider,
                        api_key,
                        model_name
                    )
                    
                    if image_analysis_output:
                        analysis_content = image_analysis_output.get('analysis', '')
                        if analysis_content:
                            # Store image analysis separately
                            st.session_state['image_analysis'] = analysis_content
                            # Combine with existing document content
                            combined_content = self._combine_content()
                            st.session_state['app_input'] = combined_content
                            st.success("Successfully analyzed the architecture diagram")
                        else:
                            st.error("No analysis content received")
                    else:
                        st.error("Failed to analyze the image")
                except Exception as e:
                    st.error(f"Error during image analysis: {str(e)}")

    def _check_llava_and_process_image(self, uploaded_image):
        """Check for llama3.2-vision:latest model and process image if available"""
        try:
            response = requests.get("http://localhost:11434/api/tags")
            models = [m["name"] for m in response.json().get("models", [])]
            if "llama3.2-vision:latest" not in models:
                st.error("llama3.2-vision:latest model not found in Ollama. Please install it using: 'ollama pull llama3.2-vision:latest'")
            else:
                self._process_image_analysis(uploaded_image, "Ollama")
        except requests.exceptions.RequestException:
            st.error("Could not connect to Ollama. Please ensure the Ollama server is running.")

    def render_mermaid(self, code: str, height: int = 500) -> None:
        """Render Mermaid diagram"""
        components.html(
            f"""
            <pre class="mermaid" style="height: {height}px;">
                {code}
            </pre>

            <script type="module">
                import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
                mermaid.initialize({{ startOnLoad: true }});
            </script>
            """,
            height=height,
        )