import streamlit as st
import streamlit.components.v1 as components
import requests
from typing import Dict, List, Any, Tuple
from services.app_service import AppService
from services.technology_analyzer import TechnologyStackAnalyzer, IntegrationAnalyzer
from services.input_processor.processor import InputContextProcessor
import os
from dotenv import load_dotenv
import logging
from streamlit_quill import st_quill

logger = logging.getLogger(__name__)

class AppUI:
    def __init__(self):
        self.service = AppService()
        self.tech_analyzer = TechnologyStackAnalyzer()
        self.integration_analyzer = IntegrationAnalyzer()
        self.setup_page_config()
        self.load_env_variables()
        self.input_processor = InputContextProcessor()
        logger.info("AppUI initialized with Input Context Processor")        

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
            2. For image analysis, ensure you have the Llava model installed 💾
            3. Provide details of the application that you would like to threat model 📝
            4. Run pre-context analysis and refine context details. 💬
            5. Generate threat scenario for complete results. 📊

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
        """Render complete input section with pre-processing capabilities"""
        
        # Create two columns for layout
        col1, col2 = st.columns([1, 1])
        
        with col1:
            # Initialize session states if not exist
            if 'app_input' not in st.session_state:
                st.session_state['app_input'] = ''
            if 'doc_content' not in st.session_state:
                st.session_state['doc_content'] = ''
            if 'image_analysis' not in st.session_state:
                st.session_state['image_analysis'] = ''
            if 'enhanced_context' not in st.session_state:
                st.session_state['enhanced_context'] = ''
            if 'analysis_results' not in st.session_state:
                st.session_state['analysis_results'] = None

            # File Upload Section
            st.markdown("### 📁 Upload Files")
            with st.expander("Upload Documentation", expanded=True):
                # Document upload
                uploaded_doc = st.file_uploader(
                    "Upload application documentation",
                    type=['pdf', 'txt'],
                    key="doc_uploader",
                    help="Upload PDF or TXT files containing application details"
                )
                
                if uploaded_doc and uploaded_doc != st.session_state.get('last_uploaded_doc', ''):
                    with st.spinner('Processing documentation...'):
                        file_content, success = self.service.process_file(uploaded_doc)
                        if success:
                            st.session_state['last_uploaded_doc'] = uploaded_doc
                            st.session_state['doc_content'] = file_content
                            combined_content = self._combine_content()
                            st.session_state['app_input'] = combined_content
                            st.success(f"✅ Successfully processed {uploaded_doc.name}")
                        else:
                            st.error("❌ Failed to process the uploaded file")

                # Architecture diagram upload
                uploaded_image = st.file_uploader(
                    "Upload architecture diagram",
                    type=["jpg", "jpeg", "png"],
                    key="image_uploader",
                    help="Upload an architecture diagram for automated analysis"
                )

                if uploaded_image:
                    with st.spinner('Analyzing architecture diagram...'):
                        self.handle_image_upload(uploaded_image)

            # Application Description
            st.markdown("### 📝 Application Description")
            input_text = st.text_area(
                label="Describe your application",
                value=st.session_state.get('app_input', ''),
                placeholder="Enter application details, architecture, and security requirements...",
                height=300,
                key="app_desc",
                help="Provide comprehensive details about your application"
            )
            st.session_state['app_input'] = input_text

            # Pre-processing Button
            if st.button("🔄 Run Context Pre-processing", type="primary", help="Analyze and enhance context"):
                if st.session_state['app_input']:
                    with st.spinner("🔍 Analyzing application context..."):
                        try:
                            # Get model configuration
                            model_config = {
                                "provider": st.session_state.get('model_provider', 'Ollama'),
                                "api_key": st.session_state.get('openai_api_key', ''),
                                "model_name": st.session_state.get('selected_model', '')
                            }

                            # Run context pre-processing
                            analysis_results = self.input_processor.process_context(
                                st.session_state['app_input'],
                                model_config
                            )

                            # Store results
                            st.session_state['analysis_results'] = analysis_results
                            
                            # Format enhanced context
                            enhanced_context = self.input_processor.format_enhanced_context(analysis_results)
                            st.session_state['enhanced_context'] = enhanced_context

                            st.success("✅ Context pre-processing completed!")
                            
                        except Exception as e:
                            logger.error(f"Pre-processing error: {str(e)}")
                            st.error(f"❌ Error during pre-processing: {str(e)}")
                else:
                    st.warning("⚠️ Please provide application description before pre-processing")

        with col2:
            # Application Configuration
            st.markdown("### ⚙️ Application Configuration")
            
            # Application Type
            app_type = st.selectbox(
                "Application Type",
                options=[
                    "Web application",
                    "Mobile application",
                    "Desktop application",
                    "Cloud application",
                    "IoT application",
                    "Microservices",
                    "Serverless",
                    "Other"
                ],
                help="Select the type of application being analyzed"
            )

            # Component Configuration
            st.markdown("#### 🔧 Components")
            components = st.multiselect(
                "Select Components",
                options=[
                    "Frontend",
                    "Backend API",
                    "Database",
                    "Authentication Service",
                    "Load Balancer",
                    "Cache",
                    "Message Queue",
                    "Storage Service",
                    "CDN",
                    "Search Service",
                    "Analytics Service",
                    "Custom"
                ],
                help="Select all components used in your application"
            )

            # Custom Component Input
            if "Custom" in components:
                custom_component = st.text_input(
                    "Custom Component Name",
                    help="Enter the name of your custom component"
                )
                if custom_component:
                    components = [c if c != "Custom" else custom_component for c in components]

            # Technology Stack
            st.markdown("#### 💻 Technology Stack")
            tech_stack = st.multiselect(
                "Select Technologies",
                options=[
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
                    "AWS",
                    "Azure",
                    "GCP",
                    "Custom"
                ],
                help="Select all technologies used in your application"
            )

            # Custom Technology Input
            if "Custom" in tech_stack:
                custom_tech = st.text_input(
                    "Custom Technology",
                    help="Enter the name of your custom technology"
                )
                if custom_tech:
                    tech_stack = [t if t != "Custom" else custom_tech for t in tech_stack]

            # Security Configuration
            st.markdown("#### 🔒 Security Configuration")
            
            # Data Sensitivity
            sensitive_data = st.select_slider(
                "Data Sensitivity Level",
                options=["Public", "Internal", "Confidential", "Restricted", "Top Secret"],
                value="Internal",
                help="Select the highest sensitivity level of data processed"
            )

            # Internet Facing
            internet_facing = st.radio(
                "Internet Accessibility",
                options=["Public (Internet Facing)", "Private (Internal Only)"],
                help="Select whether the application is accessible from the internet"
            )

            # Authentication Methods
            authentication = st.multiselect(
                "Authentication Methods",
                options=[
                    "Username/Password",
                    "OAuth 2.0",
                    "JWT",
                    "SAML",
                    "Multi-factor Authentication",
                    "Biometric",
                    "SSO",
                    "None"
                ],
                help="Select all authentication methods used"
            )

        # End the columns section and start full-width content
        if st.session_state.get('analysis_results'):
            st.markdown("---")  # Add a separator for visual organization
            
            # Enhanced Context in full width
            if 'enhanced_context' not in st.session_state:
                st.session_state['enhanced_context'] = ''

            st.markdown("### ✏️ Enhanced Context")
            enhanced_text = st_quill(
                value=st.session_state['enhanced_context'],
                key="enhanced_context_area",
                html=False,
            )

            # Update session state when text changes
            if enhanced_text != st.session_state['enhanced_context']:
                st.session_state['enhanced_context'] = enhanced_text

            # Add a small space after the editor
            st.markdown("")

            # Create a placeholder for the Generate button from main.py
            button_placeholder = st.empty()

            # Return the inputs and button placeholder
            ret_val = {
                "app_input": st.session_state.get('enhanced_context', input_text),
                "app_type": app_type,
                "components": components,
                "tech_stack": tech_stack,
                "sensitive_data": sensitive_data,
                "internet_facing": internet_facing,
                "authentication": authentication,
                "button_placeholder": button_placeholder
            }

            if not st.session_state.get('analysis_results'):
                return ret_val

            st.markdown("---")  # Add a separator
            
            # Analysis Results in full width
            st.markdown("### 📊 Analysis Results")
            tabs = st.tabs(["Data Flows", "Trust Boundaries", "Tech Stack"])
            
            with tabs[0]:
                st.markdown("#### 🔄 Data Flows")
                flows = st.session_state['analysis_results']['analyses']['data_flows'].get('data_flows', [])
                for flow in flows:
                    source = flow.get('source', 'Unknown')
                    destination = flow.get('destination', 'Unknown')
                    with st.expander(f"{source} → {destination}"):
                        st.markdown(f"""
                        - **Data Type:** {flow.get('data_type', 'Not specified')}
                        - **Sensitivity:** {flow.get('sensitivity', 'Not specified')}
                        - **Protocol:** {flow.get('protocol', 'Not specified')}
                        - **Direction:** {flow.get('direction', 'Not specified')}
                        """)

                with tabs[1]:
                    st.markdown("#### 🛡️ Trust Boundaries")
                    zones = st.session_state['analysis_results']['analyses']['trust_boundaries'].get('trust_zones', [])
                    for zone in zones:
                        with st.expander(f"{zone.get('name', 'Unknown Zone')} ({zone.get('type', 'Unknown Type')})"):
                            st.markdown(f"""
                            - **Security Level:** {zone.get('security_level', 'Not specified')}
                            - **Components:** {', '.join(zone.get('components', ['None']))}
                            """)

                with tabs[2]:
                    st.markdown("#### 🔧 Technology Stack")
                    techs = st.session_state['analysis_results']['analyses']['tech_stack'].get('technologies', [])
                    for tech in techs:
                        with st.expander(f"{tech.get('name', 'Unknown')} ({tech.get('category', 'Unknown Category')})"):
                            st.markdown(f"""
                            - **Purpose:** {tech.get('purpose', 'Not specified')}
                            - **Security Implications:**
                            """)
                            implications = tech.get('security_implications', [])
                            if implications:
                                for imp in implications:
                                    st.markdown(f"  - {imp}")
                            else:
                                st.markdown("  - No implications specified")

            # Download Options
            st.markdown("### 📥 Download Results")
            col1, col2 = st.columns(2)
            with col1:
                markdown_report = self.input_processor.get_markdown_report(
                    st.session_state['analysis_results']
                )
                st.download_button(
                    label="📄 Download Report",
                    data=markdown_report,
                    file_name="context_analysis_report.md",
                    mime="text/markdown",
                    help="Download complete analysis report"
                )

        # Return the complete input configuration
        return {
            "app_input": st.session_state.get('enhanced_context', input_text),
            "app_type": app_type,
            "components": components,
            "tech_stack": tech_stack,
            "sensitive_data": sensitive_data,
            "internet_facing": internet_facing,
            "authentication": authentication,
            "use_agents": st.session_state.get('use_agents', False),
            "analysis_results": st.session_state.get('analysis_results')
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
            with st.spinner("🔎🔄"):
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