import streamlit as st
import streamlit.components.v1 as components
import requests
from typing import Dict, Any, Tuple
from services.app_service import AppService
import os
from dotenv import load_dotenv

class AppUI:
    def __init__(self):
        self.service = AppService()
        self.setup_page_config()
        self.load_env_variables()
        
    def setup_page_config(self):
        """Configure the Streamlit page"""
        st.set_page_config(
            page_title="STRIDER",
            page_icon=":shield:",
            layout="wide",
            initial_sidebar_state="expanded",
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
            
        return model_provider, api_key, model_name

    def render_input_section(self) -> Dict[str, Any]:
        """Render input section and return input values"""
        col1, col2 = st.columns([1, 1])
        
        with col1:
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
                        st.session_state['app_input'] = file_content + "\n\n" + st.session_state.get('app_input', '')
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
            
            input_text = st.text_area(
                label="Describe the application to be modelled",
                value=st.session_state.get('app_input', ''),
                placeholder="Enter your application details...",
                height=300,
                key="app_desc",
            )
            st.session_state['app_input'] = input_text
            
        with col2:
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
                ["SSO", "MFA", "OAUTH2", "Basic", "None"],
            )
            
        return {
            "app_input": input_text,
            "app_type": app_type,
            "sensitive_data": sensitive_data,
            "internet_facing": internet_facing,
            "authentication": authentication
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
        """Process image analysis with selected provider"""
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
                    
                    if model_provider == "Ollama":
                        if image_analysis_output and image_analysis_output.get('choices'):
                            image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                            st.session_state.image_analysis_content = image_analysis_content
                            current_input = st.session_state.get('app_input', '')
                            st.session_state['app_input'] = f"Architecture Analysis:\n{image_analysis_content}\n\n{current_input}"
                            st.success("Successfully analyzed the architecture diagram")
                        else:
                            st.error("Failed to analyze the image with Ollama. Please ensure Llava model is installed and running.")
                    else:  # OpenAI
                        if not api_key:
                            st.error("Please enter your OpenAI API key to analyse the image.")
                            return
                            
                        if image_analysis_output and image_analysis_output.get('choices'):
                            image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                            st.session_state.image_analysis_content = image_analysis_content
                            current_input = st.session_state.get('app_input', '')
                            st.session_state['app_input'] = f"Architecture Analysis:\n{image_analysis_content}\n\n{current_input}"
                            st.success("Successfully analyzed the architecture diagram")
                        else:
                            st.error("Failed to analyze the image. Please check the API key and try again.")
                except Exception as e:
                    st.error(f"Error during image analysis: {str(e)}")

    def _check_llava_and_process_image(self, uploaded_image):
        """Check for Llava model and process image if available"""
        try:
            response = requests.get("http://localhost:11434/api/tags")
            models = [m["name"] for m in response.json().get("models", [])]
            if "llava:latest" not in models:
                st.error("Llava model not found in Ollama. Please install it using: 'ollama pull llava'")
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
                import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
                mermaid.initialize({{ startOnLoad: true }});
            </script>
            """,
            height=height,
        )