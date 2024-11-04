import streamlit as st
from services.dfd import create_dfd_prompt, get_data_flow_diagram, get_data_flow_diagram_ollama
import streamlit.components.v1 as components

class DataFlowDiagramUI:
    @staticmethod
    def render_mermaid(code: str, height: int = 500) -> None:
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

    @staticmethod
    def render():
        """Render the Data Flow Diagram tab content"""
        st.markdown("""
        ## Data Flow Diagram Generator
        
        Data Flow Diagrams (DFDs) help visualize how data moves through an application or system. 
        Using the context provided in the application description, this will generate a Data flow diagram.
        """)
        st.markdown("""---""")

        # Get only the app_input from session state
        app_input = st.session_state.get('app_input', '')
        
        if not app_input:
            st.info("Please provide application details in the Threat Model tab first.")
            return
            
        if st.button(label="Generate Data Flow Diagram", key="dfd_button"):
            with st.spinner("Generating data flow diagram..."):
                # Get model configuration from session state
                model_provider = st.session_state.get('model_provider', 'Ollama')
                api_key = st.session_state.get('openai_api_key', '')
                model_name = st.session_state.get('selected_model', '')
                
                model_config = {
                    "provider": model_provider,
                    "api_key": api_key,
                    "model_name": model_name
                }
                
                # Create the prompt using only app_input
                prompt = create_dfd_prompt(app_input)
                
                # Generate diagram based on model provider
                if model_config["provider"] == "OpenAI API":
                    dfd_code = get_data_flow_diagram(
                        model_config["api_key"],
                        model_config["model_name"],
                        prompt
                    )
                else:  # Ollama
                    dfd_code = get_data_flow_diagram_ollama(
                        model_config["model_name"],
                        prompt
                    )
                
                # Save to database if there's a current model ID
                if 'current_model_id' in st.session_state:
                    from utils.database import DatabaseManager
                    db_manager = DatabaseManager()
                    db_manager.update_threat_model(
                        st.session_state['current_model_id'],
                        data_flow_diagram=dfd_code
                    )
                
                # Display the diagram
                st.subheader("Generated Data Flow Diagram")
                
                col1, col2 = st.columns([9,1])
                with col1:
                    st.write("Diagram Preview:")
                    DataFlowDiagramUI.render_mermaid(dfd_code)
                with col2:
                    st.download_button(
                        "📥",
                        data=dfd_code,
                        file_name="data_flow_diagram.md",
                        mime="text/plain",
                        help="Download Diagram Code",
                        key="dfd_download"
                    )
                
                # Show the code with copy option
                with st.expander("View Diagram Code"):
                    st.code(dfd_code, language="mermaid")
                
                # Link to Mermaid Live Editor
                st.link_button("Open in Mermaid Live Editor", "https://mermaid.live")