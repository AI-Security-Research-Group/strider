import streamlit as st
from ui.app_ui import AppUI
from services.app_service import AppService
from utils.database import DatabaseManager
from ui.history_ui import HistoryUI
from ui.transcript_ui import TranscriptUI 
from ui.qa_context_ui import QAContextUI
from ui.dfd_ui import DataFlowDiagramUI
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Reduce noise from other libraries
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('openai').setLevel(logging.WARNING)

def main():
    # Initialize UI, Service, and Database components
    ui = AppUI()
    service = AppService()
    db_manager = DatabaseManager()
    history_ui = HistoryUI(db_manager)

    from services.knowledge_base.data_loader import initialize_kb
    kb = initialize_kb()  # This will load the KB data    
    
    # Get model configuration from sidebar
    model_provider, api_key, model_name = ui.render_sidebar()
    model_config = {
        "provider": model_provider,
        "api_key": api_key,
        "model_name": model_name
    }
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "Threat Model", "Q&A Context", "Mitigations", 
        "DREAD", "Test Cases", "Attack Tree", "Transcript Analysis", "Data Flow Diagram", "All Threat Models"
    ])
    
    # Handle Threat Model tab
    with tab1:
        st.markdown("""
        A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
        understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.
        """)
        st.markdown("""---""")
        
        # Input fields only in Threat Model tab
        inputs = ui.render_input_section()
        
        if st.button(label="Generate Threat Scenario", key="threat_model_button", type="primary"):
            if inputs["app_input"]:
                with st.spinner("Analysing potential threats..."):
                    model_output = service.generate_threat_model(inputs, model_config)
                    
                    # Save to database with Q&A context
                    model_id = db_manager.save_threat_model(
                        app_type=inputs["app_type"],
                        authentication=inputs["authentication"],
                        internet_facing=inputs["internet_facing"],
                        sensitive_data=inputs["sensitive_data"],
                        app_input=inputs["app_input"],
                        threat_model_output=model_output,
                        qa_context=st.session_state.get('qa_context')
                    )
                    st.session_state['current_model_id'] = model_id

                    # Format and display the output
                    if model_output:
                        markdown_output = service.format_threat_model_output(model_output)
                        st.markdown(markdown_output)
                        
                        st.download_button(
                            label="Download Threat Model",
                            data=markdown_output,
                            file_name="stride_gpt_threat_model.md",
                            mime="text/markdown",
                        )
                    else:
                        st.error("No threat model output available.")
            else:
                st.error("Please enter your application details before submitting.")

    
    # Handle Attack Tree tab
    with tab6:
        st.markdown("""
        Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, 
        with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches.
        """)
        st.markdown("""---""")
        
        if 'threat_model' in st.session_state:
            if st.button(label="Generate Attack Tree", key="attack_tree_button"):
                inputs = st.session_state.get('app_inputs')
                if inputs and inputs.get("app_input"):
                    with st.spinner("Generating attack tree..."):
                        mermaid_code = service.generate_attack_tree(inputs, model_config)
                        
                        # Save to database
                        if 'current_model_id' in st.session_state:
                            db_manager.update_threat_model(
                                st.session_state['current_model_id'],
                                attack_tree=mermaid_code
                            )
                        
                        st.write("Attack Tree Code:")
                        st.code(mermaid_code)
                        
                        st.write("Attack Tree Diagram Preview:")
                        ui.render_mermaid(mermaid_code)
                        
                        st.download_button(
                            label="Download Diagram Code",
                            data=mermaid_code,
                            file_name="attack_tree.md",
                            mime="text/plain",
                        )
                        st.link_button("Open Mermaid Live", "https://mermaid.live")
        else:
            st.warning("Please generate a threat model first in the Threat Model tab.")
    
    # Handle Mitigations tab
    with tab3:
        handle_mitigations_tab(tab3, service, model_config)
    
    # Handle DREAD tab
    with tab4:
        st.markdown("""
        DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on Damage potential, 
        Reproducibility, Exploitability, Affected users, and Discoverability.
        """)
        st.markdown("""---""")
        
        if 'threat_model' in st.session_state:
            if st.button(label="Generate DREAD Assessment", key="dread_button"):
                with st.spinner("Generating DREAD Risk Assessment..."):
                    markdown_output = service.format_threat_model_output({"threat_model": st.session_state['threat_model'], "improvement_suggestions": []})
                    dread_assessment = service.generate_dread_assessment(markdown_output, model_config)
                    
                    # Save to database
                    if 'current_model_id' in st.session_state:
                        db_manager.update_threat_model(
                            st.session_state['current_model_id'],
                            dread_assessment=dread_assessment
                        )
                    
                    dread_markdown = service.format_dread_output(dread_assessment)
                    st.markdown(dread_markdown)
                    
                    st.download_button(
                        label="Download DREAD Assessment",
                        data=dread_markdown,
                        file_name="dread_assessment.md",
                        mime="text/markdown",
                    )
        else:
            st.warning("Please generate a threat model first in the Threat Model tab.")
    
    # Handle Test Cases tab
    with tab5:
        handle_test_cases_tab(tab5, service, model_config)
    
    # Handle Transcript Analysis tab
    with tab7:
        transcript_ui = TranscriptUI()
        transcript_ui.render(model_config)
    
    # Handle Q&A Context tab
    with tab2:
        qa_context_ui = QAContextUI()
        qa_context_ui.render(inputs, model_config)

    #shows dataflow diagram
    with tab8:
        dfd_ui = DataFlowDiagramUI()
        dfd_ui.render()

    # Handle History tab
    with tab9:
        history_ui.render_history()

def handle_test_cases_tab(tab5, service, model_config):
    """Handle the Test Cases tab"""
    with tab5:
        st.markdown("""
        Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
        addressed. This tab generates test cases using Gherkin syntax for better readability and execution.
        """)
        st.markdown("""---""")
        
        # Validate threat model exists
        from services.test_cases import validate_threat_model_state, get_current_threat_model
        
        if validate_threat_model_state():
            if st.button(label="Generate Test Cases", key="test_cases_button"):
                with st.spinner("Generating test cases..."):
                    # Get current threat model
                    threat_model = get_current_threat_model()
                    
                    if threat_model:
                        try:
                            # Generate test cases using the service method
                            test_cases_markdown = service.generate_test_cases(
                                threat_model,
                                model_config
                            )
                            
                            # Display results
                            st.markdown(test_cases_markdown)
                            
                            # Add download button
                            st.download_button(
                                label="Download Test Cases",
                                data=test_cases_markdown,
                                file_name="test_cases.md",
                                mime="text/markdown",
                            )
                        except Exception as e:
                            st.error(f"Error generating test cases: {str(e)}")
                            logger.error(f"Test case generation error: {str(e)}", exc_info=True)
                    else:
                        st.error("Could not retrieve threat model data. Please try regenerating the threat model.")
        else:
            st.warning("Please generate a threat model first in the Threat Model tab.")

def handle_mitigations_tab(tab3, service, model_config):
    """Handle the Mitigations tab"""
    with tab3:
        st.markdown("""
        Use this tab to generate potential mitigations for the threats identified in the threat model.
        The suggested mitigations will be specific to each identified threat.
        """)
        st.markdown("""---""")
        
        # Validate threat model exists
        from services.mitigations import validate_threat_model_state, get_current_threat_model
        
        if validate_threat_model_state():
            if st.button(label="Suggest Mitigations", key="mitigations_button"):
                with st.spinner("Suggesting mitigations..."):
                    # Get current threat model
                    threat_model = get_current_threat_model()
                    
                    if threat_model:
                        try:
                            # Generate mitigations
                            mitigations_markdown = service.generate_mitigations(
                                threat_model,
                                model_config
                            )
                            
                            # Display results
                            st.markdown(mitigations_markdown)
                            
                            # Add download button
                            st.download_button(
                                label="Download Mitigations",
                                data=mitigations_markdown,
                                file_name="mitigations.md",
                                mime="text/markdown",
                            )
                            
                            # Update database if we have a current model ID
                            if 'current_model_id' in st.session_state:
                                service.db_manager.update_threat_model(
                                    st.session_state['current_model_id'],
                                    mitigations=mitigations_markdown
                                )
                                
                        except Exception as e:
                            st.error(f"Error generating mitigations: {str(e)}")
                            logger.error(f"Mitigation generation error: {str(e)}", exc_info=True)
                    else:
                        st.error("Could not retrieve threat model data. Please try regenerating the threat model.")
        else:
            st.warning("Please generate a threat model first in the Threat Model tab.")



if __name__ == "__main__":
    main()