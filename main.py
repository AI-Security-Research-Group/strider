import streamlit as st
from ui.app_ui import AppUI
from services.app_service import AppService
from utils.database import DatabaseManager
from ui.history_ui import HistoryUI
from ui.transcript_ui import TranscriptUI 
from ui.qa_context_ui import QAContextUI
from ui.dfd_ui import DataFlowDiagramUI

def main():
    # Initialize UI, Service, and Database components
    ui = AppUI()
    service = AppService()
    db_manager = DatabaseManager()
    history_ui = HistoryUI(db_manager)
    
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
        
        if st.button(label="Generate Threat Model", key="threat_model_button", type="primary"):
            if inputs["app_input"]:
                with st.spinner("Analysing potential threats..."):
                    model_output = service.generate_threat_model(inputs, model_config)
                    st.session_state['threat_model'] = model_output.get("threat_model", [])
                    st.session_state['app_inputs'] = inputs
                    
                    # Save to database with Q&A context if available
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
                    
                    markdown_output = service.format_threat_model_output(model_output)
                    st.markdown(markdown_output)
                    
                    st.download_button(
                        label="Download Threat Model",
                        data=markdown_output,
                        file_name="stride_gpt_threat_model.md",
                        mime="text/markdown",
                    )
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
        st.markdown("""
        Use this tab to generate potential mitigations for the threats identified in the threat model.
        """)
        st.markdown("""---""")
        
        if 'threat_model' in st.session_state:
            if st.button(label="Suggest Mitigations", key="mitigations_button"):
                with st.spinner("Suggesting mitigations..."):
                    markdown_output = service.format_threat_model_output({"threat_model": st.session_state['threat_model'], "improvement_suggestions": []})
                    mitigations_markdown = service.generate_mitigations(markdown_output, model_config)
                    
                    # Save to database
                    if 'current_model_id' in st.session_state:
                        db_manager.update_threat_model(
                            st.session_state['current_model_id'],
                            mitigations=mitigations_markdown
                        )
                    
                    st.markdown(mitigations_markdown)
                    
                    st.download_button(
                        label="Download Mitigations",
                        data=mitigations_markdown,
                        file_name="mitigations.md",
                        mime="text/markdown",
                    )
        else:
            st.warning("Please generate a threat model first in the Threat Model tab.")
    
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
        st.markdown("""
        Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
        addressed. This tab generates test cases using Gherkin syntax for better readability and execution.
        """)
        st.markdown("""---""")
        
        if 'threat_model' in st.session_state:
            if st.button(label="Generate Test Cases", key="test_cases_button"):
                with st.spinner("Generating test cases..."):
                    markdown_output = service.format_threat_model_output({"threat_model": st.session_state['threat_model'], "improvement_suggestions": []})
                    test_cases_markdown = service.generate_test_cases(markdown_output, model_config)
                    
                    # Save to database
                    if 'current_model_id' in st.session_state:
                        db_manager.update_threat_model(
                            st.session_state['current_model_id'],
                            test_cases=test_cases_markdown
                        )
                    
                    st.markdown(test_cases_markdown)
                    
                    st.download_button(
                        label="Download Test Cases",
                        data=test_cases_markdown,
                        file_name="test_cases.md",
                        mime="text/markdown",
                    )
        else:
            st.warning("Please generate a threat model first in the Threat Model tab.")
    
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


if __name__ == "__main__":
    main()