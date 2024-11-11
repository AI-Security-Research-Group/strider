import streamlit as st
import pandas as pd
from datetime import datetime
import json
import streamlit.components.v1 as components
from time import sleep

class HistoryUI:
    def __init__(self, db_manager):
        self.db_manager = db_manager

    def render_mermaid(self, code: str, height: int = 500) -> None:
        """Render Mermaid diagram"""
        try:
            # Clean and normalize the Mermaid code
            code = code.strip()
            if not code:
                st.warning("No diagram code available.")
                return

            # HTML with Mermaid initialization
            html = f"""
                <div class="mermaid-container">
                    <pre class="mermaid" style="height: {height}px;">
                        {code}
                    </pre>
                </div>

                <script type="module">
                    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
                    mermaid.initialize({{ startOnLoad: true, theme: 'neutral' }});
                </script>

                <style>
                    .mermaid-container {{
                        width: 100%;
                        overflow: auto;
                        background-color: white;
                        padding: 10px;
                        border-radius: 5px;
                        border: 1px solid #e0e0e0;
                    }}
                </style>
            """
            
            # Render the HTML
            components.html(html, height=height + 50)
            
        except Exception as e:
            st.error(f"Error rendering attack tree: {str(e)}")
            st.code(code, language="mermaid")  # Fallback to display the code

    def format_threat_model_content(self, threat_model_output):
        """Convert threat model JSON to readable format"""
        try:
            if isinstance(threat_model_output, str):
                threat_model_output = json.loads(threat_model_output)
                
            markdown = "## Identified Threats\n\n"
            markdown += "| Threat Type | Scenario | Potential Impact |\n"
            markdown += "|------------|----------|------------------|\n"
            
            for threat in threat_model_output.get('threat_model', []):
                markdown += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
            
            if 'improvement_suggestions' in threat_model_output:
                markdown += "\n## Improvement Suggestions\n\n"
                for suggestion in threat_model_output['improvement_suggestions']:
                    markdown += f"- {suggestion}\n"

            if 'open_questions' in threat_model_output:
                markdown += "\n## Open Questions\n\n"
                for question in threat_model_output['open_questions']:
                    markdown += f"- {question}\n"

            return markdown
        except Exception as e:
            st.error(f"Error formatting threat model: {str(e)}")
            return ""

    def format_dread_assessment(self, dread_data):
        """Convert DREAD JSON to readable format"""
        try:
            if isinstance(dread_data, str):
                dread_data = json.loads(dread_data)
                
            markdown = "## DREAD Risk Assessment\n\n"
            markdown += "| Threat Type | Scenario | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
            markdown += "|------------|----------|---------|-----------------|----------------|----------------|-----------------|------------|\n"
            
            for assessment in dread_data.get('Risk Assessment', []):
                risk_score = sum([
                    assessment.get('Damage Potential', 0),
                    assessment.get('Reproducibility', 0),
                    assessment.get('Exploitability', 0),
                    assessment.get('Affected Users', 0),
                    assessment.get('Discoverability', 0)
                ]) / 5
                
                markdown += (
                    f"| {assessment.get('Threat Type', 'N/A')} "
                    f"| {assessment.get('Scenario', 'N/A')} "
                    f"| {assessment.get('Damage Potential', 0)} "
                    f"| {assessment.get('Reproducibility', 0)} "
                    f"| {assessment.get('Exploitability', 0)} "
                    f"| {assessment.get('Affected Users', 0)} "
                    f"| {assessment.get('Discoverability', 0)} "
                    f"| {risk_score:.2f} |\n"
                )
                
            return markdown
        except Exception as e:
            st.error(f"Error formatting DREAD assessment: {str(e)}")
            return ""

    def handle_delete(self, model_id: int) -> None:
        """Handle the deletion of a threat model"""
        try:
            if self.db_manager.delete_threat_model(model_id):
                st.session_state['delete_success'] = True
                st.rerun()
            else:
                st.error("Failed to delete record.")
        except Exception as e:
            st.error(f"Error deleting record: {str(e)}")

    def render_attack_tree(self, model) -> None:
        """Dedicated method to render attack tree with proper error handling"""
        try:
            if model.attack_tree:
                attack_tree_code = model.attack_tree.strip()
                if attack_tree_code:
                    col1, col2 = st.columns([9,1])
                    with col1:
                        st.write("**Attack Tree Diagram:**")
                        self.render_mermaid(attack_tree_code)
                    with col2:
                        st.download_button(
                            "📥",
                            attack_tree_code,
                            file_name=f"attack_tree_{model.id}.md",
                            mime="text/plain",
                            help="Download Attack Tree"
                        )
                else:
                    st.warning("Attack tree data is empty.")
            else:
                st.info("No attack tree available for this threat model.")
        except Exception as e:
            st.error(f"Error displaying attack tree: {str(e)}")

    def render_history(self):
        """Render the history tab content"""
        st.write("# Threat Model History")
        
        models = self.db_manager.get_all_threat_models()
        
        if not models:
            st.info("No threat models found in history.")
            return

        # Check if a deletion was successful
        if st.session_state.get('delete_success'):
            st.success("Record deleted successfully!")
            st.session_state['delete_success'] = False

        # Display each threat model as an expander
        for model in models:
            with st.expander(f"Threat Model #{model.id} - {model.app_type} ({model.timestamp.strftime('%Y-%m-%d %H:%M')})"):
                # Display generic information
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Application Details:**")
                    st.write(f"- Type: {model.app_type}")
                    st.write(f"- Internet Facing: {model.internet_facing}")
                    st.write(f"- Sensitivity: {model.sensitive_data}")
                    st.write(f"- Authentication: {model.authentication}")
                
                with col2:
                    st.write("**Generated Artifacts:**")
                    artifacts_present = []
                    if model.threat_model_output:
                        artifacts_present.append("Threat Model")
                    if model.attack_tree:
                        artifacts_present.append("Attack Tree")
                    if model.mitigations:
                        artifacts_present.append("Mitigations")
                    if model.dread_assessment:
                        artifacts_present.append("DREAD Assessment")
                    if model.test_cases:
                        artifacts_present.append("Test Cases")
                        
                    for artifact in artifacts_present:
                        st.write(f"- ✅ {artifact}")
                
                # Application Description
                st.write("**Application Description:**")
                st.text_area(
                    label="Application Description",
                    value=model.app_input,
                    height=100,
                    key=f"desc_{model.id}",
                    disabled=True,
                    label_visibility="collapsed"
                )
                
                if artifacts_present:
                    # Create tabs for different artifacts
                    tabs = st.tabs(artifacts_present)
                    
                    for tab_name, tab in zip(artifacts_present, tabs):
                        with tab:
                            # Threat Model Tab
                            if tab_name == "Threat Model" and model.threat_model_output:
                                content = self.format_threat_model_content(model.threat_model_output)
                                col1, col2 = st.columns([9,1])
                                with col1:
                                    st.markdown(content)
                                with col2:
                                    st.download_button(
                                        "📥",
                                        content,
                                        file_name=f"threat_model_{model.id}.md",
                                        mime="text/markdown",
                                        help="Download Threat Model"
                                    )

                            # Attack Tree Tab
                            elif tab_name == "Attack Tree" and model.attack_tree:
                                self.render_attack_tree(model)

                            # Mitigations Tab
                            elif tab_name == "Mitigations" and model.mitigations:
                                col1, col2 = st.columns([9,1])
                                with col1:
                                    st.markdown(model.mitigations)
                                with col2:
                                    st.download_button(
                                        "📥",
                                        model.mitigations,
                                        file_name=f"mitigations_{model.id}.md",
                                        mime="text/markdown",
                                        help="Download Mitigations"
                                    )

                            # DREAD Assessment Tab
                            elif tab_name == "DREAD Assessment" and model.dread_assessment:
                                content = self.format_dread_assessment(model.dread_assessment)
                                col1, col2 = st.columns([9,1])
                                with col1:
                                    st.markdown(content)
                                with col2:
                                    st.download_button(
                                        "📥",
                                        content,
                                        file_name=f"dread_{model.id}.md",
                                        mime="text/markdown",
                                        help="Download DREAD Assessment"
                                    )

                            # Test Cases Tab
                            elif tab_name == "Test Cases" and model.test_cases:
                                col1, col2 = st.columns([9,1])
                                with col1:
                                    st.markdown(model.test_cases)
                                with col2:
                                    st.download_button(
                                        "📥",
                                        model.test_cases,
                                        file_name=f"test_cases_{model.id}.md",
                                        mime="text/markdown",
                                        help="Download Test Cases"
                                    )

                # Delete button for the entire record
                col1, col2, col3 = st.columns([6, 2, 2])
                with col3:
                    if st.button("🗑️ Delete Record", key=f"delete_{model.id}", type="primary"):
                        self.handle_delete(model.id)

                st.markdown("---")  # Separator between records