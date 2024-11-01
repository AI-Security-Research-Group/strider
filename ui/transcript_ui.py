# ui/transcript_ui.py
import streamlit as st
from services.transcript_analyzer import TranscriptAnalyzer
from utils.transcript_processor import TranscriptProcessor

class TranscriptUI:
    def __init__(self):
        self.analyzer = TranscriptAnalyzer()
        self.processor = TranscriptProcessor()

    def render(self, model_config: dict) -> None:
        """Render the transcript analysis UI section"""
        st.markdown("""
        ## Transcript Analysis
        Upload or paste walkthrough meeting transcripts for automated analysis.
        The system will extract relevant application details to enhance the threat model context.
        """)
        
        # Input methods
        input_method = st.radio(
            "Choose input method:",
            ["Upload Transcript File", "Paste Transcript Text"]
        )
        
        transcript_text = ""
        if input_method == "Upload Transcript File":
            uploaded_file = st.file_uploader(
                "Upload transcript file",
                type=['txt', 'docx', 'vtt'],
                help="Upload a transcript file (supported formats: TXT, DOCX, VTT)"
            )
            
            if uploaded_file:
                with st.spinner("Processing transcript file..."):
                    transcript_text, success = self.processor.process_transcript_file(uploaded_file)
                    if success:
                        # Clean the transcript text
                        transcript_text = self.processor.clean_transcript(transcript_text)
                        
                        # Show the processed transcript
                        st.text_area(
                            "Processed Transcript",
                            transcript_text,
                            height=200,
                            disabled=True
                        )
                        
                        # Option to edit processed text
                        if st.checkbox("Edit processed transcript"):
                            transcript_text = st.text_area(
                                "Edit transcript text",
                                value=transcript_text,
                                height=300
                            )
                    else:
                        st.error("Failed to process the uploaded file")
        else:
            transcript_text = st.text_area(
                "Paste transcript text here",
                height=300,
                help="Paste the conversation transcript or meeting notes here"
            )
            if transcript_text:
                transcript_text = self.processor.clean_transcript(transcript_text)
        
        # Analysis section
        if st.button("Analyze Transcript") and transcript_text:
            with st.spinner("Analyzing transcript..."):
                if model_config["provider"] == "OpenAI API":
                    analysis = self.analyzer.analyze_with_openai(
                        model_config["api_key"],
                        model_config["model_name"],
                        transcript_text
                    )
                else:  # Ollama
                    analysis = self.analyzer.analyze_with_ollama(
                        model_config["model_name"],
                        transcript_text
                    )
                
                if analysis:
                    # Store analysis in session state
                    st.session_state['transcript_analysis'] = analysis
                    
                    # Display formatted analysis
                    st.markdown(self.analyzer.format_analysis_output(analysis))
                    
                    # Update app input with extracted details
                    current_input = st.session_state.get('app_input', '')
                    formatted_analysis = self.analyzer.format_analysis_output(analysis)
                    st.session_state['app_input'] = f"Transcript Analysis:\n{formatted_analysis}\n\n{current_input}"
                    
                    st.success("Transcript analysis completed and added to application context")
                    
                    # Download options
                    st.download_button(
                        label="Download Analysis",
                        data=formatted_analysis,
                        file_name="transcript_analysis.md",
                        mime="text/markdown"
                    )
                else:
                    st.error("Failed to analyze transcript")