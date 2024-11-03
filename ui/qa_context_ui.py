import streamlit as st
from typing import Dict, Any
from services.qa_context import (
    create_question_generation_prompt,
    create_context_analysis_prompt,
    get_contextual_questions,
    get_contextual_questions_ollama,
    analyze_qa_context,
    analyze_qa_context_ollama
)

class QAContextUI:
    def __init__(self):
        if 'qa_questions' not in st.session_state:
            st.session_state.qa_questions = []
        if 'qa_answers' not in st.session_state:
            st.session_state.qa_answers = {}

    def render(self, inputs: Dict[str, Any], model_config: Dict[str, str]) -> None:
        st.markdown("""
        ## Q&A Context Builder
        Use this section to gather additional security context through guided questions.
        The AI agent will analyze your input and generate relevant questions to help build a more comprehensive threat model.
        """)
        
        # Generate Questions button
        if st.button("Generate Questions", key="generate_questions"):
            with st.spinner("Generating relevant questions..."):
                prompt = create_question_generation_prompt(
                    inputs["app_type"],
                    inputs["authentication"],
                    inputs["internet_facing"],
                    inputs["sensitive_data"],
                    inputs["app_input"]
                )
                
                if model_config["provider"] == "OpenAI API":
                    questions_response = get_contextual_questions(
                        model_config["api_key"],
                        model_config["model_name"],
                        prompt
                    )
                else:  # Ollama
                    questions_response = get_contextual_questions_ollama(
                        model_config["model_name"],
                        prompt
                    )
                
                try:
                    if isinstance(questions_response, str):
                        import json
                        questions_response = json.loads(questions_response)
                    st.session_state.qa_questions = questions_response.get("questions", [])
                except Exception as e:
                    st.error(f"Error processing questions: {str(e)}")
                    return

        # Display questions and collect answers
        if st.session_state.qa_questions:
            st.markdown("### Security Context Questions")
            st.markdown("Please provide detailed answers to help build a comprehensive threat model.")
            
            for i, question in enumerate(st.session_state.qa_questions):
                answer = st.text_area(
                    f"Q{i+1}: {question}",
                    key=f"qa_answer_{i}",
                    value=st.session_state.qa_answers.get(question, ""),
                    height=100
                )
                if answer:  # Only update if there's an answer
                    st.session_state.qa_answers[question] = answer
            
            # Add Context button
            if st.button("Add Context to Threat Model", key="add_context"):
                if not any(st.session_state.qa_answers.values()):
                    st.warning("Please provide at least one answer before adding context.")
                    return
                    
                with st.spinner("Adding Q&A context to threat model..."):
                    # Format Q&A session as text
                    qa_formatted = self._format_qa_session(
                        st.session_state.qa_questions,
                        st.session_state.qa_answers
                    )
                    
                    # Update the main application input with the new context
                    current_input = st.session_state.get('app_input', '')
                    if current_input:
                        st.session_state['app_input'] = f"{current_input}\n\nQuestion and Answer Context:\n{qa_formatted}"
                    else:
                        st.session_state['app_input'] = f"Question and Answer Context:\n{qa_formatted}"
                    
                    # Store Q&A context in session state for database
                    st.session_state['qa_context'] = {
                        "questions_and_answers": st.session_state.qa_answers
                    }
                    
                    st.success("Q&A context successfully added to the threat model input!")

    def _format_qa_session(self, questions: list, answers: Dict[str, str]) -> str:
        """Format Q&A session for display in the input context"""
        formatted = []
        for i, question in enumerate(questions, 1):
            answer = answers.get(question, "").strip()
            if answer:  # Only include Q&A pairs that have answers
                formatted.extend([
                    f"Question{i}: {question}",
                    f"Answer{i}: {answer}",
                    ""  # Add blank line between Q&A pairs
                ])
        
        return "\n".join(formatted)

    def _format_json_output(self, data: Dict[str, Any], indent: int = 0) -> str:
        """Helper method to format JSON-like dictionary as a readable string"""
        output = []
        indent_str = "  " * indent
        
        for key, value in data.items():
            if isinstance(value, dict):
                output.append(f"{indent_str}{key}:")
                output.append(self._format_json_output(value, indent + 1))
            elif isinstance(value, list):
                output.append(f"{indent_str}{key}:")
                for item in value:
                    output.append(f"{indent_str}  - {item}")
            else:
                output.append(f"{indent_str}{key}: {value}")
        
        return "\n".join(output)