# file_processing.py
import io
import PyPDF2
import streamlit as st
from typing import Tuple

def process_uploaded_file(uploaded_file) -> Tuple[str, bool]:
    """
    Process uploaded PDF or TXT file and return its content
    
    Args:
        uploaded_file: Streamlit UploadedFile object
    
    Returns:
        Tuple of (file_content: str, success: bool)
    """
    try:
        # Get file extension
        file_extension = uploaded_file.name.split('.')[-1].lower()
        
        if file_extension == 'pdf':
            # Read PDF file
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(uploaded_file.read()))
            content = []
            for page in pdf_reader.pages:
                content.append(page.extract_text())
            return '\n'.join(content), True
            
        elif file_extension == 'txt':
            # Read text file
            content = uploaded_file.read().decode('utf-8')
            return content, True
            
        else:
            return "", False
            
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        return "", False