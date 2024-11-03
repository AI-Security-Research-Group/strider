# file_processing.py
import io
import re
import PyPDF2
import streamlit as st
from typing import Tuple, List

def clean_pdf_text(text: str) -> str:
    """
    Clean PDF extracted text by removing common artifacts and unnecessary information
    while preserving formatting.
    
    Args:
        text: Raw text extracted from PDF
    
    Returns:
        Cleaned text
    """
    # Remove common PDF artifacts and metadata while preserving line breaks
    patterns_to_remove = [
        r'Form\s*Field\s*\[.*?\]',  # Form field artifacts
        r'Page\s*\d+\s*of\s*\d+',   # Page numbers
        r'Generated\s*by\s*PDF.*',   # PDF generator info
        r'Evaluation\s*Warning.*',   # PDF evaluation warnings
        r'This\s*PDF\s*document.*',  # PDF document headers
        r'PDF\s*Version.*',          # PDF version information
        r'Adobe\s*Acrobat.*',        # Adobe Acrobat mentions
        r'Created\s*with.*',         # Creation tool information
        r'\[.*?\]\s*Bookmark.*',     # Bookmark artifacts
        r'©.*?\d{4}',               # Copyright notices
        r'Header\s*\d+',            # Header markers
        r'Footer\s*\d+',            # Footer markers
        r'\f',                      # Form feed characters
    ]
    
    for pattern in patterns_to_remove:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)
    
    # Preserve legitimate line breaks while removing extra whitespace
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Clean extra whitespace within each line
        cleaned_line = re.sub(r'\s+', ' ', line).strip()
        if cleaned_line:
            cleaned_lines.append(cleaned_line)
    
    # Join lines back together preserving intentional line breaks
    return '\n'.join(cleaned_lines)

def extract_meaningful_sections(text: str) -> List[str]:
    """
    Extract meaningful sections from the text while preserving formatting.
    
    Args:
        text: Preprocessed text from PDF
    
    Returns:
        List of meaningful text sections with preserved formatting
    """
    sections = []
    current_section = []
    previous_line_empty = False
    
    for line in text.split('\n'):
        line = line.rstrip()  # Only remove trailing whitespace
        
        # Handle section breaks
        if not line:
            if not previous_line_empty and current_section:
                sections.append('\n'.join(current_section))
                current_section = []
            previous_line_empty = True
            continue
        
        previous_line_empty = False
        
        # Skip lines that are just page numbers or symbols
        if re.match(r'^[\d\s\-_]+$', line):
            continue
            
        # Preserve indentation by not stripping leading whitespace
        current_section.append(line)
    
    # Add the last section if exists
    if current_section:
        sections.append('\n'.join(current_section))
    
    # Filter out very short sections (likely artifacts)
    return [s for s in sections if len(s.strip()) > 50]

def process_uploaded_file(uploaded_file) -> Tuple[str, bool]:
    """
    Process uploaded PDF or TXT file and return its content while preserving formatting
    
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
            raw_content = []
            
            for page in pdf_reader.pages:
                raw_text = page.extract_text()
                if raw_text:
                    # Clean the extracted text while preserving formatting
                    cleaned_text = clean_pdf_text(raw_text)
                    if cleaned_text.strip():
                        raw_content.append(cleaned_text)
            
            # Extract meaningful sections while preserving formatting
            full_text = '\n\n'.join(raw_content)  # Use double newline for page breaks
            sections = extract_meaningful_sections(full_text)
            
            # Join sections with clear separation
            processed_content = '\n\n'.join(sections)
            
            # Return empty string if no meaningful content was extracted
            if not processed_content.strip():
                st.warning("No meaningful content could be extracted from the PDF.")
                return "", False
                
            return processed_content, True
            
        elif file_extension == 'txt':
            # Read text file preserving original formatting
            content = uploaded_file.read().decode('utf-8')
            return content, True
            
        else:
            st.error(f"Unsupported file format: {file_extension}")
            return "", False
            
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        return "", False