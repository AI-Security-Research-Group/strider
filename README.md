# STRIDER

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Adaptive STRIDE Threat Modeling System powered by AI for automated security analysis.

## 🎯 Overview

STRIDER is a cutting-edge threat modeling assistant that leverages multiple Large Language Models (LLMs) to provide comprehensive security analysis using the STRIDE methodology. It helps engineering teams identify, analyze, and mitigate potential security threats in their applications.

## ✨ Key Features

- 🔍 Multi-model security analysis
- 🌐 Support for local (Ollama) and cloud (OpenAI) LLMs
- 🎯 STRIDE-based threat modeling
- 📊 Data Flow Diagram generation
- 🌳 Attack Tree visualization
- 🎲 DREAD risk assessment
- 📝 Test case generation
- 💾 Integrated knowledge base
- 📈 Progress tracking and visualization
- 📋 Historical analysis storage

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Ollama (for local LLM support)
- OpenAI API key (optional, for GPT models)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/strider.git
cd strider

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Running STRIDER

```bash
streamlit run main.py
```

## 💻 Usage

1. **Select Model Provider**
   - Choose between Ollama (local) or OpenAI API
   - Configure model settings

2. **Input Application Details**
   - Describe your application
   - Upload architecture diagrams
   - Specify components and technology stack

3. **Generate Analysis**
   - Automated STRIDE threat analysis
   - Interactive data flow diagrams
   - Attack trees and DREAD assessment
   - Security test cases

4. **Review Results**
   - View threat details and mitigations
   - Export reports and diagrams
   - Track historical analyses

## 🏗️ Architecture

STRIDER follows a modular architecture:

- 📁 `/services`: Core analysis modules
  - Knowledge base integration
  - Threat modeling engine
  - Security agents
  - Data processors

- 📁 `/ui`: User interface components
  - Main application UI
  - Analysis dashboards
  - Visualization tools

- 📁 `/utils`: Utility functions
  - File processing
  - Database management
  - Image analysis

## 🔧 Configuration

Configuration can be done through:
- Environment variables
- UI settings
- `.env` file (for API keys)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
Built with ❤️ 
