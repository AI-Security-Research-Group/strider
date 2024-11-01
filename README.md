<h1 align="center"> STRIDER </h1> <br>
<table align="center">
<tr>
<td>
STRIDER is an intelligent threat modeling assistant that helps security professionals and developers identify potential security threats in their applications using the STRIDE methodology, powered by local LLM inference.
</td>
</tr>
</table>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## Key Features <img src="https://media.giphy.com/media/VgCDAzcKvsR6OM0uWg/giphy.gif" width="40">

✅ Comprehensive threat modeling using STRIDE methodology <br>
✅ Interactive attack tree visualization with Mermaid diagrams <br>
✅ Risk assessment using DREAD scoring system <br>
✅ Automatic generation of security test cases in Gherkin format <br>
✅ Analysis of meeting transcripts and architectural discussions <br>
✅ Local LLM support through Ollama integration <br>
✅ Support for both OpenAI API and local Ollama models <br>
✅ Persistent storage of threat models and analyses <br>

## Web UI <img src="https://www.svgrepo.com/show/343850/blog-seo-optimization-search.svg" width="25"> 
[Include screenshot of your application's UI here]

## How it works? <img src="https://www.svgrepo.com/show/530592/creativity.svg" width="20"> 

1. **Input Collection**: Gather application details through:
   - Direct input of application characteristics
   - Upload of architecture diagrams
   - Analysis of meeting transcripts
   
2. **Threat Analysis**: 
   - Identifies potential threats using STRIDE
   - Generates visual attack trees
   - Assesses risks using DREAD
   
3. **Output Generation**:
   - Detailed threat model documentation
   - Visual attack trees
   - Risk assessments
   - Security test cases

## Pre-requisites <img src="https://www.svgrepo.com/show/530571/conversation.svg" width="25"> 

* [Ollama](https://ollama.ai/) for local LLM inference (optional)
* Python 3.7+
* 8GB RAM (16GB recommended for larger models)
* OpenAI API key (optional, for using OpenAI models)

## Supported Input Formats: <img src="https://www.svgrepo.com/show/507050/cha-translate-2.svg" width="25"> 
- Application descriptions (text)
- Architecture diagrams (PNG, JPG, JPEG)
- Meeting transcripts (VTT, DOCX, TXT)
- PDF documentation

## Installation <img src="https://www.svgrepo.com/show/530572/accelerate.svg" width="25"> 

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/strider.git
   cd strider
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   streamlit run main.py
   ```

## Usage <img src="https://media.giphy.com/media/WUlplcMpOCEmTGBtBW/giphy.gif" width="30">

1. Select your preferred model provider (Ollama or OpenAI)
2. Enter your application details:
   - Application type
   - Authentication methods
   - Data sensitivity
   - Internet exposure
3. Upload any supporting documents (diagrams, transcripts)
4. Generate threat model and explore different analyses through the tabs:
   - Threat Model
   - Attack Tree
   - Mitigations
   - DREAD Assessment
   - Test Cases
   - Transcript Analysis

## Customization <img src="https://www.svgrepo.com/show/530579/set-up.svg" width="25"> 

- Configure model settings in the sidebar
- Customize threat analysis parameters

## Troubleshooting

- Ensure Ollama is running if using local models
- Check OpenAI API key if using OpenAI models
- Verify file format compatibility for uploads
- Check system memory usage for large analyses

## Use Cases

- **Security Reviews**: Conduct thorough security analysis of applications
- **Development Planning**: Identify security requirements early in development
- **Compliance Checks**: Ensure security controls meet compliance requirements
- **Team Collaboration**: Share and document security discussions
- **Risk Assessment**: Evaluate and prioritize security risks
- **Test Planning**: Generate security-focused test cases

### To-Do List for Contributors

- [ ] Add support for more diagram formats
- [ ] Implement collaborative threat modeling sessions
- [ ] Add export options for different documentation formats
- [ ] Enhance transcript analysis capabilities
- [ ] Add custom scoring systems beyond DREAD
- [ ] Implement real-time collaboration features
- [ ] Add integration with security scanning tools
- [ ] Enhance attack tree visualization options

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on GitHub.

To contribute:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Powered by [Ollama](https://ollama.ai/) and OpenAI
- Uses [Mermaid](https://mermaid-js.github.io/) for diagrams
- [python-docx](https://python-docx.readthedocs.io/) for DOCX processing
- [webvtt-py](https://pypi.org/project/webvtt-py/) for VTT processing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
