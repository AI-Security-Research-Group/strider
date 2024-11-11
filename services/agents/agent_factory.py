# services/agents/agent_factory.py

from typing import List, Optional, Dict, Any
import logging
from .agent import SecurityAgent
from .prompts import AGENT_PROMPTS

logger = logging.getLogger(__name__)

class SecurityAgentFactory:
    """Factory for creating specialized security analysis agents with component awareness"""
    
    def create_agents(self) -> List[SecurityAgent]:
        """Create and return list of specialized agents"""
        logger.info("Creating specialized security agents")
        return [SecurityAgent(name, prompt) for name, prompt in AGENT_PROMPTS]

# services/agents/agent_factory.py

    def analyze_with_agents(self, prompt: str, model_config: Dict[str, str]) -> Dict[str, Any]:
        """Analyze system using specialized security agents"""
        try:
            logger.info("Starting agent-based analysis")
            agents = self.create_agents()
            all_agent_results = []
            all_threats = []
            all_improvements = set()
            all_questions = set()

            # First pass: Run all STRIDE agents
            stride_agents = [agent for agent in agents if agent.name != "ThreatModelCompiler"]
            compiler_agent = next(agent for agent in agents if agent.name == "ThreatModelCompiler")

            with st.spinner("Running Security Analysis..."):
                # Process with STRIDE agents
                for idx, agent in enumerate(stride_agents):
                    logger.info(f"\nProcessing with {agent.name}")
                    
                    # Get agent's analysis
                    arch_analysis = st.session_state.get('architecture_analysis', {})
                    solution = agent.get_solution(prompt, None, arch_analysis)
                    
                    # Add to all results
                    all_agent_results.append((agent.name, solution))
                    
                    # Collect threats
                    if solution and 'threats' in solution:
                        for threat in solution['threats']:
                            threat['source'] = agent.name
                            all_threats.append(threat)
                    
                    # Collect improvements and questions
                    if solution:
                        if 'improvement_suggestions' in solution:
                            all_improvements.update(solution['improvement_suggestions'])
                        if 'open_questions' in solution:
                            all_questions.update(solution['open_questions'])

                    logger.info(f"{agent.name} found {len(solution.get('threats', []))} threats")

                # Log collected data
                logger.info("\nCollected data from all agents:")
                logger.info(f"Total threats: {len(all_threats)}")
                logger.info(f"Total improvements: {len(all_improvements)}")
                logger.info(f"Total questions: {len(all_questions)}")

                # Prepare data for compiler
                compiled_input = {
                    "threats": all_threats,
                    "improvement_suggestions": list(all_improvements),
                    "open_questions": list(all_questions),
                    "agent_results": all_agent_results
                }

                # Run compiler
                logger.info("\nRunning ThreatModelCompiler")
                final_result = compiler_agent.get_solution(prompt, compiled_input, arch_analysis)

                # Store all results in session state
                st.session_state['agent_analyses'] = all_agent_results + [("ThreatModelCompiler", final_result)]

                return final_result

        except Exception as e:
            logger.error(f"Agent-based analysis failed: {str(e)}")
            logger.exception("Full traceback:")
            return {
                "threat_model": [],
                "improvement_suggestions": [],
                "open_questions": []
            }

        def _get_final_result(self, all_solutions: List[tuple]) -> Dict[str, Any]:
            """Extract final result from compiler's analysis"""
            for agent_name, solution in reversed(all_solutions):
                if agent_name == "ThreatModelCompiler" and solution:
                    return solution
                    
            logger.warning("No valid compiler solution found")
            return {
                "threat_model": [],
                "improvement_suggestions": [],
                "open_questions": []
            }

    @staticmethod
    def get_agent_names() -> List[str]:
        """Get list of available agent names"""
        return [name for name, _ in AGENT_PROMPTS]