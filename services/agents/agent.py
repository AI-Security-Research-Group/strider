# services/agents/agent.py

import json
import requests
import re
import logging
from typing import Dict, Any, Optional, List
from services.knowledge_base.service import KnowledgeBaseService

import streamlit as st

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def log_agent_response(func):
    """Decorator to log agent responses"""
    def wrapper(self, *args, **kwargs):
        result = func(self, *args, **kwargs)
        
        # Pretty print the response
        import json
        logger.info(f"\n{'='*50}")
        logger.info(f"Agent: {self.name}")
        logger.info(f"Response:\n{json.dumps(result, indent=2)}")
        logger.info(f"{'='*50}\n")
        
        return result
    return wrapper

class SecurityAgent:
    """Enhanced Security Agent with component-aware analysis"""
    def __init__(self, name: str, role_prompt: str):
        self.name = name
        self.role_prompt = role_prompt
        self.base_url = "http://localhost:11434"
        self.kb_service = KnowledgeBaseService()  # Initialize KB service
        logger.info(f"Initialized {name} agent with Knowledge Base")

    @log_agent_response
    def get_solution(self, 
                    problem: str,
                    previous_solution: Optional[Dict[str, Any]] = None,
                    architecture_analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get solution from agent with KB integration"""
        try:
            logger.info(f"{self.name}: Starting analysis")
            
            if self.name == "ThreatModelCompiler":
                return self._compile_threats(previous_solution, architecture_analysis)

            # Get KB threats
            kb_threats = self._get_kb_threats(architecture_analysis)
            logger.info(f"Found {len(kb_threats)} threats from knowledge base")

            # Get LLM analysis
            llm_result = self._get_llm_analysis(problem, previous_solution, architecture_analysis)
            
            # Merge threats
            merged_result = self._merge_threats(kb_threats, llm_result)
            logger.info(f"Final merged result has {len(merged_result.get('threats', []))} threats")

            return merged_result
            
        except Exception as e:
            logger.error(f"Error in {self.name} analysis: {str(e)}", exc_info=True)
            return self._get_empty_response(str(e))

    def _get_llm_analysis(self, 
                        problem: str,
                        previous_solution: Optional[Dict[str, Any]],
                        architecture_analysis: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Get analysis from LLM with proper score handling"""
        try:
            logger.info(f"{self.name}: Getting LLM analysis")
            
            # Build messages with context
            messages = self.build_messages(problem, previous_solution, architecture_analysis)
            prompt = self.build_prompt(messages)
            
            # Get LLM response
            response = self.make_api_call(prompt)
            if not response:
                logger.warning(f"{self.name}: No response from LLM")
                return self._get_empty_response()
                
            # Process the response
            raw_result = self.process_response(response)
            
            # Normalize threat scores
            if "threats" in raw_result:
                for threat in raw_result["threats"]:
                    # Handle risk score if present
                    if "risk_score" in threat:
                        score_value = threat["risk_score"]
                        try:
                            if isinstance(score_value, str) and '/' in score_value:
                                numerator, denominator = score_value.split('/')
                                normalized_score = (float(numerator.strip()) / float(denominator.strip())) * 10
                            else:
                                normalized_score = float(score_value)
                            threat["risk_score"] = normalized_score
                        except (ValueError, TypeError):
                            threat["risk_score"] = 5.0  # default score

                    # Also handle criticality score if present
                    if "criticality_score" in threat:
                        score_value = threat["criticality_score"]
                        try:
                            if isinstance(score_value, str) and '/' in score_value:
                                numerator, denominator = score_value.split('/')
                                normalized_score = (float(numerator.strip()) / float(denominator.strip())) * 10
                            else:
                                normalized_score = float(score_value)
                            threat["criticality_score"] = normalized_score
                        except (ValueError, TypeError):
                            threat["criticality_score"] = 5.0  # default score

                    # Add source information
                    threat["source"] = self.name
            
            logger.info(f"{self.name}: Successfully processed LLM analysis")
            return raw_result

        except Exception as e:
            logger.error(f"Error getting LLM analysis: {str(e)}", exc_info=True)
            return self._get_empty_response(str(e))

    def _compile_threats(self, 
                        collective_findings: Dict[str, Any],
                        architecture_analysis: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Compile collective findings from all agents"""
        try:
            logger.info("\nThreatModelCompiler: Starting compilation")
            
            # Extract data from collective findings
            threats = collective_findings.get('threats', [])
            improvements = collective_findings.get('improvement_suggestions', [])
            questions = collective_findings.get('open_questions', [])
            
            # Log received data
            logger.info(f"Received for compilation:")
            logger.info(f"- Threats: {len(threats)}")
            logger.info(f"- Improvements: {len(improvements)}")
            logger.info(f"- Questions: {len(questions)}")

            # Process threats by STRIDE
            categorized_threats = self._categorize_by_stride(threats)
            
            # Create final model
            compiled_model = {
                "threat_model": threats,
                "improvement_suggestions": improvements,
                "open_questions": questions,
                "risk_summary": self._generate_risk_summary(threats),
                "stride_summary": {
                    category: len(cat_threats) 
                    for category, cat_threats in categorized_threats.items()
                }
            }

            # Log compilation results
            logger.info("\nCompilation complete:")
            logger.info(f"- Total threats: {len(compiled_model['threat_model'])}")
            logger.info(f"- Improvements: {len(compiled_model['improvement_suggestions'])}")
            logger.info(f"- Questions: {len(compiled_model['open_questions'])}")
            logger.info(f"- STRIDE distribution: {compiled_model['stride_summary']}")

            return compiled_model

        except Exception as e:
            logger.error(f"Error in compilation: {str(e)}")
            return self._get_empty_response(str(e))

    def _categorize_by_stride(self, threats: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize threats by STRIDE"""
        categories = {
            "Spoofing": [],
            "Tampering": [],
            "Repudiation": [],
            "Information Disclosure": [],
            "Denial of Service": [],
            "Elevation of Privilege": []
        }
        
        for threat in threats:
            category = threat.get('Threat Type')
            if category in categories:
                categories[category].append(threat)
                
        return categories

    def _analyze_component_threats(self, component_threats: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Analyze threats by component"""
        try:
            logger.info("Analyzing threats by component")
            component_analysis = {}
            
            for component, threats in component_threats.items():
                component_analysis[component] = {
                    "total_threats": len(threats),
                    "risk_level": self._calculate_risk_level(threats),
                    "critical_threats": self._get_critical_threats(threats),
                    "affected_by": self._get_affecting_components(threats),
                    "threat_categories": self._categorize_threats(threats)
                }
                logger.info(f"Analyzed {len(threats)} threats for {component}")
                
            return component_analysis
        except Exception as e:
            logger.error(f"Error analyzing component threats: {str(e)}")
            return {}

    def _calculate_risk_level(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk level for a set of threats"""
        try:
            if not threats:
                return {"level": "low", "score": 0}
                
            # Calculate average criticality score
            scores = [
                threat.get("criticality_score", 5) 
                for threat in threats
            ]
            avg_score = sum(scores) / len(scores)
            
            # Determine risk level
            if avg_score >= 7:
                level = "high"
            elif avg_score >= 4:
                level = "medium"
            else:
                level = "low"
                
            return {
                "level": level,
                "score": round(avg_score, 2)
            }
        except Exception as e:
            logger.error(f"Error calculating risk level: {str(e)}")
            return {"level": "unknown", "score": 0}

    def _get_critical_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical threats"""
        try:
            return [
                {
                    "type": threat.get("Threat Type"),
                    "scenario": threat.get("Scenario"),
                    "score": threat.get("criticality_score", 0)
                }
                for threat in threats
                if threat.get("criticality_score", 0) >= 7
            ]
        except Exception as e:
            logger.error(f"Error getting critical threats: {str(e)}")
            return []

    def _get_affecting_components(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Get list of components affecting or affected by these threats"""
        try:
            affected_components = set()
            for threat in threats:
                affected_components.update(threat.get("affected_components", []))
            return list(affected_components)
        except Exception as e:
            logger.error(f"Error getting affecting components: {str(e)}")
            return []

    def _categorize_threats(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize threats by STRIDE categories"""
        try:
            categories = {}
            for threat in threats:
                category = threat.get("Threat Type", "Unknown")
                categories[category] = categories.get(category, 0) + 1
            return categories
        except Exception as e:
            logger.error(f"Error categorizing threats: {str(e)}")
            return {}

    def _generate_risk_summary(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate basic risk summary"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        threat_categories = {}
        for threat in threats:
            # Count by severity
            score = threat.get("criticality_score", 5)
            if score >= 9:
                severity_counts["critical"] += 1
            elif score >= 7:
                severity_counts["high"] += 1
            elif score >= 4:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1

            # Count by category
            category = threat.get("Threat Type", "Unknown")
            threat_categories[category] = threat_categories.get(category, 0) + 1

        return {
            "total_threats": len(threats),
            "severity_distribution": severity_counts,
            "threat_categories": threat_categories
        }

    def _get_highest_risk_components(self, 
                                component_threats: Dict[str, List[Dict[str, Any]]],
                                limit: int = 3) -> List[Dict[str, Any]]:
        """Get components with highest risk"""
        try:
            component_risks = []
            for component, threats in component_threats.items():
                risk_level = self._calculate_risk_level(threats)
                component_risks.append({
                    "component": component,
                    "risk_score": risk_level["score"],
                    "threat_count": len(threats),
                    "critical_threats": len([
                        t for t in threats 
                        if t.get("criticality_score", 0) >= 7
                    ])
                })
            
            # Sort by risk score and get top components
            return sorted(
                component_risks,
                key=lambda x: (x["risk_score"], x["critical_threats"]),
                reverse=True
            )[:limit]
        except Exception as e:
            logger.error(f"Error getting highest risk components: {str(e)}")
            return []
    
    def _log_findings(self, findings: Dict[str, Any], agent_name: str):
        """Log detailed findings from each agent"""
        logger.info(f"\n{'='*50}")
        logger.info(f"Findings from {agent_name}:")
        logger.info(f"Threats found: {len(findings.get('threats', []))}")
        
        # Log threat details
        for threat in findings.get('threats', []):
            logger.info(f"\nThreat Details:")
            logger.info(f"Type: {threat.get('Threat Type')}")
            logger.info(f"Component: {threat.get('component_name', 'system')}")
            logger.info(f"Severity: {threat.get('severity', 'unknown')}")
            
        # Log other findings
        logger.info(f"Improvement suggestions: {len(findings.get('improvement_suggestions', []))}")
        logger.info(f"Open questions: {len(findings.get('open_questions', []))}")
        logger.info(f"{'='*50}\n")    


    def analyze_with_agents(self, 
                          system_description: str,
                          architecture_analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Enhanced agent analysis with proper data collection"""
        try:
            logger.info("Starting agent-based analysis")
            agents = self.create_agents()
            all_findings = {
                "threats": [],
                "component_threats": {},
                "improvement_suggestions": set(),
                "open_questions": set()
            }

            # Process with each STRIDE agent
            for agent in agents[:-1]:  # Exclude compiler from first pass
                logger.info(f"Processing with agent: {agent.name}")
                solution = agent.get_solution(
                    system_description,
                    all_findings,  # Pass collective findings
                    architecture_analysis
                )
                
                # Collect findings
                if solution:
                    # Add threats
                    if "threats" in solution:
                        all_findings["threats"].extend(solution["threats"])
                    
                    # Add improvement suggestions
                    if "improvement_suggestions" in solution:
                        all_findings["improvement_suggestions"].update(solution["improvement_suggestions"])
                    
                    # Add open questions
                    if "open_questions" in solution:
                        all_findings["open_questions"].update(solution["open_questions"])
                    
                    # Track component-specific threats
                    for threat in solution.get("threats", []):
                        component = threat.get("component_name", "system")
                        if component not in all_findings["component_threats"]:
                            all_findings["component_threats"][component] = []
                        all_findings["component_threats"][component].append(threat)

                logger.info(f"Agent {agent.name} found {len(solution.get('threats', []))} threats")

            # Get compiler agent (last agent)
            compiler_agent = agents[-1]
            logger.info("Processing with ThreatModelCompiler")
            
            # Prepare comprehensive input for compiler
            compiler_input = {
                "threats": all_findings["threats"],
                "component_threats": all_findings["component_threats"],
                "improvement_suggestions": list(all_findings["improvement_suggestions"]),
                "open_questions": list(all_findings["open_questions"]),
                "architecture_analysis": architecture_analysis
            }

            # Get compiled results
            compiled_result = compiler_agent.get_solution(
                system_description,
                compiler_input,
                architecture_analysis
            )

            # Log compilation results
            logger.info(f"""
            Compilation complete:
            - Total threats analyzed: {len(all_findings['threats'])}
            - Components affected: {len(all_findings['component_threats'])}
            - Improvement suggestions: {len(all_findings['improvement_suggestions'])}
            - Open questions: {len(all_findings['open_questions'])}
            """)

            # Store complete analysis results
            st.session_state['agent_analyses'] = [(agent.name, compiled_result)]
            
            return compiled_result

        except Exception as e:
            logger.error(f"Error in agent-based analysis: {str(e)}", exc_info=True)
            return {
                "threat_model": [],
                "improvement_suggestions": [],
                "open_questions": []
            }

    def _get_kb_threats(self, architecture_analysis: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get relevant threats from knowledge base"""
        try:
            if not architecture_analysis:
                return []

            threats = []
            components = architecture_analysis.get("components", [])
            relationships = architecture_analysis.get("relationships", [])

            # Get component-specific threats
            for component in components:
                kb_threats = self.kb_service.get_component_threats(
                    component.get("type", "custom"),
                    context=component
                )
                
                # Filter threats based on agent type
                filtered_threats = self._filter_threats_by_category(kb_threats)
                threats.extend(filtered_threats)

            # Add relationship-specific threats
            if relationships and self.name != "ThreatModelCompiler":
                relationship_threats = self._analyze_relationships(relationships)
                threats.extend(relationship_threats)

            return threats

        except Exception as e:
            logger.error(f"Error getting KB threats: {str(e)}", exc_info=True)
            return []

    def _filter_threats_by_category(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter threats based on agent's STRIDE category"""
        category_mapping = {
            "SpoofingExpert": ["Spoofing"],
            "TamperingExpert": ["Tampering"],
            "RepudiationExpert": ["Repudiation"],
            "DosExpert": ["Denial of Service"],
            "ElevationExpert": ["Elevation of Privilege"],
            "ThreatModelCompiler": None  # Compiler gets all threats
        }

        relevant_categories = category_mapping.get(self.name)
        if not relevant_categories:
            return threats

        return [
            threat for threat in threats 
            if threat.get("category") in relevant_categories
        ]

    def _analyze_relationships(self, relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze component relationships for threats"""
        threats = []
        
        try:
            for rel in relationships:
                source = rel.get("source", "")
                target = rel.get("target", "")
                data_flow = rel.get("data_flow", "").lower()

                # Get relationship-specific threats from KB
                kb_threats = self.kb_service.analyze_relationship(
                    source_type=rel.get("source_type"),
                    target_type=rel.get("target_type"),
                    data_flow=data_flow
                )

                threats.extend(kb_threats)

        except Exception as e:
            logger.error(f"Error analyzing relationships: {str(e)}")

        return threats

    def _merge_threats(self, 
                      kb_threats: List[Dict[str, Any]], 
                      llm_result: Dict[str, Any]) -> Dict[str, Any]:
        """Merge threats from KB and LLM analysis"""
        try:
            # Convert KB threats to common format
            formatted_kb_threats = []
            for threat in kb_threats:
                formatted_threat = {
                    "Threat Type": threat.get("category", "Unknown"),
                    "Scenario": threat.get("description", ""),
                    "Potential Impact": threat.get("impact_description", ""),
                    "component_name": threat.get("component_name", "System"),
                    "attack_vectors": threat.get("attack_vectors", []),
                    "affected_components": threat.get("affected_components", []),
                    "criticality_score": threat.get("severity_score", 5),
                    "source": "Knowledge Base",
                    "cves": threat.get("cves", []),
                    "mitigations": threat.get("mitigations", [])
                }
                formatted_kb_threats.append(formatted_threat)

            # Get LLM threats
            llm_threats = llm_result.get("threats", [])
            for threat in llm_threats:
                threat["source"] = "LLM Analysis"

            # Combine threats
            all_threats = formatted_kb_threats + llm_threats

            # Create merged result
            merged_result = {
                "threats": all_threats,
                "analysis_details": llm_result.get("analysis_details", ""),
                "confidence_level": llm_result.get("confidence_level", "5"),
                "improvement_suggestions": (
                    llm_result.get("improvement_suggestions", []) +
                    self._get_kb_suggestions(kb_threats)
                ),
                "open_questions": llm_result.get("open_questions", [])
            }

            return merged_result

        except Exception as e:
            logger.error(f"Error merging threats: {str(e)}")
            return llm_result

    def _deduplicate_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate threats with enhanced matching"""
        unique_threats = []
        seen_scenarios = {}
        
        for threat in threats:
            # Create a normalized scenario key
            scenario = threat.get('Scenario', '').lower()
            words = set(re.findall(r'\w+', scenario))
            key = ' '.join(sorted(words))
            
            if key not in seen_scenarios:
                seen_scenarios[key] = threat
                unique_threats.append(threat)
            else:
                # Merge similar threats
                existing_threat = seen_scenarios[key]
                # Preserve source information
                existing_threat['source'] = f"{existing_threat.get('source', '')} + {threat.get('source', '')}"
                # Merge affected components
                existing_components = set(existing_threat.get('affected_components', []))
                new_components = set(threat.get('affected_components', []))
                existing_threat['affected_components'] = list(existing_components.union(new_components))
                # Take highest criticality score
                existing_threat['criticality_score'] = max(
                    float(existing_threat.get('criticality_score', 0)),
                    float(threat.get('criticality_score', 0))
                )
        
        return unique_threats

    def _get_scenario_hash(self, threat: Dict[str, Any]) -> str:
        """Create a hash for threat scenario comparison"""
        scenario = threat.get('Scenario', '').lower()
        component = threat.get('component_name', '').lower()
        return f"{component}:{scenario}"

    def _merge_threat_info(self, existing_threat: Dict[str, Any], new_threat: Dict[str, Any]):
        """Merge additional information from duplicate threats"""
        # Merge attack vectors
        existing_threat["attack_vectors"] = list(set(
            existing_threat.get("attack_vectors", []) +
            new_threat.get("attack_vectors", [])
        ))

        # Merge affected components
        existing_threat["affected_components"] = list(set(
            existing_threat.get("affected_components", []) +
            new_threat.get("affected_components", [])
        ))

        # Merge CVEs if available
        existing_threat["cves"] = list(set(
            existing_threat.get("cves", []) +
            new_threat.get("cves", [])
        ))

        # Merge mitigations
        existing_threat["mitigations"] = list(set(
            existing_threat.get("mitigations", []) +
            new_threat.get("mitigations", [])
        ))

        # Update source
        sources = set([existing_threat.get("source", ""), new_threat.get("source", "")])
        existing_threat["source"] = " + ".join(filter(None, sources))

    def _get_kb_suggestions(self, kb_threats: List[Dict[str, Any]]) -> List[str]:
        """Get improvement suggestions from KB threats"""
        suggestions = set()
        for threat in kb_threats:
            suggestions.update(threat.get("mitigations", []))
        return list(suggestions)


    def build_messages(self, 
                      problem: str, 
                      previous_solution: Optional[Dict[str, Any]],
                      architecture_analysis: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Build message sequence for the agent with component context"""
        
        # For ThreatModelCompiler, focus on consolidation
        if self.name == "ThreatModelCompiler":
            return self._build_compiler_messages(previous_solution, architecture_analysis)
            
        # For other agents, build component-aware analysis prompt
        return self._build_analysis_messages(problem, architecture_analysis)

    def _build_compiler_messages(self, 
                               previous_solution: Dict[str, Any],
                               architecture_analysis: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Build messages for the ThreatModelCompiler"""
        messages = [
            {"role": "system", "content": self.role_prompt}
        ]
        
        # Add architecture context if available
        if architecture_analysis:
            arch_context = (
                f"Architecture Analysis:\n"
                f"Components: {json.dumps(architecture_analysis.get('components', []), indent=2)}\n"
                f"Relationships: {json.dumps(architecture_analysis.get('relationships', []), indent=2)}\n"
            )
            messages.append({"role": "user", "content": arch_context})
        
        # Add previous analysis
        if previous_solution:
            messages.append({
                "role": "user", 
                "content": f"Previous Analysis:\n{json.dumps(previous_solution, indent=2)}\n\nProvide final compilation."
            })
            
        return messages

    def _build_analysis_messages(self, 
                               problem: str,
                               architecture_analysis: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Build messages for STRIDE analysis agents"""
        
        base_prompt = (
            f"Based on your expertise as {self.name}, analyze the following system and its "
            f"components for security threats. Focus specifically on your area of expertise "
            f"and provide detailed analysis for each relevant component. List multiple credible threats if applicable. Each threat scenario should be specific to this application context.\n\n"
        )
        
        # Add system description
        system_context = f"System Description:\n{problem}\n\n"
        
        # Add architecture context if available
        if architecture_analysis:
            system_context += (
                f"Component Analysis:\n"
                f"{json.dumps(architecture_analysis.get('components', []), indent=2)}\n\n"
                f"Integration Analysis:\n"
                f"{json.dumps(architecture_analysis.get('relationships', []), indent=2)}\n\n"
            )
        
        return [
            {"role": "system", "content": self.role_prompt},
            {"role": "user", "content": base_prompt + system_context}
        ]

    def _get_empty_response(self, error_msg: str = "") -> Dict[str, Any]:
        """Get empty response with basic structure"""
        return {
            "threat_model": [],
            "component_analysis": {},
            "improvement_suggestions": [],
            "open_questions": [],
            "risk_summary": {
                "total_threats": 0,
                "severity_distribution": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "threat_categories": {}
            },
            "stride_summary": {
                "Spoofing": 0,
                "Tampering": 0,
                "Repudiation": 0,
                "Information Disclosure": 0,
                "Denial of Service": 0,
                "Elevation of Privilege": 0
            }
        }

    def build_prompt(self, messages: List[Dict[str, str]]) -> str:
        """Build the complete prompt for the agent"""
        return "\n\n".join(msg["content"] for msg in messages)

    def make_api_call(self, prompt: str) -> Optional[str]:
        """Make API call to the language model with debug logging"""
        try:
            # Log complete prompt for debugging
            logger.info(f"\n{'='*50}")
            logger.info(f"Agent: {self.name} - API Call")
            logger.info(f"Complete Prompt:\n{prompt}")
            logger.info(f"{'='*50}\n")

            payload = {
                "model": "qwen2.5-coder:14b",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security expert. Provide detailed analysis in JSON format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "frequency_penalty": 0.1,
                    "presence_penalty": 0.1,
                    "max_tokens": 4000,
                    "timeout": 120,
                    "request_timeout": 120
                }
            }
            
            # Log the payload
            logger.info(f"API Payload:\n{json.dumps(payload, indent=2)}")
            
            response = requests.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            
            # Log the raw response
            raw_response = response.json().get('message', {}).get('content', '')
            logger.info(f"Raw Response:\n{raw_response}\n")
            
            return raw_response
            
        except Exception as e:
            logger.error(f"API call error for {self.name}: {str(e)}", exc_info=True)
            return None

    def process_response(self, response: str) -> Dict[str, Any]:
        """Process and structure the agent's response"""
        try:
            # Log raw response before processing
            logger.info(f"\n{'='*50}")
            logger.info(f"Processing Response for {self.name}")
            logger.info(f"Raw Response to Process:\n{response}")

            # Try to extract JSON from the response
            json_pattern = r'\{[\s\S]*\}'
            matches = re.findall(json_pattern, response)
            
            for match in matches:
                try:
                    result = json.loads(match)
                    if isinstance(result, dict):
                        # Log the parsed JSON
                        logger.info(f"Successfully parsed JSON:\n{json.dumps(result, indent=2)}")
                        
                        # Validate and return the response
                        validated = self._validate_response(result)
                        logger.info(f"Validated Response:\n{json.dumps(validated, indent=2)}")
                        return validated
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {str(e)}")
                    continue
            
            logger.warning(f"{self.name}: Could not parse response as JSON")
            return self._get_empty_response()
                    
        except Exception as e:
            logger.error(f"Error processing response for {self.name}: {str(e)}", exc_info=True)
            return self._get_empty_response(str(e))


    def _validate_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and structure the agent's response"""
        try:
            logger.info(f"Validating response for {self.name}")
            logger.info(f"Original response:\n{json.dumps(response, indent=2)}")

            # Initialize validated response
            validated = {
                "threats": [],
                "analysis_details": response.get("analysis_details", ""),
                "confidence_level": response.get("confidence_level", "5"),
                "improvement_suggestions": response.get("improvement_suggestions", []),
                "open_questions": response.get("open_questions", [])
            }

            # Check both 'threats' and 'threat_model' fields
            threats = response.get("threats", []) or response.get("threat_model", [])
            
            if isinstance(threats, list):
                logger.info(f"Found {len(threats)} threats to process")
                validated["threats"] = threats
                
            logger.info(f"Final validated response:\n{json.dumps(validated, indent=2)}")
            return validated

        except Exception as e:
            logger.error(f"Validation error for {self.name}: {str(e)}", exc_info=True)
            return {
                "threats": [],
                "analysis_details": str(e),
                "confidence_level": "0",
                "improvement_suggestions": [],
                "open_questions": []
            }

    def _validate_stride_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Validate STRIDE agent response"""
        validated = {
            "threats": [],
            "analysis_details": response.get("analysis_details", "No analysis provided"),
            "confidence_level": response.get("confidence_level", "0")
        }

        # Validate threats
        for threat in response.get("threats", []):
            if self._is_valid_threat(threat):
                validated["threats"].append(threat)

        logger.info(f"{self.name}: Validated {len(validated['threats'])} threats")
        return validated

    def _validate_compiler_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Validate ThreatModelCompiler response"""
        validated = {
            "threat_model": [],
            "component_recommendations": {},
            "improvement_suggestions": [],
            "critical_paths": [],
            "open_questions": []
        }

        # Validate threat model
        for threat in response.get("threat_model", []):
            if self._is_valid_threat(threat):
                validated["threat_model"].append(threat)

        # Validate component recommendations
        for component, recs in response.get("component_recommendations", {}).items():
            if isinstance(recs, list):
                validated["component_recommendations"][component] = [
                    rec for rec in recs
                    if isinstance(rec, dict) and "recommendation" in rec
                ]

        # Validate other fields
        validated["improvement_suggestions"] = [
            str(sugg) for sugg in response.get("improvement_suggestions", [])
            if sugg
        ]
        
        validated["critical_paths"] = [
            path for path in response.get("critical_paths", [])
            if isinstance(path, dict) and "path" in path
        ]
        
        validated["open_questions"] = [
            str(q) for q in response.get("open_questions", [])
            if q
        ]

        logger.info(
            f"Compiler validation complete: "
            f"{len(validated['threat_model'])} threats, "
            f"{len(validated['component_recommendations'])} component recommendations"
        )
        return validated

    def _is_valid_threat(self, threat: Dict[str, Any]) -> bool:
        """More lenient threat validation"""
        try:
            logger.debug(f"Validating threat:\n{json.dumps(threat, indent=2)}")
            
            # Check if there's at least a scenario or description
            has_description = any([
                threat.get("Scenario"),
                threat.get("scenario"),
                threat.get("description")
            ])

            return has_description

        except Exception as e:
            logger.error(f"Error validating threat: {str(e)}")
            return False