# services/technology_analyzer.py
import logging
from typing import Dict, List, Optional, Any
import re
import streamlit as st

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TechnologyStackAnalyzer:
    """Analyzes and identifies technology stack components and their security implications"""

    def __init__(self):
        logger.info("Initializing TechnologyStackAnalyzer")
        self.tech_patterns = {
            'databases': {
                'postgresql': r'postgres(?:ql)?|psql',
                'mongodb': r'mongo(?:db)?',
                'mysql': r'mysql',
                'redis': r'redis',
                'elasticsearch': r'elastic(?:search)?'
            },
            'web_servers': {
                'nginx': r'nginx',
                'apache': r'apache|httpd',
                'iis': r'iis|internet information services'
            },
            'cloud_services': {
                'aws': r'aws|amazon|cloudfront|s3|ec2|rds',
                'azure': r'azure|microsoft cloud',
                'gcp': r'gcp|google cloud'
            },
            'authentication': {
                'oauth': r'oauth2?|openid connect',
                'jwt': r'jwt|json web token',
                'saml': r'saml'
            },
            'frameworks': {
                'spring': r'spring(?:boot)?',
                'django': r'django',
                'react': r'react(?:js)?',
                'angular': r'angular(?:js)?',
                'vue': r'vue(?:js)?'
            }
        }

    def analyze_component(self, component_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a component to identify technologies used
        
        Args:
            component_info: Dictionary containing component information
            
        Returns:
            Dictionary with identified technologies and security implications
        """
        logger.info(f"Analyzing component: {component_info.get('name', 'unnamed')}")
        
        identified_tech = {
            'technologies': [],
            'security_implications': []
        }

        try:
            component_text = f"{component_info.get('name', '')} {component_info.get('description', '')}".lower()
            
            for category, patterns in self.tech_patterns.items():
                for tech, pattern in patterns.items():
                    if re.search(pattern, component_text, re.IGNORECASE):
                        logger.debug(f"Found technology: {tech} in category {category}")
                        tech_info = self._get_technology_details(tech, category)
                        identified_tech['technologies'].append(tech_info)
                        identified_tech['security_implications'].extend(tech_info.get('security_implications', []))

            logger.info(f"Completed technology analysis for component {component_info.get('name', 'unnamed')}")
            return identified_tech

        except Exception as e:
            logger.error(f"Error analyzing component technologies: {str(e)}")
            return identified_tech

    def _get_technology_details(self, tech_name: str, category: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific technology
        
        Args:
            tech_name: Name of the technology
            category: Category of the technology
            
        Returns:
            Dictionary containing technology details and security implications
        """
        # This would typically come from a knowledge base. For now, using static mappings
        security_implications = {
            'postgresql': [
                'SQL injection vulnerabilities if not properly parameterized',
                'Privilege escalation through weak role configurations',
                'Data exposure through misconfigured connection strings'
            ],
            'redis': [
                'Data exposure if not properly authenticated',
                'Cache poisoning attacks',
                'DOS through memory exhaustion'
            ],
            'nginx': [
                'DDoS vulnerabilities if not properly configured',
                'Information disclosure through server headers',
                'Path traversal attacks'
            ],
            'aws': [
                'S3 bucket misconfigurations',
                'IAM privilege escalation',
                'CloudFront security misconfigurations'
            ],
            'oauth': [
                'Token leakage through insecure storage',
                'CSRF attacks on callback endpoints',
                'Phishing through malicious redirect_uri'
            ]
            # Add more as needed
        }

        return {
            'name': tech_name,
            'category': category,
            'security_implications': security_implications.get(tech_name, [
                'Ensure proper access controls',
                'Regular security patching required',
                'Follow security best practices'
            ])
        }

class IntegrationAnalyzer:
    """Analyzes integration patterns and their security implications"""

    def __init__(self):
        logger.info("Initializing IntegrationAnalyzer")

    def analyze_relationships(self, relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes relationships between components to identify integration patterns
        
        Args:
            relationships: List of relationship dictionaries
            
        Returns:
            Enhanced relationship list with security considerations
        """
        logger.info(f"Analyzing {len(relationships)} relationships")
        enhanced_relationships = []

        try:
            for relationship in relationships:
                enhanced_relationship = self._enhance_relationship(relationship)
                enhanced_relationships.append(enhanced_relationship)

            logger.info("Completed relationship analysis")
            return enhanced_relationships

        except Exception as e:
            logger.error(f"Error analyzing relationships: {str(e)}")
            return relationships

    def _enhance_relationship(self, relationship: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhances a single relationship with security considerations
        
        Args:
            relationship: Single relationship dictionary
            
        Returns:
            Enhanced relationship with security considerations
        """
        enhanced = relationship.copy()
        
        # Analyze data flow
        data_flow = relationship.get('data_flow', '').lower()
        description = relationship.get('description', '').lower()

        # Determine security considerations based on the relationship
        security_considerations = []

        # Check for data transfer patterns
        if 'sync' in data_flow or 'synchronous' in description:
            security_considerations.append({
                'pattern': 'Synchronous Communication',
                'risks': [
                    'DOS vulnerability due to blocking operations',
                    'Cascading failures if timeout handling is improper'
                ]
            })

        if 'async' in data_flow or 'asynchronous' in description:
            security_considerations.append({
                'pattern': 'Asynchronous Communication',
                'risks': [
                    'Message queue flooding',
                    'Data consistency issues',
                    'Message replay attacks'
                ]
            })

        if 'http' in data_flow or 'rest' in description:
            security_considerations.append({
                'pattern': 'HTTP/REST Communication',
                'risks': [
                    'MITM attacks if TLS is not properly configured',
                    'API endpoint security vulnerabilities',
                    'Input validation bypasses'
                ]
            })

        enhanced['security_considerations'] = security_considerations
        enhanced['requires_encryption'] = self._check_encryption_requirement(relationship)

        return enhanced

    def _check_encryption_requirement(self, relationship: Dict[str, Any]) -> bool:
        """
        Determines if the relationship requires encryption
        
        Args:
            relationship: Relationship dictionary
            
        Returns:
            Boolean indicating if encryption is required
        """
        # Keywords that suggest sensitive data transfer
        sensitive_patterns = [
            'auth', 'password', 'credential', 'token', 'secret', 'private', 
            'personal', 'payment', 'financial', 'health'
        ]

        description = f"{relationship.get('description', '')} {relationship.get('data_flow', '')}".lower()
        return any(pattern in description for pattern in sensitive_patterns)

def analyze_architecture(components: List[Dict[str, Any]], 
                       relationships: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Main function to analyze architecture combining component and integration analysis
    
    Args:
        components: List of components from diagram analysis
        relationships: List of relationships between components
        
    Returns:
        Complete analysis including technologies and integration patterns
    """
    logger.info("Starting comprehensive architecture analysis")
    
    try:
        tech_analyzer = TechnologyStackAnalyzer()
        integration_analyzer = IntegrationAnalyzer()

        # Analyze components
        enhanced_components = []
        for component in components:
            tech_analysis = tech_analyzer.analyze_component(component)
            enhanced_component = {**component, **tech_analysis}
            enhanced_components.append(enhanced_component)

        # Analyze relationships
        enhanced_relationships = integration_analyzer.analyze_relationships(relationships)

        analysis_result = {
            'components': enhanced_components,
            'relationships': enhanced_relationships,
            'security_summary': _generate_security_summary(enhanced_components, enhanced_relationships)
        }

        logger.info("Completed architecture analysis")
        return analysis_result

    except Exception as e:
        logger.error(f"Error in architecture analysis: {str(e)}")
        return {
            'components': components,
            'relationships': relationships,
            'error': str(e)
        }

def _generate_security_summary(components: List[Dict[str, Any]], 
                             relationships: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generates a summary of security implications
    
    Args:
        components: List of analyzed components
        relationships: List of analyzed relationships
        
    Returns:
        Security summary dictionary
    """
    return {
        'critical_components': [
            comp['name'] for comp in components 
            if any('critical' in impl.lower() 
                  for impl in comp.get('security_implications', []))
        ],
        'sensitive_data_flows': [
            rel for rel in relationships 
            if rel.get('requires_encryption', False)
        ],
        'high_risk_technologies': [
            tech['name'] for comp in components
            for tech in comp.get('technologies', [])
            if len(tech.get('security_implications', [])) > 2
        ]
    }