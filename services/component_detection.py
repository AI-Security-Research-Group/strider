# services/component_detection.py

import re
import logging
from typing import List, Dict, Any, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

class ComponentDetector:
    def __init__(self):
        # Define component patterns and their variations
        self.component_patterns = {
            "Database": {
                "patterns": [
                    r"(?i)(sql\s*server|mysql|postgresql|mongo\s*db|database|db)",
                    r"(?i)(data\s*store|persistence\s*layer)",
                    r"(?i)(nosql|redis|cassandra|oracle\s*db)"
                ],
                "type": "database",
                "indicators": [
                    "store", "query", "record", "table", "schema", 
                    "persist", "retrieve", "data"
                ]
            },
            "API Gateway": {
                "patterns": [
                    r"(?i)(api\s*gateway|gateway\s*service)",
                    r"(?i)(api\s*management|api\s*proxy)",
                    r"(?i)(reverse\s*proxy|load\s*balancer)"
                ],
                "type": "api_gateway",
                "indicators": [
                    "route", "endpoint", "proxy", "forward", "request", 
                    "traffic", "throttle", "rate limit"
                ]
            },
            "Authentication Service": {
                "patterns": [
                    r"(?i)(auth\w*\s*service|identity\s*provider)",
                    r"(?i)(oauth|openid|authentication|authorization)",
                    r"(?i)(sso|single\s*sign\s*on|identity\s*management)"
                ],
                "type": "authentication_service",
                "indicators": [
                    "login", "authenticate", "authorize", "token", "jwt", 
                    "credential", "permission", "role"
                ]
            },
            "Azure Storage": {
                "patterns": [
                    r"(?i)(azure\s*storage|blob\s*storage)",
                    r"(?i)(azure\s*blob|azure\s*files)",
                    r"(?i)(storage\s*account|azure\s*container)"
                ],
                "type": "storage",
                "indicators": [
                    "blob", "container", "storage", "file", "upload", 
                    "download", "store"
                ]
            },
            "Frontend": {
                "patterns": [
                    r"(?i)(frontend|front[\s-]end|ui|user\s*interface)",
                    r"(?i)(client[\s-]side|web\s*app|spa)",
                    r"(?i)(react|angular|vue|web\s*interface)"
                ],
                "type": "frontend",
                "indicators": [
                    "user interface", "browser", "client", "page", 
                    "component", "view", "render"
                ]
            },
            "Cache": {
                "patterns": [
                    r"(?i)(redis|memcached|cache\s*service)",
                    r"(?i)(in[\s-]memory|caching\s*layer)",
                    r"(?i)(distributed\s*cache|cache\s*store)"
                ],
                "type": "cache",
                "indicators": [
                    "cache", "temporary", "in-memory", "quick access", 
                    "performance"
                ]
            }
        }

    def detect_components(self, description: str) -> List[Dict[str, Any]]:
        """
        Detect components from application description with confidence scores
        """
        try:
            logger.info("Starting component detection from description")
            detected_components = []
            
            # Preprocess description
            cleaned_description = self._preprocess_text(description)
            logger.debug(f"Preprocessed description: {cleaned_description}")
            
            # Detect components and calculate confidence
            for component_name, config in self.component_patterns.items():
                confidence_score = self._calculate_component_confidence(
                    cleaned_description,
                    config["patterns"],
                    config["indicators"]
                )
                
                if confidence_score > 0:
                    component_info = {
                        "name": component_name,
                        "type": config["type"],
                        "confidence": confidence_score,
                        "matches": self._find_pattern_matches(
                            cleaned_description,
                            config["patterns"]
                        )
                    }
                    detected_components.append(component_info)
                    logger.info(f"Detected {component_name} with confidence {confidence_score}")
            
            # Sort by confidence score
            detected_components.sort(key=lambda x: x["confidence"], reverse=True)
            
            return detected_components

        except Exception as e:
            logger.error(f"Error in component detection: {str(e)}")
            return []

    def _preprocess_text(self, text: str) -> str:
        """Clean and normalize text for better pattern matching"""
        try:
            # Convert to lowercase
            text = text.lower()
            # Replace multiple spaces with single space
            text = re.sub(r'\s+', ' ', text)
            # Remove special characters but keep spaces
            text = re.sub(r'[^a-z0-9\s]', ' ', text)
            # Remove multiple spaces again after special char removal
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        except Exception as e:
            logger.error(f"Error in text preprocessing: {str(e)}")
            return text

    def _calculate_component_confidence(self, 
                                     text: str, 
                                     patterns: List[str], 
                                     indicators: List[str]) -> float:
        """
        Calculate confidence score for component detection
        Returns score between 0 and 1
        """
        try:
            # Initialize weights
            pattern_weight = 0.7
            indicator_weight = 0.3
            
            # Calculate pattern matches
            pattern_matches = sum(
                1 for pattern in patterns 
                if re.search(pattern, text, re.IGNORECASE)
            )
            pattern_score = min(pattern_matches / len(patterns), 1.0)
            
            # Calculate indicator matches
            indicator_matches = sum(
                1 for indicator in indicators 
                if indicator.lower() in text
            )
            indicator_score = min(indicator_matches / len(indicators), 1.0)
            
            # Calculate weighted score
            confidence = (pattern_score * pattern_weight) + (indicator_score * indicator_weight)
            
            return round(confidence, 2)

        except Exception as e:
            logger.error(f"Error calculating confidence: {str(e)}")
            return 0.0

    def _find_pattern_matches(self, text: str, patterns: List[str]) -> List[str]:
        """Find actual text matches for patterns"""
        matches = []
        try:
            for pattern in patterns:
                found = re.finditer(pattern, text, re.IGNORECASE)
                matches.extend([match.group(0) for match in found])
            return list(set(matches))
        except Exception as e:
            logger.error(f"Error finding pattern matches: {str(e)}")
            return matches

    def suggest_additional_components(self, 
                                   detected_components: List[Dict[str, Any]],
                                   description: str) -> List[Dict[str, Any]]:
        """Suggest additional components based on context"""
        try:
            suggestions = []
            detected_types = {comp["type"] for comp in detected_components}
            
            # Common component relationships
            relationships = {
                "frontend": ["api_gateway", "authentication_service"],
                "api_gateway": ["backend", "authentication_service"],
                "database": ["cache", "backend"],
                "authentication_service": ["database", "cache"]
            }
            
            # Check for missing related components
            for comp in detected_components:
                if comp["type"] in relationships:
                    for related_type in relationships[comp["type"]]:
                        if related_type not in detected_types:
                            suggestions.append({
                                "type": related_type,
                                "reason": f"Commonly used with {comp['name']}",
                                "confidence": 0.5
                            })
            
            return suggestions

        except Exception as e:
            logger.error(f"Error suggesting additional components: {str(e)}")
            return []