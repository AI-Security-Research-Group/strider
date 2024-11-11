# services/knowledge_base/models.py

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum

class ComponentType(str, Enum):
    API_GATEWAY = "api_gateway"
    DATABASE = "database"
    CACHE = "cache"
    FRONTEND = "frontend"
    BACKEND = "backend"
    AUTH_SERVICE = "authentication_service"
    LOAD_BALANCER = "load_balancer"
    CDN = "cdn"
    MESSAGE_QUEUE = "message_queue"
    CUSTOM = "custom"

class ThreatCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DOS = "Denial of Service"
    ELEVATION = "Elevation of Privilege"

class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class CVE(BaseModel):
    cve_id: str
    description: str
    severity: Severity
    affected_versions: Optional[List[str]]
    mitigation: str
    references: List[str] = Field(default_factory=list)

class ComponentThreat(BaseModel):
    id: str = Field(..., description="Unique identifier for the threat")
    name: str
    category: ThreatCategory
    description: str
    attack_vectors: List[str]
    prerequisites: List[str] = Field(default_factory=list)
    severity: Severity
    impact: Dict[str, int] = Field(..., description="Impact scores for different aspects")
    mitigations: List[str]
    cves: List[CVE] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    detection_methods: List[str] = Field(default_factory=list)

class Component(BaseModel):
    type: ComponentType
    common_threats: List[ComponentThreat]
    security_considerations: List[str]
    best_practices: List[str]
    compliance_requirements: Optional[Dict[str, List[str]]]