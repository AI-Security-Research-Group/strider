# services/knowledge_base/database.py

import logging
from typing import Dict, List, Optional, Any
from sqlalchemy import create_engine, Column, String, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .models import Component, ComponentThreat
import json

logger = logging.getLogger(__name__)
Base = declarative_base()

class KnowledgeBaseEntry(Base):
    __tablename__ = 'knowledge_base'
    
    id = Column(Integer, primary_key=True)
    component_type = Column(String, index=True)
    data = Column(JSON)

class KnowledgeBaseDB:
    def __init__(self, db_url: str = "sqlite:///knowledge_base.db"):
        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        logger.info("Knowledge base database initialized")

    def add_component(self, component: Component) -> bool:
        """Add or update component data in knowledge base"""
        try:
            session = self.Session()
            entry = session.query(KnowledgeBaseEntry).filter_by(
                component_type=component.type
            ).first()

            if entry:
                entry.data = component.dict()
            else:
                entry = KnowledgeBaseEntry(
                    component_type=component.type,
                    data=component.dict()
                )
                session.add(entry)

            session.commit()
            logger.info(f"Successfully added component type: {component.type}")
            return True
        except Exception as e:
            logger.error(f"Error adding component: {str(e)}")
            session.rollback()
            return False
        finally:
            session.close()

    def get_component(self, component_type: str) -> Optional[Component]:
        """Retrieve component data from knowledge base"""
        try:
            session = self.Session()
            entry = session.query(KnowledgeBaseEntry).filter_by(
                component_type=component_type
            ).first()
            
            if entry:
                return Component(**entry.data)
            return None
        except Exception as e:
            logger.error(f"Error retrieving component: {str(e)}")
            return None
        finally:
            session.close()

    def get_component_threats(self, component_type: str) -> List[ComponentThreat]:
        """Get threats for specific component type"""
        component = self.get_component(component_type)
        return component.common_threats if component else []