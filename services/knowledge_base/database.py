# services/knowledge_base/database.py

import logging
from typing import Dict, List, Optional, Any
from sqlalchemy import create_engine, Column, String, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import json

logger = logging.getLogger(__name__)

# Create the base class
Base = declarative_base()

class KnowledgeBaseEntry(Base):
    """SQLAlchemy model for knowledge base entries"""
    __tablename__ = 'knowledge_base'
    
    id = Column(Integer, primary_key=True)
    component_type = Column(String, index=True)
    data = Column(JSON)

class KnowledgeBaseDB:
    def __init__(self, db_url: str = "sqlite:///knowledge_base.db"):
        """Initialize database connection"""
        try:
            self.engine = create_engine(db_url)
            Base.metadata.create_all(self.engine)
            self.Session = sessionmaker(bind=self.engine)
            logger.info("Knowledge base database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise

    def add_component(self, comp_type: str, comp_data: Dict[str, Any]) -> bool:
        """
        Add or update component data in knowledge base
        
        Args:
            comp_type: Type/name of the component
            comp_data: Component data dictionary
        """
        session = None
        try:
            session = self.Session()
            entry = session.query(KnowledgeBaseEntry).filter_by(
                component_type=comp_type
            ).first()

            if entry:
                logger.info(f"Updating existing component: {comp_type}")
                entry.data = comp_data
            else:
                logger.info(f"Adding new component: {comp_type}")
                entry = KnowledgeBaseEntry(
                    component_type=comp_type,
                    data=comp_data
                )
                session.add(entry)

            session.commit()
            logger.info(f"Successfully added/updated component: {comp_type}")
            return True

        except Exception as e:
            logger.error(f"Error adding component {comp_type}: {str(e)}")
            if session:
                session.rollback()
            return False

        finally:
            if session:
                session.close()

    def get_component(self, component_type: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve component data from knowledge base
        
        Args:
            component_type: Type of component to retrieve
        """
        session = None
        try:
            session = self.Session()
            entry = session.query(KnowledgeBaseEntry).filter_by(
                component_type=component_type
            ).first()
            
            if entry:
                return entry.data
            logger.warning(f"No component found for type: {component_type}")
            return None

        except Exception as e:
            logger.error(f"Error retrieving component {component_type}: {str(e)}")
            return None

        finally:
            if session:
                session.close()

    def get_component_threats(self, component_type: str) -> List[Dict[str, Any]]:
        """
        Get threats for specific component type
        
        Args:
            component_type: Type of component to get threats for
        """
        try:
            component_data = self.get_component(component_type)
            if component_data and 'common_threats' in component_data:
                threats = component_data['common_threats']
                logger.info(f"Retrieved {len(threats)} threats for {component_type}")
                # Mark threats as coming from KB
                for threat in threats:
                    threat['source'] = 'Knowledge Base'
                return threats
            return []

        except Exception as e:
            logger.error(f"Error getting threats for {component_type}: {str(e)}")
            return []

    def delete_component(self, component_type: str) -> bool:
        """
        Delete a component from the knowledge base
        
        Args:
            component_type: Type of component to delete
        """
        session = None
        try:
            session = self.Session()
            entry = session.query(KnowledgeBaseEntry).filter_by(
                component_type=component_type
            ).first()
            
            if entry:
                session.delete(entry)
                session.commit()
                logger.info(f"Successfully deleted component: {component_type}")
                return True
            
            logger.warning(f"No component found to delete: {component_type}")
            return False

        except Exception as e:
            logger.error(f"Error deleting component {component_type}: {str(e)}")
            if session:
                session.rollback()
            return False

        finally:
            if session:
                session.close()

    def list_components(self) -> List[str]:
        """List all component types in the knowledge base"""
        session = None
        try:
            session = self.Session()
            components = session.query(KnowledgeBaseEntry.component_type).all()
            return [comp[0] for comp in components]

        except Exception as e:
            logger.error(f"Error listing components: {str(e)}")
            return []

        finally:
            if session:
                session.close()