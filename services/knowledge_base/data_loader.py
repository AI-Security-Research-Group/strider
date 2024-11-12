# services/knowledge_base/data_loader.py

import json
import os
import logging
from typing import Dict, Any
from .database import KnowledgeBaseDB

logger = logging.getLogger(__name__)

class KBDataLoader:
    def __init__(self, db: KnowledgeBaseDB):
        self.db = db
        self.data_dir = os.path.join(
            os.path.dirname(__file__),
            'data'
        )
        logger.info(f"Initialized KBDataLoader with data directory: {self.data_dir}")

    def load_all_data(self):
        """Load all KB data files"""
        try:
            # Check if data directory exists
            if not os.path.exists(self.data_dir):
                logger.warning(f"Data directory not found: {self.data_dir}")
                return

            # Load each JSON file in the data directory
            files = [f for f in os.listdir(self.data_dir) if f.endswith('.json')]
            logger.info(f"Found {len(files)} JSON files to load")

            for filename in files:
                self.load_file(filename)
                
            logger.info("Successfully loaded all KB data")
        except Exception as e:
            logger.error(f"Error loading KB data: {str(e)}")

    def load_file(self, filename: str):
        """Load a specific KB data file"""
        try:
            file_path = os.path.join(self.data_dir, filename)
            logger.info(f"Loading file: {file_path}")

            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Load each component
            components = data.get('components', {})
            logger.info(f"Found {len(components)} components in {filename}")

            for comp_name, comp_data in components.items():
                logger.info(f"Adding component: {comp_name}")
                success = self.db.add_component(comp_name, comp_data)
                if not success:
                    logger.error(f"Failed to add component: {comp_name}")

        except Exception as e:
            logger.error(f"Error loading {filename}: {str(e)}")

# Initialize function
def initialize_kb() -> KnowledgeBaseDB:
    """Initialize the knowledge base and load data"""
    try:
        logger.info("Initializing knowledge base")
        db = KnowledgeBaseDB()
        loader = KBDataLoader(db)
        loader.load_all_data()
        return db
    except Exception as e:
        logger.error(f"Error initializing knowledge base: {str(e)}")
        return KnowledgeBaseDB()  # Return empty DB as fallback