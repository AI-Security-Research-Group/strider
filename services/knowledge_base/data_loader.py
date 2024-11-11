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

    def load_all_data(self):
        """Load all KB data files"""
        try:
            # Load each JSON file in the data directory
            for filename in os.listdir(self.data_dir):
                if filename.endswith('.json'):
                    self.load_file(filename)
            logger.info("Successfully loaded all KB data")
        except Exception as e:
            logger.error(f"Error loading KB data: {str(e)}")

    def load_file(self, filename: str):
        """Load a specific KB data file"""
        try:
            file_path = os.path.join(self.data_dir, filename)
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Add each component to the database
            for comp_type, comp_data in data.get('components', {}).items():
                self.db.add_component(comp_type, comp_data)
                
            logger.info(f"Successfully loaded {filename}")
        except Exception as e:
            logger.error(f"Error loading {filename}: {str(e)}")

# Usage example
def initialize_kb():
    db = KnowledgeBaseDB()
    loader = KBDataLoader(db)
    loader.load_all_data()
    return db