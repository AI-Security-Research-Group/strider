from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

# Create the base class
Base = declarative_base()

class ThreatModel(Base):
    __tablename__ = 'threat_models'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    app_type = Column(String(100))
    authentication = Column(String(200))
    internet_facing = Column(String(5))
    sensitive_data = Column(String(100))
    app_input = Column(Text)
    threat_model_output = Column(JSON)
    attack_tree = Column(Text, nullable=True)
    mitigations = Column(Text, nullable=True)
    dread_assessment = Column(JSON, nullable=True)
    test_cases = Column(Text, nullable=True)
    qa_context = Column(JSON, nullable=True)  
    data_flow_diagram = Column(Text, nullable=True) 

class DatabaseManager:
    def __init__(self, db_path="threat_models.db"):
        self.engine = create_engine(f'sqlite:///{db_path}')
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def save_threat_model(self, 
                        app_type: str,
                        authentication: list,
                        internet_facing: str,
                        sensitive_data: str,
                        app_input: str,
                        threat_model_output: dict,
                        qa_context: dict = None) -> int:
        """Save a new threat model to database"""
        try:
            threat_model = ThreatModel(
                app_type=app_type,
                authentication=','.join(authentication) if isinstance(authentication, list) else authentication,
                internet_facing=internet_facing,
                sensitive_data=sensitive_data,
                app_input=app_input,
                threat_model_output=threat_model_output,
                qa_context=qa_context
            )
            self.session.add(threat_model)
            self.session.commit()
            return threat_model.id
        except Exception as e:
            self.session.rollback()
            raise e

    def update_threat_model(self, model_id: int, **kwargs) -> bool:
        """Update specific fields of a threat model"""
        try:
            threat_model = self.session.query(ThreatModel).filter_by(id=model_id).first()
            if threat_model:
                for key, value in kwargs.items():
                    setattr(threat_model, key, value)
                self.session.commit()
                return True
            return False
        except Exception as e:
            self.session.rollback()
            raise e

    def get_all_threat_models(self):
        """Retrieve all threat models"""
        return self.session.query(ThreatModel).order_by(ThreatModel.timestamp.desc()).all()

    def get_threat_model(self, model_id: int):
        """Retrieve a specific threat model"""
        return self.session.query(ThreatModel).filter_by(id=model_id).first()

    def delete_threat_model(self, model_id: int) -> bool:
        """Delete a threat model"""
        try:
            threat_model = self.session.query(ThreatModel).filter_by(id=model_id).first()
            if threat_model:
                self.session.delete(threat_model)
                self.session.commit()
                return True
            return False
        except Exception as e:
            self.session.rollback()
            raise e