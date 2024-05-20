from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .database import Base
import datetime
import bcrypt


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    hashed_api_key = Column(String, unique=True, index=True)
    notes = Column(String)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    logs = relationship("RequestLog", back_populates="api_key")

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        return bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()

    def verify_api_key(self, api_key: str) -> bool:
        return bcrypt.checkpw(api_key.encode(), self.hashed_api_key.encode())


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"))
    endpoint = Column(String)
    method = Column(String)
    status_code = Column(Integer)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    api_key = relationship("APIKey", back_populates="logs")
