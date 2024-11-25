from database.database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from datetime import datetime, timezone

class User(Base):
    __tablename__ = "users"
    id = Column(String(100), primary_key=True, nullable=False)
    username = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True,nullable=False)
    is_verified = Column(Boolean, default=False,nullable=False)
    created_at = Column(DateTime, default=datetime.now,nullable=False) 
    modified_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    is_deleted = Column(Boolean, default=False,nullable=False)


class OTP(Base):
    __tablename__ = "otps"
    id = Column(String(100), primary_key=True, nullable=False)
    user_id = Column(String(100),ForeignKey("users.id"), nullable=False)
    email = Column(String(100), nullable=False)
    otp = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    modified_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)