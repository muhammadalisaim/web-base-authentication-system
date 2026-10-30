"""
SQLAlchemy ORM Models
Web Base Authentication System — Matches security_scanner.db schema
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    url = Column(String(1024), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    profile = Column(String(64), default="full")
    status = Column(String(32), default="pending")
    score = Column(Integer, default=100)
    grade = Column(String(2), default="A")
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    category = Column(String(128), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False)
    confidence = Column(Float, default=1.0)
    affected_url = Column(String(1024), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(32), default="open")
    fingerprint = Column(String(64), index=True)
    risk_score = Column(Float, default=0.0)
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(Integer, ForeignKey("findings.id"), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
