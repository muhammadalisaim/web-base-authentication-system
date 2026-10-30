"""
Pydantic Request & Response Schemas
Web Base Authentication System — API Validation Layer
"""
from pydantic import BaseModel, HttpUrl, EmailStr, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_email: str

class ScanRequest(BaseModel):
    url: str
    profile: Optional[str] = "full"

class StackCategoryItem(BaseModel):
    title: str
    icon: str
    name: str
    version: Optional[str] = None
    detail: str
    status: str
    statusText: str

class StackBadgeItem(BaseModel):
    name: str
    icon: str
    color: str

class StackDetectionResponse(BaseModel):
    targetUrl: str
    hostname: str
    confidence: str
    confidenceBadge: str
    categories: List[StackCategoryItem]
    badges: List[StackBadgeItem]
    securityAdvisories: List[str] = []

class AIReviewRequest(BaseModel):
    url: str
    findings: Optional[List[Dict[str, Any]]] = []

class AIReviewResponse(BaseModel):
    status: str
    target: str
    aiAdvisor: str
    riskLevel: str
    analysisSummary: List[str]
    actionItems: List[Dict[str, str]]
    remediationScript: str


class NumberTraceRequest(BaseModel):
    number: str = Field(min_length=1, max_length=40)
    sender: Optional[str] = Field(default=None, max_length=40)


class SMSAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    sender: Optional[str] = Field(default=None, max_length=40)
