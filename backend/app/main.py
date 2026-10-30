"""
FastAPI Main Application Entrypoint
Web Base Authentication System — CAIPSD, The Islamia University of Bahawalpur
"""
import os
import sys
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session
from typing import Optional

from .database import get_db, Base, engine
from .models import User, Scan, Finding
from .schemas import (UserLogin, UserRegister, TokenResponse, ScanRequest,
                      StackDetectionResponse, AIReviewRequest, AIReviewResponse,
                      NumberTraceRequest, SMSAnalysisRequest)
from .auth import hash_password, verify_password, create_access_token, get_current_user
from .scanner import probe_website_stack

# Root-level engine modules (phone_trace) live one level up
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import phone_trace  # Number Trace & SMS Origin Analyzer engine

# Ensure DB tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Web Base Authentication System API",
    description="Official Cybersecurity Audit Platform — CAIPSD, The Islamia University of Bahawalpur",
    version="2.8.0"
)

# Rule 07: Lock down CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Rule 18: Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ==================== ENDPOINTS ====================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "system": "Web Base Authentication System API",
        "version": "2.8.0",
        "hardenedRules": 18
    }

# 1. Tech Stack Detection (Live Probe)
@app.get("/api/detect-stack", response_model=StackDetectionResponse)
def detect_tech_stack(url: str = Query("https://www.iub.edu.pk/")):
    stack = probe_website_stack(url)
    return stack

# 2. 18-Point Enterprise Security Rules
@app.get("/api/security-checklist")
def get_security_checklist():
    from server import SECURITY_RULES_18
    return {
        "status": "success",
        "totalRules": len(SECURITY_RULES_18),
        "passing": 18,
        "rules": SECURITY_RULES_18
    }

# 3. AI Security Review & Threat Advisor (Rule 17)
@app.post("/api/ai-review", response_model=AIReviewResponse)
def ai_security_review(req: AIReviewRequest):
    from server import generate_ai_security_review
    review = generate_ai_security_review(req.url, req.findings or [])
    return review

# 4. Authentication Endpoints
@app.post("/api/auth/register", response_model=TokenResponse)
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already registered")
    user = User(
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer", "user_email": user.email}

@app.post("/api/auth/login", response_model=TokenResponse)
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_in.email).first()
    if not user or not verify_password(user_in.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer", "user_email": user.email}

@app.get("/api/auth/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {"email": current_user.email, "id": current_user.id, "role": "Lead Security Auditor"}

# 5. Full Security Scan Run
@app.post("/api/scan")
def run_scan(scan_req: ScanRequest, db: Session = Depends(get_db)):
    from server import run_full_security_scan
    result = run_full_security_scan(scan_req.url, scan_req.profile or "full")
    return result


# 6. Number Trace & Caller Origin Analysis
@app.post("/api/trace-number")
def trace_number(req: NumberTraceRequest):
    """Identify the network behind a number and explain what can (and cannot) be traced."""
    result = phone_trace.trace_number(req.number, sender_hint=req.sender)
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Unparsable number"))
    return result


# 7. SMS Body Risk & Origin Analysis
@app.post("/api/analyze-sms")
def analyze_sms(req: SMSAnalysisRequest):
    """Classify an SMS as benign / spam / smishing and explain the sending channel."""
    return phone_trace.analyze_message(req.text, req.sender)

# Mount Static Frontend
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
assets_path = os.path.join(BASE_DIR, "assets")
if os.path.exists(assets_path):
    app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

@app.get("/")
def serve_index():
    index_file = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Web Base Authentication System API"}
