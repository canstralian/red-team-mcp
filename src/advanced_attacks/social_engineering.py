#!/usr/bin/env python3
"""
Social Engineering Attack Framework

Advanced social engineering capabilities including sophisticated phishing campaigns,
pretexting operations, psychological manipulation techniques, and human intelligence gathering.
"""

import asyncio
import json
import random
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from email.mime.base import MimeBase
from email import encoders
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import httpx
import re
import base64
import tempfile
import os


class AttackVector(str, Enum):
    """Social engineering attack vectors."""
    PHISHING_EMAIL = "phishing_email"
    SPEAR_PHISHING = "spear_phishing"
    VISHING = "voice_phishing"
    SMISHING = "sms_phishing"
    PRETEXTING = "pretexting"
    BAITING = "baiting"
    QUID_PRO_QUO = "quid_pro_quo"
    WATERING_HOLE = "watering_hole"


class PsychologyTechnique(str, Enum):
    """Psychological manipulation techniques."""
    AUTHORITY = "authority"
    SCARCITY = "scarcity"
    URGENCY = "urgency"
    SOCIAL_PROOF = "social_proof"
    RECIPROCITY = "reciprocity"
    COMMITMENT = "commitment"
    LIKABILITY = "likability"
    FEAR = "fear"


@dataclass
class Target:
    """Target individual or organization."""
    name: str
    email: str
    phone: Optional[str] = None
    company: Optional[str] = None
    position: Optional[str] = None
    interests: List[str] = field(default_factory=list)
    social_media: Dict[str, str] = field(default_factory=dict)
    personality_profile: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class Campaign:
    """Social engineering campaign."""
    name: str
    attack_vector: AttackVector
    targets: List[Target]
    psychology_techniques: List[PsychologyTechnique]
    payload_url: Optional[str] = None
    success_metrics: Dict[str, int] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class CampaignResult:
    """Results of a social engineering campaign."""
    campaign_name: str
    total_targets: int
    emails_sent: int
    emails_opened: int
    links_clicked: int
    credentials_captured: int
    payloads_executed: int
    success_rate: float
    detailed_results: List[Dict[str, Any]] = field(default_factory=list)


class PersonalityAnalyzer:
    """Analyze target personality for tailored attacks."""
    
    def __init__(self):
        self.personality_indicators = {
            "high_openness": ["creative", "artistic", "curious", "innovative"],
            "high_conscientiousness": ["organized", "reliable", "punctual", "methodical"],
            "high_extraversion": ["social", "outgoing", "talkative", "assertive"],
            "high_agreeableness": ["cooperative", "trusting", "helpful", "sympathetic"],
            "high_neuroticism": ["anxious", "stressed", "worried", "emotional"]
        }
        
    def analyze_social_media(self, target: Target) -> Dict[str, float]:
        """Analyze target's social media for personality traits."""
        # This would integrate with actual social media APIs
        # Simulated analysis based on common patterns
        
        personality_scores = {
            "openness": random.uniform(0.3, 0.9),
            "conscientiousness": random.uniform(0.2, 0.8),
            "extraversion": random.uniform(0.1, 0.9),
            "agreeableness": random.uniform(0.4, 0.9),
            "neuroticism": random.uniform(0.1, 0.7)
        }
        
        return personality_scores
    
    def recommend_techniques(self, personality_scores: Dict[str, float]) -> List[PsychologyTechnique]:
        """Recommend psychology techniques based on personality."""
        techniques = []
        
        if personality_scores["neuroticism"] > 0.6:
            techniques.extend([PsychologyTechnique.FEAR, PsychologyTechnique.URGENCY])
            
        if personality_scores["agreeableness"] > 0.7:
            techniques.extend([PsychologyTechnique.AUTHORITY, PsychologyTechnique.SOCIAL_PROOF])
            
        if personality_scores["openness"] > 0.7:
            techniques.append(PsychologyTechnique.SCARCITY)
            
        if personality_scores["conscientiousness"] > 0.7:
            techniques.append(PsychologyTechnique.COMMITMENT)
            
        return techniques[:3]  # Limit to top 3 techniques


class PhishingTemplateGenerator:
    """Generate sophisticated phishing templates."""
    
    def __init__(self):
        self.templates = {
            "corporate": {
                "subject_templates": [
                    "Urgent: {company} Security Update Required",
                    "Action Required: {company} Account Verification",
                    "{company} IT Security Alert - Immediate Action Needed",
                    "Your {company} Account Has Been Suspended"
                ],
                "body_template": """
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="max-width: 600px; margin: 0 auto;">
                        <div style="background: #f8f9fa; padding: 20px; border-left: 4px solid #dc3545;">
                            <h2 style="color: #dc3545; margin: 0;">Security Alert</h2>
                        </div>
                        <div style="padding: 20px; background: white; border: 1px solid #dee2e6;">
                            <p>Dear {name},</p>
                            <p>{urgency_message}</p>
                            <p>{action_required}</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{payload_url}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">
                                    {cta_text}
                                </a>
                            </div>
                            <p style="font-size: 12px; color: #6c757d;">
                                If you did not request this, please contact IT support immediately.
                            </p>
                        </div>
                        <div style="background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d;">
                            <p>{company} IT Security Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """
            },
            "financial": {
                "subject_templates": [
                    "Urgent: Suspicious Activity on Your Account",
                    "Security Alert: Unusual Login Detected",
                    "Your Account Will Be Suspended - Verify Now",
                    "Fraud Alert: Immediate Action Required"
                ],
                "body_template": """
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd;">
                        <div style="background: #1a365d; color: white; padding: 20px; text-align: center;">
                            <h1 style="margin: 0;">Security Alert</h1>
                        </div>
                        <div style="padding: 30px;">
                            <p>Dear {name},</p>
                            <p>We have detected unusual activity on your account that requires immediate verification:</p>
                            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px;">
                                <strong>Suspicious Activity:</strong> Login attempt from {suspicious_location}
                            </div>
                            <p>To protect your account, please verify your identity immediately:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{payload_url}" style="background: #dc3545; color: white; padding: 15px 40px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                                    VERIFY ACCOUNT NOW
                                </a>
                            </div>
                            <p style="color: #dc3545;"><strong>Note:</strong> Your account will be temporarily suspended if not verified within 24 hours.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
            },
            "social": {
                "subject_templates": [
                    "Someone tried to log into your account",
                    "New message from {sender_name}",
                    "Your post has been reported",
                    "Suspicious activity on your profile"
                ],
                "body_template": """
                <html>
                <body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif;">
                    <div style="max-width: 500px; margin: 0 auto;">
                        <div style="background: #4267b2; color: white; padding: 15px; text-align: center;">
                            <h2 style="margin: 0;">Security Notification</h2>
                        </div>
                        <div style="padding: 25px; background: white;">
                            <p>Hi {name},</p>
                            <p>We noticed a login to your account from a device we don't recognize:</p>
                            <div style="background: #f0f2f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
                                <p><strong>Device:</strong> {device_info}</p>
                                <p><strong>Location:</strong> {location}</p>
                                <p><strong>Time:</strong> {timestamp}</p>
                            </div>
                            <p>If this was you, you can ignore this message. Otherwise, please secure your account immediately.</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{payload_url}" style="background: #4267b2; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">
                                    Review Activity
                                </a>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """
            }
        }