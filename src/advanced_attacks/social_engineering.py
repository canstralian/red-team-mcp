"""Social engineering tooling for advanced campaign simulations."""

from __future__ import annotations

import asyncio
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Dict, Iterable, List, Optional

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
"""Basic email validation pattern used across the module."""


class AttackVector(str, Enum):
    """Enumerate social engineering attack vectors."""

    PHISHING_EMAIL = "phishing_email"
    SPEAR_PHISHING = "spear_phishing"
    VISHING = "voice_phishing"
    SMISHING = "sms_phishing"
    PRETEXTING = "pretexting"
    BAITING = "baiting"
    QUID_PRO_QUO = "quid_pro_quo"
    WATERING_HOLE = "watering_hole"


class PsychologyTechnique(str, Enum):
    """Enumerate persuasive psychological techniques."""

    AUTHORITY = "authority"
    SCARCITY = "scarcity"
    URGENCY = "urgency"
    SOCIAL_PROOF = "social_proof"
    RECIPROCITY = "reciprocity"
    COMMITMENT = "commitment"
    LIKABILITY = "likability"
    FEAR = "fear"


@dataclass(slots=True)
class Target:
    """Representation of a social engineering target."""

    name: str
    email: str
    phone: Optional[str] = None
    company: Optional[str] = None
    position: Optional[str] = None
    interests: List[str] = field(default_factory=list)
    social_media: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)

    def is_valid(self) -> bool:
        """Validate the target contact details using regex for emails."""

        return bool(EMAIL_PATTERN.fullmatch(self.email))


@dataclass(slots=True)
class Campaign:
    """Configuration for a social engineering campaign."""

    name: str
    attack_vector: AttackVector
    targets: List[Target]
    psychology_techniques: List[PsychologyTechnique]
    payload_url: Optional[str] = None
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None


@dataclass(slots=True)
class CampaignResult:
    """Aggregate statistics for a simulated campaign run."""

    campaign_name: str
    total_targets: int
    emails_sent: int
    emails_opened: int
    links_clicked: int
    credentials_captured: int
    payloads_executed: int
    success_rate: float


class PersonalityAnalyzer:
    """Simulate personality profiling to drive template selection."""

    def analyze(self, target: Target) -> Dict[str, float]:
        """Return pseudo-random personality scores for a target."""

        random.seed(target.email)
        return {
            "openness": random.uniform(0.3, 0.9),
            "conscientiousness": random.uniform(0.2, 0.8),
            "extraversion": random.uniform(0.1, 0.9),
            "agreeableness": random.uniform(0.4, 0.9),
            "neuroticism": random.uniform(0.1, 0.7),
        }

    def recommend(self, scores: Dict[str, float]) -> List[PsychologyTechnique]:
        """Recommend techniques aligned with the supplied scores."""

        recommendations: List[PsychologyTechnique] = []
        if scores["neuroticism"] > 0.6:
            recommendations.append(PsychologyTechnique.FEAR)
        if scores["agreeableness"] > 0.7:
            recommendations.append(PsychologyTechnique.AUTHORITY)
        if scores["openness"] > 0.7:
            recommendations.append(PsychologyTechnique.SCARCITY)
        if scores["conscientiousness"] > 0.7:
            recommendations.append(PsychologyTechnique.COMMITMENT)
        return recommendations or [PsychologyTechnique.URGENCY]


class PhishingTemplateGenerator:
    """Generate phishing templates with consistent structure."""

    def __init__(self) -> None:
        self.templates: Dict[str, Dict[str, Iterable[str] | str]] = {
            "corporate": {
                "subjects": [
                    "{company} Security Update Required",
                    "Action Required: Verify your {company} credentials",
                ],
                "body": """
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2 style="background:#dc3545;color:white;padding:16px;">Security Alert</h2>
                    <p>Dear {name},</p>
                    <p>{urgency_message}</p>
                    <p style="text-align:center;">
                        <a href="{payload_url}" style="background:#007bff;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;">
                            {cta_text}
                        </a>
                    </p>
                    <p style="font-size:12px;color:#6c757d;">This message is confidential.</p>
                </body>
                </html>
                """,
            },
            "financial": {
                "subjects": [
                    "Suspicious activity detected on your account",
                    "Fraud alert: Confirm recent transactions",
                ],
                "body": """
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2 style="background:#1a365d;color:white;padding:18px;text-align:center;">Security Alert</h2>
                    <p>Dear {name},</p>
                    <p>We observed an unusual login from {suspicious_location}.</p>
                    <p>Please confirm the activity using the secure link below.</p>
                    <p style="text-align:center;">
                        <a href="{payload_url}" style="background:#dc3545;color:white;padding:12px 36px;text-decoration:none;border-radius:4px;">Review Activity</a>
                    </p>
                </body>
                </html>
                """,
            },
            "social": {
                "subjects": [
                    "Security notice for your social profile",
                    "New message requires verification",
                ],
                "body": """
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2 style="background:#4267b2;color:white;padding:16px;text-align:center;">Profile Security</h2>
                    <p>Hi {name},</p>
                    <p>We noticed a login from {location} using {device_info}.</p>
                    <p>If this was not you, please secure your account.</p>
                    <p style="text-align:center;">
                        <a href="{payload_url}" style="background:#4267b2;color:white;padding:10px 28px;text-decoration:none;border-radius:4px;">Secure Account</a>
                    </p>
                </body>
                </html>
                """,
            },
        }

    def available_templates(self) -> List[str]:
        """Return the list of template identifiers."""

        return sorted(self.templates.keys())

    def render(self, template_key: str, context: Dict[str, str]) -> str:
        """Render a phishing email using the selected template."""

        template = self.templates.get(template_key)
        if not template:
            raise ValueError(f"Unknown template: {template_key}")
        body = template["body"].format(**context)
        return body

    def pick_subject(self, template_key: str, context: Dict[str, str]) -> str:
        """Return a subject line for the template with contextual data."""

        template = self.templates.get(template_key)
        if not template:
            raise ValueError(f"Unknown template: {template_key}")
        subject = random.choice(list(template["subjects"]))
        return subject.format(**context)


class SocialEngineeringEngine:
    """Coordinate phishing campaigns using generated templates."""

    def __init__(self, generator: Optional[PhishingTemplateGenerator] = None) -> None:
        self.generator = generator or PhishingTemplateGenerator()
        self.analyzer = PersonalityAnalyzer()

    def validate_targets(self, targets: Iterable[Target]) -> List[Target]:
        """Return only targets with valid email addresses."""

        return [target for target in targets if target.is_valid()]

    def compose_email(self, template_key: str, target: Target, payload_url: str) -> MIMEMultipart:
        """Compose a phishing email for the target."""

        context = {
            "name": target.name,
            "company": target.company or "Your Company",
            "urgency_message": "Your credentials must be verified within 24 hours.",
            "action_required": "Click the secure link below to validate your session.",
            "cta_text": "Verify Now",
            "payload_url": payload_url,
            "suspicious_location": "New York, USA",
            "transaction_summary": "Multiple failed login attempts",
            "location": "Unknown",
            "device_info": "Chrome on Windows 10",
        }
        subject = self.generator.pick_subject(template_key, context)
        body = self.generator.render(template_key, context)

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["To"] = target.email
        message.attach(MIMEText(body, "html"))
        return message

    async def simulate_campaign(self, campaign: Campaign, payload_url: str) -> CampaignResult:
        """Simulate campaign results with deterministic randomness."""

        valid_targets = self.validate_targets(campaign.targets)
        total = len(valid_targets)
        if total == 0:
            return CampaignResult(campaign.name, 0, 0, 0, 0, 0, 0, 0.0)

        random.seed(campaign.name)
        emails_sent = total
        emails_opened = int(total * random.uniform(0.4, 0.8))
        links_clicked = int(emails_opened * random.uniform(0.3, 0.6))
        credentials_captured = int(links_clicked * random.uniform(0.2, 0.4))
        payloads_executed = int(credentials_captured * random.uniform(0.3, 0.5))
        success_rate = payloads_executed / total

        # Simulate asynchronous delays to mimic campaign runtime.
        await asyncio.sleep(0)

        return CampaignResult(
            campaign_name=campaign.name,
            total_targets=total,
            emails_sent=emails_sent,
            emails_opened=emails_opened,
            links_clicked=links_clicked,
            credentials_captured=credentials_captured,
            payloads_executed=payloads_executed,
            success_rate=round(success_rate, 3),
        )

    def build_campaign(
        self,
        name: str,
        vector: AttackVector,
        targets: Iterable[Target],
        payload_url: str,
    ) -> Campaign:
        """Construct a campaign object with recommended techniques."""

        valid_targets = self.validate_targets(targets)
        if not valid_targets:
            raise ValueError("No valid targets supplied for campaign")

        scores = self.analyzer.analyze(valid_targets[0])
        techniques = self.analyzer.recommend(scores)

        return Campaign(
            name=name,
            attack_vector=vector,
            targets=valid_targets,
            psychology_techniques=techniques,
            payload_url=payload_url,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(days=3),
        )
