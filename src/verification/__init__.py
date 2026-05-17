"""
Verification Integrity Agent for Red Team MCP.

This module provides Kicksecure-inspired security verification capabilities including:
- Trusted time source detection and validation
- Artifact provenance and signature verification
- APT source security checking
- Environment hardening posture detection
- Multi-factor confidence scoring
"""

from .verification_integrity_agent import VerificationIntegrityAgent
from .time_integrity import TimeIntegrityChecker
from .provenance_checker import ProvenanceChecker
from .apt_security import AptSecurityChecker
from .hardening_detector import HardeningDetector
from .confidence_model import ConfidenceModel

__all__ = [
    'VerificationIntegrityAgent',
    'TimeIntegrityChecker',
    'ProvenanceChecker',
    'AptSecurityChecker',
    'HardeningDetector',
    'ConfidenceModel',
]
