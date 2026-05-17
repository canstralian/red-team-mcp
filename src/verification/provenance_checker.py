"""
Provenance Checker - Artifact signature and notation validation.

This module implements provenance verification following Kicksecure's Digital
Signature Policy, ensuring artifacts are signed and bound to specific files/hashes.

References:
- Kicksecure Digital Signature Policy: https://www.kicksecure.com/wiki/Trust
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List
import re
import hashlib

from .base import BaseVerificationChecker, SubprocessUtils, FileSystemUtils


class ProvenanceLevel(str, Enum):
    """Provenance verification levels."""
    HIGH = "high"  # Signed with notation binding
    MEDIUM = "medium"  # Signed without notation
    LOW = "low"  # Unsigned or weak signature
    NONE = "none"  # No provenance


@dataclass
class SignatureInfo:
    """GPG signature information."""
    is_valid: bool
    key_id: str
    timestamp: Optional[str]
    notation: Optional[Dict[str, str]]
    warnings: List[str]
    metadata: Dict[str, Any]


@dataclass
class ProvenanceResult:
    """Result of provenance check."""
    level: ProvenanceLevel
    signature_info: Optional[SignatureInfo]
    artifact_hash: str
    notation_binding_verified: bool
    chain_validation: bool
    confidence: str  # "high", "medium", "low"
    warnings: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]


class ProvenanceChecker(BaseVerificationChecker):
    """
    Check artifact provenance and signature binding.

    Validates:
    - GPG signature presence and validity
    - Notation binding to artifact (file@name or hash)
    - Chain of trust validation
    - Freshness (via TimeIntegrityChecker)
    """

    def check_provenance(
        self,
        artifact_path: Path,
        signature_path: Optional[Path] = None,
        require_notation: bool = True
    ) -> ProvenanceResult:
        """
        Check artifact provenance and signature binding.

        Args:
            artifact_path: Path to artifact file
            signature_path: Path to detached signature (if None, looks for .sig/.asc)
            require_notation: If True, require notation binding

        Returns:
            ProvenanceResult with provenance level and details
        """
        if self.fixture_mode:
            return self._check_fixture_provenance()

        warnings = []
        recommendations = []
        metadata = {}

        # Calculate artifact hash
        artifact_hash = self._calculate_hash(artifact_path)
        metadata["artifact_hash"] = artifact_hash

        # Find signature file
        if signature_path is None:
            signature_path = self._find_signature_file(artifact_path)

        if signature_path is None:
            return ProvenanceResult(
                level=ProvenanceLevel.NONE,
                signature_info=None,
                artifact_hash=artifact_hash,
                notation_binding_verified=False,
                chain_validation=False,
                confidence="low",
                warnings=["No signature file found"],
                recommendations=[
                    "Sign artifact with: gpg --detach-sign --armor <file>",
                    "Add notation with: gpg --set-notation file@name=<filename>"
                ],
                metadata=metadata
            )

        # Verify signature
        sig_info = self._verify_signature(artifact_path, signature_path)
        metadata["signature_file"] = str(signature_path)

        if not sig_info.is_valid:
            warnings.extend(sig_info.warnings)
            return ProvenanceResult(
                level=ProvenanceLevel.LOW,
                signature_info=sig_info,
                artifact_hash=artifact_hash,
                notation_binding_verified=False,
                chain_validation=False,
                confidence="low",
                warnings=warnings,
                recommendations=[
                    "Verify signature with trusted key",
                    "Check key expiration and revocation status"
                ],
                metadata=metadata
            )

        # Check notation binding
        notation_verified = False
        if sig_info.notation:
            notation_verified = self._verify_notation_binding(
                artifact_path,
                artifact_hash,
                sig_info.notation
            )
            metadata["notation"] = sig_info.notation

            if not notation_verified:
                warnings.append("Notation present but does not match artifact")
        elif require_notation:
            warnings.append("Signature lacks notation binding (vulnerable to substitution)")
            recommendations.append(
                "Add notation: gpg --set-notation file@name=<filename> or hash@sha256=<hash>"
            )

        # Determine provenance level
        if sig_info.is_valid and notation_verified:
            level = ProvenanceLevel.HIGH
            confidence = "high"
        elif sig_info.is_valid:
            level = ProvenanceLevel.MEDIUM
            confidence = "medium"
            if require_notation:
                warnings.append("Missing notation binding reduces provenance confidence")
        else:
            level = ProvenanceLevel.LOW
            confidence = "low"

        # Chain validation (simplified)
        chain_validation = self._check_chain_validation(sig_info.key_id)
        if not chain_validation:
            warnings.append("Key chain validation incomplete")

        return ProvenanceResult(
            level=level,
            signature_info=sig_info,
            artifact_hash=artifact_hash,
            notation_binding_verified=notation_verified,
            chain_validation=chain_validation,
            confidence=confidence,
            warnings=warnings,
            recommendations=recommendations,
            metadata=metadata
        )

    def _calculate_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """
        Calculate cryptographic hash of file.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha512)

        Returns:
            Hex digest of file hash
        """
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _find_signature_file(self, artifact_path: Path) -> Optional[Path]:
        """
        Find signature file for artifact.

        Looks for:
        - artifact.sig
        - artifact.asc
        - artifact.gpg

        Args:
            artifact_path: Path to artifact

        Returns:
            Path to signature file if found, None otherwise
        """
        for ext in ['.sig', '.asc', '.gpg']:
            sig_path = artifact_path.with_suffix(artifact_path.suffix + ext)
            if sig_path.exists():
                return sig_path
        return None

    def _verify_signature(
        self,
        artifact_path: Path,
        signature_path: Path
    ) -> SignatureInfo:
        """
        Verify GPG signature on artifact.

        Args:
            artifact_path: Path to artifact
            signature_path: Path to signature file

        Returns:
            SignatureInfo with verification results
        """
        warnings = []
        metadata = {}

        # Run GPG verification using utility
        result = SubprocessUtils.run_command(
            [
                "gpg",
                "--verify",
                "--status-fd", "1",
                str(signature_path),
                str(artifact_path)
            ],
            timeout=30
        )

        if result is None:
            warnings.append("GPG verification timed out or failed")
            return SignatureInfo(
                is_valid=False,
                key_id="unknown",
                timestamp=None,
                notation=None,
                warnings=warnings,
                metadata={"error": "timeout or command failed"}
            )

        metadata["gpg_output"] = result.stdout
        metadata["gpg_stderr"] = result.stderr

        # Parse GPG status output
        is_valid = "[GNUPG:] VALIDSIG" in result.stdout

        # Extract key ID
        key_id_match = re.search(r'\[GNUPG:\] VALIDSIG (\S+)', result.stdout)
        key_id = key_id_match.group(1) if key_id_match else "unknown"

        # Extract timestamp
        timestamp_match = re.search(r'\[GNUPG:\] SIGNATURE_TIMESTAMP (\d+)', result.stdout)
        timestamp = timestamp_match.group(1) if timestamp_match else None

        # Extract notation
        notation = self._extract_notation(result.stdout)

        # Check for warnings in GPG output
        if "EXPKEYSIG" in result.stdout:
            warnings.append("Signature made with expired key")
        if "REVKEYSIG" in result.stdout:
            warnings.append("Signature made with revoked key")
        if "BADSIG" in result.stdout:
            warnings.append("Bad signature")
            is_valid = False

        return SignatureInfo(
            is_valid=is_valid,
            key_id=key_id,
            timestamp=timestamp,
            notation=notation,
            warnings=warnings,
            metadata=metadata
        )

    def _extract_notation(self, gpg_output: str) -> Optional[Dict[str, str]]:
        """
        Extract notation from GPG output.

        Args:
            gpg_output: GPG status output

        Returns:
            Dictionary of notation key-value pairs, or None
        """
        notation = {}

        # Look for notation lines: [GNUPG:] NOTATION_NAME name
        for line in gpg_output.splitlines():
            if "[GNUPG:] NOTATION_NAME" in line:
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[2]
                    # Next line should have NOTATION_DATA
                    notation[key] = None
            elif "[GNUPG:] NOTATION_DATA" in line:
                parts = line.split(maxsplit=2)
                if len(parts) >= 3 and notation:
                    # Get last added key
                    last_key = list(notation.keys())[-1]
                    notation[last_key] = parts[2]

        return notation if notation else None

    def _verify_notation_binding(
        self,
        artifact_path: Path,
        artifact_hash: str,
        notation: Dict[str, str]
    ) -> bool:
        """
        Verify notation binds to artifact.

        Checks for:
        - file@name matching artifact filename
        - hash@sha256 (or similar) matching artifact hash

        Args:
            artifact_path: Path to artifact
            artifact_hash: Calculated artifact hash
            notation: Notation from signature

        Returns:
            True if notation binding is verified
        """
        # Check for file@name notation
        if "file@name" in notation:
            expected_name = artifact_path.name
            actual_name = notation["file@name"]
            if expected_name == actual_name:
                return True

        # Check for hash notation (various formats)
        for key in notation:
            if key.startswith("hash@"):
                if notation[key].lower() == artifact_hash.lower():
                    return True

        return False

    def _check_chain_validation(self, key_id: str) -> bool:
        """
        Check if key has chain of trust validation.

        This is a simplified check - full implementation would verify
        key signatures, trust levels, etc.

        Args:
            key_id: GPG key ID

        Returns:
            True if chain validation passes
        """
        # Check if key is in keyring using utility
        result = SubprocessUtils.run_command(
            ["gpg", "--list-keys", key_id],
            timeout=10
        )

        # Basic check: key exists and has trust level
        if result and result.returncode == 0 and "pub" in result.stdout:
            return True

        return False

    def _check_fixture_provenance(self) -> ProvenanceResult:
        """
        Return fixture provenance data for testing.

        Returns:
            ProvenanceResult from fixture data
        """
        fixture = self.fixture_data

        sig_info = None
        if fixture.get("signature_info"):
            sig_data = fixture["signature_info"]
            sig_info = SignatureInfo(
                is_valid=sig_data.get("is_valid", False),
                key_id=sig_data.get("key_id", "unknown"),
                timestamp=sig_data.get("timestamp"),
                notation=sig_data.get("notation"),
                warnings=sig_data.get("warnings", []),
                metadata=sig_data.get("metadata", {})
            )

        return ProvenanceResult(
            level=ProvenanceLevel(fixture.get("level", "none")),
            signature_info=sig_info,
            artifact_hash=fixture.get("artifact_hash", ""),
            notation_binding_verified=fixture.get("notation_binding_verified", False),
            chain_validation=fixture.get("chain_validation", False),
            confidence=fixture.get("confidence", "low"),
            warnings=fixture.get("warnings", []),
            recommendations=fixture.get("recommendations", []),
            metadata=fixture.get("metadata", {})
        )
