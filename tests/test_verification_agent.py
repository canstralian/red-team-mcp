#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic unit tests for VerificationIntegrityAgent.
"""
from __future__ import annotations

from app.agents.verification_integrity import VerificationIntegrityAgent


def test_detects_core_controls():
    sample = r'''
        gpg --status-fd 1 --verify sig.asc artifact
        gpg_bash_lib_output_signed_on_unixtime=1700000000
        gpg_bash_lib_input_maximum_age_in_seconds=604800
        gpg_bash_lib_input_verify_timeout_after=30
        gpg_bash_lib_input_kill_after=45
        notation["file@name"]="artifact.tar.gz"
    '''
    agent = VerificationIntegrityAgent()
    finding = agent.analyze_text(sample, file_path="inline.sh")

    ctrl = {c.control_name: c for c in finding.controls}
    assert ctrl["status_fd"].implemented is True
    assert ctrl["rollback"].implemented is True
    assert ctrl["freeze"].implemented is True
    assert ctrl["endless_data"].implemented is True
    assert ctrl["tampering"].implemented is True
    assert "possible_rollback_missing_freshness_check" not in finding.risk_flags


def test_flags_missing_controls():
    sample = r'''
        gpg --verify sig.asc artifact
        # no freshness check, no timeouts, no notation
    '''
    agent = VerificationIntegrityAgent()
    finding = agent.analyze_text(sample, file_path="weak.sh")

    assert "possible_endless_data_dos_no_timeouts" in finding.risk_flags
    assert "possible_filename_tampering_risk" in finding.risk_flags
