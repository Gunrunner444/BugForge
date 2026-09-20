"""Vulnerability classes used by static security analysis and later reports."""

from __future__ import annotations

from enum import StrEnum


class VulnerabilityClass(StrEnum):
    INJECTION = "injection"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XSS = "xss"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    AUTHENTICATION = "authentication_flaw"
    AUTHORIZATION = "authorization_flaw"
    IDOR = "insecure_direct_object_reference"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_FILE_HANDLING = "insecure_file_handling"
    DYNAMIC_EXECUTION = "dangerous_dynamic_execution"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    INSECURE_CONFIGURATION = "insecure_configuration"
    UNSAFE_REDIRECT = "unsafe_redirect"
    MISSING_SECURITY_CONTROL = "missing_security_control"
    BUSINESS_LOGIC = "business_logic_risk"


class EvidenceTier(StrEnum):
    """How strongly a finding is supported. Phase 2 never reaches verified."""

    STATIC_INDICATOR = "static_indicator"
    AI_HYPOTHESIS = "ai_hypothesis"
    CORROBORATED = "corroborated"
    REPRODUCED = "reproduced"
    VERIFIED = "verified"
