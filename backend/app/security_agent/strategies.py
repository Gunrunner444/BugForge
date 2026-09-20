"""Research strategies. The AI may recommend; BugForge decides allowed tools."""

from __future__ import annotations

from enum import StrEnum

from app.security_agent.states import ToolRiskLevel


class ResearchStrategy(StrEnum):
    PASSIVE_RECON = "passive_recon"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    API_BEHAVIOR = "api_behavior"
    BUSINESS_LOGIC = "business_logic"
    CLIENT_SIDE = "client_side"
    SERVER_SIDE = "server_side"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    REPRODUCTION = "reproduction"


_STRATEGY_TOOLS: dict[ResearchStrategy, tuple[str, ...]] = {
    ResearchStrategy.PASSIVE_RECON: ("source_inspect", "evidence_inspect", "proxy_evidence"),
    ResearchStrategy.AUTHENTICATION: ("http_request", "browser_navigate", "source_inspect"),
    ResearchStrategy.AUTHORIZATION: ("http_request", "api_test", "reproduce"),
    ResearchStrategy.INPUT_VALIDATION: ("fuzz", "http_request", "api_test"),
    ResearchStrategy.API_BEHAVIOR: ("api_test", "http_request", "source_inspect"),
    ResearchStrategy.BUSINESS_LOGIC: ("api_test", "http_request", "reproduce"),
    ResearchStrategy.CLIENT_SIDE: ("browser_navigate", "source_inspect", "http_request"),
    ResearchStrategy.SERVER_SIDE: ("source_inspect", "http_request", "nuclei_scan"),
    ResearchStrategy.CONFIGURATION: ("nuclei_scan", "zap_scan", "source_inspect"),
    ResearchStrategy.DEPENDENCY: ("nuclei_scan", "source_inspect"),
    ResearchStrategy.REPRODUCTION: ("reproduce", "http_request"),
}


def tools_for_strategy(strategy: ResearchStrategy) -> tuple[str, ...]:
    return _STRATEGY_TOOLS.get(strategy, ())


def strategy_risk(strategy: ResearchStrategy) -> ToolRiskLevel:
    if strategy in {ResearchStrategy.PASSIVE_RECON, ResearchStrategy.CONFIGURATION}:
        return ToolRiskLevel.PASSIVE
    if strategy in {ResearchStrategy.INPUT_VALIDATION}:
        return ToolRiskLevel.ACTIVE
    if strategy in {ResearchStrategy.REPRODUCTION}:
        return ToolRiskLevel.ACTIVE
    return ToolRiskLevel.LOW_RISK_ACTIVE
