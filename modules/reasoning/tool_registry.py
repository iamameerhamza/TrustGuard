"""
TrustGuard Reasoning - Agentic Tool Registry
Registers modular investigation tools usable by the agentic decision loop.
"""
from __future__ import annotations
import logging
from typing import Dict, Any, Callable, List, Optional
from core.schemas.evidence import EvidenceItem, EvidenceType, SeverityLevel

logger = logging.getLogger(__name__)


class AgentTool:
    """Encapsulates an injectable diagnostic tool."""
    def __init__(self, name: str, description: str, handler: Callable[..., Any]):
        self.name = name
        self.description = description
        self.handler = handler

    async def execute(self, **kwargs) -> Any:
        return await self.handler(**kwargs)


class ToolRegistry:
    """Registry holding callable security investigation tools."""

    def __init__(self):
        self._tools: Dict[str, AgentTool] = {}
        self._register_default_tools()

    def register_tool(self, name: str, description: str, handler: Callable[..., Any]):
        self._tools[name] = AgentTool(name, description, handler)

    def get_tool(self, name: str) -> Optional[AgentTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        return [{"name": t.name, "description": t.description} for t in self._tools.values()]

    def _register_default_tools(self):
        # 1. WHOIS Registry Lookup
        async def dummy_whois(domain: str) -> Dict[str, Any]:
            return {"domain": domain, "creation_date": "2026-01-01", "domain_age_days": 15, "is_new_domain": True}

        # 2. Threat Feed Search
        async def dummy_threat_feed_search(target: str) -> Dict[str, Any]:
            return {"target": target, "in_openphish": True, "in_urlhaus": False}

        # 3. DOM Snapshot Inspector
        async def dummy_dom_inspector(url: str) -> Dict[str, Any]:
            return {"url": url, "has_hidden_iFrames": False, "external_script_count": 8}

        self.register_tool("WHOIS_LOOKUP", "Inspect domain registration age and owner details", dummy_whois)
        self.register_tool("THREAT_FEED_SEARCH", "Search threat intelligence feeds for target", dummy_threat_feed_search)
        self.register_tool("DOM_SNAPSHOT", "Analyze page DOM script counts and iFrames", dummy_dom_inspector)
