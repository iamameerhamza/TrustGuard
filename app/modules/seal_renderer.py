import html
from datetime import datetime, timedelta
from typing import Any
from app.api.schemas import SealRequest, SealResponse

SEAL_TEMPLATES = {
    "certified": {
        "title": "TrustGuard Certified",
        "accent": "#10b981",
        "icon_path": "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
    },
    "pci_dss": {
        "title": "PCI-DSS Compliant",
        "accent": "#3b82f6",
        "icon_path": "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z",
    },
    "malware_free": {
        "title": "Malware-Free Verified",
        "accent": "#8b5cf6",
        "icon_path": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    },
    "real_time_guard": {
        "title": "Real-Time Guard Active",
        "accent": "#f59e0b",
        "icon_path": "M13 10V3L4 14h7v7l9-11h-7z",
    },
}

THEME_STYLES = {
    "dark": {"bg": "#0f172a", "text": "#f8fafc", "sub": "#94a3b8", "border": "rgba(255,255,255,0.1)"},
    "light": {"bg": "#ffffff", "text": "#0f172a", "sub": "#475569", "border": "#e2e8f0"},
    "minimal": {"bg": "transparent", "text": "#0f172a", "sub": "#64748b", "border": "#cbd5e1"},
}

def render_seal_svg(request: SealRequest) -> str:
    tmpl = SEAL_TEMPLATES[request.seal_type]
    theme = THEME_STYLES[request.theme]
    domain = html.escape(request.domain)
    title = html.escape(tmpl["title"])
    now = datetime.now().strftime("%Y-%m-%d")
    
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="240" height="80" viewBox="0 0 240 80" style="border-radius:8px;">
  <rect width="240" height="80" rx="8" fill="{theme['bg']}" stroke="{theme['border']}" stroke-width="1"/>
  <g transform="translate(12, 16)">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="{tmpl['accent']}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="{tmpl['icon_path']}"/>
    </svg>
  </g>
  <text x="48" y="32" font-family="system-ui, sans-serif" font-size="12" font-weight="600" fill="{theme['text']}">{title}</text>
  <text x="48" y="50" font-family="system-ui, sans-serif" font-size="10" fill="{theme['sub']}">{domain}</text>
  <text x="48" y="64" font-family="system-ui, sans-serif" font-size="9" fill="{theme['sub']}">Verified {now}</text>
  <circle cx="220" cy="40" r="6" fill="{tmpl['accent']}" opacity="0.9">
    <animate attributeName="opacity" values="0.9;0.4;0.9" dur="2s" repeatCount="indefinite"/>
  </circle>
</svg>'''
    return svg

def build_embed_code(svg_markup: str, verification_url: str) -> str:
    escaped_svg = html.escape(svg_markup)
    return f'''<a href="{html.escape(verification_url)}" target="_blank" rel="noopener noreferrer" title="TrustGuard Security Seal">
  {svg_markup}
</a>'''

def generate_seal(request: SealRequest) -> SealResponse:
    svg = render_seal_svg(request)
    expires = datetime.now() + timedelta(days=90)
    vid = f"https://trustguard.example.com/verify/{request.domain}/{request.seal_type}"
    
    return SealResponse(
        svg_markup=svg,
        html_embed=build_embed_code(svg, vid),
        expires_at=expires,
        verification_url=vid
    )
