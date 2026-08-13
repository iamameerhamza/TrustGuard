"""
TrustGuard Visual Inspection - Screenshot Capture Service
Renders web pages in a sandboxed headless browser to capture page snapshots and DOM state.
"""
from __future__ import annotations
import base64
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class ScreenshotService:
    """Headless browser rendering service for capturing visual evidence."""

    def __init__(self, timeout_ms: int = 15000):
        self.timeout_ms = timeout_ms

    async def capture_url(self, url: str) -> dict:
        """
        Capture screenshot and DOM metadata for a target URL.
        Returns dict containing base64 screenshot image, viewport metadata, and login form presence.
        """
        try:
            # Try importing playwright if available in environment
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page(viewport={"width": 1280, "height": 800})
                
                await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                
                # Check for login/credential form inputs
                has_login_form = await page.evaluate("""() => {
                    const inputs = Array.from(document.querySelectorAll('input'));
                    return inputs.some(i => i.type === 'password' || i.name.toLowerCase().includes('pass') || i.name.toLowerCase().includes('login'));
                }""")
                
                screenshot_bytes = await page.screenshot(type="png")
                await browser.close()

                return {
                    "url": url,
                    "screenshot_b64": base64.b64encode(screenshot_bytes).decode("utf-8"),
                    "has_login_form": bool(has_login_form),
                    "dimensions": {"width": 1280, "height": 800},
                    "captured": True,
                }
        except Exception as e:
            logger.warning(f"Headless Playwright screenshot fallback used for {url}: {e}")
            # Fallback mock/synthetic response for non-GUI / headless missing environments
            return {
                "url": url,
                "screenshot_b64": "",
                "has_login_form": False,
                "dimensions": {"width": 1280, "height": 800},
                "captured": False,
                "error": str(e),
            }
