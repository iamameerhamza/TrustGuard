/**
 * Content Script - Runs in page context.
 * Extracts links, scans on hover/click, shows inline warnings.
 */
import { Verdict, VerdictLabel } from './types';

// State
let isScanning = false;
let scannedUrls = new Set<string>();
let settings: any = { autoScan: true, blockPhishing: true };

// Load settings
chrome.storage.local.get('settings', (result) => {
  if (result.settings) settings = result.settings;
});

// Listen for settings updates
chrome.storage.onChanged.addListener((changes) => {
  if (changes.settings) settings = changes.settings.newValue;
});

// Scan a URL and show result
async function scanAndShow(url: string, element: HTMLElement): Promise<void> {
  if (isScanning || scannedUrls.has(url)) return;
  
  // Skip if not http/https
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return;
  } catch {
    return;
  }
  
  scannedUrls.add(url);
  isScanning = true;
  
  try {
    const response = await chrome.runtime.sendMessage({ type: 'SCAN_URL', url });
    
    if (response?.verdict) {
      showIndicator(element, response.verdict);
    }
  } catch (error) {
    console.warn('[Content] Scan failed:', error);
  } finally {
    isScanning = false;
  }
}

// Show inline indicator next to link
function showIndicator(element: HTMLElement, verdict: Verdict): void {
  // Remove existing indicator
  const existing = element.querySelector('.trustguard-indicator');
  if (existing) existing.remove();
  
  // Create indicator
  const indicator = document.createElement('span');
  indicator.className = 'trustguard-indicator';
  indicator.style.cssText = `
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    margin-left: 4px;
    white-space: nowrap;
    z-index: 2147483647;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  `;
  
  // Color by verdict
  const colors: Record<VerdictLabel, { bg: string; text: string; icon: string }> = {
    safe: { bg: '#dcfce7', text: '#166534', icon: '✓' },
    suspicious: { bg: '#fef9c3', text: '#854d0e', icon: '⚠' },
    phishing: { bg: '#fee2e2', text: '#991b1b', icon: '🛡' },
    malicious: { bg: '#fecaca', text: '#7f1d1d', icon: '🚫' },
  };
  
  const { bg, text, icon } = colors[verdict.prediction] || colors.suspicious;
  indicator.style.backgroundColor = bg;
  indicator.style.color = text;
  indicator.innerHTML = `${icon} ${verdict.risk_score}%`;
  indicator.title = `TrustGuard: ${verdict.prediction} (${verdict.risk_score}%)\n${verdict.chain_of_thought?.join('\n') || ''}`;
  
  // Insert after link
  element.parentNode?.insertBefore(indicator, element.nextSibling);
  
  // Auto-remove after 10 seconds
  setTimeout(() => indicator.remove(), 10000);
}

// Scan all links on page
function scanPageLinks(): void {
  if (!settings.autoScan) return;
  
  const links = document.querySelectorAll('a[href]');
  links.forEach((link) => {
    const href = link.getAttribute('href');
    if (href && !scannedUrls.has(href)) {
      // Debounce scans
      setTimeout(() => scanAndShow(href, link as HTMLElement), Math.random() * 1000);
    }
  });
}

// Hover scanning for immediate feedback
let hoverTimeout: number;
document.addEventListener('mouseover', (event) => {
  const target = event.target as HTMLElement;
  const link = target.closest('a[href]');
  if (link && settings.autoScan) {
    const href = link.getAttribute('href');
    if (href && !scannedUrls.has(href)) {
      hoverTimeout = window.setTimeout(() => scanAndShow(href, link as HTMLElement), 300);
    }
  }
});

document.addEventListener('mouseout', () => {
  if (hoverTimeout) clearTimeout(hoverTimeout);
});

// Listen for scan results from background
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'SCAN_RESULT' && message.verdict) {
    // Find and update indicator
    const links = document.querySelectorAll(`a[href="${message.url}"]`);
    links.forEach((link) => showIndicator(link as HTMLElement, message.verdict));
  }
});

// Initial scan after DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scanPageLinks);
} else {
  scanPageLinks();
}

// Re-scan on dynamic content (SPA navigation)
let lastUrl = location.href;
new MutationObserver(() => {
  if (location.href !== lastUrl) {
    lastUrl = location.href;
    scannedUrls.clear();
    setTimeout(scanPageLinks, 500);
  }
}).observe(document, { subtree: true, childList: true });

console.log('[Content] TrustGuard content script loaded');