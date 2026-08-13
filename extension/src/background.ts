/**
 * TrustGuard Background Service Worker (Manifest V3)
 * Handles scan requests, manages offscreen document, stores history.
 */
import { Verdict, VerdictLabel, ScanRequest, ScanResponse, Settings, HistoryEntry } from './types';
import { evaluateUrlLocally, isIpAddress } from './edge/url_evaluator';

// Default settings
const DEFAULT_SETTINGS: Settings = {
  autoScan: true,
  blockPhishing: true,
  showNotifications: true,
  enableAgentic: false,
  offlineMode: true,
};

// In-memory state (persisted to chrome.storage)
let settings: Settings = { ...DEFAULT_SETTINGS };
let history: HistoryEntry[] = [];
let offscreenDocumentCreated = false;

// Initialize on startup
chrome.runtime.onInstalled.addListener(async () => {
  await loadSettings();
  await loadHistory();
  console.log('[Background] TrustGuard extension installed/updated');
});

chrome.runtime.onStartup.addListener(async () => {
  await loadSettings();
  await loadHistory();
  console.log('[Background] TrustGuard extension started');
});

// Load settings from storage
async function loadSettings(): Promise<void> {
  const stored = await chrome.storage.local.get('settings');
  if (stored.settings) {
    settings = { ...DEFAULT_SETTINGS, ...stored.settings };
  }
  console.log('[Background] Settings loaded:', settings);
}

// Save settings to storage
async function saveSettings(): Promise<void> {
  await chrome.storage.local.set({ settings });
  console.log('[Background] Settings saved');
}

// Load history from storage
async function loadHistory(): Promise<void> {
  const stored = await chrome.storage.local.get('history');
  if (stored.history) {
    history = stored.history.slice(-1000); // Keep last 1000 entries
  }
}

// Save history to storage
async function saveHistory(): Promise<void> {
  await chrome.storage.local.set({ history: history.slice(-1000) });
}

// Ensure offscreen document exists
async function ensureOffscreenDocument(): Promise<void> {
  if (offscreenDocumentCreated) return;
  
  const existing = await chrome.offscreen.hasDocument();
  if (existing) {
    offscreenDocumentCreated = true;
    return;
  }
  
  try {
    await chrome.offscreen.createDocument({
      url: chrome.runtime.getURL('offscreen.html'),
      reasons: ['WORKERS'],
      justification: 'Run ONNX Runtime Web inference for phishing detection',
    });
    offscreenDocumentCreated = true;
    console.log('[Background] Offscreen document created');
  } catch (error) {
    console.error('[Background] Failed to create offscreen document:', error);
    throw error;
  }
}

// Scan URL via fast edge pre-flight evaluator & offscreen document
async function scanUrl(url: string, source = 'extension'): Promise<Verdict | null> {
  // 1. Fast pre-flight edge scan (< 5ms)
  const preflight = evaluateUrlLocally(url);
  console.log('[Background] Pre-flight evaluation:', preflight);

  if (!settings.offlineMode) {
    // TODO: Fallback to API if online mode enabled
    console.log('[Background] Online mode not implemented yet');
  }

  try {
    await ensureOffscreenDocument();

    const offscreenVerdict = await new Promise<Verdict | null>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Offscreen scan timeout'));
      }, 5000);

      chrome.runtime.sendMessage(
        { type: 'OFFSCREEN_SCAN', payload: { url, source } },
        (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (response?.error) {
            reject(new Error(response.error));
            return;
          }
          resolve(response.verdict || null);
        }
      );
    });

    if (offscreenVerdict) {
      // Combine offscreen ML prediction with pre-flight explanations
      return {
        ...offscreenVerdict,
        explanation: Array.from(new Set([...offscreenVerdict.explanation, ...preflight.reasons])),
      };
    }
  } catch (error) {
    console.warn('[Background] Offscreen scan failed/timed out, using pre-flight verdict:', error);
  }

  // Fallback to local pre-flight verdict
  return {
    url,
    prediction: preflight.verdict,
    risk_score: preflight.riskScore,
    confidence: preflight.verdict === 'safe' ? 0.9 : 0.8,
    explanation: preflight.reasons,
    features: {
      url_length: url.length,
      domain_length: preflight.domain.length,
      entropy: preflight.entropy,
      subdomain_count: preflight.subdomainCount,
      is_ip_address: isIpAddress(preflight.domain) ? 1 : 0,
      punycode_detected: preflight.isPunycode ? 1 : 0,
      suspicious_keyword_count: preflight.suspiciousKeywordsFound.length,
      tld_risk_score: preflight.tldRiskScore,
      brand_impersonation_score: preflight.brandImpersonationScore,
    },
    scanned_at: new Date().toISOString(),
  };
}

// Handle scan requests from popup/content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_URL') {
    const { url, source = 'extension' } = message;
    
    scanUrl(url, source)
      .then(verdict => {
        if (verdict) {
          // Add to history
          addToHistory(url, verdict, source);
          
          // Notify content script if from page
          if (sender.tab?.id) {
            chrome.tabs.sendMessage(sender.tab.id, {
              type: 'SCAN_RESULT',
              url,
              verdict,
            }).catch(() => {}); // Ignore if content script not ready
          }
          
          // Show notification if enabled
          if (settings.showNotifications && verdict.prediction !== 'safe') {
            showNotification(verdict);
          }
          
          // Block if enabled and phishing
          if (settings.blockPhishing && verdict.prediction === 'phishing') {
            // In real implementation, would redirect or block navigation
            console.log('[Background] Would block navigation to:', url);
          }
        }
        sendResponse({ verdict });
      })
      .catch(error => {
        console.error('[Background] Scan error:', error);
        sendResponse({ error: error.message });
      });
    
    return true; // Async response
  }
  
  if (message.type === 'GET_SETTINGS') {
    sendResponse({ settings });
    return true;
  }
  
  if (message.type === 'UPDATE_SETTINGS') {
    settings = { ...settings, ...message.settings };
    saveSettings().then(() => sendResponse({ settings }));
    return true;
  }
  
  if (message.type === 'GET_HISTORY') {
    sendResponse({ history: history.slice(-100) });
    return true;
  }
  
  if (message.type === 'CLEAR_HISTORY') {
    history = [];
    saveHistory().then(() => sendResponse({ success: true }));
    return true;
  }
});

// Add scan result to history
function addToHistory(url: string, verdict: Verdict, source: string): void {
  const entry: HistoryEntry = {
    url,
    verdict: verdict.prediction,
    risk_score: verdict.risk_score,
    timestamp: Date.now(),
    source,
  };
  history.unshift(entry);
  if (history.length > 1000) history = history.slice(0, 1000);
  saveHistory();
}

// Show desktop notification
function showNotification(verdict: Verdict): void {
  const labels: Record<VerdictLabel, string> = {
    safe: 'Safe',
    suspicious: 'Suspicious',
    phishing: 'Phishing',
    malicious: 'Malicious',
  };
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon-48.png'),
    title: `TrustGuard: ${labels[verdict.prediction]} Detected`,
    message: `${verdict.url}\nRisk: ${verdict.risk_score}/100`,
    priority: verdict.prediction === 'phishing' ? 2 : 1,
  });
}

// Context menu for right-click scanning
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'trustguard-scan-link',
    title: 'Scan with TrustGuard',
    contexts: ['link'],
  });
  
  chrome.contextMenus.create({
    id: 'trustguard-scan-page',
    title: 'Scan this page',
    contexts: ['page'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  
  let url: string;
  if (info.menuItemId === 'trustguard-scan-link' && info.linkUrl) {
    url = info.linkUrl;
  } else if (info.menuItemId === 'trustguard-scan-page' && tab.url) {
    url = tab.url;
  } else {
    return;
  }
  
  const verdict = await scanUrl(url, 'context_menu');
  if (verdict) {
    chrome.tabs.sendMessage(tab.id, {
      type: 'SCAN_RESULT',
      url,
      verdict,
    }).catch(() => {});
  }
});

// Health check
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'HEALTH_CHECK') {
    sendResponse({ 
      status: 'ok', 
      version: chrome.runtime.getManifest().version,
      settings,
      historyCount: history.length,
    });
    return true;
  }
});

console.log('[Background] TrustGuard service worker ready');