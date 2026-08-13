/**
 * Popup UI - Minimal interface for manual scanning and settings.
 */
import { Verdict, VerdictLabel, Settings } from './types';

// DOM elements
const urlInput = document.getElementById('url-input') as HTMLInputElement;
const scanBtn = document.getElementById('scan-btn') as HTMLButtonElement;
const resultDiv = document.getElementById('result') as HTMLDivElement;
const historyList = document.getElementById('history-list') as HTMLUListElement;
const settingsForm = document.getElementById('settings-form') as HTMLFormElement;

// Tabs
const tabBtns = document.querySelectorAll('.tab-btn');
const tabPanels = document.querySelectorAll('.tab-panel');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadHistory();
  setupTabs();
  setupEventListeners();
});

function setupTabs(): void {
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${tab}`)?.classList.add('active');
    });
  });
}

function setupEventListeners(): void {
  // Scan button
  scanBtn.addEventListener('click', handleScan);
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleScan();
  });
  
  // Settings form
  settingsForm.addEventListener('submit', handleSettingsSave);
  
  // Current tab button
  const currentTabBtn = document.getElementById('current-tab-btn');
  currentTabBtn?.addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab.url) {
      urlInput.value = tab.url;
      handleScan();
    }
  });
}

async function handleScan(): Promise<void> {
  const url = urlInput.value.trim();
  if (!url) return;
  
  setLoading(true);
  resultDiv.innerHTML = '';
  
  try {
    const response = await chrome.runtime.sendMessage({ type: 'SCAN_URL', url });
    
    if (response?.verdict) {
      showResult(response.verdict);
      addToHistory(response.verdict);
    } else if (response?.error) {
      showError(response.error);
    }
  } catch (error) {
    showError(error instanceof Error ? error.message : 'Scan failed');
  } finally {
    setLoading(false);
  }
}

function showResult(verdict: Verdict): void {
  const colors: Record<VerdictLabel, { bg: string; text: string; border: string }> = {
    safe: { bg: '#dcfce7', text: '#166534', border: '#86efac' },
    suspicious: { bg: '#fef9c3', text: '#854d0e', border: '#fde047' },
    phishing: { bg: '#fee2e2', text: '#991b1b', border: '#fca5a5' },
    malicious: { bg: '#fecaca', text: '#7f1d1d', border: '#ef4444' },
  };
  
  const { bg, text, border } = colors[verdict.prediction] || colors.suspicious;
  
  resultDiv.innerHTML = `
    <div style="
      background: ${bg};
      color: ${text};
      border: 2px solid ${border};
      border-radius: 8px;
      padding: 12px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    ">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <strong style="font-size: 14px; text-transform: capitalize;">${verdict.prediction}</strong>
        <span style="font-size: 20px; font-weight: bold;">${verdict.risk_score}%</span>
      </div>
      <div style="font-size: 12px; opacity: 0.9; margin-bottom: 8px;">
        ${verdict.url}
      </div>
      <details style="font-size: 11px;">
        <summary style="cursor: pointer; margin-bottom: 4px;">Why?</summary>
        <ul style="margin: 0; padding-left: 16px;">
          ${verdict.chain_of_thought?.map(step => `<li>${step.thought}</li>`).join('') || '<li>Analysis complete</li>'}
        </ul>
      </details>
    </div>
  `;
}

function showError(message: string): void {
  resultDiv.innerHTML = `
    <div style="
      background: #fef2f2;
      color: #991b1b;
      border: 1px solid #fca5a5;
      border-radius: 8px;
      padding: 12px;
      font-size: 13px;
    ">
      Error: ${message}
    </div>
  `;
}

function setLoading(loading: boolean): void {
  scanBtn.disabled = loading;
  scanBtn.textContent = loading ? 'Scanning...' : 'Scan';
  urlInput.disabled = loading;
}

async function loadSettings(): Promise<void> {
  const result = await chrome.storage.local.get('settings');
  const settings: Settings = result.settings || {
    autoScan: true,
    blockPhishing: false,
    showNotifications: true,
    enableAgentic: false,
    offlineMode: true,
  };
  
  // Populate form
  Object.entries(settings).forEach(([key, value]) => {
    const input = settingsForm.querySelector(`[name="${key}"]`) as HTMLInputElement;
    if (input) input.checked = value;
  });
}

async function handleSettingsSave(event: Event): Promise<void> {
  event.preventDefault();
  
  const formData = new FormData(settingsForm);
  const settings: Settings = {
    autoScan: formData.get('autoScan') === 'on',
    blockPhishing: formData.get('blockPhishing') === 'on',
    showNotifications: formData.get('showNotifications') === 'on',
    enableAgentic: formData.get('enableAgentic') === 'on',
    offlineMode: formData.get('offlineMode') === 'on',
  };
  
  await chrome.storage.local.set({ settings });
  
  // Notify content scripts
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, { type: 'SETTINGS_UPDATED', settings });
      }
    });
  });
  
  // Show saved feedback
  const saveBtn = settingsForm.querySelector('button[type="submit"]') as HTMLButtonElement;
  const originalText = saveBtn.textContent;
  saveBtn.textContent = 'Saved!';
  setTimeout(() => saveBtn.textContent = originalText, 1000);
}

async function loadHistory(): Promise<void> {
  const result = await chrome.storage.local.get('tg:history');
  const history = result['tg:history'] || [];
  
  historyList.innerHTML = history.slice(0, 20).map(entry => `
    <li style="
      display: flex;
      justify-content: space-between;
      padding: 8px;
      border-bottom: 1px solid #eee;
      font-size: 12px;
    ">
      <span style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${entry.url}</span>
      <span style="
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 600;
        background: ${verdictColor(entry.verdict)};
        color: white;
      ">${entry.risk_score}%</span>
    </li>
  `).join('');
}

function verdictColor(verdict: VerdictLabel): string {
  const colors: Record<VerdictLabel, string> = {
    safe: '#22c55e',
    suspicious: '#eab308',
    phishing: '#ef4444',
    malicious: '#dc2626',
  };
  return colors[verdict] || colors.suspicious;
}

function addToHistory(verdict: Verdict): void {
  const entry = {
    url: verdict.url,
    verdict: verdict.prediction,
    risk_score: verdict.risk_score,
    timestamp: Date.now(),
    source: 'popup',
  };
  
  chrome.storage.local.get('tg:history', (result) => {
    const history = result['tg:history'] || [];
    history.unshift(entry);
    if (history.length > 100) history.pop();
    chrome.storage.local.set({ 'tg:history': history });
    loadHistory();
  });
}