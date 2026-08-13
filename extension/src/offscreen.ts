/**
 * Offscreen Document - Runs ONNX Runtime Web inference.
 * Manifest V3 Service Workers can't run WASM, so we use offscreen documents.
 */
import * as ort from 'onnxruntime-web';
import { Verdict, VerdictLabel, Evidence, EvidenceType, ModelOutput, ChainOfThoughtStep } from './types';

// Global model session
let session: ort.InferenceSession | null = null;
let featureNames: string[] = [];
let modelLoaded = false;

// Initialize ONNX session
async function initModel(): Promise<void> {
  try {
    // Load model from extension resources
    const modelUrl = chrome.runtime.getURL('models/phishing_rf_int8.onnx');
    const metaUrl = chrome.runtime.getURL('models/phishing_rf_int8.json');
    
    // Load metadata first
    const metaResponse = await fetch(metaUrl);
    const metadata = await metaResponse.json();
    featureNames = metadata.feature_names || [];
    
    // Create session with WASM backend
    session = await ort.InferenceSession.create(modelUrl, {
      executionProviders: ['wasm'],
      graphOptimizationLevel: 'all',
    });
    
    modelLoaded = true;
    console.log('[Offscreen] Model loaded successfully');
    console.log('[Offscreen] Feature names:', featureNames);
  } catch (error) {
    console.error('[Offscreen] Failed to load model:', error);
    modelLoaded = false;
  }
}

// Extract features from URL (mirrors Python extractor)
function extractFeatures(url: string): Float32Array {
  const features: Record<string, number> = {};
  
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const path = parsed.pathname;
    const query = parsed.search.slice(1); // Remove leading ?
    
    // Basic lexical features
    features.url_length = url.length;
    features.domain_length = domain.length;
    features.path_length = path.length;
    features.query_length = query.length;
    features.subdomain_count = Math.max(0, domain.split('.').length - 2);
    features.has_special_chars = /[@\-]/.test(domain) ? 1 : 0;
    features.has_at_symbol = url.includes('@') ? 1 : 0;
    features.has_dash_in_domain = domain.split('.')[0]?.includes('-') ? 1 : 0;
    features.has_port = parsed.port ? 1 : 0;
    features.is_ip_address = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) ? 1 : 0;
    
    // Entropy
    features.entropy = calculateEntropy(url);
    features.path_entropy = calculateEntropy(path);
    features.subdomain_entropy = calculateEntropy(domain.split('.').slice(0, -2).join('.'));
    
    // Suspicious keywords
    const suspiciousKeywords = [
      'login', 'secure', 'bank', 'account', 'update', 'verify',
      'credential', 'password', 'signin', 'auth', 'authenticate',
      'confirm', 'validate', 'security', 'wallet', 'crypto', 'bitcoin',
      'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
      'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'onedrive',
      'office365', 'outlook', 'webmail', 'mail', 'email', 'inbox',
      'suspended', 'locked', 'disabled', 'expired', 'urgent', 'immediate',
      'action', 'required', 'verify', 'validation', 'unusual', 'activity'
    ];
    features.suspicious_keyword_count = suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw)).length;
    
    // TLD risk
    const tld = domain.split('.').pop() || '';
    const highRiskTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date'];
    features.has_suspicious_tld = highRiskTlds.includes(tld) ? 1 : 0;
    features.tld_risk_score = highRiskTlds.includes(tld) ? 0.8 : (['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'ai'].includes(tld) ? 0.1 : 0.3);
    
    // Brand impersonation
    const brands = [
      'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
      'amazon.com', 'paypal.com', 'github.com', 'twitter.com',
      'instagram.com', 'linkedin.com', 'netflix.com', 'spotify.com',
    ];
    let impersonationScore = 0;
    for (const brand of brands) {
      const brandBase = brand.split('.')[0];
      if (domain.includes(brandBase + '.') && !domain.endsWith(brand)) {
        impersonationScore = 0.9;
        break;
      }
      if (domain.includes(brandBase) && !domain.endsWith(brand)) {
        impersonationScore = Math.max(impersonationScore, 0.7);
      }
    }
    features.brand_impersonation_score = impersonationScore;
    
    // Punycode
    features.punycode_detected = domain.includes('xn--') ? 1 : 0;
    
    // Query params
    features.query_param_count = query ? query.split('&').length : 0;
    
    // URL hash prefix (for privacy-preserving blocklist)
    features.url_hash_prefix = urlHashPrefix(url);
    
  } catch (e) {
    console.warn('[Offscreen] Feature extraction error:', e);
  }
  
  // Return in correct order
  const ordered = featureNames.map(name => features[name] ?? 0);
  return new Float32Array(ordered);
}

function calculateEntropy(text: string): number {
  if (!text) return 0;
  const freq: Record<string, number> = {};
  for (const char of text) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = text.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function urlHashPrefix(url: string, length = 8): number {
  // Simple hash for demo - in production use SHA-256 via Web Crypto API
  let hash = 0;
  for (let i = 0; i < url.length; i++) {
    hash = ((hash << 5) - hash) + url.charCodeAt(i);
    hash |= 0;
  }
  // Normalize to 0-1
  return (Math.abs(hash) % Math.pow(16, length)) / Math.pow(16, length);
}

// Run inference
async function runInference(url: string): Promise<Verdict> {
  if (!modelLoaded || !session) {
    await initModel();
  }
  
  if (!session) {
    throw new Error('Model not loaded');
  }
  
  const startTime = performance.now();
  
  // Extract features
  const features = extractFeatures(url);
  const inputTensor = new ort.Tensor('float32', features, [1, features.length]);
  
  // Run inference
  const feeds: Record<string, ort.Tensor> = {};
  feeds[session.inputNames[0]] = inputTensor;
  
  const results = await session.run(feeds);
  const outputName = session.outputNames[0];
  const output = results[outputName].data as Float32Array;
  
  // Parse output (assuming binary classification: [prob_safe, prob_phishing])
  const phishingProb = output.length > 1 ? output[1] : output[0];
  const latencyMs = performance.now() - startTime;
  
  // Determine verdict
  let prediction: VerdictLabel;
  if (phishingProb >= 0.7) prediction = 'phishing';
  else if (phishingProb >= 0.3) prediction = 'suspicious';
  else prediction = 'safe';
  
  // Build evidence
  const evidence: Evidence[] = [
    {
      type: 'ML_SCORE',
      source_module: 'rf_url_onnx_web',
      timestamp: new Date().toISOString(),
      confidence: Math.abs(phishingProb - 0.5) * 2,
      description: `ML model score: ${phishingProb.toFixed(3)} (${prediction})`,
      raw_data: { score: phishingProb, prediction, latency_ms: latencyMs },
      tags: ['ml', 'inference'],
    },
  ];
  
  // Add feature highlights
  const extractedFeatures = extractFeatures(url);
  const featureObj: Record<string, number> = {};
  featureNames.forEach((name, i) => featureObj[name] = extractedFeatures[i]);
  
  if (featureObj.brand_impersonation_score > 0.5) {
    evidence.push({
      type: 'BRAND_IMPERSONATION',
      source_module: 'url_features_web',
      timestamp: new Date().toISOString(),
      confidence: featureObj.brand_impersonation_score,
      description: `Brand impersonation detected (score: ${featureObj.brand_impersonation_score.toFixed(2)})`,
      raw_data: { score: featureObj.brand_impersonation_score },
      tags: ['phishing_indicator', 'brand_impersonation'],
    });
  }
  
  if (featureObj.punycode_detected) {
    evidence.push({
      type: 'PUNYCODE_DETECTED',
      source_module: 'url_features_web',
      timestamp: new Date().toISOString(),
      confidence: 0.9,
      description: 'Punycode domain detected (possible homograph attack)',
      raw_data: { domain: new URL(url).hostname },
      tags: ['phishing_indicator', 'homograph'],
    });
  }
  
  if (featureObj.has_suspicious_tld) {
    evidence.push({
      type: 'SUSPICIOUS_TLD',
      source_module: 'url_features_web',
      timestamp: new Date().toISOString(),
      confidence: 0.7,
      description: 'High-risk TLD detected',
      raw_data: { tld: new URL(url).hostname.split('.').pop() },
      tags: ['phishing_indicator', 'tld'],
    });
  }
  
  // Build chain of thought
  const chainOfThought: ChainOfThoughtStep[] = [
    {
      step: 1,
      thought: `Analyzing URL: ${url}`,
      evidence_produced: [],
    },
    {
      step: 2,
      thought: `Extracted ${featureNames.length} lexical/structural features`,
      evidence_produced: [],
    },
    {
      step: 3,
      thought: `Random Forest model (ONNX Web) predicted: ${prediction} (score: ${phishingProb.toFixed(3)})`,
      evidence_produced: evidence.slice(0, 1),
    },
  ];
  
  // Add feature-based reasoning
  if (featureObj.brand_impersonation_score > 0.5) {
    chainOfThought.push({
      step: 4,
      thought: 'Brand impersonation detected in subdomain structure',
      evidence_produced: evidence.slice(1, 2),
    });
  }
  if (featureObj.punycode_detected) {
    chainOfThought.push({
      step: chainOfThought.length + 1,
      thought: 'Punycode encoding indicates possible homograph attack',
      evidence_produced: evidence.slice(-1),
    });
  }
  
  const modelOutput: ModelOutput = {
    score: phishingProb,
    prediction,
    confidence: Math.abs(phishingProb - 0.5) * 2,
    latency_ms: latencyMs,
    model_name: 'rf_url_onnx_web',
    model_version: '1.0.0',
  };
  
  return {
    url,
    risk_score: Math.round(phishingProb * 100),
    prediction,
    confidence: modelOutput.confidence,
    latency_ms: latencyMs,
    evidence,
    chain_of_thought: chainOfThought,
    model_outputs: { rf_url_onnx_web: modelOutput },
    pipeline_version: '2030.1.0-web',
    timestamp: new Date().toISOString(),
    primary_reasons: evidence.map(e => e.description),
    mitigating_factors: [],
  };
}

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'OFFSCREEN_SCAN') {
    const { url, source } = message.payload;
    
    runInference(url)
      .then(verdict => {
        sendResponse({ type: 'OFFSCREEN_SCAN_RESULT', verdict, error: null });
      })
      .catch(error => {
        console.error('[Offscreen] Inference error:', error);
        sendResponse({ 
          type: 'OFFSCREEN_SCAN_RESULT', 
          verdict: null, 
          error: error.message 
        });
      });
    
    return true; // Async response
  }
  
  if (message.type === 'OFFSCREEN_HEALTH_CHECK') {
    sendResponse({ 
      type: 'OFFSCREEN_HEALTH_RESPONSE', 
      modelLoaded, 
      featureCount: featureNames.length 
    });
    return true;
  }
});

// Initialize on load
initModel().catch(console.error);

console.log('[Offscreen] TrustGuard offscreen document ready');