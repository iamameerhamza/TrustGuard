/**
 * TrustGuard Edge - Local Pre-Flight URL Evaluator
 * High-speed, pure lexical and rule-based evaluation engine running directly in browser background context.
 */

import { calculateEntropy } from './entropy';

export interface LocalScanResult {
  url: string;
  domain: string;
  isPunycode: boolean;
  subdomainCount: number;
  entropy: number;
  suspiciousKeywordsFound: string[];
  tldRiskScore: number;
  brandImpersonationScore: number;
  riskScore: number; // 0 to 100
  verdict: 'safe' | 'suspicious' | 'phishing';
  reasons: string[];
}

// Suspicious keywords matched in phishing URLs
export const SUSPICIOUS_KEYWORDS: ReadonlySet<string> = new Set([
  'login', 'secure', 'bank', 'account', 'update', 'verify',
  'credential', 'password', 'signin', 'auth', 'authenticate',
  'confirm', 'validate', 'security', 'wallet', 'crypto', 'bitcoin',
  'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
  'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'onedrive',
  'office365', 'outlook', 'webmail', 'mail', 'email', 'inbox',
  'suspended', 'locked', 'disabled', 'expired', 'urgent', 'immediate',
  'action', 'required', 'validation', 'unusual', 'activity'
]);

// High risk TLD list frequently used in phishing campaigns
export const HIGH_RISK_TLDS: ReadonlySet<string> = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work',
  'date', 'racing', 'download', 'stream', 'science', 'loan',
  'win', 'party', 'review', 'trade', 'bid', 'cricket', 'faith'
]);

// High-value brand domains targeted for impersonation
export const BRAND_DOMAINS: ReadonlySet<string> = new Set([
  'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
  'amazon.com', 'paypal.com', 'github.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'netflix.com', 'spotify.com',
  'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com',
  'zoom.us', 'teams.microsoft.com', 'webex.com'
]);

/**
 * Count subdomain depth (excluding TLD and SLD).
 * e.g., "login.secure.paypal.phishersite.com" -> 3 subdomains
 */
export function countSubdomains(hostname: string): number {
  if (!hostname) return 0;
  const parts = hostname.split('.');
  return Math.max(0, parts.length - 2);
}

/**
 * Check if hostname contains punycode prefix (xn--), indicative of homograph attacks.
 */
export function hasPunycode(hostname: string): boolean {
  return hostname.toLowerCase().includes('xn--');
}

/**
 * Check if hostname is an IP address.
 */
export function isIpAddress(hostname: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

/**
 * Evaluate TLD risk score (0.0 to 1.0).
 */
export function getTldRiskScore(hostname: string): number {
  if (!hostname) return 0.0;
  const parts = hostname.toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  if (HIGH_RISK_TLDS.has(tld)) return 0.8;
  if (['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'ai'].includes(tld)) return 0.1;
  return 0.3;
}

/**
 * Detect potential brand impersonation in domain / subdomains.
 */
export function getBrandImpersonationScore(hostname: string): { score: number; targetBrand?: string } {
  if (!hostname) return { score: 0.0 };

  const hostLower = hostname.toLowerCase();

  for (const brand of BRAND_DOMAINS) {
    const brandBase = brand.split('.')[0];
    
    // Subdomain spoofing (e.g. google.com.malicious.net or paypal.security-check.xyz)
    if (hostLower.includes(`${brandBase}.`) && !hostLower.endsWith(brand)) {
      return { score: 0.9, targetBrand: brandBase };
    }

    // Keyword insertion into domain (e.g. paypal-verify-login.com)
    if (hostLower.includes(brandBase) && !hostLower.endsWith(brand)) {
      if (countSubdomains(hostLower) >= 1 || hostLower.includes('-')) {
        return { score: 0.75, targetBrand: brandBase };
      }
    }
  }

  return { score: 0.0 };
}

/**
 * Perform pure client-side pre-flight lexical URL evaluation.
 */
export function evaluateUrlLocally(rawUrl: string): LocalScanResult {
  const reasons: string[] = [];
  let riskPoints = 0;

  let hostname = '';
  let urlLower = rawUrl.toLowerCase();

  try {
    const parsed = new URL(rawUrl);
    hostname = parsed.hostname;
  } catch {
    hostname = rawUrl.split('/')[0];
  }

  // 1. Check IP address
  const isIp = isIpAddress(hostname);
  if (isIp) {
    riskPoints += 25;
    reasons.push('Domain is a raw IP address');
  }

  // 2. Check Punycode / Homograph
  const punycode = hasPunycode(hostname);
  if (punycode) {
    riskPoints += 30;
    reasons.push('Punycode (homograph attack pattern) detected');
  }

  // 3. Subdomain Depth
  const subdomains = countSubdomains(hostname);
  if (subdomains >= 3) {
    riskPoints += 20;
    reasons.push(`Excessive subdomain nesting level (${subdomains})`);
  } else if (subdomains === 2) {
    riskPoints += 10;
  }

  // 4. Entropy calculation
  const urlEntropy = calculateEntropy(rawUrl);
  if (urlEntropy > 4.5) {
    riskPoints += 20;
    reasons.push(`High Shannon entropy (${urlEntropy.toFixed(2)}) indicating randomized string`);
  } else if (urlEntropy > 4.0) {
    riskPoints += 10;
  }

  // 5. Suspicious Keywords
  const keywordsFound: string[] = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (urlLower.includes(kw)) {
      keywordsFound.push(kw);
    }
  }
  if (keywordsFound.length > 0) {
    const keywordWeight = Math.min(30, keywordsFound.length * 10);
    riskPoints += keywordWeight;
    reasons.push(`Contains suspicious security/credential keywords: ${keywordsFound.slice(0, 3).join(', ')}`);
  }

  // 6. High Risk TLD
  const tldScore = getTldRiskScore(hostname);
  if (tldScore >= 0.8) {
    riskPoints += 20;
    reasons.push('Uses high-risk top-level domain (TLD)');
  }

  // 7. Brand Impersonation
  const brandCheck = getBrandImpersonationScore(hostname);
  if (brandCheck.score > 0.5) {
    riskPoints += Math.round(brandCheck.score * 35);
    reasons.push(`Potential brand impersonation targeted at ${brandCheck.targetBrand?.toUpperCase()}`);
  }

  // Cap risk score 0 to 100
  const finalRiskScore = Math.min(100, Math.max(0, riskPoints));

  let verdict: 'safe' | 'suspicious' | 'phishing' = 'safe';
  if (finalRiskScore >= 65) {
    verdict = 'phishing';
  } else if (finalRiskScore >= 30) {
    verdict = 'suspicious';
  }

  if (reasons.length === 0) {
    reasons.push('No obvious lexical threat patterns detected in pre-flight scan');
  }

  return {
    url: rawUrl,
    domain: hostname,
    isPunycode: punycode,
    subdomainCount: subdomains,
    entropy: urlEntropy,
    suspiciousKeywordsFound: keywordsFound,
    tldRiskScore: tldScore,
    brandImpersonationScore: brandCheck.score,
    riskScore: finalRiskScore,
    verdict,
    reasons,
  };
}
