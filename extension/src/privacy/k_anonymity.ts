/**
 * TrustGuard Extension Privacy - K-Anonymity Query Anonymizer
 * Prevents full URL/domain exposure by querying server with truncated SHA-256 hash prefixes (5 hex characters).
 */

export interface PrefixRangeItem {
  hashSuffix: string; // Remaining SHA-256 hex characters after prefix
  riskScore: number;
  verdictLabel: string;
}

export interface KAnonymityResponse {
  prefix: string;
  matches: PrefixRangeItem[];
}

/**
 * Compute SHA-256 hash of a string using browser Web Crypto API.
 */
export async function computeSha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text.trim().toLowerCase());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Extract k-Anonymity prefix and suffix from URL/domain string.
 */
export async function getKAnonymityQuery(text: string, prefixLength = 5): Promise<{
  fullHash: string;
  prefix: string;
  suffix: string;
}> {
  const fullHash = await computeSha256(text);
  const prefix = fullHash.substring(0, prefixLength);
  const suffix = fullHash.substring(prefixLength);
  return { fullHash, prefix, suffix };
}

/**
 * Anonymized threat query service executing k-Anonymity privacy protocol.
 */
export class KAnonymityClient {
  private apiBaseUrl: string;

  constructor(apiBaseUrl = 'http://localhost:8000') {
    this.apiBaseUrl = apiBaseUrl;
  }

  /**
   * Perform privacy-preserving lookup for target domain/URL.
   * Server ONLY sees the 5-character hash prefix, never the domain/URL.
   */
  async lookupAnonymized(target: string): Promise<{
    isMatched: boolean;
    verdictLabel?: string;
    riskScore?: number;
  }> {
    try {
      const { fullHash, prefix, suffix } = await getKAnonymityQuery(target);

      const response = await fetch(`${this.apiBaseUrl}/api/v1/lookup/prefix/${prefix}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        return { isMatched: false };
      }

      const data: KAnonymityResponse = await response.json();

      // Perform local client-side exact match against returned suffix list
      const match = data.matches.find(item => item.hashSuffix.toLowerCase() === suffix.toLowerCase());

      if (match) {
        return {
          isMatched: true,
          verdictLabel: match.verdictLabel,
          riskScore: match.riskScore,
        };
      }

      return { isMatched: false };
    } catch (error) {
      console.warn('[KAnonymityClient] Lookup error:', error);
      return { isMatched: false };
    }
  }
}
