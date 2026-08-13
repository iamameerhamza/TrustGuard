/**
 * TrustGuard Edge - Entropy & Text Analytics Utilities
 * Provides Shannon entropy and string complexity metrics for client-side pre-flight checks.
 */

/**
 * Calculate Shannon Entropy of a string.
 * @param text Target text to evaluate
 * @returns Entropy value in bits (typically 0.0 to 5.0+)
 */
export function calculateEntropy(text: string): number {
  if (!text || text.length === 0) {
    return 0.0;
  }

  const charCounts: Map<string, number> = new Map();
  for (const char of text) {
    charCounts.set(char, (charCounts.get(char) || 0) + 1);
  }

  let entropy = 0.0;
  const len = text.length;
  for (const count of charCounts.values()) {
    const pX = count / len;
    entropy -= pX * Math.log2(pX);
  }

  return entropy;
}

/**
 * Calculate component-wise entropy for URL parts (domain, path, query).
 */
export function calculateUrlComponentEntropy(url: string): {
  urlEntropy: number;
  domainEntropy: number;
  pathEntropy: number;
  queryEntropy: number;
} {
  try {
    const parsed = new URL(url);
    return {
      urlEntropy: calculateEntropy(url),
      domainEntropy: calculateEntropy(parsed.hostname),
      pathEntropy: calculateEntropy(parsed.pathname),
      queryEntropy: calculateEntropy(parsed.search),
    };
  } catch {
    return {
      urlEntropy: calculateEntropy(url),
      domainEntropy: 0.0,
      pathEntropy: 0.0,
      queryEntropy: 0.0,
    };
  }
}
