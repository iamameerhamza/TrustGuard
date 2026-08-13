/**
 * TrustGuard Extension Cache - IndexedDB Verdict Cache & Local Bloom Filter Lookup
 * Provides TTL-based local verdict storage and double-hashing Bloom Filter lookup in client TypeScript context.
 */

import { Verdict } from '../types';

export interface CachedVerdict {
  url: string;
  verdict: Verdict;
  timestamp: number; // Date.now()
  ttlMs: number;     // e.g., 24 hours (86400000 ms)
}

const DB_NAME = 'TrustGuardCache';
const DB_VERSION = 1;
const STORE_NAME = 'verdicts';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * IndexedDB storage wrapper for caching scan verdicts locally.
 */
export class LocalVerdictCache {
  private dbPromise: Promise<IDBDatabase> | null = null;

  private getDB(): Promise<IDBDatabase> {
    if (this.dbPromise) return this.dbPromise;

    this.dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'url' });
          store.createIndex('timestamp', 'timestamp', { unique: false });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    return this.dbPromise;
  }

  /**
   * Get cached verdict if present and not expired.
   */
  async get(url: string): Promise<Verdict | null> {
    try {
      const db = await this.getDB();
      return new Promise((resolve) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(url);

        req.onsuccess = () => {
          const item: CachedVerdict | undefined = req.result;
          if (!item) {
            resolve(null);
            return;
          }

          const now = Date.now();
          if (now - item.timestamp > item.ttlMs) {
            // Expired - delete asynchronously
            this.delete(url).catch(() => {});
            resolve(null);
          } else {
            resolve(item.verdict);
          }
        };

        req.onerror = () => resolve(null);
      });
    } catch {
      return null;
    }
  }

  /**
   * Put scan verdict into local cache with TTL.
   */
  async set(url: string, verdict: Verdict, ttlMs: number = DEFAULT_TTL_MS): Promise<void> {
    try {
      const db = await this.getDB();
      const item: CachedVerdict = {
        url,
        verdict,
        timestamp: Date.now(),
        ttlMs,
      };

      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.put(item);

        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    } catch (error) {
      console.warn('[VerdictCache] Failed to set cache entry:', error);
    }
  }

  /**
   * Delete entry from cache.
   */
  async delete(url: string): Promise<void> {
    try {
      const db = await this.getDB();
      return new Promise((resolve) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.delete(url);
        req.onsuccess = () => resolve();
        req.onerror = () => resolve();
      });
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * TypeScript Client Double-Hashing Bloom Filter
 */
export class ClientBloomFilter {
  private size: number;
  private hashCount: number;
  private bitArray: Uint8Array;

  constructor(size = 95851, hashCount = 10, bitsHex?: string) {
    this.size = size;
    this.hashCount = hashCount;
    const byteLen = Math.ceil(size / 8);

    if (bitsHex) {
      this.bitArray = new Uint8Array(byteLen);
      for (let i = 0; i < bitsHex.length; i += 2) {
        this.bitArray[i / 2] = parseInt(bitsHex.substring(i, i + 2), 16);
      }
    } else {
      this.bitArray = new Uint8Array(byteLen);
    }
  }

  /**
   * FNV-1a Hash 1
   */
  private fnv1a(str: string): number {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = (hash * 16777619) >>> 0;
    }
    return hash;
  }

  /**
   * Jenkins Hash 2
   */
  private jenkins(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash += str.charCodeAt(i);
      hash += (hash << 10);
      hash ^= (hash >>> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >>> 11);
    hash += (hash << 15);
    return hash >>> 0;
  }

  /**
   * Add item to local Bloom Filter
   */
  add(item: string): void {
    const h1 = this.fnv1a(item);
    const h2 = this.jenkins(item);

    for (let i = 0; i < this.hashCount; i++) {
      const idx = Math.abs((h1 + i * h2) % this.size);
      const byteIdx = Math.floor(idx / 8);
      const bitIdx = idx % 8;
      this.bitArray[byteIdx] |= (1 << bitIdx);
    }
  }

  /**
   * Check if item is possibly present in local Bloom Filter
   */
  contains(item: string): boolean {
    const h1 = this.fnv1a(item);
    const h2 = this.jenkins(item);

    for (let i = 0; i < this.hashCount; i++) {
      const idx = Math.abs((h1 + i * h2) % this.size);
      const byteIdx = Math.floor(idx / 8);
      const bitIdx = idx % 8;
      if (!(this.bitArray[byteIdx] & (1 << bitIdx))) {
        return false;
      }
    }

    return true;
  }
}
