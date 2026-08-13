/**
 * Shared types for TrustGuard extension.
 * Matches backend Verdict schema for consistency.
 */

// Core message types
export interface Message {
  type: string;
  [key: string]: any;
}

export interface ScanRequest extends Message {
  type: 'SCAN_URL';
  url: string;
  source?: string;
}

export interface ScanResponse extends Message {
  type: 'SCAN_RESULT';
  url: string;
  verdict: Verdict;
  timestamp: number;
}

// Verdict types (matching backend core/schemas/evidence.py)
export type VerdictLabel = 'safe' | 'suspicious' | 'phishing' | 'malicious';

export interface Evidence {
  type: string;
  source_module: string;
  timestamp: string;
  confidence: number;
  description: string;
  raw_data: Record<string, any>;
  tags: string[];
}

export interface ChainOfThoughtStep {
  step: number;
  thought: string;
  tool_called?: string;
  tool_input?: Record<string, any>;
  tool_output?: Record<string, any>;
  evidence_produced: Evidence[];
}

export interface Verdict {
  url: string;
  risk_score: number;          // 0-100
  prediction: VerdictLabel;
  confidence: number;          // 0-1
  latency_ms: number;
  evidence: Evidence[];
  chain_of_thought: ChainOfThoughtStep[];
  model_outputs: Record<string, ModelOutput>;
  pipeline_version: string;
  timestamp: string;
  errors?: string[];
  primary_reasons: string[];
  mitigating_factors: string[];
}

export interface ModelOutput {
  score: number;
  prediction: string;
  confidence: number;
  latency_ms: number;
  model_name: string;
  model_version: string;
  latent_vector?: number[];
}

// Settings
export interface Settings {
  autoScan: boolean;
  blockPhishing: boolean;
  showNotifications: boolean;
  enableAgentic: boolean;
  offlineMode: boolean;
}

// History
export interface HistoryEntry {
  url: string;
  verdict: VerdictLabel;
  risk_score: number;
  timestamp: number;
  source: string;
}

// Offscreen messages
export interface OffscreenScanRequest extends Message {
  type: 'OFFSCREEN_SCAN';
  payload: ScanRequest;
}

export interface OffscreenScanResponse extends Message {
  type: 'OFFSCREEN_SCAN_RESULT';
  verdict: Verdict;
  error?: string;
}