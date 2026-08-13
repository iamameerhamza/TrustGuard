import { useState } from 'react';
import { Bot, CreditCard, KeyRound, BrainCircuit, ShieldCheck, AlertTriangle, Loader2, Clock, Search } from 'lucide-react';
import { postJson } from '../../lib/api';

type GuardTab = 'pii' | 'prompt';

interface PiiFinding {
  type: 'credit_card' | 'ssn' | 'api_key' | 'email' | 'phone' | 'password';
  value?: string;
  snippet?: string;
  redacted?: string;
  position: number;
  confidence?: number;
}

interface PromptGuardResult {
  injection_detected?: boolean;
  detected?: boolean;
  injection_type?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number;
  matched_patterns?: string[];
  matches?: any[];
}

interface AgenticScanResult {
  pii_findings: PiiFinding[];
  prompt_guard?: PromptGuardResult;
  prompt_injection_detected?: boolean;
  injection_confidence?: number;
  risk_level?: 'low' | 'medium' | 'high' | 'critical';
  risk_score?: number;
  scan_duration_ms?: number;
  sanitized_text?: string;
}

const PII_ICONS: Record<string, React.ReactNode> = {
  credit_card: <CreditCard size={14} />,
  api_key: <KeyRound size={14} />,
  ssn: <ShieldCheck size={14} />,
  email: <Bot size={14} />,
  phone: <Bot size={14} />,
  password: <KeyRound size={14} />,
};

const SEVERITY_COLOR: Record<string, string> = {
  low: '#59A14F',
  medium: '#F28E2B',
  high: '#E15759',
  critical: '#E15759',
};

export default function AgenticGuardTab() {
  const [content, setContent] = useState('');
  const [activeTab, setActiveTab] = useState<GuardTab>('pii');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AgenticScanResult | null>(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!content.trim()) return;
    setLoading(true);
    setError('');
    try {
      const data = await postJson<AgenticScanResult>('/scan/agentic/', {
        text: content,
        scan_type: 'full',
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Agentic scan failed');
    } finally {
      setLoading(false);
    }
  };

  const riskLevel = result?.risk_score !== undefined
    ? result.risk_score > 70 ? 'high' : result.risk_score > 30 ? 'medium' : 'low'
    : result?.risk_level || 'low';

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: 24 }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, fontSize: 20, color: '#e0e0e0' }}>
        <BrainCircuit size={22} color="#76B7B2" /> Agentic Investigation & PII Guard
      </h2>

      <div style={{ marginBottom: 16 }}>
        <textarea
          value={content}
          onChange={e => setContent(e.target.value)}
          placeholder="Paste prompt, document text, or chat log here..."
          rows={6}
          style={{
            width: '100%', padding: 16, borderRadius: 12, border: '1px solid #2a2a4e',
            background: '#0f0f1a', color: '#e0e0e0', fontSize: 14, resize: 'vertical', outline: 'none',
            fontFamily: 'inherit',
          }}
        />
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div style={{ fontSize: 12, color: '#666' }}>{content.length} characters</div>
        <button
          onClick={handleScan}
          disabled={loading || !content.trim()}
          style={{
            padding: '12px 28px', borderRadius: 10, background: '#76B7B2', color: '#0f0f1a',
            border: 'none', fontSize: 14, fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
          }}
        >
          {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={16} />}
          Investigate
        </button>
      </div>

      {error && (
        <div style={{ padding: 14, borderRadius: 10, background: 'rgba(225,87,89,0.12)', color: '#E15759', marginBottom: 20, fontSize: 13 }}>
          <AlertTriangle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} /> {error}
        </div>
      )}

      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{
            padding: '16px 20px', borderRadius: 14, border: '1px solid',
            borderColor: SEVERITY_COLOR[riskLevel],
            background: `${SEVERITY_COLOR[riskLevel]}11`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <ShieldCheck size={20} color={SEVERITY_COLOR[riskLevel]} />
              <span style={{ fontWeight: 700, color: SEVERITY_COLOR[riskLevel], textTransform: 'uppercase' }}>
                {riskLevel} Risk (Score: {result.risk_score || 0})
              </span>
            </div>
            {result.scan_duration_ms && (
              <span style={{ fontSize: 12, color: '#666', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Clock size={12} /> {result.scan_duration_ms}ms
              </span>
            )}
          </div>

          <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid #2a2a4e', paddingBottom: 1 }}>
            {(['pii', 'prompt'] as GuardTab[]).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  padding: '10px 20px', borderRadius: '8px 8px 0 0', border: 'none', fontSize: 13, fontWeight: 600,
                  cursor: 'pointer', background: activeTab === tab ? '#1a1a2e' : 'transparent',
                  color: activeTab === tab ? '#e0e0e0' : '#666', borderBottom: activeTab === tab ? '2px solid #76B7B2' : '2px solid transparent',
                }}
              >
                {tab === 'pii' ? `PII Findings (${result.pii_findings.length})` : 'Prompt Injection'}
              </button>
            ))}
          </div>

          <div style={{ padding: 20, borderRadius: '0 0 14px 14px', background: '#1a1a2e', minHeight: 200 }}>
            {activeTab === 'pii' && (
              <div>
                {result.pii_findings.length === 0 ? (
                  <div style={{ color: '#aaa', fontSize: 14, textAlign: 'center', marginTop: 40 }}>No PII detected in payload.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {result.pii_findings.map((finding, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 12, background: '#0f0f1a', borderRadius: 8 }}>
                        <div style={{ color: '#76B7B2', padding: 8, background: 'rgba(118,183,178,0.1)', borderRadius: 6 }}>
                          {PII_ICONS[finding.type] || <ShieldCheck size={14} />}
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 11, color: '#aaa', textTransform: 'uppercase', marginBottom: 4 }}>{finding.type}</div>
                          <div style={{ fontSize: 14, color: '#e0e0e0', fontFamily: 'monospace' }}>
                            {finding.redacted || finding.value || finding.snippet}
                          </div>
                        </div>
                        <div style={{ fontSize: 12, color: '#666' }}>pos: {finding.position}</div>
                      </div>
                    ))}
                  </div>
                )}
                {result.sanitized_text && (
                  <div style={{ marginTop: 20 }}>
                    <h4 style={{ fontSize: 11, color: '#aaa', textTransform: 'uppercase', marginBottom: 10 }}>Sanitized Output</h4>
                    <pre style={{ margin: 0, padding: 12, background: '#0f0f1a', borderRadius: 8, color: '#ccc', fontSize: 12, whiteSpace: 'pre-wrap' }}>
                      {result.sanitized_text}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'prompt' && (
              <div>
                {(result.prompt_injection_detected || result.prompt_guard?.detected) ? (
                  <div style={{ color: '#E15759', display: 'flex', alignItems: 'center', gap: 10, fontSize: 14, fontWeight: 600 }}>
                    <AlertTriangle size={18} /> Prompt Injection Attempt Detected
                    <span style={{ fontSize: 12, color: '#aaa', fontWeight: 400, marginLeft: 'auto' }}>
                      Confidence: {((result.injection_confidence || result.prompt_guard?.confidence || 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                ) : (
                  <div style={{ color: '#59A14F', display: 'flex', alignItems: 'center', gap: 10, fontSize: 14, fontWeight: 600, justifyContent: 'center', marginTop: 40 }}>
                    <ShieldCheck size={24} /> No Prompt Injection Detected
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
