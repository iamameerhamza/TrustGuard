import { useState } from 'react';
import { Globe, Shield, Search, Loader2, Clock, AlertTriangle, CheckCircle } from 'lucide-react';
import { postJson } from '../../lib/api';

interface WhoisData {
  domain_age_days?: number;
  risk_score?: number;
  risk_level?: string;
  reason?: string;
}

interface ScanResult {
  url: string;
  risk_score: number;
  risk_level: 'safe' | 'suspicious' | 'phishing';
  features: Record<string, number | string | boolean>;
  explanation: string;
  whois?: WhoisData;
  blacklist_match?: boolean;
  virustotal?: { malicious: number; total: number };
}

export default function UrlScannerTab() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await postJson<ScanResult>('/scan/', { url });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const riskColor = (level?: string) => {
    if (level === 'safe') return '#59A14F';
    if (level === 'suspicious') return '#F28E2B';
    return '#E15759';
  };

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: 24 }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, fontSize: 20, color: '#e0e0e0' }}>
        <Globe size={22} color="#4E79A7" /> URL & Domain Intelligence
      </h2>

      <form onSubmit={handleScan} style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
        <input
          type="url"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://suspicious-bank-login.tk"
          required
          style={{
            flex: 1, padding: '12px 16px', borderRadius: 10, border: '1px solid #2a2a4e',
            background: '#0f0f1a', color: '#e0e0e0', fontSize: 14, outline: 'none',
          }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{
            padding: '12px 24px', borderRadius: 10, background: '#4E79A7', color: '#fff',
            border: 'none', fontSize: 14, fontWeight: 600, cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 8, opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={16} />}
          Scan
        </button>
      </form>

      {error && (
        <div style={{ padding: 14, borderRadius: 10, background: 'rgba(225,87,89,0.12)', color: '#E15759', marginBottom: 20, fontSize: 13 }}>
          <AlertTriangle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
          {error}
        </div>
      )}

      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ padding: 24, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <span style={{ fontSize: 13, color: '#aaa', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Aggregate Risk</span>
              <span style={{
                padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 700, textTransform: 'uppercase',
                background: `${riskColor(result.risk_level)}22`, color: riskColor(result.risk_level),
              }}>
                {result.risk_level}
              </span>
            </div>
            <div style={{ height: 10, borderRadius: 5, background: '#0f0f1a', overflow: 'hidden' }}>
              <div style={{
                width: `${Math.min(result.risk_score, 100)}%`, height: '100%', borderRadius: 5,
                background: `linear-gradient(90deg, ${riskColor(result.risk_level)}, ${riskColor(result.risk_level)}88)`,
                transition: 'width 0.6s ease',
              }} />
            </div>
            <div style={{ marginTop: 8, fontSize: 13, color: '#666' }}>Score: {result.risk_score.toFixed(1)} / 100</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            {result.whois && (
              <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
                <h4 style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, color: '#aaa', fontSize: 11, textTransform: 'uppercase' }}>
                  <Clock size={13} /> WHOIS Age
                </h4>
                <div style={{ fontSize: 26, fontWeight: 800, color: '#e0e0e0' }}>
                  {result.whois.domain_age_days !== undefined ? `${result.whois.domain_age_days}d` : '—'}
                </div>
                <div style={{ fontSize: 12, color: '#666', marginTop: 6 }}>{result.whois.reason || result.whois.risk_level}</div>
              </div>
            )}

            {result.virustotal && (
              <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
                <h4 style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, color: '#aaa', fontSize: 11, textTransform: 'uppercase' }}>
                  <Shield size={13} /> VirusTotal
                </h4>
                <div style={{ fontSize: 26, fontWeight: 800, color: result.virustotal.malicious > 0 ? '#E15759' : '#59A14F' }}>
                  {result.virustotal.malicious}<span style={{ fontSize: 14, color: '#666' }}> / {result.virustotal.total}</span>
                </div>
                <div style={{ fontSize: 12, color: '#666', marginTop: 6 }}>Vendor detections</div>
              </div>
            )}

            <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, color: '#aaa', fontSize: 11, textTransform: 'uppercase' }}>
                <CheckCircle size={13} /> Verdict
              </h4>
              <p style={{ fontSize: 13, color: '#ccc', lineHeight: 1.6, margin: 0 }}>{result.explanation}</p>
            </div>
          </div>

          <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
            <h4 style={{ marginBottom: 12, color: '#aaa', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Extracted Features</h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 8 }}>
              {Object.entries(result.features).map(([k, v]) => (
                <div key={k} style={{ padding: '10px 12px', background: '#0f0f1a', borderRadius: 8, fontSize: 12, border: '1px solid #1f1f35' }}>
                  <span style={{ color: '#666' }}>{k}</span>
                  <div style={{ color: '#e0e0e0', fontWeight: 600, marginTop: 2, wordBreak: 'break-all' }}>{String(v)}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
