import { useState } from 'react';
import { Award, ShieldCheck, Calendar, Copy, Check, Code, Loader2, AlertTriangle } from 'lucide-react';
import { postJson } from '../../lib/api';

interface TrustSealResult {
  svg_markup: string;
  html_embed: string;
  expires_at: string;
  verification_url: string;
}

export default function TrustSealsTab() {
  const [domain, setDomain] = useState('');
  const [sealType, setSealType] = useState('certified');
  const [theme, setTheme] = useState('dark');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TrustSealResult | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;
    setLoading(true);
    setError('');
    setCopied(false);
    
    try {
      const data = await postJson<TrustSealResult>('/seals/generate', {
        domain,
        seal_type: sealType,
        theme,
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Seal generation failed');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    if (result) {
      navigator.clipboard.writeText(result.html_embed);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: 24 }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, fontSize: 20, color: '#e0e0e0' }}>
        <Award size={22} color="#EDC948" /> Dynamic Trust Seals
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        <div style={{ padding: 24, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
          <form onSubmit={handleGenerate} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, color: '#aaa', textTransform: 'uppercase', marginBottom: 8 }}>Target Domain</label>
              <input
                type="text"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                placeholder="example.com"
                required
                style={{
                  width: '100%', padding: '12px 16px', borderRadius: 10, border: '1px solid #2a2a4e',
                  background: '#0f0f1a', color: '#e0e0e0', fontSize: 14, outline: 'none', boxSizing: 'border-box'
                }}
              />
            </div>
            
            <div>
              <label style={{ display: 'block', fontSize: 12, color: '#aaa', textTransform: 'uppercase', marginBottom: 8 }}>Seal Type</label>
              <select
                value={sealType}
                onChange={e => setSealType(e.target.value)}
                style={{
                  width: '100%', padding: '12px 16px', borderRadius: 10, border: '1px solid #2a2a4e',
                  background: '#0f0f1a', color: '#e0e0e0', fontSize: 14, outline: 'none', boxSizing: 'border-box'
                }}
              >
                <option value="certified">TrustGuard Certified</option>
                <option value="pci_dss">PCI-DSS Compliant</option>
                <option value="malware_free">Malware-Free Verified</option>
                <option value="real_time_guard">Real-Time Guard</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, color: '#aaa', textTransform: 'uppercase', marginBottom: 8 }}>Visual Theme</label>
              <select
                value={theme}
                onChange={e => setTheme(e.target.value)}
                style={{
                  width: '100%', padding: '12px 16px', borderRadius: 10, border: '1px solid #2a2a4e',
                  background: '#0f0f1a', color: '#e0e0e0', fontSize: 14, outline: 'none', boxSizing: 'border-box'
                }}
              >
                <option value="dark">Dark Slate</option>
                <option value="light">Light Crisp</option>
                <option value="minimal">Minimal Transparent</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={loading || !domain}
              style={{
                marginTop: 8, padding: '14px 24px', borderRadius: 10, background: '#EDC948', color: '#0f0f1a',
                border: 'none', fontSize: 14, fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              }}
            >
              {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Award size={16} />}
              Generate Seal
            </button>
          </form>

          {error && (
            <div style={{ marginTop: 16, padding: 14, borderRadius: 10, background: 'rgba(225,87,89,0.12)', color: '#E15759', fontSize: 13 }}>
              <AlertTriangle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} /> {error}
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {result ? (
            <>
              <div style={{ padding: 24, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 120 }}>
                <div dangerouslySetInnerHTML={{ __html: result.svg_markup }} />
              </div>

              <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <h4 style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#aaa', textTransform: 'uppercase', margin: 0 }}>
                    <Code size={13} /> HTML Embed Code
                  </h4>
                  <button
                    onClick={copyToClipboard}
                    style={{
                      background: 'none', border: 'none', color: copied ? '#59A14F' : '#4E79A7',
                      fontSize: 12, fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                    }}
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <pre style={{ margin: 0, padding: 16, background: '#0f0f1a', borderRadius: 8, color: '#ccc', fontSize: 12, overflowX: 'auto', border: '1px solid #1f1f35' }}>
                  {result.html_embed}
                </pre>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderRadius: 10, background: 'rgba(89,161,79,0.1)', color: '#59A14F', fontSize: 13, border: '1px solid rgba(89,161,79,0.2)' }}>
                <Calendar size={16} /> Valid until {new Date(result.expires_at).toLocaleDateString()}
              </div>
            </>
          ) : (
            <div style={{ padding: 24, borderRadius: 14, background: '#1a1a2e', border: '1px dashed #3a3a5e', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 200, color: '#666', textAlign: 'center' }}>
              <ShieldCheck size={40} style={{ marginBottom: 16, opacity: 0.5 }} />
              <div style={{ fontSize: 14 }}>Configure settings and click Generate to see your dynamic trust seal preview and embed code.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
