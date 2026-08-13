import { useState, useRef } from 'react';
import { QrCode, Upload, Link2, AlertOctagon, ChevronRight, CheckCircle, Loader2 } from 'lucide-react';
import { postJson } from '../../lib/api';

interface RedirectHop {
  url: string;
  status_code?: number;
  is_safe?: boolean;
}

interface QrScanResult {
  success: boolean;
  decoded_data?: string;
  decoded_url?: string;
  redirect_chain?: RedirectHop[];
  final_url?: string;
  safety?: {
    is_safe: boolean;
    threats: string[];
    risk_score: number;
  };
  error?: string;
}

export default function QrScannerTab() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QrScanResult | null>(null);
  const [error, setError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const onFile = (f: File) => {
    setFile(f);
    setPreview(URL.createObjectURL(f));
    setResult(null);
    setError('');
  };

  const handleScan = async () => {
    if (!file) return;
    setLoading(true);
    setError('');
    
    try {
      // The backend takes base64 JSON, so let's convert the file
      const reader = new FileReader();
      reader.onloadend = async () => {
        const b64 = reader.result as string;
        try {
          const data = await postJson<any>('/scan/qr/', { image_base64: b64 });
          // Map backend schema to UI state
          setResult({
            success: true,
            decoded_url: data.decoded_url,
            redirect_chain: data.redirect_chain?.map((u: string) => ({ url: u })),
            safety: data.safety_report ? {
              is_safe: !data.is_malicious,
              risk_score: data.risk_score,
              threats: data.safety_report.prediction === "phishing" ? ["Phishing signature matched"] : []
            } : undefined
          });
        } catch (err: any) {
          setError(err.message || 'QR analysis failed');
        } finally {
          setLoading(false);
        }
      };
      reader.readAsDataURL(file);
    } catch (err: any) {
      setError('File read failed');
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: 24 }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, fontSize: 20, color: '#e0e0e0' }}>
        <QrCode size={22} color="#F28E2B" /> QR Code Threat Decoder
      </h2>

      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); }}
        onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) onFile(f); }}
        style={{
          border: '2px dashed #3a3a5e', borderRadius: 16, padding: '40px 24px', textAlign: 'center',
          cursor: 'pointer', background: '#1a1a2e', transition: 'border-color 0.2s',
        }}
      >
        <Upload size={36} color="#4E79A7" style={{ marginBottom: 12 }} />
        <div style={{ color: '#aaa', fontSize: 14 }}>Click or drop a QR image here</div>
        <input ref={inputRef} type="file" accept="image/*" hidden onChange={e => e.target.files?.[0] && onFile(e.target.files[0])} />
      </div>

      {preview && (
        <div style={{ marginTop: 20, display: 'flex', gap: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}>
          <img src={preview} alt="QR preview" style={{ maxHeight: 180, borderRadius: 10, border: '1px solid #2a2a4e' }} />
          <button
            onClick={handleScan}
            disabled={loading}
            style={{
              padding: '12px 28px', borderRadius: 10, background: '#F28E2B', color: '#fff',
              border: 'none', fontSize: 14, fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <QrCode size={16} />}
            Decode & Analyze
          </button>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 16, padding: 14, borderRadius: 10, background: 'rgba(225,87,89,0.12)', color: '#E15759', fontSize: 13 }}>
          <AlertOctagon size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} /> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
            <h4 style={{ fontSize: 11, color: '#aaa', textTransform: 'uppercase', marginBottom: 10 }}>Decoded Payload</h4>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: '#e0e0e0', wordBreak: 'break-all' }}>
              <Link2 size={14} color="#4E79A7" />
              {result.decoded_url || result.decoded_data || '—'}
            </div>
          </div>

          {result.redirect_chain && result.redirect_chain.length > 0 && (
            <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
              <h4 style={{ fontSize: 11, color: '#aaa', textTransform: 'uppercase', marginBottom: 12 }}>Redirect Chain</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.redirect_chain.map((hop, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13 }}>
                    <ChevronRight size={14} color="#666" />
                    <span style={{ color: '#ccc', wordBreak: 'break-all', flex: 1 }}>{hop.url}</span>
                    {hop.status_code && <span style={{ color: '#666', fontSize: 11 }}>{hop.status_code}</span>}
                    {hop.is_safe === false && <AlertOctagon size={14} color="#E15759" />}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.safety && (
            <div style={{
              padding: 20, borderRadius: 14, border: '1px solid',
              borderColor: result.safety.is_safe ? '#59A14F' : '#E15759',
              background: result.safety.is_safe ? 'rgba(89,161,79,0.08)' : 'rgba(225,87,89,0.08)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                {result.safety.is_safe ? <CheckCircle size={20} color="#59A14F" /> : <AlertOctagon size={20} color="#E15759" />}
                <span style={{ fontSize: 16, fontWeight: 700, color: result.safety.is_safe ? '#59A14F' : '#E15759' }}>
                  {result.safety.is_safe ? 'Target appears safe' : 'Threats detected in destination'}
                </span>
              </div>
              {result.safety.threats.length > 0 && (
                <ul style={{ margin: '8px 0 0 0', paddingLeft: 18, color: '#ccc', fontSize: 13 }}>
                  {result.safety.threats.map((t, i) => <li key={i}>{t}</li>)}
                </ul>
              )}
              <div style={{ marginTop: 10, fontSize: 12, color: '#666' }}>Risk score: {result.safety.risk_score}/100</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
