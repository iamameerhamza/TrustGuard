import { useState, useRef } from 'react';
import { FileText, Bug, Link2, ShieldAlert, ScrollText, Upload, Loader2, AlertTriangle, CheckCircle } from 'lucide-react';
import { postJson } from '../../lib/api';

interface DocumentScanResult {
  file_type: 'pdf' | 'docx' | 'xlsx' | 'pptx' | 'unknown';
  embedded_urls?: string[];
  external_links?: string[]; // The backend returns external_links instead of embedded_urls for some reason
  javascript_snippets?: string[];
  vba_macros?: string[];
  threats_found?: any[];
  risk_score: number;
  prediction?: string;
  is_malicious?: boolean;
  summary?: string;
}

export default function DocumentInspectorTab() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DocumentScanResult | null>(null);
  const [error, setError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const onFile = (f: File) => {
    setFile(f);
    setResult(null);
    setError('');
  };

  const handleScan = async () => {
    if (!file) return;
    setLoading(true);
    setError('');
    try {
      const reader = new FileReader();
      reader.onloadend = async () => {
        const b64 = (reader.result as string).split(',')[1];
        try {
          const data = await postJson<DocumentScanResult>('/scan/document/', {
            filename: file.name,
            content_base64: b64,
            mime_type: file.type || 'application/octet-stream'
          });
          setResult(data);
        } catch (err: any) {
          setError(err.message || 'Document analysis failed');
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

  const badge = (label: string, color: string) => (
    <span style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 600, background: `${color}22`, color, textTransform: 'uppercase' }}>
      {label}
    </span>
  );

  const isMalicious = result?.prediction === "malicious" || result?.is_malicious;
  const links = result?.external_links || result?.embedded_urls || [];
  const threats = result?.threats_found || [];

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: 24 }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, fontSize: 20, color: '#e0e0e0' }}>
        <FileText size={22} color="#E15759" /> Document Malware Inspector
      </h2>

      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) onFile(f); }}
        style={{
          border: '2px dashed #3a3a5e', borderRadius: 16, padding: '40px 24px', textAlign: 'center',
          cursor: 'pointer', background: '#1a1a2e',
        }}
      >
        <Upload size={36} color="#E15759" style={{ marginBottom: 12 }} />
        <div style={{ color: '#aaa', fontSize: 14 }}>Drop PDF, DOCX, XLSX, or PPTX</div>
        <input ref={inputRef} type="file" accept=".pdf,.docx,.xlsx,.pptx" hidden onChange={e => e.target.files?.[0] && onFile(e.target.files[0])} />
      </div>

      {file && (
        <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
          <ScrollText size={18} color="#aaa" />
          <span style={{ color: '#ccc', fontSize: 14 }}>{file.name}</span>
          <span style={{ color: '#666', fontSize: 12 }}>{(file.size / 1024).toFixed(1)} KB</span>
          <button
            onClick={handleScan}
            disabled={loading}
            style={{
              marginLeft: 'auto', padding: '10px 24px', borderRadius: 10, background: '#E15759', color: '#fff',
              border: 'none', fontSize: 14, fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Bug size={16} />}
            Inspect
          </button>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 16, padding: 14, borderRadius: 10, background: 'rgba(225,87,89,0.12)', color: '#E15759', fontSize: 13 }}>
          <AlertTriangle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} /> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <FileText size={20} color="#aaa" />
              <span style={{ color: '#e0e0e0', fontWeight: 600 }}>{file?.name}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {badge(result.file_type?.toUpperCase() || 'DOC', '#4E79A7')}
              {isMalicious ? badge('MALICIOUS', '#E15759') : badge('CLEAN', '#59A14F')}
            </div>
          </div>

          {result.summary && (
            <div style={{ padding: 16, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e', fontSize: 13, color: '#ccc' }}>
              {result.summary}
            </div>
          )}
          
          {threats.length > 0 && (
            <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #E1575944' }}>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#E15759', textTransform: 'uppercase', marginBottom: 10 }}>
                <ShieldAlert size={13} /> Threats Detected
              </h4>
              <ul style={{ margin: 0, paddingLeft: 18, color: '#ccc', fontSize: 13 }}>
                {threats.map((t, i) => (
                   <li key={i}>{t.description || t.type} <span style={{color: '#666'}}>({t.severity})</span></li>
                ))}
              </ul>
            </div>
          )}

          {links.length > 0 && (
            <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#aaa', textTransform: 'uppercase', marginBottom: 10 }}>
                <Link2 size={13} /> Embedded URLs ({links.length})
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {links.map((u, i) => (
                  <div key={i} style={{ fontSize: 12, color: '#ccc', wordBreak: 'break-all', padding: '6px 10px', background: '#0f0f1a', borderRadius: 6 }}>
                    {u}
                  </div>
                ))}
              </div>
            </div>
          )}

          {links.length === 0 && threats.length === 0 && (
            <div style={{ padding: 20, textAlign: 'center', color: '#59A14F', fontSize: 14 }}>
              <CheckCircle size={32} style={{ marginBottom: 8, display: 'inline-block' }} /><br />
              No suspicious content or links detected.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
