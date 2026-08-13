import { useState, useRef } from 'react';
import { Eye, Fingerprint, Camera, AlertTriangle, Loader2, CheckCircle } from 'lucide-react';
import { postJson } from '../../lib/api';

interface VisualMatch {
  brand: string;
  hamming_distance: number;
  threshold: number;
  is_match: boolean;
}

interface VisualScanResult {
  phash_signature?: string;
  phash?: string;
  matches?: VisualMatch[];
  matched_brand?: string;
  similarity_score?: number;
  is_spoof: boolean;
  closest_brand?: string;
  confidence?: number;
}

export default function VisualInspectorTab() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VisualScanResult | null>(null);
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
      const reader = new FileReader();
      reader.onloadend = async () => {
        const b64 = reader.result as string;
        try {
          const data = await postJson<VisualScanResult>('/scan/visual/', { image_base64: b64 });
          setResult(data);
        } catch (err: any) {
          setError(err.message || 'Visual analysis failed');
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
        <Eye size={22} color="#B07AA1" /> Visual Impersonation & pHash Inspector
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
        <Camera size={36} color="#B07AA1" style={{ marginBottom: 12 }} />
        <div style={{ color: '#aaa', fontSize: 14 }}>Upload a screenshot to compare against brand references</div>
        <input ref={inputRef} type="file" accept="image/*" hidden onChange={e => e.target.files?.[0] && onFile(e.target.files[0])} />
      </div>

      {preview && (
        <div style={{ marginTop: 20, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <img src={preview} alt="Screenshot" style={{ maxHeight: 200, borderRadius: 10, border: '1px solid #2a2a4e' }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <button
              onClick={handleScan}
              disabled={loading}
              style={{
                padding: '12px 28px', borderRadius: 10, background: '#B07AA1', color: '#fff',
                border: 'none', fontSize: 14, fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
              }}
            >
              {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Fingerprint size={16} />}
              Compute pHash
            </button>
          </div>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 16, padding: 14, borderRadius: 10, background: 'rgba(225,87,89,0.12)', color: '#E15759', fontSize: 13 }}>
          <AlertTriangle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} /> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
            <div style={{ padding: 20, borderRadius: 14, background: '#1a1a2e', border: '1px solid #2a2a4e' }}>
              <h4 style={{ fontSize: 11, color: '#aaa', textTransform: 'uppercase', marginBottom: 8 }}>64-bit pHash</h4>
              <div style={{ fontFamily: 'monospace', fontSize: 13, color: '#e0e0e0', wordBreak: 'break-all' }}>{result.phash_signature || result.phash || 'N/A'}</div>
            </div>

            <div style={{
              padding: 20, borderRadius: 14, border: '1px solid',
              borderColor: result.is_spoof ? '#E15759' : '#59A14F',
              background: result.is_spoof ? 'rgba(225,87,89,0.08)' : 'rgba(89,161,79,0.08)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {result.is_spoof ? <AlertTriangle size={20} color="#E15759" /> : <CheckCircle size={20} color="#59A14F" />}
                <span style={{ fontSize: 16, fontWeight: 700, color: result.is_spoof ? '#E15759' : '#59A14F' }}>
                  {result.is_spoof ? 'Spoofing Detected' : 'No Spoofing Detected'}
                </span>
              </div>
              {(result.matched_brand || result.closest_brand) && (
                <div style={{ marginTop: 8, fontSize: 13, color: '#ccc' }}>
                  Closest match: <strong>{result.matched_brand || result.closest_brand}</strong>
                  {result.similarity_score !== undefined && ` (${(result.similarity_score * 100).toFixed(1)}% similarity)`}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
