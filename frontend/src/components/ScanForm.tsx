import { useState } from 'react';
import { Shield, ShieldAlert, Search, AlertTriangle, Loader } from 'lucide-react';

interface ScanFormProps {
  url: string;
  setUrl: (url: string) => void;
  loading: boolean;
  error: string | null;
  setError: (error: string | null) => void;
  handleScan: () => Promise<void>;
  handleReport: (isPhishing: boolean) => Promise<void>;
  reporting: boolean;
  reportDone: boolean;
  reportComment: string;
  setReportComment: (comment: string) => void;
}

const ScanForm = ({
  url,
  setUrl,
  loading,
  error,
  setError,
  handleScan,
  handleReport,
  reporting,
  reportDone,
  reportComment,
  setReportComment,
}: ScanFormProps) => {

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await handleScan();
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="search-container">
        <input type="text" className="search-input"
          placeholder="Enter a URL to analyze (e.g., https://example.com)"
          value={url} onChange={e => setUrl(e.target.value)} disabled={loading} />
        <button type="submit" className="btn" disabled={loading || !url}>
          {loading ? <><div className="loader"/>Scanning…</> : <><Shield size={20}/>Analyze</>}
        </button>
      </form>

      {error && (
        <div className="card" style={{borderLeft:'4px solid var(--accent-red)'}}>
          <div style={{display:'flex',alignItems:'center',gap:'1rem',color:'var(--accent-red)'}}>
            <AlertTriangle size={24}/><p style={{color:'var(--text-primary)'}}>{error}</p>
          </div>
        </div>
      )}

      {/* Report section would go here if we had result */}
    </>
  );
};

export default ScanForm;