import { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Search, ShieldCheck, Clock, Activity, AlertTriangle, Flag, BarChart2 } from 'lucide-react';

interface ScanResult {
  url: string;
  domain: string;
  risk_score: number;
  prediction: string;
  ml_score: number | null;
  ml_prediction: string | null;
  vt_score: number | null;
  blacklisted: boolean;
  reasons: string[];
  whois: { age_days: any; score: any; label: any; reason: any } | null;
}

interface HistoryItem {
  id: number;
  url: string;
  risk_score: number;
  prediction: string;
  ml_score: number | null;
  ml_prediction: string | null;
  vt_score: number | null;
  blacklisted: boolean;
  timestamp: string;
}

const API_BASE = import.meta.env.VITE_API_BASE || '';
const API_KEY = import.meta.env.VITE_API_KEY || '';
const authHeaders: Record<string, string> = API_KEY ? { 'X-API-Key': API_KEY } : {};

function riskClass(score: number) {
  if (score < 30) return 'score-safe';
  if (score < 70) return 'score-medium';
  return 'score-high';
}

function predBadge(pred: string | null, blacklisted?: boolean) {
  if (blacklisted) return <span className="badge badge-danger"><ShieldAlert size={12} style={{display:'inline',marginRight:3}}/>Blacklisted</span>;
  if (!pred) return null;
  const cls = pred === 'phishing' ? 'badge-danger' : pred === 'suspicious' ? 'badge-warn' : 'badge-safe';
  return <span className={`badge ${cls}`}>{pred}</span>;
}

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [activeTab, setActiveTab] = useState<'scan' | 'history' | 'dashboard'>('scan');
  const [error, setError] = useState<string | null>(null);
  const [reporting, setReporting] = useState(false);
  const [reportDone, setReportDone] = useState(false);
  const [reportComment, setReportComment] = useState('');

  useEffect(() => { fetchHistory(); }, [activeTab]);

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/history?limit=100`, { headers: authHeaders });
      if (res.ok) setHistory(await res.json());
    } catch {}
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    setLoading(true); setError(null); setResult(null); setReportDone(false);
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ url })
      });
      if (!res.ok) throw new Error(`API error: ${res.statusText}`);
      setResult(await res.json());
      fetchHistory();
    } catch (e: any) {
      setError(e.message || 'Failed to scan URL');
    } finally {
      setLoading(false);
    }
  };

  const handleReport = async (isPhishing: boolean) => {
    if (!result) return;
    setReporting(true);
    try {
      await fetch(`${API_BASE}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ url: result.url, is_phishing: isPhishing, comments: reportComment || null })
      });
      setReportDone(true);
    } finally {
      setReporting(false);
    }
  };

  // Dashboard stats
  const total = history.length;
  const phishing = history.filter(h => h.prediction === 'phishing' || h.blacklisted).length;
  const suspicious = history.filter(h => h.prediction === 'suspicious' && !h.blacklisted).length;
  const safe = history.filter(h => h.prediction === 'safe' && !h.blacklisted).length;
  const avgScore = total ? Math.round(history.reduce((a, h) => a + h.risk_score, 0) / total) : 0;

  return (
    <div className="container">
      <h1>TrustGuard</h1>
      <p style={{ textAlign: 'center', marginBottom: '2rem', fontFamily: 'Space Grotesk', fontSize: '1.1rem', letterSpacing: '0.5px' }}>
        ML-powered phishing &amp; threat detection
      </p>

      <div className="tabs">
        {([['scan','Scan URL',<Search size={16}/>],['history','History',<Clock size={16}/>],['dashboard','Dashboard',<BarChart2 size={16}/>]] as const).map(([id,label,icon]) => (
          <button key={id} className={`tab ${activeTab === id ? 'active' : ''}`} onClick={() => setActiveTab(id as any)}>
            <span style={{display:'inline',marginRight:6,verticalAlign:'text-bottom'}}>{icon}</span>{label}
          </button>
        ))}
      </div>

      {/* ── SCAN TAB ── */}
      {activeTab === 'scan' && (
        <>
          <form onSubmit={handleScan} className="search-container">
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

          {result && (
            <div className="card">
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:'1.5rem',flexWrap:'wrap',gap:'1rem'}}>
                <div>
                  <h2 style={{marginBottom:'0.3rem'}}>Analysis Complete</h2>
                  <p style={{wordBreak:'break-all'}}>{result.url}</p>
                </div>
                <div style={{display:'flex',gap:'0.5rem',flexWrap:'wrap'}}>
                  {predBadge(result.prediction, result.blacklisted)}
                </div>
              </div>

              {/* Risk ring */}
              <div className="risk-meter">
                <svg viewBox="0 0 36 36" className={`circular-chart ${riskClass(result.risk_score)}`}>
                  <path className="circle-bg" d="M18 2.0845 a15.9155 15.9155 0 0 1 0 31.831 a15.9155 15.9155 0 0 1 0-31.831"/>
                  <path className="circle" strokeDasharray={`${result.risk_score},100`}
                    d="M18 2.0845 a15.9155 15.9155 0 0 1 0 31.831 a15.9155 15.9155 0 0 1 0-31.831"/>
                  <text x="18" y="20.35" className="percentage">{result.risk_score}</text>
                </svg>
                <span className="score-label">Risk Score / 100</span>
              </div>

              {/* Detection grid */}
              <div className="results-grid">
                <div className="card inner-card">
                  <h3 style={{color:'var(--accent-cyan)',display:'flex',alignItems:'center',gap:'0.5rem',marginBottom:'1rem'}}>
                    <Activity size={18}/>Detection Engines
                  </h3>
                  <div className="detail-rows">
                    <div className="detail-row"><span>Rule-based</span><span style={{color: result.prediction==='phishing'?'var(--accent-red)':result.prediction==='suspicious'?'var(--accent-yellow)':'var(--accent-green)',textTransform:'capitalize'}}>{result.prediction}</span></div>
                    <div className="detail-row"><span>ML Model</span><span style={{color: result.ml_prediction==='phishing'?'var(--accent-red)':result.ml_prediction==='suspicious'?'var(--accent-yellow)':'var(--accent-green)',textTransform:'capitalize'}}>{result.ml_prediction ?? 'N/A'}</span></div>
                    {result.ml_score !== null && <div className="detail-row"><span>ML Confidence</span><span>{(result.ml_score*100).toFixed(1)}%</span></div>}
                    {result.vt_score !== null && <div className="detail-row"><span>VirusTotal</span><span style={{color: result.vt_score>0?'var(--accent-red)':'var(--accent-green)'}}>{result.vt_score > 0 ? `${result.vt_score} engines flagged` : 'Clean'}</span></div>}
                  </div>
                </div>

                <div className="card inner-card">
                  <h3 style={{color:'var(--accent-magenta)',display:'flex',alignItems:'center',gap:'0.5rem',marginBottom:'1rem'}}>
                    <ShieldCheck size={18}/>Risk Factors
                  </h3>
                  {result.reasons.length > 0 ? (
                    <ul className="results-reasons" style={{listStyle:'none'}}>
                      {result.reasons.map((r,i) => <li key={i}>{r}</li>)}
                    </ul>
                  ) : <p>No specific risk factors detected.</p>}
                </div>

                {result.whois && (
                  <div className="card inner-card">
                    <h3 style={{color:'var(--accent-purple)',display:'flex',alignItems:'center',gap:'0.5rem',marginBottom:'1rem'}}>
                      <Clock size={18}/>WHOIS
                    </h3>
                    <div className="detail-rows">
                      {result.whois.age_days !== null && <div className="detail-row"><span>Domain Age</span><span>{result.whois.age_days} days</span></div>}
                      <div className="detail-row"><span>Trust Label</span><span style={{textTransform:'capitalize',color: result.whois.label==='new'?'var(--accent-red)':'var(--accent-green)'}}>{result.whois.label ?? 'N/A'}</span></div>
                      {result.whois.reason && <div className="detail-row"><span>Reason</span><span>{result.whois.reason}</span></div>}
                    </div>
                  </div>
                )}

                <div className="card inner-card">
                  <h3 style={{color:'var(--accent-yellow)',display:'flex',alignItems:'center',gap:'0.5rem',marginBottom:'1rem'}}>
                    <Flag size={18}/>Report This URL
                  </h3>
                  {reportDone ? (
                    <p style={{color:'var(--accent-green)'}}>✓ Report submitted. Thank you!</p>
                  ) : (
                    <>
                      <input type="text" className="search-input" style={{fontSize:'0.95rem',padding:'0.7rem 1rem',marginBottom:'0.8rem'}}
                        placeholder="Optional comment…" value={reportComment} onChange={e=>setReportComment(e.target.value)}/>
                      <div style={{display:'flex',gap:'0.8rem'}}>
                        <button className="btn btn-sm btn-danger" disabled={reporting} onClick={()=>handleReport(true)}>Phishing</button>
                        <button className="btn btn-sm btn-safe" disabled={reporting} onClick={()=>handleReport(false)}>Legitimate</button>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── HISTORY TAB ── */}
      {activeTab === 'history' && (
        <div className="card">
          <h2 style={{display:'flex',alignItems:'center',gap:'0.5rem',marginBottom:'1.5rem'}}>
            <Clock size={22} color="var(--accent-cyan)"/>Recent Scans
          </h2>
          <div style={{overflowX:'auto'}}>
            <table className="history-table">
              <thead><tr><th>Time</th><th>URL</th><th>Score</th><th>ML</th><th>VT</th><th>Status</th></tr></thead>
              <tbody>
                {history.map(item => (
                  <tr key={item.id}>
                    <td style={{color:'var(--text-secondary)',whiteSpace:'nowrap'}}>{new Date(item.timestamp).toLocaleString()}</td>
                    <td style={{maxWidth:260,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{item.url}</td>
                    <td><span className={`badge ${item.risk_score<30?'badge-safe':item.risk_score<70?'badge-warn':'badge-danger'}`}>{item.risk_score}</span></td>
                    <td style={{color:item.ml_prediction==='phishing'?'var(--accent-red)':item.ml_prediction==='suspicious'?'var(--accent-yellow)':'var(--accent-green)',textTransform:'capitalize'}}>{item.ml_prediction??'—'}</td>
                    <td style={{color:item.vt_score&&item.vt_score>0?'var(--accent-red)':'var(--accent-green)'}}>{item.vt_score!==null?(item.vt_score>0?`${item.vt_score} flagged`:'Clean'):'—'}</td>
                    <td>{predBadge(item.prediction, item.blacklisted)}</td>
                  </tr>
                ))}
                {history.length === 0 && (
                  <tr><td colSpan={6} style={{textAlign:'center',padding:'2rem',color:'var(--text-secondary)'}}>No history yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── DASHBOARD TAB ── */}
      {activeTab === 'dashboard' && (
        <>
          <div className="stats-grid">
            {[
              {label:'Total Scans',value:total,color:'var(--accent-cyan)'},
              {label:'Phishing / Blacklisted',value:phishing,color:'var(--accent-red)'},
              {label:'Suspicious',value:suspicious,color:'var(--accent-yellow)'},
              {label:'Safe',value:safe,color:'var(--accent-green)'},
              {label:'Avg Risk Score',value:avgScore,color:'var(--text-primary)'},
            ].map(s => (
              <div key={s.label} className="card stat-card">
                <div className="stat-value" style={{color:s.color}}>{s.value}</div>
                <div className="stat-label">{s.label}</div>
              </div>
            ))}
          </div>

          <div className="card" style={{marginTop:'2rem'}}>
            <h2 style={{marginBottom:'1.5rem',display:'flex',alignItems:'center',gap:'0.5rem'}}>
              <BarChart2 size={22} color="var(--accent-cyan)"/>Threat Breakdown
            </h2>
            {total === 0 ? <p>No scan data yet. Run some scans first.</p> : (
              <div style={{display:'flex',flexDirection:'column',gap:'1rem'}}>
                {[
                  {label:'Phishing / Blacklisted',count:phishing,color:'var(--accent-red)'},
                  {label:'Suspicious',count:suspicious,color:'var(--accent-yellow)'},
                  {label:'Safe',count:safe,color:'var(--accent-green)'},
                ].map(b => (
                  <div key={b.label}>
                    <div style={{display:'flex',justifyContent:'space-between',marginBottom:'0.4rem'}}>
                      <span style={{color:'var(--text-secondary)',fontSize:'0.9rem'}}>{b.label}</span>
                      <span style={{color:b.color,fontFamily:'Space Grotesk',fontWeight:600}}>{b.count} ({total?Math.round(b.count/total*100):0}%)</span>
                    </div>
                    <div style={{background:'rgba(255,255,255,0.05)',borderRadius:6,height:10,overflow:'hidden'}}>
                      <div style={{width:`${total?b.count/total*100:0}%`,height:'100%',background:b.color,borderRadius:6,transition:'width 0.8s ease',boxShadow:`0 0 8px ${b.color}`}}/>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card" style={{marginTop:'2rem'}}>
            <h2 style={{marginBottom:'1.5rem',display:'flex',alignItems:'center',gap:'0.5rem'}}>
              <Clock size={22} color="var(--accent-cyan)"/>Latest 5 Scans
            </h2>
            <div style={{overflowX:'auto'}}>
              <table className="history-table">
                <thead><tr><th>Time</th><th>URL</th><th>Score</th><th>Status</th></tr></thead>
                <tbody>
                  {history.slice(0,5).map(item => (
                    <tr key={item.id}>
                      <td style={{color:'var(--text-secondary)',whiteSpace:'nowrap'}}>{new Date(item.timestamp).toLocaleString()}</td>
                      <td style={{maxWidth:300,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{item.url}</td>
                      <td><span className={`badge ${item.risk_score<30?'badge-safe':item.risk_score<70?'badge-warn':'badge-danger'}`}>{item.risk_score}</span></td>
                      <td>{predBadge(item.prediction, item.blacklisted)}</td>
                    </tr>
                  ))}
                  {history.length===0&&<tr><td colSpan={4} style={{textAlign:'center',padding:'2rem',color:'var(--text-secondary)'}}>No data.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default App;
