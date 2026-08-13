import { useState, useEffect } from 'react';
import './App.css';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend
} from 'recharts';
import {
  Search,
  QrCode,
  FileText,
  Eye,
  Cpu,
  Award,
  Clock,
  BarChart2,
  ShieldCheck,
  Activity,
  Lock
} from 'lucide-react';

import UrlScannerTab from './components/tabs/UrlScannerTab';
import QrScannerTab from './components/tabs/QrScannerTab';
import DocumentInspectorTab from './components/tabs/DocumentInspectorTab';
import VisualInspectorTab from './components/tabs/VisualInspectorTab';
import AgenticGuardTab from './components/tabs/AgenticGuardTab';
import TrustSealsTab from './components/tabs/TrustSealsTab';

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

export function App() {
  const [activeTab, setActiveTab] = useState<'url' | 'qr' | 'doc' | 'visual' | 'agentic' | 'seals' | 'history' | 'dashboard'>('url');
  const [history, setHistory] = useState<HistoryItem[]>([]);

  useEffect(() => {
    fetchHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/history?limit=100`, { headers: authHeaders });
      if (res.ok) setHistory(await res.json());
    } catch {
      // Ignore initial network load errors
    }
  };

  // Dashboard calculations
  const totalScans = history.length;
  const phishingCount = history.filter(h => h.prediction === 'phishing' || h.blacklisted).length;
  const suspiciousCount = history.filter(h => h.prediction === 'suspicious' && !h.blacklisted).length;
  const safeCount = history.filter(h => h.prediction === 'safe' && !h.blacklisted).length;
  const avgRiskScore = totalScans ? Math.round(history.reduce((a, h) => a + h.risk_score, 0) / totalScans) : 0;

  const pieData = [
    { name: 'Safe', value: safeCount, color: '#10b981' },
    { name: 'Suspicious', value: suspiciousCount, color: '#f59e0b' },
    { name: 'Phishing', value: phishingCount, color: '#ef4444' }
  ].filter(d => d.value > 0);

  const barData = history.slice(0, 10).map((h, i) => ({
    name: `Scan ${totalScans - i}`,
    Risk: h.risk_score
  })).reverse();

  return (
    <div className="platform-layout">
      {/* ── PLATFORM HEADER ── */}
      <header className="platform-header">
        <div className="header-brand">
          <div className="logo-icon">
            <ShieldCheck size={32} />
          </div>
          <div>
            <h1 className="brand-title">TRUSTGUARD</h1>
            <p className="brand-subtitle">Multi-Modal Internet Trust &amp; Cyber Threat Platform</p>
          </div>
        </div>

        <div className="header-status">
          <div className="status-item">
            <Activity size={16} className="icon-pulse" />
            <span>AI Models: <strong>Active (v2.0)</strong></span>
          </div>
          <div className="status-item">
            <Lock size={16} />
            <span>PQC &amp; Differential Privacy: <strong>Enabled</strong></span>
          </div>
        </div>
      </header>

      {/* ── NAVIGATION TABS ── */}
      <nav className="platform-nav">
        {[
          ['url', 'URL Scanner', <Search size={16} key="url" />],
          ['qr', 'QR Code Decoder', <QrCode size={16} key="qr" />],
          ['doc', 'Document Malware', <FileText size={16} key="doc" />],
          ['visual', 'Visual Impersonation', <Eye size={16} key="visual" />],
          ['agentic', 'Agentic PII Guard', <Cpu size={16} key="agentic" />],
          ['seals', 'Trust Seals &amp; Audit', <Award size={16} key="seals" />],
          ['history', 'Audit History', <Clock size={16} key="hist" />],
          ['dashboard', 'Analytics Radar', <BarChart2 size={16} key="dash" />],
        ].map(([id, label, icon]) => (
          <button
            key={id as string}
            className={`nav-tab ${activeTab === id ? 'active' : ''}`}
            onClick={() => setActiveTab(id as any)}
          >
            <span className="tab-icon">{icon}</span>
            <span className="tab-label">{label}</span>
          </button>
        ))}
      </nav>

      {/* ── TAB CONTENT ── */}
      <main className="platform-body">
        {activeTab === 'url' && <UrlScannerTab />}
        {activeTab === 'qr' && <QrScannerTab />}
        {activeTab === 'doc' && <DocumentInspectorTab />}
        {activeTab === 'visual' && <VisualInspectorTab />}
        {activeTab === 'agentic' && <AgenticGuardTab />}
        {activeTab === 'seals' && <TrustSealsTab />}

        {/* ── HISTORY TAB ── */}
        {activeTab === 'history' && (
          <div className="tab-container">
            <div className="tab-header">
              <h2>📜 Threat Audit History Log</h2>
              <p>Historical log of analyzed targets, threat predictions, and VirusTotal matches.</p>
            </div>

            <div className="card">
              {history.length === 0 ? (
                <p style={{ textAlign: 'center', color: '#94a3b8', padding: '2rem' }}>No scan history recorded yet.</p>
              ) : (
                <div className="table-responsive">
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Target URL</th>
                        <th>Verdict</th>
                        <th>Risk Score</th>
                        <th>VirusTotal</th>
                        <th>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((item) => (
                        <tr key={item.id}>
                          <td className="url-cell" title={item.url}>{item.url}</td>
                          <td>
                            <span className={`badge ${item.prediction === 'phishing' || item.blacklisted ? 'badge-danger' : item.prediction === 'suspicious' ? 'badge-warn' : 'badge-safe'}`}>
                              {item.blacklisted ? 'BLACKLISTED' : item.prediction.toUpperCase()}
                            </span>
                          </td>
                          <td style={{ fontWeight: 'bold' }}>{item.risk_score} / 100</td>
                          <td>{item.vt_score !== null ? `${item.vt_score}%` : 'Clean'}</td>
                          <td style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{new Date(item.timestamp).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── DASHBOARD TAB ── */}
        {activeTab === 'dashboard' && (
          <div className="tab-container">
            <div className="tab-header">
              <h2>📊 Platform Threat Analytics Radar</h2>
              <p>Aggregated telemetry across multi-modal inspection layers.</p>
            </div>

            <div className="metrics-grid" style={{ marginBottom: '1.5rem' }}>
              <div className="metric-card">
                <span className="card-title">Total Targets Scanned</span>
                <span className="card-value">{totalScans}</span>
              </div>
              <div className="metric-card" style={{ borderColor: '#ef4444' }}>
                <span className="card-title">Phishing &amp; Malicious</span>
                <span className="card-value" style={{ color: '#ef4444' }}>{phishingCount}</span>
              </div>
              <div className="metric-card" style={{ borderColor: '#f59e0b' }}>
                <span className="card-title">Suspicious Targets</span>
                <span className="card-value" style={{ color: '#f59e0b' }}>{suspiciousCount}</span>
              </div>
              <div className="metric-card" style={{ borderColor: '#10b981' }}>
                <span className="card-title">Clean &amp; Verified</span>
                <span className="card-value" style={{ color: '#10b981' }}>{safeCount}</span>
              </div>
            </div>

            <div className="card">
              <h3>System Telemetry Summary</h3>
              <p style={{ marginBottom: '1rem', color: '#94a3b8' }}>Average Risk Index across network scans: <strong>{avgRiskScore} / 100</strong></p>
              
              {totalScans > 0 ? (
                <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap', marginTop: '2rem' }}>
                  <div style={{ flex: 1, minWidth: '300px', height: '300px' }}>
                    <h4 style={{ textAlign: 'center', marginBottom: '1rem' }}>Verdict Distribution</h4>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} innerRadius={60} stroke="rgba(255,255,255,0.1)">
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#070a12', borderColor: 'rgba(56,189,248,0.3)', borderRadius: '8px' }} />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  
                  <div style={{ flex: 1, minWidth: '300px', height: '300px' }}>
                    <h4 style={{ textAlign: 'center', marginBottom: '1rem' }}>Recent Scan Risk Trend</h4>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={barData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                        <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
                        <YAxis stroke="#94a3b8" fontSize={12} />
                        <Tooltip contentStyle={{ backgroundColor: '#070a12', borderColor: 'rgba(56,189,248,0.3)', borderRadius: '8px' }} />
                        <Bar dataKey="Risk" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              ) : (
                <div className="empty-state" style={{ marginTop: '2rem' }}>
                  <BarChart2 size={48} className="empty-icon" />
                  <h3>No Data to Graphify</h3>
                  <p>Run some scans in the Platform to generate dynamic telemetry graphs.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      <footer className="platform-footer">
        <p>TrustGuard Internet Security Platform &copy; 2026. Powered by Multi-Modal Machine Learning &amp; Agentic Reasoning.</p>
      </footer>
    </div>
  );
}

export default App;
