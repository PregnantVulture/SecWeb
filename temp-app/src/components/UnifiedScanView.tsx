'use client';

import React, { useState, useEffect } from 'react';
import SecWebVerification from './SecWebVerification';

interface ZapAlert {
  id: string;
  alertId: string;
  name: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: 'High' | 'Medium' | 'Low';
  url: string;
  param?: string;
  cweId?: string;
  description?: string;
  evidence?: string;
  solution?: string;
  remediationLink?: {
    title: string;
    url: string;
  };
  tool: 'OWASP ZAP';
  fingerprint: string;
}

interface TinyFishPage {
  url: string;
  title: string;
  description: string;
  language: string;
  latencyMs: number;
  format: string;
  pageType: 'Public Page' | 'Login / Auth' | 'Admin Portal' | 'API Endpoint' | 'Static Asset';
  observedFacts: string[];
  inferredClassifications: string[];
}

interface RemediationRecommendation {
  id: string;
  findingId: string;
  findingName: string;
  issueSummary: string;
  beginnerExplanation: string;
  practicalNextSteps: string[];
  remediationLink?: {
    title: string;
    url: string;
  };
  isTargetSpecific: boolean;
  priority: 'High' | 'Medium' | 'Low' | 'Informational';
}

interface ScanRecord {
  id: string;
  targetUrl: string;
  normalizedHost: string;
  startTime: string;
  endTime?: string;
  status: 'completed' | 'partial' | 'failed' | 'timed_out';
  scanType: 'live-unified-scan' | 'demo-illustrative-scan';
  isIllustrativeDemo: boolean;
  totalFindings: number;
  severityCounts: {
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  };
  zapAlerts: ZapAlert[];
  tinyfishIntelligence: {
    discoveredPages: TinyFishPage[];
    summary: string;
  };
  remediationRecommendations: RemediationRecommendation[];
  coverageAndStatus: {
    toolAttribution: string[];
    latencyMs: number;
    completionStatus: string;
  };
  error?: string;
}

interface ComparisonResult {
  olderScanId: string;
  newerScanId: string;
  targetHost: string;
  summary: {
    newCount: number;
    persistentCount: number;
    resolvedCount: number;
  };
  newFindings: ZapAlert[];
  persistentFindings: { older: ZapAlert; newer: ZapAlert; severityChanged: boolean }[];
  resolvedFindings: ZapAlert[];
}

export default function UnifiedScanView() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [isDemoActive, setIsDemoActive] = useState(false);
  const [olderId, setOlderId] = useState('');
  const [newerId, setNewerId] = useState('');
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showVerificationModal, setShowVerificationModal] = useState(false);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);

  const [tabKey, setTabKey] = useState(0);

  const switchTab = (tab: typeof activeTab) => {
    setActiveTab(tab);
    setTabKey(k => k + 1);
  };
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'intelligence' | 'remediation'>('overview');
  const [selectedFindingId, setSelectedFindingId] = useState<string>('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>('all');
  const [findingSearchQuery, setFindingSearchQuery] = useState<string>('');
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  const fetchScans = async () => {
    try {
      const res = await fetch('/api/scans');
      const data = await res.json() as { success: boolean; scans: ScanRecord[] };
      if (data.success) {
        setScans(data.scans);
        if (data.scans.length > 0 && !activeScan) {
          setActiveScan(data.scans[0]);
          if (data.scans[0].zapAlerts.length > 0) {
            setSelectedFindingId(data.scans[0].zapAlerts[0].id);
          }
        }
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchScans();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleScanWebsite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    setLoading(true);
    setError(null);
    setComparison(null);

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, isDemo: isDemoActive }),
      });
      const data = await res.json() as { error?: string; requiresVerification?: boolean; scan?: ScanRecord };
      if (!res.ok) {
        if (data.requiresVerification) {
          setShowVerificationModal(true);
        }
        throw new Error(data.error || 'Failed to run security scan');
      }

      if (data.scan) {
        setActiveScan(data.scan);
        if (data.scan.zapAlerts.length > 0) {
          setSelectedFindingId(data.scan.zapAlerts[0].id);
        }
      }
      setShowVerificationModal(false);
      await fetchScans();
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoClick = () => {
    setTargetUrl('https://demositeforsecweb.com');
    setIsDemoActive(true);
  };

  const handleSelectScan = (scan: ScanRecord) => {
    setActiveScan(scan);
    if (scan.zapAlerts.length > 0) {
      setSelectedFindingId(scan.zapAlerts[0].id);
    }
    setShowHistoryModal(false);
  };

  const handleCompare = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!olderId || !newerId) {
      setError('Please select both older and newer completed scans to compare.');
      return;
    }

    setLoading(true);
    setError(null);
    setComparison(null);

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'compare', olderScanId: olderId, newerScanId: newerId }),
      });
      const data = await res.json() as { error?: string; comparison?: ComparisonResult };
      if (!res.ok) throw new Error(data.error || 'Comparison failed');
      setComparison(data.comparison || null);
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  const completedScans = scans.filter(s => s.status === 'completed');

  const filteredFindings = activeScan ? activeScan.zapAlerts.filter(f => {
    const matchesSev = findingSeverityFilter === 'all' || f.risk.toLowerCase() === findingSeverityFilter.toLowerCase();
    const matchesSearch = findingSearchQuery === '' || f.name.toLowerCase().includes(findingSearchQuery.toLowerCase()) || f.url.toLowerCase().includes(findingSearchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  }) : [];

  const selectedFinding = activeScan?.zapAlerts.find(f => f.id === selectedFindingId) || activeScan?.zapAlerts[0];

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 font-sans pb-16">
      {/* Top Scanner Control Bar */}
      <div className="bg-zinc-900/50 backdrop-blur-md rounded-2xl shadow-xl border border-zinc-800/60 space-y-5 animate-fade-in">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-[11px] font-mono tracking-widest text-emerald-400 uppercase">SecWeb Intelligence & Scanner</span>
            </div>
            <h2 className="text-xl font-black text-zinc-100 tracking-tight mt-0.5">
              Unified Vulnerability Assessment
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleDemoClick}
              className="px-3 py-1.5 text-xs font-semibold bg-blue-950/60 text-blue-300 border border-blue-800/80 rounded-lg hover:bg-blue-900/60 transition-colors shadow-sm"
            >
              🚀 Demo Scan (demositeforsecweb.com)
            </button>
            <button
              type="button"
              onClick={() => setShowVerificationModal(!showVerificationModal)}
              className="px-3 py-1.5 text-xs font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/80 rounded-lg hover:bg-emerald-900/60 transition-colors"
            >
              {showVerificationModal ? 'Hide SecWeb' : '🛡️ SecWeb Domain Verification'}
            </button>
            {scans.length > 0 && (
              <button
                type="button"
                onClick={() => setShowHistoryModal(!showHistoryModal)}
                className="px-3 py-1.5 text-xs font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-lg hover:bg-zinc-700 transition-colors"
              >
                📂 History & Compare ({scans.length})
              </button>
            )}
          </div>
        </div>

        {showVerificationModal && (
          <SecWebVerification
            targetHost={targetUrl}
            onVerified={() => setShowVerificationModal(false)}
          />
        )}

        {showHistoryModal && (
          <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-zinc-200">Scan History & Comparison Vault</h3>
              <button onClick={() => setShowHistoryModal(false)} className="text-xs text-zinc-400 hover:text-zinc-200">✕ Close</button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-zinc-300">
                <thead className="bg-zinc-900 text-zinc-400 uppercase">
                  <tr>
                    <th className="px-3 py-2">Scan ID</th>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Findings</th>
                    <th className="px-3 py-2">Date</th>
                    <th className="px-3 py-2">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {scans.map(s => (
                    <tr key={s.id} className="hover:bg-zinc-900/50">
                      <td className="px-3 py-2 font-mono font-medium text-emerald-400">{s.id}</td>
                      <td className="px-3 py-2 truncate max-w-[180px]">{s.normalizedHost}</td>
                      <td className="px-3 py-2">
                        <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${s.isIllustrativeDemo ? 'bg-blue-950 text-blue-300' : 'bg-emerald-950 text-emerald-300'}`}>
                          {s.isIllustrativeDemo ? 'Demo' : 'Live'}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-semibold">H:{s.severityCounts.High} M:{s.severityCounts.Medium}</td>
                      <td className="px-3 py-2 text-zinc-400">{new Date(s.startTime).toLocaleDateString()}</td>
                      <td className="px-3 py-2">
                        <button onClick={() => handleSelectScan(s)} className="px-2.5 py-1 text-[11px] font-semibold bg-emerald-600 text-white rounded hover:bg-emerald-700">
                          Select
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Quick Compare subsection */}
            <div className="pt-3 border-t border-zinc-800 space-y-3">
              <h4 className="text-xs font-bold text-zinc-300">Compare Two Scans</h4>
              <form onSubmit={handleCompare} className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <select value={olderId} onChange={e => setOlderId(e.target.value)} className="px-2.5 py-1.5 text-xs bg-zinc-900 border border-zinc-700 rounded text-zinc-200">
                  <option value="">Older scan...</option>
                  {completedScans.map(s => <option key={s.id} value={s.id}>{s.id} ({s.normalizedHost})</option>)}
                </select>
                <select value={newerId} onChange={e => setNewerId(e.target.value)} className="px-2.5 py-1.5 text-xs bg-zinc-900 border border-zinc-700 rounded text-zinc-200">
                  <option value="">Newer scan...</option>
                  {completedScans.map(s => <option key={s.id} value={s.id}>{s.id} ({s.normalizedHost})</option>)}
                </select>
                <button type="submit" disabled={loading} className="px-3 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-700">
                  Compare
                </button>
              </form>
              {comparison && (
                <div className="p-3 bg-zinc-900 rounded border border-zinc-800 grid grid-cols-3 text-center text-xs">
                  <div><span className="text-[10px] text-red-400 block font-bold">NEW</span><span className="text-sm font-black text-red-300">{comparison.summary.newCount}</span></div>
                  <div><span className="text-[10px] text-amber-400 block font-bold">PERSISTENT</span><span className="text-sm font-black text-amber-300">{comparison.summary.persistentCount}</span></div>
                  <div><span className="text-[10px] text-emerald-400 block font-bold">RESOLVED</span><span className="text-sm font-black text-emerald-300">{comparison.summary.resolvedCount}</span></div>
                </div>
              )}
            </div>
          </div>
        )}

        {error && (
          <div className="p-3 text-xs text-red-400 bg-red-950/40 rounded-xl border border-red-900">
            {error}
          </div>
        )}

        {/* Workflow steps hint & form */}
        <div className="space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-zinc-400 font-mono">
            <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
              <span className="text-emerald-500 font-bold">01</span> Validate Target
            </div>
            <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
              <span className="text-emerald-500 font-bold">02</span> TinyFish Discovery
            </div>
            <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
              <span className="text-emerald-500 font-bold">03</span> OWASP ZAP Analysis
            </div>
            <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
              <span className="text-emerald-500 font-bold">04</span> Verified Report
            </div>
          </div>

          <form onSubmit={handleScanWebsite} className="flex flex-col sm:flex-row gap-3 pt-1">
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => {
                setTargetUrl(e.target.value);
                if (isDemoActive && e.target.value !== 'https://demositeforsecweb.com') {
                  setIsDemoActive(false);
                }
              }}
              placeholder="https://example.com"
              required
              className="flex-1 px-4 py-3 text-sm border border-zinc-700 rounded-xl bg-zinc-950 text-zinc-100 focus:outline-none focus:ring-2 focus:ring-emerald-500 font-mono"
            />
            <button
              type="submit"
              disabled={loading}
              className={`px-8 py-3 text-sm font-semibold text-white rounded-xl transition-colors shadow-lg disabled:opacity-50 flex items-center justify-center gap-2 ${
                isDemoActive
                  ? 'bg-blue-600 hover:bg-blue-700 shadow-blue-600/20'
                  : 'bg-emerald-600 hover:bg-emerald-700 shadow-emerald-600/20'
              }`}
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Running Pipeline...
                </>
              ) : isDemoActive ? (
                'Run Demo Scan'
              ) : (
                'Scan Website'
              )}
            </button>
          </form>
        </div>
      </div>

      {/* Redesigned Dashboard Report Interface */}
      {activeScan ? (
        <div className="bg-zinc-900/60 backdrop-blur-xl rounded-2xl shadow-2xl border border-zinc-800/40 overflow-hidden space-y-6 animate-fade-in">
          {/* Compact Scan Header Bar */}
          <div className="p-6 bg-zinc-950/70 border-b border-zinc-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2.5">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  {activeScan.id}
                </span>
                {activeScan.isIllustrativeDemo ? (
                  <span className="px-2 py-0.5 text-[10px] font-bold bg-blue-950 text-blue-300 rounded-full border border-blue-800">
                    Illustrative Demo Data
                  </span>
                ) : (
                  <span className="px-2 py-0.5 text-[10px] font-bold bg-emerald-950 text-emerald-300 rounded-full border border-emerald-800">
                    Live Scan Result
                  </span>
                )}
                <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">
                  ● {activeScan.status}
                </span>
              </div>
              <h3 className="text-xl font-black text-zinc-100 tracking-tight font-mono">
                {activeScan.targetUrl}
              </h3>
              <p className="text-xs text-zinc-400">
                Completed on {new Date(activeScan.startTime).toLocaleString()} • {activeScan.coverageAndStatus.latencyMs}ms pipeline latency
              </p>
            </div>

            {/* Severity Pill Summary */}
            <div className="flex items-center gap-2">
              <div className="px-3.5 py-2 bg-red-950/50 border border-red-900/60 rounded-xl text-center min-w-[70px]">
                <span className="text-[10px] text-red-400 block font-bold uppercase">High</span>
                <span className="text-base font-black text-red-300">{activeScan.severityCounts.High}</span>
              </div>
              <div className="px-3.5 py-2 bg-amber-950/50 border border-amber-900/60 rounded-xl text-center min-w-[70px]">
                <span className="text-[10px] text-amber-400 block font-bold uppercase">Medium</span>
                <span className="text-base font-black text-amber-300">{activeScan.severityCounts.Medium}</span>
              </div>
              <div className="px-3.5 py-2 bg-zinc-800/80 border border-zinc-700/60 rounded-xl text-center min-w-[70px]">
                <span className="text-[10px] text-zinc-400 block font-bold uppercase">Total</span>
                <span className="text-base font-black text-zinc-100">{activeScan.totalFindings}</span>
              </div>
            </div>
          </div>

          {/* Report Navigation Tabs */}
          <div className="px-6 flex border-b border-zinc-800 gap-2 overflow-x-auto">
            <button
              onClick={() => switchTab('overview')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'overview'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              📊 Overview & Status
            </button>
            <button
              onClick={() => switchTab('findings')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'findings'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              🛡️ Security Findings ({activeScan.zapAlerts.length})
            </button>
            <button
              onClick={() => switchTab('intelligence')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'intelligence'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              🌐 Website Intelligence ({activeScan.tinyfishIntelligence.discoveredPages.length})
            </button>
            <button
              onClick={() => switchTab('remediation')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'remediation'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              🔧 Fixes & Recommendations ({activeScan.remediationRecommendations.length})
            </button>
          </div>

          {/* Tab Content Area */}
          <div key={tabKey} className="p-6 pt-2 animate-fade-in animate-blur-in">
            {/* 1. OVERVIEW TAB */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-2">
                    <span className="text-xs text-zinc-400 uppercase tracking-wider font-bold">Execution Engine</span>
                    <div className="text-sm font-bold text-zinc-200">{activeScan.coverageAndStatus.toolAttribution.join(' + ')}</div>
                    <p className="text-xs text-zinc-500">Combined surface intelligence crawler and core vulnerability scanner.</p>
                  </div>
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-2">
                    <span className="text-xs text-zinc-400 uppercase tracking-wider font-bold">Surface Mapped</span>
                    <div className="text-sm font-bold text-zinc-200">{activeScan.tinyfishIntelligence.discoveredPages.length} Public Endpoints</div>
                    <p className="text-xs text-zinc-500">Discovered during active TinyFish intelligence phase.</p>
                  </div>
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-200 dark:border-zinc-800 space-y-2">
                    <span className="text-xs text-zinc-400 uppercase tracking-wider font-bold">Risk Assessment</span>
                    <div className="text-sm font-bold text-zinc-200">
                      {activeScan.severityCounts.High > 0 ? '⚠️ High Risk Action Required' : '✅ Posture Secure'}
                    </div>
                    <p className="text-xs text-zinc-500">{activeScan.totalFindings} total security observations recorded.</p>
                  </div>
                </div>

                {/* Top Critical Findings Quick Preview */}
                <div className="space-y-3 pt-2">
                  <h4 className="text-sm font-bold text-zinc-200">Most Critical Findings Overview</h4>
                  {activeScan.zapAlerts.length === 0 ? (
                    <p className="text-xs text-zinc-500 italic p-4 bg-zinc-950/40 rounded-xl">No security findings reported.</p>
                  ) : (
                    <div className="space-y-2">
                      {activeScan.zapAlerts.slice(0, 2).map(alert => (
                        <div key={alert.id} className="p-4 bg-zinc-950/50 rounded-xl border border-zinc-800 flex items-center justify-between gap-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${alert.risk === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                                {alert.risk} Risk
                              </span>
                              <span className="text-xs font-bold text-zinc-200">{alert.name}</span>
                            </div>
                            <p className="text-xs text-zinc-400 truncate max-w-xl">{alert.description}</p>
                          </div>
                          <button
                            onClick={() => { setActiveTab('findings'); setSelectedFindingId(alert.id); }}
                            className="px-3 py-1.5 text-xs font-semibold bg-zinc-800 text-zinc-200 rounded-lg hover:bg-zinc-700 shrink-0"
                          >
                            Inspect Details →
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 2. SECURITY FINDINGS TAB (Master-Detail Layout on Desktop) */}
            {activeTab === 'findings' && (
              <div className="space-y-4">
                {/* Filters */}
                <div className="flex flex-col sm:flex-row gap-3 items-center justify-between pb-2">
                  <div className="flex items-center gap-2 w-full sm:w-auto">
                    <input
                      type="text"
                      placeholder="Search findings by title or URL..."
                      value={findingSearchQuery}
                      onChange={e => setFindingSearchQuery(e.target.value)}
                      className="px-3 py-2 text-xs bg-zinc-950 border border-zinc-700 rounded-lg text-zinc-200 w-full sm:w-72 font-mono"
                    />
                    <select
                      value={findingSeverityFilter}
                      onChange={e => setFindingSeverityFilter(e.target.value)}
                      className="px-3 py-2 text-xs bg-zinc-950 border border-zinc-700 rounded-lg text-zinc-200"
                    >
                      <option value="all">All Severities</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <span className="text-xs text-zinc-400 font-mono">
                    Showing {filteredFindings.length} of {activeScan.zapAlerts.length} findings
                  </span>
                </div>

                {filteredFindings.length === 0 ? (
                  <p className="text-xs text-zinc-500 italic p-6 bg-zinc-950/40 rounded-xl text-center">No findings match your search criteria.</p>
                ) : (
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                    {/* Left List */}
                    <div className="lg:col-span-5 space-y-2 max-h-[550px] overflow-y-auto pr-1">
                      {filteredFindings.map(alert => {
                        const isSelected = selectedFinding?.id === alert.id;
                        return (
                          <div
                            key={alert.id}
                            onClick={() => setSelectedFindingId(alert.id)}
                            className={`p-3.5 rounded-xl border cursor-pointer transition-all space-y-1.5 ${
                              isSelected
                                ? 'bg-emerald-950/30 border-emerald-500/80 shadow-md'
                                : 'bg-zinc-950/50 border-zinc-800 hover:border-zinc-700'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className={`px-2 py-0.5 text-[9px] font-bold rounded ${alert.risk === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                                {alert.risk} Risk
                              </span>
                              <span className="text-[10px] font-mono text-zinc-400">{alert.alertId}</span>
                            </div>
                            <h5 className="text-xs font-bold text-zinc-200 line-clamp-1">{alert.name}</h5>
                            <p className="text-[11px] text-zinc-400 truncate font-mono">{alert.url}</p>
                          </div>
                        );
                      })}
                    </div>

                    {/* Right Details Panel */}
                    <div className="lg:col-span-7 bg-zinc-950/80 p-6 rounded-2xl border border-zinc-800 space-y-4">
                      {selectedFinding ? (
                        <>
                          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                            <div>
                              <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase tracking-wider">
                                {selectedFinding.tool} • {selectedFinding.alertId}
                              </span>
                              <h4 className="text-base font-bold text-zinc-100 mt-0.5">{selectedFinding.name}</h4>
                            </div>
                            <span className={`px-2.5 py-1 text-xs font-bold rounded ${selectedFinding.risk === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                              {selectedFinding.risk} Risk ({selectedFinding.confidence} Confidence)
                            </span>
                          </div>

                          <div className="space-y-3 text-xs text-zinc-300">
                            <div>
                              <strong className="text-zinc-400 block mb-1">Affected URL:</strong>
                              <span className="font-mono bg-zinc-900 p-2 rounded block text-emerald-300 truncate">{selectedFinding.url}</span>
                            </div>

                            <div>
                              <strong className="text-zinc-400 block mb-1">Description & Risk Analysis:</strong>
                              <p className="text-zinc-300 leading-relaxed">{selectedFinding.description}</p>
                            </div>

                            {selectedFinding.evidence && (
                              <div>
                                <strong className="text-zinc-400 block mb-1">Observed Evidence:</strong>
                                <div className="font-mono bg-zinc-900/90 p-2.5 rounded border border-zinc-800 text-zinc-200 text-[11px]">
                                  {selectedFinding.evidence}
                                </div>
                              </div>
                            )}

                            {selectedFinding.solution && (
                              <div>
                                <strong className="text-zinc-400 block mb-1">Remediation Guidance:</strong>
                                <p className="text-emerald-400 font-medium">{selectedFinding.solution}</p>
                              </div>
                            )}

                            {selectedFinding.remediationLink && (
                              <div className="pt-2">
                                <a
                                  href={selectedFinding.remediationLink.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:underline bg-emerald-950/40 px-3 py-2 rounded-lg border border-emerald-900/60"
                                >
                                  🔗 Read official guide: {selectedFinding.remediationLink.title}
                                </a>
                              </div>
                            )}
                          </div>
                        </>
                      ) : (
                        <p className="text-xs text-zinc-500 italic p-6 text-center">Select a finding from the left list to view technical details.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 3. WEBSITE INTELLIGENCE TAB */}
            {activeTab === 'intelligence' && (
              <div className="space-y-4">
                <p className="text-xs text-zinc-400">
                  {activeScan.tinyfishIntelligence.summary} These entries represent website observations and asset discovery, not verified vulnerabilities.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {activeScan.tinyfishIntelligence.discoveredPages.map((page, idx) => (
                    <div key={idx} className="p-4 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-sm text-zinc-200 truncate">{page.title}</span>
                        <span className="text-[10px] bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded font-mono border border-emerald-900">
                          {page.pageType} • {page.latencyMs}ms
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400">{page.description}</p>
                      <div className="space-y-1 text-[11px] bg-zinc-900/50 p-2.5 rounded border border-zinc-800">
                        <div className="text-zinc-300"><strong>Observed Facts:</strong> {page.observedFacts.join(', ')}</div>
                        <div className="text-zinc-400 italic"><strong>Classifications:</strong> {page.inferredClassifications.join(', ')}</div>
                      </div>
                      <a href={page.url} target="_blank" rel="noopener noreferrer" className="text-xs font-medium text-emerald-400 hover:underline truncate block pt-1 font-mono">
                        {page.url}
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 4. FIXES & RECOMMENDATIONS TAB */}
            {activeTab === 'remediation' && (
              <div className="space-y-4">
                <p className="text-xs text-zinc-400">
                  Prioritized checklist of actionable remediation steps ordered by severity. Each item links directly to official OWASP guidance.
                </p>
                {activeScan.remediationRecommendations.length === 0 ? (
                  <p className="text-xs text-zinc-500 italic p-6 bg-zinc-950/40 rounded-xl text-center">No remediation actions required for this target.</p>
                ) : (
                  <div className="space-y-3">
                    {activeScan.remediationRecommendations.map(rec => (
                      <div key={rec.id} className="p-5 bg-zinc-950/60 rounded-2xl border border-zinc-800 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm text-zinc-200">{rec.findingName}</span>
                            <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${rec.priority === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                              {rec.priority} Priority
                            </span>
                          </div>
                          <span className="text-[10px] bg-blue-950 text-blue-300 px-2 py-0.5 rounded font-semibold border border-blue-900">
                            {rec.isTargetSpecific ? 'Target-Specific' : 'Standard Advisory'}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-300 leading-relaxed">{rec.beginnerExplanation}</p>
                        <div className="space-y-1.5 bg-zinc-900/80 p-3.5 rounded-xl border border-zinc-800">
                          <strong className="text-xs text-zinc-200 block mb-1">Beginner-Friendly Action Steps:</strong>
                          <ul className="list-disc list-inside text-xs text-zinc-300 space-y-1 font-mono">
                            {rec.practicalNextSteps.map((step, sIdx) => (
                              <li key={sIdx}>{step}</li>
                            ))}
                          </ul>
                        </div>
                        {rec.remediationLink && (
                          <div className="pt-1">
                            <a
                              href={rec.remediationLink.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:underline bg-emerald-950/30 px-3 py-2 rounded-lg border border-emerald-900/50"
                            >
                              📖 Read reference guide in {rec.remediationLink.title}
                            </a>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="bg-zinc-900/95 p-12 rounded-2xl shadow-xl border border-zinc-800 text-center space-y-4">
          <div className="w-12 h-12 bg-emerald-950 text-emerald-400 rounded-2xl flex items-center justify-center mx-auto text-xl border border-emerald-800">
            🛡️
          </div>
          <h3 className="text-lg font-bold text-zinc-100">No Active Scan Report Loaded</h3>
          <p className="text-xs text-zinc-400 max-w-md mx-auto">
            Enter a target URL above and click <span className="text-emerald-400 font-semibold">Scan Website</span>, or load the <span className="text-blue-400 font-semibold">Demo Scan</span> to explore the fully redesigned SecWeb dashboard.
          </p>
        </div>
      )}
    </div>
  );
}
