'use client';

import React, { useState, useEffect } from 'react';
import SecWebVerification from './SecWebVerification';
import ScanStream from './ScanStream';
import type { ScanRecord, ComparisonResult } from '@/lib/types';

export default function UnifiedScanView() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [isDemoActive, setIsDemoActive] = useState(false);
  const [olderId, setOlderId] = useState('');
  const [newerId, setNewerId] = useState('');
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showVerificationModal, setShowVerificationModal] = useState(false);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);
  const [scanDepth, setScanDepth] = useState<'quick' | 'comprehensive'>('comprehensive');

  const [tabKey, setTabKey] = useState(0);
  const switchTab = (tab: typeof activeTab) => {
    setActiveTab(tab);
    setTabKey(k => k + 1);
  };
  const [activeTab, setActiveTab] = useState<'overview' | 'threatmodel' | 'findings' | 'intelligence' | 'remediation'>('overview');
  const [selectedFindingId, setSelectedFindingId] = useState<string>('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>('all');
  const [findingSearchQuery, setFindingSearchQuery] = useState<string>('');
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  const getClientIdHeaders = (): Record<string, string> => {
    if (typeof window === 'undefined') return {};
    let clientId = localStorage.getItem('secweb_device_id');
    if (!clientId) {
      clientId = 'sec_' + Math.random().toString(36).substring(2) + '_' + Date.now().toString(36);
      localStorage.setItem('secweb_device_id', clientId);
    }
    return { 'x-secweb-client-id': clientId };
  };

  const fetchScans = async () => {
    try {
      const res = await fetch('/api/scans', {
        headers: getClientIdHeaders(),
      });
      const data = await res.json() as { success: boolean; scans: ScanRecord[] };
      if (data.success) {
        setScans(data.scans);
        if (data.scans.length > 0 && !activeScan) {
          setActiveScan(data.scans[0]);
          if (data.scans[0].findings.length > 0) {
            setSelectedFindingId(data.scans[0].findings[0].id);
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

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    setError(null);
    setComparison(null);
    setIsStreaming(true);
  };

  const handleScanComplete = async (scan: ScanRecord) => {
    setIsStreaming(false);
    setActiveScan(scan);
    if (scan.findings.length > 0) {
      setSelectedFindingId(scan.findings[0].id);
    }
    setShowVerificationModal(false);
    await fetchScans();
  };

  const handleStreamError = (errMsg: string) => {
    setIsStreaming(false);
    if (errMsg.includes('verification required')) {
      setShowVerificationModal(true);
    }
    setError(errMsg);
  };

  const handleDemoClick = () => {
    setTargetUrl('https://demositeforsecweb.com');
    setIsDemoActive(true);
  };

  const handleSelectScan = (scan: ScanRecord) => {
    setActiveScan(scan);
    if (scan.findings.length > 0) {
      setSelectedFindingId(scan.findings[0].id);
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
      const headersObj: Record<string, string> = {
        'Content-Type': 'application/json',
        ...getClientIdHeaders(),
      };
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: headersObj,
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

  const filteredFindings = activeScan ? activeScan.findings.filter(f => {
    const matchesSev = findingSeverityFilter === 'all' || f.risk.toLowerCase() === findingSeverityFilter.toLowerCase();
    const matchesSearch = findingSearchQuery === '' || f.name.toLowerCase().includes(findingSearchQuery.toLowerCase()) || f.url.toLowerCase().includes(findingSearchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  }) : [];

  const selectedFinding = activeScan?.findings.find(f => f.id === selectedFindingId) || activeScan?.findings[0];

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 font-sans pb-16">
      {/* Top Scanner Control Bar */}
      <div className="bg-zinc-900/50 backdrop-blur-md rounded-2xl shadow-xl border border-zinc-800/60 space-y-5 animate-fade-in">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-[11px] font-mono tracking-widest text-emerald-400 uppercase">SecWeb AI Pentesting Engine (Strix-Powered)</span>
            </div>
            <h2 className="text-xl font-black text-zinc-100 tracking-tight mt-0.5">
              Autonomous Vulnerability Assessment & PoC Validation
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleDemoClick}
              className="px-3 py-1.5 text-xs font-semibold bg-blue-950/60 text-blue-300 border border-blue-800/80 rounded-lg hover:bg-blue-900/60 transition-colors shadow-sm"
            >
              Demo Scan (demositeforsecweb.com)
            </button>
            <button
              type="button"
              onClick={() => setShowVerificationModal(!showVerificationModal)}
              className="px-3 py-1.5 text-xs font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/80 rounded-lg hover:bg-emerald-900/60 transition-colors"
            >
              {showVerificationModal ? 'Hide Domain Verification' : 'Domain Verification'}
            </button>
            {scans.length > 0 && (
              <button
                type="button"
                onClick={() => setShowHistoryModal(!showHistoryModal)}
                className="px-3 py-1.5 text-xs font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-lg hover:bg-zinc-700 transition-colors"
              >
                History & Compare ({scans.length})
              </button>
            )}
          </div>
        </div>

        <SecWebVerification
          targetHost={targetUrl}
          onVerified={() => setShowVerificationModal(false)}
          onDomainSelected={(dom) => {
            setTargetUrl(`https://${dom}`);
            setIsDemoActive(false);
          }}
        />

        {showHistoryModal && (
          <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-zinc-200">Scan History & Comparison Vault</h3>
              <button onClick={() => setShowHistoryModal(false)} className="text-xs text-zinc-400 hover:text-zinc-200">Close</button>
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
                          {s.isIllustrativeDemo ? 'Demo' : 'AI Live'}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-semibold">C:{s.severityCounts.Critical} H:{s.severityCounts.High} M:{s.severityCounts.Medium}</td>
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
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-zinc-400 font-mono">
              <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
                <span className="text-emerald-500 font-bold">01</span> Recon & Crawl
              </div>
              <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
                <span className="text-emerald-500 font-bold">02</span> Threat Model
              </div>
              <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
                <span className="text-emerald-500 font-bold">03</span> AI Exploit Probe
              </div>
              <div className="bg-zinc-950/60 p-2 rounded border border-zinc-800 flex items-center gap-1.5">
                <span className="text-emerald-500 font-bold">04</span> CVSS & PoC Report
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[11px] font-bold text-zinc-400 uppercase">Scan Depth:</span>
              <button
                type="button"
                onClick={() => setScanDepth('quick')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg border transition-colors ${
                  scanDepth === 'quick'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-500'
                    : 'bg-zinc-950 text-zinc-400 border-zinc-800 hover:text-zinc-200'
                }`}
              >
                Quick
              </button>
              <button
                type="button"
                onClick={() => setScanDepth('comprehensive')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg border transition-colors ${
                  scanDepth === 'comprehensive'
                    ? 'bg-purple-950 text-purple-300 border-purple-500'
                    : 'bg-zinc-950 text-zinc-400 border-zinc-800 hover:text-zinc-200'
                }`}
              >
                Deep Comprehensive (OWASP Top 10)
              </button>
            </div>
          </div>

          <form onSubmit={handleStartScan} className="flex flex-col sm:flex-row gap-3 pt-1">
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
              disabled={isStreaming}
              className={`px-8 py-3 text-sm font-semibold text-white rounded-xl transition-colors shadow-lg disabled:opacity-50 flex items-center justify-center gap-2 ${
                isDemoActive
                  ? 'bg-blue-600 hover:bg-blue-700 shadow-blue-600/20'
                  : scanDepth === 'comprehensive'
                  ? 'bg-purple-600 hover:bg-purple-700 shadow-purple-600/20'
                  : 'bg-emerald-600 hover:bg-emerald-700 shadow-emerald-600/20'
              }`}
            >
              {isStreaming ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Running AI Pentest...
                </>
              ) : isDemoActive ? (
                'Run Demo AI Scan'
              ) : scanDepth === 'comprehensive' ? (
                'Start Deep Comprehensive Scan'
              ) : (
                'Start Quick AI Scan'
              )}
            </button>
          </form>
        </div>
      </div>

      {/* Live Stream View when scanning */}
      {isStreaming && (
        <ScanStream
          targetUrl={targetUrl}
          isDemo={isDemoActive}
          scanDepth={scanDepth}
          onScanComplete={handleScanComplete}
          onError={handleStreamError}
          onCancel={() => setIsStreaming(false)}
        />
      )}

      {/* Redesigned Dashboard Report Interface */}
      {!isStreaming && activeScan ? (
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
                    AI Autonomous Scan
                  </span>
                )}
                <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">
                  {activeScan.status}
                </span>
              </div>
              <h3 className="text-xl font-black text-zinc-100 tracking-tight font-mono">
                {activeScan.targetUrl}
              </h3>
              <p className="text-xs text-zinc-400">
                Completed on {new Date(activeScan.startTime).toLocaleString()} • {activeScan.coverageAndStatus.latencyMs}ms probe latency
              </p>
            </div>

            {/* Severity Pill Summary */}
            <div className="flex items-center gap-2">
              <div className="px-3 py-2 bg-purple-950/50 border border-purple-900/60 rounded-xl text-center min-w-[65px]">
                <span className="text-[10px] text-purple-400 block font-bold uppercase">Crit</span>
                <span className="text-base font-black text-purple-300">{activeScan.severityCounts.Critical}</span>
              </div>
              <div className="px-3 py-2 bg-red-950/50 border border-red-900/60 rounded-xl text-center min-w-[65px]">
                <span className="text-[10px] text-red-400 block font-bold uppercase">High</span>
                <span className="text-base font-black text-red-300">{activeScan.severityCounts.High}</span>
              </div>
              <div className="px-3 py-2 bg-amber-950/50 border border-amber-900/60 rounded-xl text-center min-w-[65px]">
                <span className="text-[10px] text-amber-400 block font-bold uppercase">Med</span>
                <span className="text-base font-black text-amber-300">{activeScan.severityCounts.Medium}</span>
              </div>
              <div className="px-3.5 py-2 bg-zinc-800/80 border border-zinc-700/60 rounded-xl text-center min-w-[65px]">
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
              Overview & Status
            </button>
            <button
              onClick={() => switchTab('threatmodel')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'threatmodel'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Attack Surface & Threat Model
            </button>
            <button
              onClick={() => switchTab('findings')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'findings'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Vulnerabilities & PoC ({activeScan.findings.length})
            </button>
            <button
              onClick={() => switchTab('intelligence')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'intelligence'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Discovered Assets ({activeScan.tinyfishIntelligence.discoveredPages.length})
            </button>
            <button
              onClick={() => switchTab('remediation')}
              className={`px-4 py-3 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                activeTab === 'remediation'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Fixes & Patches ({activeScan.remediationRecommendations.length})
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
                    <p className="text-xs text-zinc-500">Autonomous Claude AI agent driver with active HTTP probe validation.</p>
                  </div>
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-2">
                    <span className="text-xs text-zinc-400 uppercase tracking-wider font-bold">Surface Mapped</span>
                    <div className="text-sm font-bold text-zinc-200">{activeScan.tinyfishIntelligence.discoveredPages.length} Endpoints & APIs</div>
                    <p className="text-xs text-zinc-500">Discovered during active reconnaissance crawl.</p>
                  </div>
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-2">
                    <span className="text-xs text-zinc-400 uppercase tracking-wider font-bold">Risk Assessment</span>
                    <div className="text-sm font-bold text-zinc-200">
                      {activeScan.severityCounts.Critical > 0 || activeScan.severityCounts.High > 0 ? 'High Risk Action Required' : 'Posture Secure'}
                    </div>
                    <p className="text-xs text-zinc-500">{activeScan.totalFindings} CVSS-scored vulnerabilities recorded.</p>
                  </div>
                </div>

                {/* Top Critical Findings Quick Preview */}
                <div className="space-y-3 pt-2">
                  <h4 className="text-sm font-bold text-zinc-200">Most Critical Vulnerabilities</h4>
                  {activeScan.findings.length === 0 ? (
                    <p className="text-xs text-zinc-500 italic p-4 bg-zinc-950/40 rounded-xl">No security findings reported.</p>
                  ) : (
                    <div className="space-y-2">
                      {activeScan.findings.slice(0, 3).map(alert => (
                        <div key={alert.id} className="p-4 bg-zinc-950/50 rounded-xl border border-zinc-800 flex items-center justify-between gap-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${alert.risk === 'Critical' ? 'bg-purple-950 text-purple-300' : alert.risk === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                                {alert.risk} {alert.cvss ? `(CVSS ${alert.cvss.baseScore})` : ''}
                              </span>
                              <span className="text-xs font-bold text-zinc-200">{alert.name}</span>
                            </div>
                            <p className="text-xs text-zinc-400 truncate max-w-xl">{alert.description}</p>
                          </div>
                          <button
                            onClick={() => { setActiveTab('findings'); setSelectedFindingId(alert.id); }}
                            className="px-3 py-1.5 text-xs font-semibold bg-zinc-800 text-zinc-200 rounded-lg hover:bg-zinc-700 shrink-0"
                          >
                            Inspect PoC →
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 2. ATTACK SURFACE & THREAT MODEL TAB */}
            {activeTab === 'threatmodel' && (
              <div className="space-y-6">
                <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-2">
                  <span className="text-xs font-mono text-emerald-400 uppercase font-bold tracking-wider">Strix Threat Model Summary</span>
                  <p className="text-xs text-zinc-300 leading-relaxed">{activeScan.threatModel?.summary || 'Attack surface mapped successfully.'}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Entry Points */}
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-3">
                    <h5 className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Entry Points ({activeScan.threatModel?.entryPoints.length ?? 0})</h5>
                    {activeScan.threatModel?.entryPoints.map((ep, idx) => (
                      <div key={idx} className="p-3 bg-zinc-900/60 rounded-lg border border-zinc-800 space-y-1">
                        <span className="text-xs font-bold text-zinc-200 block">{ep.label}</span>
                        {ep.url && <span className="text-[10px] font-mono text-emerald-300 truncate block">{ep.url}</span>}
                        <p className="text-[11px] text-zinc-400">{ep.description}</p>
                      </div>
                    ))}
                  </div>

                  {/* High Value Assets */}
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-3">
                    <h5 className="text-xs font-bold text-amber-400 uppercase tracking-wider">High-Value Assets ({activeScan.threatModel?.highValueAssets.length ?? 0})</h5>
                    {activeScan.threatModel?.highValueAssets.map((ha, idx) => (
                      <div key={idx} className="p-3 bg-zinc-900/60 rounded-lg border border-zinc-800 space-y-1">
                        <span className="text-xs font-bold text-zinc-200 block">{ha.label}</span>
                        <p className="text-[11px] text-zinc-400">{ha.description}</p>
                      </div>
                    ))}
                  </div>

                  {/* Trust Boundaries */}
                  <div className="p-5 bg-zinc-950/60 rounded-xl border border-zinc-800 space-y-3">
                    <h5 className="text-xs font-bold text-blue-400 uppercase tracking-wider">Trust Boundaries ({activeScan.threatModel?.trustBoundaries.length ?? 0})</h5>
                    {activeScan.threatModel?.trustBoundaries.map((tb, idx) => (
                      <div key={idx} className="p-3 bg-zinc-900/60 rounded-lg border border-zinc-800 space-y-1">
                        <span className="text-xs font-bold text-zinc-200 block">{tb.label}</span>
                        <p className="text-[11px] text-zinc-400">{tb.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 3. FINDINGS & PoC TAB */}
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
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <span className="text-xs text-zinc-400 font-mono">
                    Showing {filteredFindings.length} of {activeScan.findings.length} findings
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
                              <span className={`px-2 py-0.5 text-[9px] font-bold rounded ${alert.risk === 'Critical' ? 'bg-purple-950 text-purple-300' : alert.risk === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                                {alert.risk} {alert.cvss ? `(CVSS ${alert.cvss.baseScore})` : ''}
                              </span>
                              <span className="text-[10px] font-mono text-zinc-400">{alert.alertId}</span>
                            </div>
                            <h5 className="text-xs font-bold text-zinc-200 line-clamp-1">{alert.name}</h5>
                            <p className="text-[11px] text-zinc-400 truncate font-mono">{alert.url}</p>
                          </div>
                        );
                      })}
                    </div>

                    {/* Right Details Panel with PoC & CVSS */}
                    <div className="lg:col-span-7 bg-zinc-950/80 p-6 rounded-2xl border border-zinc-800 space-y-4">
                      {selectedFinding ? (
                        <>
                          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                            <div>
                              <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase tracking-wider">
                                {selectedFinding.tool} • {selectedFinding.cweId || selectedFinding.alertId} {selectedFinding.owasp ? `• ${selectedFinding.owasp}` : ''}
                              </span>
                              <h4 className="text-base font-bold text-zinc-100 mt-0.5">{selectedFinding.name}</h4>
                            </div>
                            <span className={`px-2.5 py-1 text-xs font-bold rounded ${selectedFinding.risk === 'Critical' ? 'bg-purple-950 text-purple-300' : selectedFinding.risk === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
                              {selectedFinding.risk} {selectedFinding.cvss ? `(CVSS ${selectedFinding.cvss.baseScore})` : ''}
                            </span>
                          </div>

                          <div className="space-y-3 text-xs text-zinc-300">
                            <div>
                              <strong className="text-zinc-400 block mb-1">Affected URL:</strong>
                              <span className="font-mono bg-zinc-900 p-2 rounded block text-emerald-300 truncate">{selectedFinding.url}</span>
                            </div>

                            {selectedFinding.cvss && (
                              <div>
                                <strong className="text-zinc-400 block mb-1">CVSS v3.1 Scoring:</strong>
                                <div className="p-3 bg-zinc-900/90 rounded border border-zinc-800 space-y-1 font-mono text-[11px]">
                                  <div className="text-emerald-400 font-bold">Base Score: {selectedFinding.cvss.baseScore} / 10.0</div>
                                  <div className="text-zinc-400 truncate">Vector: {selectedFinding.cvss.vectorString}</div>
                                </div>
                              </div>
                            )}

                            <div>
                              <strong className="text-zinc-400 block mb-1">Technical Description:</strong>
                              <p className="text-zinc-300 leading-relaxed">{selectedFinding.description}</p>
                            </div>

                            {selectedFinding.poc && (
                              <div>
                                <div className="flex items-center justify-between mb-1">
                                  <strong className="text-zinc-400">Proof-of-Concept (PoC) Exploit Payload:</strong>
                                  <span className="px-2 py-0.5 text-[10px] font-bold bg-emerald-950 text-emerald-300 rounded border border-emerald-900">
                                    Validated Exploit
                                  </span>
                                </div>
                                <div className="font-mono bg-zinc-900 p-3 rounded-xl border border-zinc-800 text-emerald-300 text-[11px] whitespace-pre-wrap overflow-x-auto">
                                  {selectedFinding.poc.payload}
                                </div>
                                {selectedFinding.poc.responseSummary && (
                                  <div className="mt-2 text-[11px] text-zinc-400">
                                    <strong className="text-zinc-500">Observed Response:</strong> {selectedFinding.poc.responseSummary}
                                  </div>
                                )}
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
                                  Read official guide: {selectedFinding.remediationLink.title}
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

            {/* 4. DISCOVERED ASSETS TAB */}
            {activeTab === 'intelligence' && (
              <div className="space-y-4">
                <p className="text-xs text-zinc-400">
                  {activeScan.tinyfishIntelligence.summary} These entries represent assets discovered during active reconnaissance.
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

            {/* 5. FIXES & RECOMMENDATIONS TAB */}
            {activeTab === 'remediation' && (
              <div className="space-y-4">
                <p className="text-xs text-zinc-400">
                  Prioritized checklist of actionable remediation steps ordered by severity. Each item links directly to official reference guidance.
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
                            <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${rec.priority === 'Critical' ? 'bg-purple-950 text-purple-300' : rec.priority === 'High' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}`}>
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
                              Read reference guide in {rec.remediationLink.title}
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
      ) : !isStreaming && (
        <div className="bg-zinc-900/95 p-12 rounded-2xl shadow-xl border border-zinc-800 text-center space-y-4">
          <div className="w-12 h-12 bg-emerald-950 text-emerald-400 rounded-2xl flex items-center justify-center mx-auto text-xl border border-emerald-800 font-bold font-mono">
            AI
          </div>
          <h3 className="text-lg font-bold text-zinc-100">No Active Scan Report Loaded</h3>
          <p className="text-xs text-zinc-400 max-w-md mx-auto">
            Enter a target URL above and click <span className="text-emerald-400 font-semibold">Start AI Scan</span>, or load the <span className="text-blue-400 font-semibold">Demo AI Scan</span> to explore the Strix-powered SecWeb dashboard.
          </p>
        </div>
      )}
    </div>
  );
}
