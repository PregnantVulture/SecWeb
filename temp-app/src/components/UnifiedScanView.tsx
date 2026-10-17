'use client';

import React, { useState, useEffect } from 'react';
import SiteShieldVerification from './SiteShieldVerification';

interface Finding {
  id: string;
  name: string;
  risk: string;
  url: string;
  cweId?: string;
  description?: string;
  solution?: string;
}

interface DiscoveredPage {
  url: string;
  title: string;
  description: string;
  language: string;
  latencyMs: number;
}

interface ScanRecord {
  id: string;
  targetUrl: string;
  normalizedHost: string;
  startTime: string;
  status: string;
  totalFindings: number;
  severityCounts: {
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  };
  findings: Finding[];
  discoveredPages: DiscoveredPage[];
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
  newFindings: Finding[];
  persistentFindings: { older: Finding; newer: Finding; severityChanged: boolean }[];
  resolvedFindings: Finding[];
}

export default function UnifiedScanView() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [olderId, setOlderId] = useState('');
  const [newerId, setNewerId] = useState('');
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showVerificationModal, setShowVerificationModal] = useState(false);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);

  const fetchScans = async () => {
    try {
      const res = await fetch('/api/scans');
      const data = await res.json() as { success: boolean; scans: ScanRecord[] };
      if (data.success) {
        setScans(data.scans);
        if (data.scans.length > 0 && !activeScan) {
          setActiveScan(data.scans[0]);
        }
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchScans();
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
        body: JSON.stringify({ targetUrl }),
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
      }
      setTargetUrl('');
      setShowVerificationModal(false);
      await fetchScans();
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
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

  return (
    <div className="w-full max-w-5xl mx-auto space-y-8 font-sans">
      {/* Top Banner / Hero */}
      <div className="bg-white dark:bg-zinc-900 p-8 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-800 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-6">
          <div>
            <h2 className="text-2xl font-black text-zinc-900 dark:text-zinc-100 tracking-tight">
              Unified Security Scanner
            </h2>
            <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
              Coordinate TinyFish intelligence discovery and OWASP ZAP vulnerability analysis in one click.
            </p>
          </div>
          <button
            onClick={() => setShowVerificationModal(!showVerificationModal)}
            className="self-start px-4 py-2 text-xs font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 rounded-lg hover:bg-emerald-100 transition-colors"
          >
            {showVerificationModal ? 'Hide SiteShield Verification' : '🛡️ SiteShield Domain Verification'}
          </button>
        </div>

        {showVerificationModal && (
          <SiteShieldVerification
            targetHost={targetUrl}
            onVerified={() => setShowVerificationModal(false)}
          />
        )}

        {error && (
          <div className="p-4 text-sm text-red-700 bg-red-100 dark:bg-red-900/30 dark:text-red-400 rounded-xl border border-red-200">
            {error}
          </div>
        )}

        {/* One-Click Scan Form */}
        <form onSubmit={handleScanWebsite} className="flex flex-col sm:flex-row gap-3">
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://anshwadhwaold.vercel.app"
            required
            className="flex-1 px-4 py-3 text-sm border border-zinc-300 dark:border-zinc-700 rounded-xl bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-8 py-3 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-xl transition-colors shadow-lg shadow-emerald-600/20 disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Orchestrating Scan...
              </>
            ) : (
              'Scan Website'
            )}
          </button>
        </form>
      </div>

      {/* Unified Report View (Active Scan) */}
      {activeScan && (
        <div className="bg-white dark:bg-zinc-900 p-8 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-800 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-zinc-200 dark:border-zinc-800 gap-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                Unified Report • {activeScan.id}
              </span>
              <h3 className="text-xl font-black text-zinc-900 dark:text-zinc-100 mt-1">
                {activeScan.targetUrl}
              </h3>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                Scanned on {new Date(activeScan.startTime).toLocaleString()} • Status: <span className="font-semibold text-emerald-600">{activeScan.status}</span>
              </p>
            </div>
            <div className="flex gap-2">
              <div className="px-3 py-1.5 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 rounded-lg text-center">
                <span className="text-[10px] text-red-600 dark:text-red-400 block font-bold uppercase">High</span>
                <span className="text-sm font-black text-red-700 dark:text-red-300">{activeScan.severityCounts.High}</span>
              </div>
              <div className="px-3 py-1.5 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 rounded-lg text-center">
                <span className="text-[10px] text-amber-600 dark:text-amber-400 block font-bold uppercase">Medium</span>
                <span className="text-sm font-black text-amber-700 dark:text-amber-300">{activeScan.severityCounts.Medium}</span>
              </div>
            </div>
          </div>

          {/* Section A: Confirmed Scanner Findings (OWASP ZAP) */}
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
              <h4 className="text-md font-bold text-zinc-900 dark:text-zinc-100">
                A. Confirmed Scanner Findings (OWASP ZAP)
              </h4>
            </div>
            {activeScan.findings.length === 0 ? (
              <p className="text-sm text-zinc-500 italic p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-xl">No security findings detected.</p>
            ) : (
              <div className="space-y-3">
                {activeScan.findings.map(f => (
                  <div key={f.id} className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-xl border border-zinc-200 dark:border-zinc-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-sm text-zinc-900 dark:text-zinc-100">{f.name}</span>
                      <span className={`px-2 py-0.5 text-xs font-bold rounded ${
                        f.risk === 'High' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-400' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-400'
                      }`}>
                        {f.risk} Risk
                      </span>
                    </div>
                    <p className="text-xs text-zinc-600 dark:text-zinc-300">{f.description}</p>
                    {f.solution && (
                      <p className="text-xs text-emerald-700 dark:text-emerald-400 font-medium">
                        <strong>Remediation:</strong> {f.solution}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section B: Website Context & Discovered Pages (TinyFish) */}
          <div className="space-y-4 pt-4 border-t border-zinc-200 dark:border-zinc-800">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <h4 className="text-md font-bold text-zinc-900 dark:text-zinc-100">
                B. Website Context & Discovered Pages (TinyFish Intelligence)
              </h4>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {activeScan.discoveredPages.map((page, idx) => (
                <div key={idx} className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-xl border border-zinc-200 dark:border-zinc-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-zinc-900 dark:text-zinc-100 truncate">{page.title}</span>
                    <span className="text-[10px] bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 px-2 py-0.5 rounded font-mono">
                      {page.latencyMs}ms
                    </span>
                  </div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">{page.description}</p>
                  <a href={page.url} target="_blank" rel="noreferrer" className="text-xs font-medium text-emerald-600 dark:text-emerald-400 hover:underline truncate block">
                    {page.url}
                  </a>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Scan History & Comparison */}
      <div className="bg-white dark:bg-zinc-900 p-8 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-800 space-y-6">
        <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">Scan History & Comparison</h3>
        {scans.length === 0 ? (
          <p className="text-sm text-zinc-500 italic">No historical scans recorded yet.</p>
        ) : (
          <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-xl">
            <table className="w-full text-left text-sm text-zinc-600 dark:text-zinc-300">
              <thead className="bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-200 uppercase text-xs">
                <tr>
                  <th className="px-4 py-3">Scan ID</th>
                  <th className="px-4 py-3">Target Host</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Date</th>
                  <th className="px-4 py-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                    <td className="px-4 py-3 font-mono font-medium text-zinc-900 dark:text-zinc-100">{scan.id}</td>
                    <td className="px-4 py-3">{scan.normalizedHost}</td>
                    <td className="px-4 py-3 font-semibold text-zinc-900 dark:text-zinc-100">
                      {scan.totalFindings} (H:{scan.severityCounts.High}, M:{scan.severityCounts.Medium})
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">{new Date(scan.startTime).toLocaleString()}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setActiveScan(scan)}
                        className="px-3 py-1 text-xs font-semibold bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors"
                      >
                        View Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Scan-to-Scan Comparison */}
        <div className="pt-6 border-t border-zinc-200 dark:border-zinc-800 space-y-4">
          <h4 className="text-md font-semibold text-zinc-900 dark:text-zinc-100">Scan-to-Scan Comparison</h4>
          <form onSubmit={handleCompare} className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-zinc-500 mb-1">Older Scan</label>
              <select
                value={olderId}
                onChange={(e) => setOlderId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-xl bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
              >
                <option value="">Select older scan...</option>
                {completedScans.map(s => (
                  <option key={s.id} value={s.id}>{s.id} ({s.normalizedHost})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-500 mb-1">Newer Scan</label>
              <select
                value={newerId}
                onChange={(e) => setNewerId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-xl bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
              >
                <option value="">Select newer scan...</option>
                {completedScans.map(s => (
                  <option key={s.id} value={s.id}>{s.id} ({s.normalizedHost})</option>
                ))}
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={loading}
                className="w-full px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition-colors disabled:opacity-50"
              >
                Compare Scans
              </button>
            </div>
          </form>

          {comparison && (
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-xl border border-zinc-200 dark:border-zinc-800 space-y-3">
              <h5 className="font-bold text-sm text-zinc-900 dark:text-zinc-100">Comparison Results ({comparison.targetHost})</h5>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-2 bg-red-50 dark:bg-red-950/30 rounded-lg">
                  <span className="text-[10px] text-red-600 font-bold block">NEW</span>
                  <span className="text-lg font-black text-red-700">{comparison.summary.newCount}</span>
                </div>
                <div className="p-2 bg-amber-50 dark:bg-amber-950/30 rounded-lg">
                  <span className="text-[10px] text-amber-600 font-bold block">PERSISTENT</span>
                  <span className="text-lg font-black text-amber-700">{comparison.summary.persistentCount}</span>
                </div>
                <div className="p-2 bg-emerald-50 dark:bg-emerald-950/30 rounded-lg">
                  <span className="text-[10px] text-emerald-600 font-bold block">RESOLVED</span>
                  <span className="text-lg font-black text-emerald-700">{comparison.summary.resolvedCount}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
