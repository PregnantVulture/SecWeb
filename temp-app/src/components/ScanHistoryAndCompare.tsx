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

export default function ScanHistoryAndCompare() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [olderId, setOlderId] = useState('');
  const [newerId, setNewerId] = useState('');
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showVerificationModal, setShowVerificationModal] = useState(false);

  const fetchScans = async () => {
    try {
      const res = await fetch('/api/scans');
      const data = await res.json() as { success: boolean; scans: ScanRecord[] };
      if (data.success) {
        setScans(data.scans);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl }),
      });
      const data = await res.json() as { error?: string; requiresVerification?: boolean };
      if (!res.ok) {
        if (data.requiresVerification) {
          setShowVerificationModal(true);
        }
        throw new Error(data.error || 'Failed to start scan');
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
    <div className="w-full max-w-4xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-xl shadow-md border border-zinc-200 dark:border-zinc-800 my-8 space-y-8">
      <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">
            Scan History & Scan-to-Scan Comparison
          </h2>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            Track persistent scan records and compare security postures over time.
          </p>
        </div>
        <button
          onClick={() => setShowVerificationModal(!showVerificationModal)}
          className="px-3 py-1 text-xs font-semibold bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-400 rounded-full hover:underline"
        >
          {showVerificationModal ? 'Hide SiteShield' : 'SiteShield Verification'}
        </button>
      </div>

      {showVerificationModal && (
        <SiteShieldVerification
          targetHost={targetUrl}
          onVerified={() => {
            setShowVerificationModal(false);
          }}
        />
      )}

      {error && (
        <div className="p-4 text-sm text-red-700 bg-red-100 dark:bg-red-900/30 dark:text-red-400 rounded-lg border border-red-200 dark:border-red-800">
          {error}
        </div>
      )}

      {/* New Scan Trigger */}
      <form onSubmit={handleStartScan} className="flex gap-3">
        <input
          type="url"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="https://anshwadhwaold.vercel.app"
          required
          className="flex-1 px-4 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-lg bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50"
        >
          {loading ? 'Running...' : 'Run New Scan'}
        </button>
      </form>

      {/* Scan History Table */}
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 mb-3">Recorded Scans</h3>
        {scans.length === 0 ? (
          <p className="text-sm text-zinc-500 dark:text-zinc-400 italic">No historical scans recorded yet.</p>
        ) : (
          <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-lg">
            <table className="w-full text-left text-sm text-zinc-600 dark:text-zinc-300">
              <thead className="bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-200 uppercase text-xs">
                <tr>
                  <th className="px-4 py-3">Scan ID</th>
                  <th className="px-4 py-3">Target Host</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                    <td className="px-4 py-3 font-mono font-medium text-zinc-900 dark:text-zinc-100">{scan.id}</td>
                    <td className="px-4 py-3">{scan.normalizedHost}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${
                        scan.status === 'completed' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-400' :
                        scan.status === 'failed' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-400' :
                        'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-400'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-zinc-900 dark:text-zinc-100">
                      {scan.totalFindings} (H:{scan.severityCounts.High}, M:{scan.severityCounts.Medium})
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">{new Date(scan.startTime).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Compare Scans Section */}
      <div className="border-t border-zinc-200 dark:border-zinc-800 pt-6">
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 mb-3">Scan-to-Scan Comparison</h3>
        <form onSubmit={handleCompare} className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-xs font-medium text-zinc-500 mb-1">Older Scan</label>
            <select
              value={olderId}
              onChange={(e) => setOlderId(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-lg bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
            >
              <option value="">Select older scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>{s.id} ({s.normalizedHost}) - {new Date(s.startTime).toLocaleDateString()}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-500 mb-1">Newer Scan</label>
            <select
              value={newerId}
              onChange={(e) => setNewerId(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-lg bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
            >
              <option value="">Select newer scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>{s.id} ({s.normalizedHost}) - {new Date(s.startTime).toLocaleDateString()}</option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full px-4 py-2 text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg transition-colors disabled:opacity-50"
            >
              Compare Scans
            </button>
          </div>
        </form>

        {comparison && (
          <div className="space-y-4 p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-xl border border-zinc-200 dark:border-zinc-800">
            <h4 className="text-md font-bold text-zinc-900 dark:text-zinc-100">Comparison Results ({comparison.targetHost})</h4>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div className="p-3 bg-red-50 dark:bg-red-950/30 rounded-lg border border-red-200 dark:border-red-900">
                <span className="text-xs text-red-600 dark:text-red-400 block font-medium">New Findings</span>
                <span className="text-xl font-bold text-red-700 dark:text-red-300">{comparison.summary.newCount}</span>
              </div>
              <div className="p-3 bg-amber-50 dark:bg-amber-950/30 rounded-lg border border-amber-200 dark:border-amber-900">
                <span className="text-xs text-amber-600 dark:text-amber-400 block font-medium">Persistent</span>
                <span className="text-xl font-bold text-amber-700 dark:text-amber-300">{comparison.summary.persistentCount}</span>
              </div>
              <div className="p-3 bg-emerald-50 dark:bg-emerald-950/30 rounded-lg border border-emerald-200 dark:border-emerald-900">
                <span className="text-xs text-emerald-600 dark:text-emerald-400 block font-medium">Resolved</span>
                <span className="text-xl font-bold text-emerald-700 dark:text-emerald-300">{comparison.summary.resolvedCount}</span>
              </div>
            </div>

            {comparison.newFindings.length > 0 && (
              <div>
                <h5 className="text-sm font-semibold text-red-600 dark:text-red-400 mb-1">New Vulnerabilities:</h5>
                <ul className="list-disc list-inside text-xs space-y-1">
                  {comparison.newFindings.map((f: Finding) => (
                    <li key={f.id}><span className="font-semibold">{f.name}</span> [{f.risk}]</li>
                  ))}
                </ul>
              </div>
            )}

            {comparison.resolvedFindings.length > 0 && (
              <div>
                <h5 className="text-sm font-semibold text-emerald-600 dark:text-emerald-400 mb-1">Resolved Vulnerabilities:</h5>
                <ul className="list-disc list-inside text-xs space-y-1">
                  {comparison.resolvedFindings.map((f: Finding) => (
                    <li key={f.id}><span className="font-semibold">{f.name}</span> [{f.risk}]</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
