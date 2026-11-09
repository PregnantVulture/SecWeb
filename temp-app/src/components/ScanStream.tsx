'use client';

import React, { useState, useEffect } from 'react';
import type { ScanRecord, ScanStreamEvent, DiscoveredPage, ThreatModel, Finding } from '@/lib/types';

interface ScanStreamProps {
  targetUrl: string;
  isDemo: boolean;
  scanDepth?: 'quick' | 'comprehensive';
  onScanComplete: (scan: ScanRecord) => void;
  onError: (msg: string) => void;
  onCancel: () => void;
}

export default function ScanStream({ targetUrl, isDemo, scanDepth = 'quick', onScanComplete, onError, onCancel }: ScanStreamProps) {
  const [logs, setLogs] = useState<string[]>([]);
  const [pages, setPages] = useState<DiscoveredPage[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [threatModel, setThreatModel] = useState<ThreatModel | null>(null);
  const [statusMessage, setStatusMessage] = useState('Initializing AI penetration testing engine...');
  const [progressPercent, setProgressPercent] = useState(15);

  useEffect(() => {
    const encodedUrl = encodeURIComponent(targetUrl);
    const eventSource = new EventSource(`/api/scans/stream?targetUrl=${encodedUrl}&isDemo=${isDemo}&scanDepth=${scanDepth}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as ScanStreamEvent;

        if (data.type === 'status') {
          setStatusMessage(data.message);
          setLogs(prev => [...prev, data.message]);
          setProgressPercent(p => Math.min(p + 20, 90));
        } else if (data.type === 'page_discovered') {
          setPages(prev => [...prev, data.page]);
          setLogs(prev => [...prev, `Discovered asset: ${data.page.url} (${data.page.pageType})`]);
        } else if (data.type === 'attack_surface') {
          setThreatModel(data.threatModel);
          setLogs(prev => [...prev, `Threat model mapped: ${data.threatModel.entryPoints.length} entry points identified`]);
        } else if (data.type === 'finding') {
          setFindings(prev => [...prev, data.finding]);
          setLogs(prev => [...prev, `[${data.finding.risk}] Finding confirmed: ${data.finding.name}`]);
        } else if (data.type === 'complete') {
          setProgressPercent(100);
          setStatusMessage('Scan completed successfully with CVSS scoring & PoC validation.');
          eventSource.close();
          onScanComplete(data.scan);
        } else if (data.type === 'error') {
          eventSource.close();
          onError(data.message);
        }
      } catch {
        // parse error
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      onError('Scan stream connection lost or server error');
    };

    return () => {
      eventSource.close();
    };
  }, [targetUrl, isDemo, scanDepth, onScanComplete, onError]);

  return (
    <div className="bg-zinc-950/90 backdrop-blur-xl p-8 rounded-2xl border border-zinc-800 shadow-2xl space-y-6 animate-fade-in">
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
            <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider">SecWeb AI Engine Live Stream</span>
          </div>
          <h3 className="text-lg font-black text-zinc-100 mt-1 font-mono">{targetUrl}</h3>
        </div>
        <button
          onClick={onCancel}
          className="px-3 py-1.5 text-xs font-semibold bg-zinc-900 text-zinc-400 border border-zinc-800 rounded-lg hover:text-zinc-200"
        >
          Cancel Scan
        </button>
      </div>

      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
          <span>{statusMessage}</span>
          <span className="text-emerald-400 font-bold">{progressPercent}%</span>
        </div>
        <div className="w-full h-2 bg-zinc-900 rounded-full overflow-hidden border border-zinc-800">
          <div
            className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 transition-all duration-500 ease-out"
            style={{ width: `${progressPercent}%` }}
          ></div>
        </div>
      </div>

      {/* Live metrics counters */}
      <div className="grid grid-cols-3 gap-3">
        <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800 text-center">
          <span className="text-[10px] text-zinc-400 uppercase block font-bold">Discovered Assets</span>
          <span className="text-base font-black text-zinc-100">{pages.length}</span>
        </div>
        <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800 text-center">
          <span className="text-[10px] text-zinc-400 uppercase block font-bold">Attack Surface Entries</span>
          <span className="text-base font-black text-blue-400">{threatModel ? threatModel.entryPoints.length : 0}</span>
        </div>
        <div className="p-3 bg-zinc-900/60 rounded-xl border border-zinc-800 text-center">
          <span className="text-[10px] text-red-400 uppercase block font-bold">Findings Confirmed</span>
          <span className="text-base font-black text-red-300">{findings.length}</span>
        </div>
      </div>

      {/* Terminal Live Output Log */}
      <div className="space-y-2">
        <span className="text-xs font-bold text-zinc-400 uppercase font-mono">Agent Execution Log & Thoughts</span>
        <div className="p-4 bg-zinc-900/95 rounded-xl border border-zinc-800 font-mono text-[11px] text-zinc-300 h-48 overflow-y-auto space-y-1.5 shadow-inner">
          {logs.map((log, idx) => (
            <div key={idx} className="flex items-start gap-2">
              <span className="text-emerald-500 select-none">❯</span>
              <span className={log.includes('Finding confirmed') ? 'text-red-400 font-bold' : log.includes('Threat model') ? 'text-blue-400 font-bold' : 'text-zinc-300'}>
                {log}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
