'use client';

import React, { useState, useEffect, useCallback } from 'react';

interface DomainRecord {
  id: string;
  domain: string;
  verificationToken: string;
  status: 'pending' | 'verified';
  verifiedAt: string | null;
}

export default function SecWebVerification({
  targetHost,
  onVerified,
  onDomainSelected,
}: {
  targetHost: string;
  onVerified: () => void;
  onDomainSelected?: (domain: string) => void;
}) {
  const [domains, setDomains] = useState<DomainRecord[]>([]);
  const [selectedDomainId, setSelectedDomainId] = useState<string>('');
  const [newDomainInput, setNewDomainInput] = useState(targetHost || '');
  const [activeTokenInfo, setActiveTokenInfo] = useState<{ id: string; domain: string; token: string; metaTag: string; status: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);

  // Sync client id helper
  const getClientIdHeaders = (): Record<string, string> => {
    if (typeof window === 'undefined') return {};
    let clientId = localStorage.getItem('secweb_device_id');
    if (!clientId) {
      clientId = 'sec_' + Math.random().toString(36).substring(2) + '_' + Date.now().toString(36);
      localStorage.setItem('secweb_device_id', clientId);
    }
    return { 'x-secweb-client-id': clientId };
  };

  const fetchDomains = useCallback(async () => {
    try {
      const headersObj = getClientIdHeaders();
      const res = await fetch('/api/domains', {
        headers: headersObj,
      });
      const data = await res.json() as { success: boolean; domains: DomainRecord[] };
      if (data.success) {
        setDomains(data.domains);
        if (targetHost && !selectedDomainId) {
          const match = data.domains.find(d => d.domain === targetHost.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''));
          if (match) {
            setSelectedDomainId(match.id);
            if (match.status === 'verified') onVerified();
          }
        }
      }
    } catch {
      // ignore
    }
  }, [targetHost, selectedDomainId, onVerified]);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  useEffect(() => {
    if (targetHost) {
      setNewDomainInput(targetHost);
    }
  }, [targetHost]);

  const handleRegisterDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomainInput.trim()) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const headersObj: Record<string, string> = {
        'Content-Type': 'application/json',
        ...getClientIdHeaders(),
      };
      const res = await fetch('/api/domains/register', {
        method: 'POST',
        headers: headersObj,
        body: JSON.stringify({ targetUrl: newDomainInput }),
      });
      const data = await res.json() as { error?: string; domain?: DomainRecord; metaTag?: string };
      if (!res.ok) throw new Error(data.error || 'Failed to register domain');

      if (data.domain) {
        setActiveTokenInfo({
          id: data.domain.id,
          domain: data.domain.domain,
          token: data.domain.verificationToken,
          metaTag: `<meta name="secweb-verify" content="${data.domain.verificationToken}" />`,
          status: data.domain.status,
        });
        setSelectedDomainId(data.domain.id);
        if (onDomainSelected) onDomainSelected(data.domain.domain);
      }
      await fetchDomains();
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'Error registering domain');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOwnership = async (domainId: string) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const headersObj: Record<string, string> = {
        'Content-Type': 'application/json',
        ...getClientIdHeaders(),
      };
      const res = await fetch('/api/domains/verify', {
        method: 'POST',
        headers: headersObj,
        body: JSON.stringify({ domainId }),
      });
      const data = await res.json() as { error?: string; verified: boolean; message?: string };
      if (!res.ok || !data.verified) {
        throw new Error(data.error || 'Verification check failed. Please ensure meta tag is deployed.');
      }
      setSuccessMsg('Domain ownership successfully verified!');
      await fetchDomains();
      onVerified();
      setShowAddModal(false);
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteDomain = async (domainId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to remove this saved domain?')) return;
    try {
      const headersObj = getClientIdHeaders();
      await fetch(`/api/domains/${domainId}`, {
        method: 'DELETE',
        headers: headersObj,
      });
      await fetchDomains();
      if (selectedDomainId === domainId) {
        setSelectedDomainId('');
        setActiveTokenInfo(null);
      }
    } catch {
      // ignore
    }
  };

  const selectedDomainRecord = domains.find(d => d.id === selectedDomainId);

  return (
    <div className="p-6 bg-zinc-950/90 rounded-2xl shadow-xl border border-zinc-800 my-4 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
        <div>
          <h3 className="text-base font-bold text-zinc-100">
            Domain Verification & Persistent Identity
          </h3>
          <p className="text-xs text-zinc-400 mt-0.5">
            Your verified domains are securely linked to your long-lived browser session. No login required.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(!showAddModal)}
          className="px-3.5 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl transition-colors shadow-lg shadow-emerald-600/20"
        >
          {showAddModal ? 'Close Registration' : '+ Add New Domain'}
        </button>
      </div>

      {/* Saved Domains Quick Selector */}
      {domains.length > 0 && !showAddModal && (
        <div className="space-y-2.5">
          <label className="block text-xs font-bold uppercase tracking-wider text-zinc-400">
            Your Saved & Verified Domains ({domains.length})
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {domains.map(d => {
              const isSelected = selectedDomainId === d.id;
              const isVerified = d.status === 'verified';
              return (
                <div
                  key={d.id}
                  onClick={() => {
                    setSelectedDomainId(d.id);
                    if (onDomainSelected) onDomainSelected(d.domain);
                    if (isVerified) onVerified();
                    setActiveTokenInfo({
                      id: d.id,
                      domain: d.domain,
                      token: d.verificationToken,
                      metaTag: `<meta name="secweb-verify" content="${d.verificationToken}" />`,
                      status: d.status,
                    });
                  }}
                  className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center justify-between gap-2 ${
                    isSelected
                      ? 'bg-emerald-950/40 border-emerald-500/80 shadow-md'
                      : 'bg-zinc-900/60 border-zinc-800 hover:border-zinc-700'
                  }`}
                >
                  <div className="truncate">
                    <div className="text-xs font-bold text-zinc-200 truncate font-mono">{d.domain}</div>
                    <div className="text-[10px] flex items-center gap-1 mt-0.5">
                      {isVerified ? (
                        <span className="text-emerald-400 font-semibold">Verified Ready</span>
                      ) : (
                        <span className="text-amber-400 font-semibold">Verification Pending</span>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={(e) => handleDeleteDomain(d.id, e)}
                    className="text-zinc-500 hover:text-red-400 p-1 text-xs"
                    title="Remove Domain"
                  >
                    ✕
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Add / Register Domain Modal or Section */}
      {(showAddModal || domains.length === 0) && (
        <div className="p-5 bg-zinc-900/60 rounded-xl border border-zinc-800 space-y-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-300">Register Target Domain for Ownership Check</h4>
          <form onSubmit={handleRegisterDomain} className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={newDomainInput}
              onChange={(e) => setNewDomainInput(e.target.value)}
              placeholder="e.g. example.com or https://example.com"
              required
              className="flex-1 px-4 py-2.5 text-xs border border-zinc-700 rounded-xl bg-zinc-950 text-zinc-100 focus:ring-2 focus:ring-emerald-500 font-mono"
            />
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition-colors disabled:opacity-50"
            >
              {loading ? 'Generating...' : 'Get Challenge'}
            </button>
          </form>

          {activeTokenInfo && (
            <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800 space-y-3">
              <div className="text-xs font-semibold text-zinc-300">
                Deploy this meta tag into the <code className="text-emerald-400 font-mono">&lt;head&gt;</code> of <span className="font-mono text-emerald-300">{activeTokenInfo.domain}</span>:
              </div>
              <div className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg font-mono text-xs text-emerald-400 select-all overflow-x-auto">
                {activeTokenInfo.metaTag}
              </div>
              <div className="flex items-center justify-between pt-1">
                <span className="text-[11px] text-zinc-400">
                  Status: <strong className={activeTokenInfo.status === 'verified' ? 'text-emerald-400' : 'text-amber-400'}>{activeTokenInfo.status}</strong>
                </span>
                <button
                  type="button"
                  onClick={() => handleVerifyOwnership(activeTokenInfo.id)}
                  disabled={loading}
                  className="px-5 py-2 text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg transition-colors shadow-md shadow-emerald-600/20"
                >
                  {loading ? 'Verifying...' : 'Verify Ownership Now'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {selectedDomainRecord && selectedDomainRecord.status === 'verified' && !showAddModal && (
        <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-xl flex items-center justify-between text-xs">
          <span className="text-emerald-300 font-medium">
            Active Target <strong className="font-mono">{selectedDomainRecord.domain}</strong> is Verified and Ready for Scanning.
          </span>
          <span className="text-emerald-400 font-bold">Ready</span>
        </div>
      )}

      {error && (
        <div className="p-3 text-xs text-red-400 bg-red-950/40 rounded-xl border border-red-900">
          {error}
        </div>
      )}

      {successMsg && (
        <div className="p-3 text-xs text-emerald-400 bg-emerald-950/40 rounded-xl border border-emerald-900">
          {successMsg}
        </div>
      )}
    </div>
  );
}
