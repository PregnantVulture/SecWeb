'use client';

import React, { useState, useEffect, useCallback } from 'react';

export default function SiteShieldVerification({ targetHost, onVerified }: { targetHost: string; onVerified: () => void }) {
  const [domain, setDomain] = useState(targetHost || '');
  const [tokenInfo, setTokenInfo] = useState<{ token: string; metaTag: string; verified: boolean } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchToken = useCallback(async (targetDomain: string) => {
    if (!targetDomain.trim()) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`/api/ownership/verify?domain=${encodeURIComponent(targetDomain)}`);
      const data = await res.json() as { error?: string; token: string; metaTag: string; verified: boolean };
      if (!res.ok) throw new Error(data.error || 'Failed to fetch verification challenge');
      setTokenInfo({
        token: data.token,
        metaTag: data.metaTag,
        verified: data.verified,
      });
      if (data.verified) {
        setSuccessMsg('Domain is already verified.');
        onVerified();
      }
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'Error fetching verification challenge');
    } finally {
      setLoading(false);
    }
  }, [onVerified]);

  useEffect(() => {
    if (targetHost) {
      setDomain(targetHost);
      fetchToken(targetHost);
    }
  }, [targetHost, fetchToken]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch('/api/ownership/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json() as { error?: string; verified: boolean };
      if (!res.ok || !data.verified) {
        throw new Error(data.error || 'Verification check failed. Please ensure the meta tag is correctly deployed.');
      }
      setSuccessMsg('Domain ownership successfully verified!');
      if (tokenInfo) {
        setTokenInfo({ ...tokenInfo, verified: true });
      }
      onVerified();
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 bg-white dark:bg-zinc-900 rounded-xl shadow-md border border-zinc-200 dark:border-zinc-800 my-4 space-y-4">
      <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
        <div>
          <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
            SiteShield Domain Ownership Verification
          </h3>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            Verify ownership of your target domain before executing vulnerability scans.
          </p>
        </div>
        {tokenInfo?.verified ? (
          <span className="px-3 py-1 text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-400 rounded-full flex items-center gap-1">
            ✓ Verified
          </span>
        ) : (
          <span className="px-3 py-1 text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-400 rounded-full">
            Pending Verification
          </span>
        )}
      </div>

      <form onSubmit={handleVerify} className="space-y-4">
        <div className="flex gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="e.g. anshwadhwaold.vercel.app"
            required
            className="flex-1 px-4 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-lg bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="button"
            onClick={() => fetchToken(domain)}
            disabled={loading}
            className="px-4 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-200 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 rounded-lg"
          >
            Get Challenge
          </button>
        </div>

        {tokenInfo && (
          <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-zinc-200 dark:border-zinc-700 space-y-2">
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
              Add this meta tag to the &lt;head&gt; of your website:
            </label>
            <div className="p-2 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded font-mono text-xs text-zinc-800 dark:text-zinc-200 select-all">
              {tokenInfo.metaTag}
            </div>
            <p className="text-xs text-zinc-500">
              Once deployed and published (e.g. on Vercel), click Verify Ownership below.
            </p>
          </div>
        )}

        {error && (
          <div className="p-3 text-sm text-red-700 bg-red-100 dark:bg-red-900/30 dark:text-red-400 rounded-lg border border-red-200">
            {error}
          </div>
        )}

        {successMsg && (
          <div className="p-3 text-sm text-emerald-700 bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400 rounded-lg border border-emerald-200">
            {successMsg}
          </div>
        )}

        {!tokenInfo?.verified && (
          <button
            type="submit"
            disabled={loading || !tokenInfo}
            className="w-full px-6 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify Ownership'}
          </button>
        )}
      </form>
    </div>
  );
}
