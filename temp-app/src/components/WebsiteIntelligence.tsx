'use client';

import React, { useState } from 'react';

export default function WebsiteIntelligence() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    url: string;
    finalUrl: string;
    title: string;
    description: string;
    language: string;
    text: string;
    author: string | null;
    publishedDate: string | null;
    latencyMs: number;
    format: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFetch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/api/website-intelligence', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to fetch website intelligence');
      }

      setResult(data.data);
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      setError(errorObj.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-xl shadow-md border border-zinc-200 dark:border-zinc-800 my-8">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">
            Website Intelligence
          </h2>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            Extract clean markdown, titles, and metadata using TinyFish AI.
          </p>
        </div>
        <span className="px-3 py-1 text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400 rounded-full">
          TinyFish Powered
        </span>
      </div>

      <form onSubmit={handleFetch} className="flex gap-3 mb-6">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          required
          className="flex-1 px-4 py-2 text-sm border border-zinc-300 dark:border-zinc-700 rounded-lg bg-zinc-50 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2 text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Extracting...
            </>
          ) : (
            'Inspect URL'
          )}
        </button>
      </form>

      {error && (
        <div className="p-4 mb-4 text-sm text-red-700 bg-red-100 dark:bg-red-900/30 dark:text-red-400 rounded-lg border border-red-200 dark:border-red-800">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4 border-t border-zinc-200 dark:border-zinc-800 pt-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-zinc-200 dark:border-zinc-800">
              <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 block mb-1">Page Title</span>
              <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate block">
                {result.title || 'No Title'}
              </span>
            </div>
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-zinc-200 dark:border-zinc-800">
              <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 block mb-1">Final URL</span>
              <a
                href={result.finalUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-medium text-emerald-600 dark:text-emerald-400 hover:underline truncate block"
              >
                {result.finalUrl}
              </a>
            </div>
            <div className="p-4 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-zinc-200 dark:border-zinc-800">
              <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 block mb-1">Latency / Format</span>
              <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 block">
                {Math.round(result.latencyMs)}ms ({result.format})
              </span>
            </div>
          </div>

          <div className="border border-zinc-200 dark:border-zinc-800 rounded-lg overflow-hidden">
            <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-2 border-b border-zinc-200 dark:border-zinc-800 flex justify-between items-center">
              <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 uppercase tracking-wider">
                Extracted Markdown Content
              </span>
              <span className="text-xs text-zinc-500 dark:text-zinc-400">
                {result.language ? `Lang: ${result.language}` : ''}
              </span>
            </div>
            <div className="p-4 bg-zinc-50 dark:bg-zinc-900/50 max-h-96 overflow-y-auto text-sm font-mono text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap">
              {result.text || 'No content extracted.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
