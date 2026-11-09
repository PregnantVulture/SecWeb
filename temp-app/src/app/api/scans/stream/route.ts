/**
 * SSE streaming endpoint for live scan progress (Strix TUI-style stream).
 * Streams real-time agent thoughts, discovered pages, attack surface, and findings.
 */

import { NextRequest } from 'next/server';
import { getOrCreateClientId } from '@/lib/session';
import { getDomainRecord, upsertDomain } from '@/lib/db';
import { runAiScan } from '@/lib/scanner';
import { saveScan } from '@/lib/persistence';
import type { ScanStreamEvent } from '@/lib/types';
import crypto from 'crypto';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const targetUrl = searchParams.get('targetUrl');
  const isDemo = searchParams.get('isDemo') === 'true';
  const scanDepth = (searchParams.get('scanDepth') === 'comprehensive' ? 'comprehensive' : 'quick') as 'quick' | 'comprehensive';

  if (!targetUrl) {
    return new Response(JSON.stringify({ error: 'targetUrl is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { clientId, setCookieHeader } = getOrCreateClientId(req);

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid URL format' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const normalizedHost = parsedUrl.hostname.toLowerCase();

  // Guardrail: domain verification check
  if (!isDemo) {
    const domainRecord = getDomainRecord(clientId, normalizedHost);
    if (!domainRecord || domainRecord.status !== 'verified') {
      if (!domainRecord) {
        const token = 'secweb_verify_' + crypto.randomBytes(16).toString('hex');
        upsertDomain({
          id: 'dom_' + crypto.randomBytes(6).toString('hex'),
          clientId,
          domain: normalizedHost,
          verificationToken: token,
          status: 'pending',
          verifiedAt: null,
          lastScannedAt: null,
          createdAt: new Date().toISOString(),
        });
      }
      return new Response(JSON.stringify({
        error: `Domain ownership verification required for ${normalizedHost}.`,
        requiresVerification: true,
        normalizedHost,
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const sendEvent = (event: ScanStreamEvent) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          // stream closed
        }
      };

      try {
        const scan = await runAiScan({
          targetUrl,
          isDemo,
          scanDepth,
          onEvent: (event) => sendEvent(event),
        });

        if (scan) {
          scan.clientId = clientId;
          saveScan(scan);
        }
      } catch (err: unknown) {
        const e = err as { message?: string };
        sendEvent({ type: 'error', message: e.message ?? 'Scan failed' });
      } finally {
        try { controller.close(); } catch { /* ignore */ }
      }
    },
  });

  const headers: Record<string, string> = {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
  };
  if (setCookieHeader) {
    headers['Set-Cookie'] = setCookieHeader;
  }

  return new Response(stream, { headers });
}
