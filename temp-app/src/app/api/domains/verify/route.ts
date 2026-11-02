import { NextResponse } from 'next/server';
import { getOrCreateClientId } from '@/lib/session';
import { getDomainsForClient, updateDomainStatus } from '@/lib/db';

function normalizeDomain(input: string): string {
  try {
    const parsed = new URL(input.includes('://') ? input : `https://${input}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return input.trim().toLowerCase();
  }
}

export async function POST(request: Request) {
  try {
    const { clientId, setCookieHeader } = getOrCreateClientId();
    const body = await request.json() as { domainId?: string; domain?: string };
    const { domainId, domain: domainParam } = body;

    const userDomains = getDomainsForClient(clientId);
    let targetRecord = userDomains.find(d => (domainId && d.id === domainId) || (domainParam && d.domain === normalizeDomain(domainParam)));

    if (!targetRecord && domainParam) {
      const norm = normalizeDomain(domainParam);
      targetRecord = userDomains.find(d => d.domain === norm);
    }

    if (!targetRecord) {
      return NextResponse.json({ error: 'Domain record not found. Please register the domain first.' }, { status: 404 });
    }

    const domain = targetRecord.domain;
    let html = '';
    const targetUrl = `https://${domain}`;

    // Try fetching with standard User-Agent, then fallbacks
    const userAgents = [
      'SecWeb-Verifier/1.0',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
    ];

    for (const ua of userAgents) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        const res = await fetch(targetUrl, {
          signal: controller.signal,
          headers: { 'User-Agent': ua, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          html = await res.text();
          if (html && html.length > 50) break;
        }
      } catch {
        // try next
      }
    }

    if (!html) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        const res = await fetch(`http://${domain}`, {
          signal: controller.signal,
          headers: { 'User-Agent': 'SecWeb-Verifier/1.0' },
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          html = await res.text();
        }
      } catch {
        // failed
      }
    }

    const token = targetRecord.verificationToken.trim();

    // Check robustly for token presence anywhere in the fetched HTML document (e.g. in <meta>, comments, or attributes)
    const normalizedHtml = html.toLowerCase();
    const lowerToken = token.toLowerCase();

    const isVerified = normalizedHtml.includes('secweb-verify') && normalizedHtml.includes(lowerToken);

    if (isVerified) {
      const verifiedAt = new Date().toISOString();
      updateDomainStatus(clientId, targetRecord.id, 'verified', verifiedAt);
      const res = NextResponse.json({
        success: true,
        verified: true,
        message: 'Domain ownership successfully verified.',
      });
      if (setCookieHeader) res.headers.set('Set-Cookie', setCookieHeader);
      return res;
    } else {
      const res = NextResponse.json({
        success: false,
        verified: false,
        error: `Verification meta tag not found on ${targetUrl}. Please ensure <meta name="secweb-verify" content="${token}" /> is deployed in the <head> of your website.`,
      }, { status: 400 });
      if (setCookieHeader) res.headers.set('Set-Cookie', setCookieHeader);
      return res;
    }
  } catch (err: unknown) {
    const errorObj = err as { message?: string };
    return NextResponse.json({ error: errorObj.message || 'Verification failed' }, { status: 500 });
  }
}
