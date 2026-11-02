import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { getOrCreateClientId } from '@/lib/session';
import { getDomainRecord, upsertDomain } from '@/lib/db';

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
    const body = await request.json() as { targetUrl?: string };
    const { targetUrl } = body;

    if (!targetUrl) {
      return NextResponse.json({ error: 'Target URL or domain is required' }, { status: 400 });
    }

    const domain = normalizeDomain(targetUrl);
    let record = getDomainRecord(clientId, domain);

    if (!record) {
      const token = 'secweb_verify_' + crypto.randomBytes(16).toString('hex');
      record = {
        id: 'dom_' + crypto.randomBytes(6).toString('hex'),
        clientId,
        domain,
        verificationToken: token,
        status: 'pending',
        verifiedAt: null,
        lastScannedAt: null,
        createdAt: new Date().toISOString(),
      };
      upsertDomain(record);
    }

    const res = NextResponse.json({
      success: true,
      domain: record,
      metaTag: `<meta name="secweb-verify" content="${record.verificationToken}" />`,
    });

    if (setCookieHeader) {
      res.headers.set('Set-Cookie', setCookieHeader);
    }
    return res;
  } catch (err: unknown) {
    const errorObj = err as { message?: string };
    return NextResponse.json({ error: errorObj.message || 'Failed to register domain' }, { status: 500 });
  }
}
