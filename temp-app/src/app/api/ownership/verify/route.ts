import { NextResponse } from 'next/server';
import crypto from 'crypto';

interface OwnershipRecord {
  domain: string;
  token: string;
  verified: boolean;
  verifiedAt?: string;
  expiresAt: number;
}

const globalStore = global as unknown as {
  __secweb_ownership?: Map<string, OwnershipRecord>;
};

if (!globalStore.__secweb_ownership) {
  globalStore.__secweb_ownership = new Map<string, OwnershipRecord>();
}

const ownershipStore = globalStore.__secweb_ownership;

function normalizeDomain(inputUrlOrDomain: string): string {
  try {
    const parsed = new URL(inputUrlOrDomain.includes('://') ? inputUrlOrDomain : `https://${inputUrlOrDomain}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return inputUrlOrDomain.trim().toLowerCase();
  }
}

export async function GET(request: Request) {
  const urlObj = new URL(request.url);
  const domainParam = urlObj.searchParams.get('domain');

  if (!domainParam) {
    return NextResponse.json({ error: 'Domain parameter is required' }, { status: 400 });
  }

  const domain = normalizeDomain(domainParam);
  let record = ownershipStore.get(domain);

  if (!record) {
    // Generate new token
    const token = 'tf_verify_' + crypto.randomBytes(16).toString('hex');
    record = {
      domain,
      token,
      verified: false,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    };
    ownershipStore.set(domain, record);
  } else if (record.expiresAt < Date.now()) {
    // Refresh expired token
    const token = 'tf_verify_' + crypto.randomBytes(16).toString('hex');
    record.token = token;
    record.verified = false;
    record.expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    ownershipStore.set(domain, record);
  }

  return NextResponse.json({
    success: true,
    domain,
    token: record.token,
    verified: record.verified,
    metaTag: `<meta name="siteshield-verify" content="${record.token}" />`,
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as { domain?: string };
    const { domain: domainParam } = body;

    if (!domainParam) {
      return NextResponse.json({ error: 'Domain is required for verification' }, { status: 400 });
    }

    const domain = normalizeDomain(domainParam);
    const record = ownershipStore.get(domain);

    if (!record) {
      return NextResponse.json({ error: 'No active verification challenge found for domain. Please request a token first.' }, { status: 404 });
    }

    if (record.expiresAt < Date.now()) {
      return NextResponse.json({ error: 'Verification token expired. Please request a new token.' }, { status: 400 });
    }

    // Server-side verification fetch
    let html = '';
    const targetUrl = `https://${domain}`;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(targetUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'SecWeb-SiteShield-Verifier/1.0',
        },
      });
      clearTimeout(timeoutId);
      if (res.ok) {
        html = await res.text();
      }
    } catch {
      // Try http if https fails
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        const res = await fetch(`http://${domain}`, {
          signal: controller.signal,
          headers: {
            'User-Agent': 'SecWeb-SiteShield-Verifier/1.0',
          },
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          html = await res.text();
        }
      } catch {
        // Fetch failed
      }
    }

    // Check if meta tag containing the token is present in the HTML
    const expectedMeta = `<meta name="siteshield-verify" content="${record.token}" />`;
    const altMeta1 = `<meta content="${record.token}" name="siteshield-verify"/>`;
    const altMeta2 = `<meta name="siteshield-verify" content='${record.token}' />`;

    const isVerified = html.includes(expectedMeta) ||
                       html.includes(altMeta1) ||
                       html.includes(altMeta2) ||
                       html.includes(`name="siteshield-verify"`) && html.includes(record.token);

    if (isVerified) {
      record.verified = true;
      record.verifiedAt = new Date().toISOString();
      ownershipStore.set(domain, record);
      return NextResponse.json({
        success: true,
        verified: true,
        message: 'Domain ownership successfully verified.',
      });
    } else {
      return NextResponse.json({
        success: false,
        verified: false,
        error: `Verification meta tag not found on ${targetUrl}. Please ensure <meta name="siteshield-verify" content="${record.token}" /> is deployed in the <head> of your website.`,
      }, { status: 400 });
    }
  } catch (err: unknown) {
    const errorObj = err as { message?: string };
    return NextResponse.json({ error: errorObj.message || 'Verification failed' }, { status: 500 });
  }
}
