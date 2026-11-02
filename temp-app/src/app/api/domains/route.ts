import { NextResponse } from 'next/server';
import { getOrCreateClientId } from '@/lib/session';
import { getDomainsForClient } from '@/lib/db';

export async function GET() {
  const { clientId, setCookieHeader } = getOrCreateClientId();
  const domains = getDomainsForClient(clientId);

  const res = NextResponse.json({
    success: true,
    domains,
  });

  if (setCookieHeader) {
    res.headers.set('Set-Cookie', setCookieHeader);
  }
  return res;
}
