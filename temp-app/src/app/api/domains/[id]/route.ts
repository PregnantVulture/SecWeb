import { NextResponse } from 'next/server';
import { getOrCreateClientId } from '@/lib/session';
import { deleteDomainRecord } from '@/lib/db';

export async function DELETE(request: Request) {
  const urlObj = new URL(request.url);
  const segments = urlObj.pathname.split('/');
  const domainId = segments[segments.length - 1];

  const { clientId, setCookieHeader } = getOrCreateClientId();

  if (!domainId) {
    return NextResponse.json({ error: 'Domain ID is required' }, { status: 400 });
  }

  const success = deleteDomainRecord(clientId, domainId);
  const res = NextResponse.json({ success });
  if (setCookieHeader) res.headers.set('Set-Cookie', setCookieHeader);
  return res;
}
