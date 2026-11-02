import { headers } from 'next/headers';
import { NextRequest } from 'next/server';

export function getOrCreateClientId(req?: NextRequest): { clientId: string; setCookieHeader?: string } {
  let clientId = '';

  if (req) {
    const cookieHeader = req.headers.get('cookie') || '';
    const match = cookieHeader.match(/secweb_sid=([^;]+)/);
    if (match) {
      clientId = match[1];
    }
    if (!clientId) {
      clientId = req.headers.get('x-secweb-client-id') || '';
    }
  } else {
    try {
      const h = headers();
      const cookieHeader = h.get('cookie') || '';
      const match = cookieHeader.match(/secweb_sid=([^;]+)/);
      if (match) {
        clientId = match[1];
      }
      if (!clientId) {
        clientId = h.get('x-secweb-client-id') || '';
      }
    } catch {
      // ignore
    }
  }

  let needsNew = false;
  if (!clientId || clientId.length < 10) {
    clientId = 'sec_' + Math.random().toString(36).substring(2) + '_' + Date.now().toString(36);
    needsNew = true;
  }

  const cookieStr = `secweb_sid=${clientId}; Max-Age=315360000; Path=/; SameSite=Lax`;
  return {
    clientId,
    setCookieHeader: needsNew ? cookieStr : undefined,
  };
}
