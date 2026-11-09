import { NextResponse } from 'next/server';
import { getOrCreateClientId } from '@/lib/session';
import { loadAllScans, loadScan } from '@/lib/persistence';
import type { Finding, ComparisonResult } from '@/lib/types';

export async function GET() {
  const { clientId, setCookieHeader } = getOrCreateClientId();
  const scans = loadAllScans(clientId);

  const res = NextResponse.json({
    success: true,
    scans,
  });

  if (setCookieHeader) res.headers.set('Set-Cookie', setCookieHeader);
  return res;
}

export async function POST(request: Request) {
  try {
    const { clientId, setCookieHeader } = getOrCreateClientId();
    const body = await request.json() as {
      action?: string;
      olderScanId?: string;
      newerScanId?: string;
    };
    const { action, olderScanId, newerScanId } = body;

    if (action === 'compare') {
      if (!olderScanId || !newerScanId) {
        return NextResponse.json({ error: 'Both olderScanId and newerScanId are required for comparison' }, { status: 400 });
      }

      const olderScan = loadScan(olderScanId);
      const newerScan = loadScan(newerScanId);

      if (!olderScan || !newerScan || olderScan.clientId !== clientId || newerScan.clientId !== clientId) {
        return NextResponse.json({ error: 'One or both scan records not found' }, { status: 404 });
      }

      if (olderScan.status !== 'completed' || newerScan.status !== 'completed') {
        return NextResponse.json({ error: 'Only completed scans can be compared' }, { status: 400 });
      }

      if (olderScan.normalizedHost !== newerScan.normalizedHost) {
        return NextResponse.json({ error: 'Cannot compare scans from different target hosts' }, { status: 400 });
      }

      const olderMap = new Map<string, Finding>();
      olderScan.findings.forEach(f => olderMap.set(f.fingerprint, f));

      const newerMap = new Map<string, Finding>();
      newerScan.findings.forEach(f => newerMap.set(f.fingerprint, f));

      const newFindings: Finding[] = [];
      const persistentFindings: { older: Finding; newer: Finding; severityChanged: boolean }[] = [];
      const resolvedFindings: Finding[] = [];

      newerScan.findings.forEach(newerF => {
        const olderF = olderMap.get(newerF.fingerprint);
        if (!olderF) {
          newFindings.push(newerF);
        } else {
          const severityChanged = olderF.risk !== newerF.risk;
          persistentFindings.push({ older: olderF, newer: newerF, severityChanged });
        }
      });

      olderScan.findings.forEach(olderF => {
        if (!newerMap.has(olderF.fingerprint)) {
          resolvedFindings.push(olderF);
        }
      });

      const comparison: ComparisonResult = {
        olderScanId,
        newerScanId,
        targetHost: olderScan.normalizedHost,
        summary: {
          newCount: newFindings.length,
          persistentCount: persistentFindings.length,
          resolvedCount: resolvedFindings.length,
        },
        newFindings,
        persistentFindings,
        resolvedFindings,
      };

      const res = NextResponse.json({
        success: true,
        comparison,
      });
      if (setCookieHeader) res.headers.set('Set-Cookie', setCookieHeader);
      return res;
    }

    return NextResponse.json({ error: 'Invalid action or use GET /api/scans/stream for scanning' }, { status: 400 });
  } catch (err: unknown) {
    const errorObj = err as { message?: string };
    return NextResponse.json({ error: errorObj.message || 'Internal server error' }, { status: 500 });
  }
}
