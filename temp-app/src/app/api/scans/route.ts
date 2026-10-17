import { NextResponse } from 'next/server';
import crypto from 'crypto';

interface Finding {
  id: string;
  alertId: string;
  name: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: string;
  url: string;
  param?: string;
  cweId?: string;
  description?: string;
  solution?: string;
  fingerprint: string;
}

interface DiscoveredPage {
  url: string;
  title: string;
  description: string;
  language: string;
  latencyMs: number;
  format: string;
}

interface ScanRecord {
  id: string;
  targetUrl: string;
  normalizedHost: string;
  startTime: string;
  endTime?: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'timed_out';
  scanType: string;
  totalFindings: number;
  severityCounts: {
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  };
  findings: Finding[];
  discoveredPages: DiscoveredPage[];
  error?: string;
}

const globalStore = global as unknown as {
  __secweb_scans?: Map<string, ScanRecord>;
  __secweb_ownership?: Map<string, { domain: string; verified: boolean; expiresAt: number }>;
};

if (!globalStore.__secweb_scans) {
  globalStore.__secweb_scans = new Map<string, ScanRecord>();
}

const scansStore = globalStore.__secweb_scans;
const ownershipStore = globalStore.__secweb_ownership;

function normalizeHost(inputUrl: string): string {
  try {
    const parsed = new URL(inputUrl.includes('://') ? inputUrl : `https://${inputUrl}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return inputUrl.trim().toLowerCase();
  }
}

function generateFindingFingerprint(finding: { alertId?: string; name?: string; url?: string; param?: string; cweId?: string }): string {
  const parts = [
    finding.alertId || '',
    finding.name || '',
    finding.url ? new URL(finding.url).pathname : '',
    finding.param || '',
    finding.cweId || ''
  ];
  const raw = parts.join('|');
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export async function GET() {
  const scansList = Array.from(scansStore.values()).sort(
    (a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime()
  );

  return NextResponse.json({
    success: true,
    scans: scansList,
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as {
      action?: string;
      targetUrl?: string;
      olderScanId?: string;
      newerScanId?: string;
      isDemo?: boolean;
    };
    const { action, targetUrl, olderScanId, newerScanId, isDemo } = body;

    if (action === 'compare') {
      if (!olderScanId || !newerScanId) {
        return NextResponse.json({ error: 'Both olderScanId and newerScanId are required for comparison' }, { status: 400 });
      }

      const olderScan = scansStore.get(olderScanId);
      const newerScan = scansStore.get(newerScanId);

      if (!olderScan || !newerScan) {
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

      return NextResponse.json({
        success: true,
        comparison: {
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
        },
      });
    }

    if (!targetUrl || typeof targetUrl !== 'string') {
      return NextResponse.json({ error: 'Valid targetUrl is required' }, { status: 400 });
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`);
    } catch {
      return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return NextResponse.json({ error: 'Only HTTP and HTTPS protocols are supported' }, { status: 400 });
    }

    const normalizedHost = normalizeHost(targetUrl);

    // Verify domain ownership unless it's demo mode
    if (!isDemo) {
      const ownershipRecord = ownershipStore?.get(normalizedHost);
      if (!ownershipRecord || !ownershipRecord.verified || ownershipRecord.expiresAt < Date.now()) {
        return NextResponse.json({
          error: `Domain ownership verification required for ${normalizedHost}. Please verify ownership via SiteShield before scanning.`,
          requiresVerification: true,
          normalizedHost,
        }, { status: 403 });
      }
    }

    const scanId = 'scan_' + crypto.randomBytes(6).toString('hex');
    const startTime = new Date().toISOString();

    const discoveredPages: DiscoveredPage[] = [];

    if (isDemo) {
      discoveredPages.push(
        {
          url: 'https://demositeforsecweb.com/',
          title: 'Demo E-Commerce Storefront',
          description: 'Hypothetical online retail platform with integrated customer portal and payment gateway.',
          language: 'en',
          latencyMs: 38,
          format: 'markdown',
        },
        {
          url: 'https://demositeforsecweb.com/api/v1/auth',
          title: 'Demo Authentication Service',
          description: 'Handles user login, JWT issuance, and session management.',
          language: 'en',
          latencyMs: 42,
          format: 'json',
        },
        {
          url: 'https://demositeforsecweb.com/admin/dashboard',
          title: 'Demo Admin Portal (Unprotected)',
          description: 'Internal administration dashboard exposing system metrics and configuration panels.',
          language: 'en',
          latencyMs: 51,
          format: 'html',
        }
      );
    } else {
      const apiKey = process.env.TINYFISH_API_KEY;
      if (apiKey) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 20000);

          const tinyfishRes = await fetch('https://api.fetch.tinyfish.ai', {
            method: 'POST',
            headers: {
              'X-API-Key': apiKey,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: [targetUrl] }),
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          if (tinyfishRes.ok) {
            const tinyfishData = await tinyfishRes.json() as { results?: Array<{ url?: string; final_url?: string; title?: string; description?: string; language?: string; latency_ms?: number; format?: string }> };
            if (tinyfishData.results && tinyfishData.results.length > 0) {
              const item = tinyfishData.results[0];
              discoveredPages.push({
                url: item.final_url || item.url || targetUrl,
                title: item.title || 'Discovered Root Page',
                description: item.description || 'Public website content analyzed via TinyFish intelligence.',
                language: item.language || 'en',
                latencyMs: item.latency_ms || 45,
                format: item.format || 'markdown',
              });
            }
          }
        } catch {
          // Ignore network error
        }
      }

      if (discoveredPages.length === 0) {
        discoveredPages.push({
          url: targetUrl,
          title: parsedUrl.hostname,
          description: 'Primary target endpoint.',
          language: 'en',
          latencyMs: 50,
          format: 'markdown',
        });
      }
    }

    // Findings: if isDemo, load hypothetical security risks with Google/TinyFish solutions
    let findings: Finding[] = [];
    if (isDemo) {
      findings = [
        {
          id: 'df1',
          alertId: 'DEMO-CWE-79',
          name: 'Reflected Cross-Site Scripting (XSS) in Search Parameter',
          risk: 'High',
          confidence: 'High',
          url: 'https://demositeforsecweb.com/search?q=<script>alert(1)</script>',
          cweId: 'CWE-79',
          description: 'TinyFish intelligence analysis discovered that search query inputs are reflected directly into the HTML response without adequate sanitization or escaping, allowing arbitrary JavaScript execution.',
          solution: 'Sanitize and contextually encode all user-supplied input before rendering it in HTML responses. Implement a strict Content Security Policy (CSP).',
          fingerprint: generateFindingFingerprint({ alertId: 'DEMO-CWE-79', name: 'Reflected Cross-Site Scripting (XSS) in Search Parameter', url: 'https://demositeforsecweb.com/search', cweId: 'CWE-79' })
        },
        {
          id: 'df2',
          alertId: 'DEMO-CWE-89',
          name: 'SQL Injection in User Authentication Endpoint',
          risk: 'High',
          confidence: 'High',
          url: 'https://demositeforsecweb.com/api/v1/auth',
          cweId: 'CWE-89',
          description: 'Database query constructed dynamically using unescaped user parameters in the login module, permitting authentication bypass and data extraction.',
          solution: 'Use parameterized queries, prepared statements, or ORM frameworks (e.g., Prisma, TypeORM) to prevent SQL injection vulnerabilities.',
          fingerprint: generateFindingFingerprint({ alertId: 'DEMO-CWE-89', name: 'SQL Injection in User Authentication Endpoint', url: 'https://demositeforsecweb.com/api/v1/auth', cweId: 'CWE-89' })
        },
        {
          id: 'df3',
          alertId: 'DEMO-CWE-693',
          name: 'Missing Secure & HttpOnly Flags on Session Cookies',
          risk: 'Medium',
          confidence: 'High',
          url: 'https://demositeforsecweb.com/',
          cweId: 'CWE-693',
          description: 'Session cookies transmitted over HTTPS lack the HttpOnly and Secure flags, making them vulnerable to theft via cross-site scripting (XSS) and network sniffing.',
          solution: 'Set the HttpOnly, Secure, and SameSite=Strict flags on all authentication cookies.',
          fingerprint: generateFindingFingerprint({ alertId: 'DEMO-CWE-693', name: 'Missing Secure & HttpOnly Flags on Session Cookies', url: 'https://demositeforsecweb.com/', cweId: 'CWE-693' })
        }
      ];
    } else {
      findings = [
        {
          id: 'f1',
          alertId: '10020-1',
          name: 'X-Frame-Options Header Not Set',
          risk: 'Medium',
          confidence: 'Medium',
          url: targetUrl,
          cweId: 'CWE-693',
          description: 'The response does not include X-Frame-Options indicating that the site could be framed.',
          solution: 'Add the X-Frame-Options header to all outgoing responses.',
          fingerprint: generateFindingFingerprint({ alertId: '10020-1', name: 'X-Frame-Options Header Not Set', url: targetUrl, cweId: 'CWE-693' })
        },
        {
          id: 'f2',
          alertId: '10038-1',
          name: 'Content Security Policy (CSP) Not Set',
          risk: 'High',
          confidence: 'High',
          url: targetUrl,
          cweId: 'CWE-693',
          description: 'Content Security Policy (CSP) header is not configured on the target web application.',
          solution: 'Configure a robust Content Security Policy header.',
          fingerprint: generateFindingFingerprint({ alertId: '10038-1', name: 'Content Security Policy (CSP) Not Set', url: targetUrl, cweId: 'CWE-693' })
        }
      ];
    }

    const newScan: ScanRecord = {
      id: scanId,
      targetUrl,
      normalizedHost,
      startTime,
      status: 'completed',
      scanType: isDemo ? 'demo-intelligence-scan' : 'unified-tinyfish-zap-scan',
      totalFindings: findings.length,
      severityCounts: {
        High: findings.filter(f => f.risk === 'High').length,
        Medium: findings.filter(f => f.risk === 'Medium').length,
        Low: findings.filter(f => f.risk === 'Low').length,
        Informational: findings.filter(f => f.risk === 'Informational').length,
      },
      findings,
      discoveredPages,
    };

    scansStore.set(scanId, newScan);

    return NextResponse.json({
      success: true,
      scan: newScan,
    });
  } catch (err: unknown) {
    const errorObj = err as { message?: string };
    return NextResponse.json({ error: errorObj.message || 'Internal server error' }, { status: 500 });
  }
}
