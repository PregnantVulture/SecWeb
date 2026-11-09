/**
 * File-based scan persistence — mirrors the way Strix writes each run to
 * strix_runs/<run-name>/.  Every scan is a JSON file in .data/scans/<scanId>.json.
 * Domain records stay in the existing .data/secweb_db.json handled by lib/db.ts.
 */

import fs from 'fs';
import path from 'path';
import type { ScanRecord } from './types';

const dataDir = path.join(process.cwd(), '.data', 'scans');

function ensureDir() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
}

export function saveScan(scan: ScanRecord): void {
  ensureDir();
  const filePath = path.join(dataDir, `${scan.id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(scan, null, 2), 'utf8');
}

export function loadScan(scanId: string): ScanRecord | null {
  const filePath = path.join(dataDir, `${scanId}.json`);
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8')) as ScanRecord;
  } catch {
    return null;
  }
}

export function loadAllScans(clientId: string): ScanRecord[] {
  ensureDir();
  const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.json'));
  const scans: ScanRecord[] = [];
  for (const file of files) {
    try {
      const raw = fs.readFileSync(path.join(dataDir, file), 'utf8');
      const scan = JSON.parse(raw) as ScanRecord;
      if (scan.clientId === clientId) scans.push(scan);
    } catch {
      // skip corrupt file
    }
  }
  return scans.sort(
    (a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime()
  );
}

export function updateScanStatus(
  scanId: string,
  patch: Partial<Pick<ScanRecord, 'status' | 'endTime' | 'error'>>
): void {
  const scan = loadScan(scanId);
  if (!scan) return;
  saveScan({ ...scan, ...patch });
}
