import fs from 'fs';
import path from 'path';

const dataDir = path.join(process.cwd(), '.data');
if (!fs.existsSync(dataDir)) {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
  } catch {
    // ignore
  }
}

const dbFilePath = path.join(dataDir, 'secweb_db.json');

interface DomainRecord {
  id: string;
  clientId: string;
  domain: string;
  verificationToken: string;
  status: 'pending' | 'verified';
  verifiedAt: string | null;
  lastScannedAt: string | null;
  createdAt: string;
}

interface ScanStoreRecord {
  id: string;
  clientId: string;
  targetUrl: string;
  normalizedHost: string;
  startTime: string;
  status: string;
  [key: string]: unknown;
}

interface DatabaseData {
  domains: DomainRecord[];
  scans: ScanStoreRecord[];
}

function readDb(): DatabaseData {
  try {
    if (fs.existsSync(dbFilePath)) {
      const raw = fs.readFileSync(dbFilePath, 'utf8');
      const parsed = JSON.parse(raw);
      return {
        domains: Array.isArray(parsed.domains) ? parsed.domains : [],
        scans: Array.isArray(parsed.scans) ? parsed.scans : [],
      };
    }
  } catch {
    // ignore
  }
  return { domains: [], scans: [] };
}

function writeDb(data: DatabaseData) {
  try {
    fs.writeFileSync(dbFilePath, JSON.stringify(data, null, 2), 'utf8');
  } catch {
    // ignore
  }
}

export function getDomainsForClient(clientId: string): DomainRecord[] {
  const db = readDb();
  return db.domains.filter(d => d.clientId === clientId);
}

export function getDomainRecord(clientId: string, domain: string): DomainRecord | undefined {
  const db = readDb();
  return db.domains.find(d => d.clientId === clientId && d.domain === domain);
}

export function upsertDomain(record: DomainRecord): DomainRecord {
  const db = readDb();
  const idx = db.domains.findIndex(d => d.clientId === record.clientId && d.domain === record.domain);
  if (idx >= 0) {
    db.domains[idx] = { ...db.domains[idx], ...record };
  } else {
    db.domains.push(record);
  }
  writeDb(db);
  return record;
}

export function updateDomainStatus(clientId: string, domainId: string, status: 'pending' | 'verified', verifiedAt?: string): DomainRecord | null {
  const db = readDb();
  const idx = db.domains.findIndex(d => d.clientId === clientId && d.id === domainId);
  if (idx < 0) return null;
  db.domains[idx].status = status;
  if (verifiedAt !== undefined) {
    db.domains[idx].verifiedAt = verifiedAt;
  }
  writeDb(db);
  return db.domains[idx];
}

export function deleteDomainRecord(clientId: string, domainId: string): boolean {
  const db = readDb();
  const initialLen = db.domains.length;
  db.domains = db.domains.filter(d => !(d.clientId === clientId && d.id === domainId));
  if (db.domains.length !== initialLen) {
    writeDb(db);
    return true;
  }
  return false;
}
