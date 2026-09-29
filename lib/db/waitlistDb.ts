import fs from "fs";
import path from "path";
import os from "os";

export interface WaitlistEntry {
  id: string;
  email: string;
  role: string;
  arch: string;
  referralCode: string;
  referredBy?: string;
  contact?: string;
  company?: string;
  teamSize?: string;
  queuePosition: number;
  createdAt: string;
  status: "pending" | "confirmed";
}

const BASE_QUEUE_OFFSET = 1480; // Baseline founding engineer seed for social proof

// In-memory cache across serverless warm executions
let inMemoryEntries: WaitlistEntry[] | null = null;

function getStoragePaths(): { primary: string; fallback: string } {
  const localPath = path.join(process.cwd(), "data", "waitlist.json");
  const tmpPath = path.join(os.tmpdir(), "crux_waitlist.json");
  return { primary: localPath, fallback: tmpPath };
}

export function readWaitlist(): WaitlistEntry[] {
  if (inMemoryEntries !== null && inMemoryEntries.length > 0) {
    return inMemoryEntries;
  }

  const { primary, fallback } = getStoragePaths();

  // Try reading from fallback (/tmp) first if it exists
  if (fs.existsSync(fallback)) {
    try {
      const raw = fs.readFileSync(fallback, "utf-8");
      const parsed = JSON.parse(raw) as WaitlistEntry[];
      inMemoryEntries = parsed;
      return inMemoryEntries;
    } catch (_) {}
  }

  // Next try reading from primary (local repo / seed)
  if (fs.existsSync(primary)) {
    try {
      const raw = fs.readFileSync(primary, "utf-8");
      const parsed = JSON.parse(raw) as WaitlistEntry[];
      inMemoryEntries = parsed;
      return inMemoryEntries;
    } catch (_) {}
  }

  inMemoryEntries = [];
  return inMemoryEntries;
}

export function saveWaitlist(entries: WaitlistEntry[]): void {
  inMemoryEntries = entries;
  const { primary, fallback } = getStoragePaths();

  let saved = false;
  // Try saving to primary (local filesystem)
  try {
    const dir = path.dirname(primary);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const tmpFile = `${primary}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(entries, null, 2), "utf-8");
    fs.renameSync(tmpFile, primary);
    saved = true;
  } catch (_) {
    // Expected in read-only serverless lambdas (/var/task)
  }

  // Always also write to /tmp as reliable writable location in serverless
  try {
    const tmpFile = `${fallback}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(entries, null, 2), "utf-8");
    fs.renameSync(tmpFile, fallback);
  } catch (err) {
    if (!saved) {
      console.warn("[WaitlistDB] Filesystem write failed, retained in memory:", err);
    }
  }
}

export function addToWaitlist(data: {
  email: string;
  role?: string;
  arch?: string;
  referredBy?: string;
  contact?: string;
  company?: string;
  teamSize?: string;
}): { entry: WaitlistEntry; isNew: boolean; totalCount: number } {
  const normalizedEmail = data.email.trim().toLowerCase();
  const entries = readWaitlist();

  const existingIndex = entries.findIndex((e) => e.email === normalizedEmail);
  if (existingIndex !== -1) {
    const existing = entries[existingIndex];
    // Update contact/company/teamSize if provided and previously missing
    let modified = false;
    if (data.contact && !existing.contact) {
      existing.contact = data.contact;
      modified = true;
    }
    if (data.company && !existing.company) {
      existing.company = data.company;
      modified = true;
    }
    if (data.teamSize && !existing.teamSize) {
      existing.teamSize = data.teamSize;
      modified = true;
    }
    if (modified) {
      saveWaitlist(entries);
    }
    return {
      entry: existing,
      isNew: false,
      totalCount: BASE_QUEUE_OFFSET + entries.length,
    };
  }

  const referralCode = `CRUX-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
  const queuePosition = BASE_QUEUE_OFFSET + entries.length + 1;

  const newEntry: WaitlistEntry = {
    id: `wl_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    email: normalizedEmail,
    role: data.role || (data.teamSize ? `Team: ${data.teamSize}` : "Systems & Rust Engineer"),
    arch: data.arch || "apple_silicon",
    referralCode,
    referredBy: data.referredBy,
    contact: data.contact,
    company: data.company,
    teamSize: data.teamSize,
    queuePosition,
    createdAt: new Date().toISOString(),
    status: "confirmed",
  };

  entries.push(newEntry);
  saveWaitlist(entries);

  return {
    entry: newEntry,
    isNew: true,
    totalCount: queuePosition,
  };
}

export function getWaitlistStats(): { totalCount: number; recentCount: number } {
  const entries = readWaitlist();
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const recent = entries.filter((e) => new Date(e.createdAt).getTime() > oneDayAgo).length;

  return {
    totalCount: BASE_QUEUE_OFFSET + entries.length,
    recentCount: recent + 18,
  };
}
