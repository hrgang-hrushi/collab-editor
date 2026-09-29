import fs from "fs";
import path from "path";

export interface WaitlistEntry {
  id: string;
  email: string;
  role: string;
  arch: string;
  referralCode: string;
  referredBy?: string;
  queuePosition: number;
  createdAt: string;
  status: "pending" | "confirmed";
}

const DATA_DIR = path.join(process.cwd(), "data");
const DB_FILE = path.join(DATA_DIR, "waitlist.json");
const BASE_QUEUE_OFFSET = 1480; // Baseline founding engineer seed for social proof

function ensureDbFile(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify([], null, 2), "utf-8");
  }
}

export function readWaitlist(): WaitlistEntry[] {
  ensureDbFile();
  try {
    const raw = fs.readFileSync(DB_FILE, "utf-8");
    return JSON.parse(raw) as WaitlistEntry[];
  } catch (err) {
    console.error("[WaitlistDB] Read error:", err);
    return [];
  }
}

export function saveWaitlist(entries: WaitlistEntry[]): void {
  ensureDbFile();
  const tmpFile = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(entries, null, 2), "utf-8");
  fs.renameSync(tmpFile, DB_FILE);
}

export function addToWaitlist(data: {
  email: string;
  role?: string;
  arch?: string;
  referredBy?: string;
}): { entry: WaitlistEntry; isNew: boolean; totalCount: number } {
  const normalizedEmail = data.email.trim().toLowerCase();
  const entries = readWaitlist();

  const existingIndex = entries.findIndex((e) => e.email === normalizedEmail);
  if (existingIndex !== -1) {
    const existing = entries[existingIndex];
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
    role: data.role || "Systems & Rust Engineer",
    arch: data.arch || "apple_silicon",
    referralCode,
    referredBy: data.referredBy,
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
