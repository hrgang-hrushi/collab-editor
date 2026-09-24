import { LocalWriteAheadLog } from "@crux/wal";
import { SyncVector } from "./types";

// Monotonic local-first persistent write-ahead store
export const wal = new LocalWriteAheadLog({
  path: "/var/crux/wal.bin",
  fsyncIntervalMs: 50,
});

/**
 * Commits a state vector change directly to the memory-mapped ring buffer.
 * Automatically replicated to all subscribed edge workers.
 */
export async function persistStateVector(docId: string, bytes: Uint8Array): Promise<number> {
  const monotonicSequence = await wal.append({
    docId,
    payload: bytes,
    timestamp: Date.now(),
  });

  return monotonicSequence;
}

// Verification write
persistStateVector("doc-primary", new Uint8Array([1, 0, 1])).then((seq) => {
  console.log(`[WAL] Committed frame sequence #${seq} to ring buffer`);
});
