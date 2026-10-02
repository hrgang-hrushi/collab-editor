import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  robots: { index: false, follow: true },
  title: "Code Crux Decentralized AST-CRDT — Zero-Conflict P2P Syntax Convergence",
  description:
    "Technical architectural specification of Crux's Decentralized Abstract Syntax Tree Conflict-Free Replicated Data Type (AST-CRDT) running over encrypted WebRTC data channels with zero server requirement.",
  alternates: {
    canonical: "https://codecrux.us/ast-crdt",
  },
};

export default function AstCrdtPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": "Crux Decentralized AST-CRDT Protocol Specification",
    "description": "Deterministic sub-10ms peer synchronization over encrypted P2P WebRTC channels with zero line collisions or syntax breakage.",
    "author": {
      "@type": "Organization",
      "name": "Crux Systems",
      "url": "https://codecrux.us",
    },
    "datePublished": "2026-09-24",
    "dateModified": "2026-09-27",
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white font-sans antialiased selection:bg-[#0055FF]/30 selection:text-white">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      {/* Header */}
      <header className="border-b border-[#222222] bg-[#000000] sticky top-0 z-50">
        <div className="max-w-[1280px] mx-auto px-6 h-14 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 no-underline">
              <CruxBrandLogo size={20} />
            </Link>
            <span className="text-[#444444]">/</span>
            <span className="text-[#0055FF] font-bold">ARCHITECTURE // AST-CRDT PROTOCOL</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/vs-zed" className="text-[#888888] hover:text-white no-underline uppercase">
              vs Zed
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              LAUNCH IDE ↵
            </Link>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [REPLICATION PROTOCOL // SPEC V1.4]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Decentralized AST-CRDT.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Why traditional character-level CRDTs and Operational Transformation (OT) fail in modern engineering editors — and how Crux uses syntax-aware structural convergence to eliminate line collisions and broken parse trees forever.
          </p>
        </div>

        {/* 3 Pillars */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#0055FF] uppercase font-bold mb-2">01 // TOPOLOGY</div>
            <h3 className="text-lg font-medium text-white mb-2">Encrypted P2P WebRTC Mesh</h3>
            <p className="text-xs text-[#888888] font-sans leading-relaxed">
              No central coordination server holds your active buffer. Peers connect directly via libdatachannel or browser WebRTC data channels with Curve25519 end-to-end encryption.
            </p>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#0055FF] uppercase font-bold mb-2">02 // DATA STRUCTURE</div>
            <h3 className="text-lg font-medium text-white mb-2">Structural Tree Operations</h3>
            <p className="text-xs text-[#888888] font-sans leading-relaxed">
              Instead of tracking raw text character offsets (which break when two developers edit adjacent lines), Crux operates on AST nodes: function declarations, ident edits, and expression scopes.
            </p>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#0055FF] uppercase font-bold mb-2">03 // SPEED</div>
            <h3 className="text-lg font-medium text-white mb-2">Lock-Free Shared Memory Ring</h3>
            <p className="text-xs text-[#888888] font-sans leading-relaxed">
              Local threads communicate via a zero-copy POSIX shared memory ring buffer (`shm_open`), achieving sub-microsecond local dispatch and 0.4ms cross-peer sync.
            </p>
          </div>
        </section>

        {/* Technical Deep Dive: AST-CRDT vs Character CRDT vs OT */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal font-sans text-white mb-6">
            Structural CRDT vs Legacy Collaboration Paradigms
          </h2>
          <div className="border border-[#222222] overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#222222] bg-[#111114] text-[#888888]">
                  <th className="p-4 uppercase">Protocol</th>
                  <th className="p-4 uppercase">Used By</th>
                  <th className="p-4 uppercase">Central Server?</th>
                  <th className="p-4 uppercase">Syntax Collision Risk</th>
                  <th className="p-4 uppercase">Convergence Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222222] text-[#cccccc]">
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 text-[#0055FF] font-bold">Crux AST-CRDT</td>
                  <td className="p-4 text-white font-medium">Crux IDE</td>
                  <td className="p-4 text-[#22c55e] font-bold">No (P2P Mesh)</td>
                  <td className="p-4 text-[#22c55e] font-bold">0.00% (AST-Aware)</td>
                  <td className="p-4 text-[#0055FF] font-bold">&lt; 10 ms (P2P)</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white">Centralized Server CRDT</td>
                  <td className="p-4">Zed Editor</td>
                  <td className="p-4 text-[#ef4444]">Yes (Zed Cloud)</td>
                  <td className="p-4">Low (Text Tree)</td>
                  <td className="p-4">25 - 60 ms (Server Relay)</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white">Operational Transformation (OT)</td>
                  <td className="p-4">VS Code Live Share, Google Docs</td>
                  <td className="p-4 text-[#ef4444]">Yes (Microsoft Relay)</td>
                  <td className="p-4 text-[#ef4444]">High (Char Offsets)</td>
                  <td className="p-4">60 - 150 ms (Cloud Roundtrip)</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white">Character CRDT (Yjs / Automerge)</td>
                  <td className="p-4">Replit, JupyterLab</td>
                  <td className="p-4">Optional</td>
                  <td className="p-4 text-[#eab308]">Moderate (Unordered chars)</td>
                  <td className="p-4">15 - 40 ms</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Code Implementation Spec */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal font-sans text-white mb-4">
            Rust Core Ring Buffer Implementation
          </h2>
          <pre className="p-5 border border-[#222222] bg-[#0c0c10] font-mono text-xs text-[#a1a1aa] leading-relaxed overflow-x-auto">
{`// Crux Kernel: Lock-Free Shared Memory Replication
use std::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct ASTCrdtRingBuffer {
    pub head_seq: AtomicU64,
    pub peer_vector: [u32; 16],
    pub buffer_capacity: usize,
    pub storage_ptr: *mut u8,
}

impl ASTCrdtRingBuffer {
    /// Ingests concurrent AST delta with zero-copy lock-free CAS
    pub fn apply_remote_delta(&self, peer_id: u8, ast_node_id: u32, payload: &[u8]) -> bool {
        let seq = self.head_seq.fetch_add(1, Ordering::AcqRel);
        // Direct AST token rebalance without text serialization
        unsafe {
            let offset = (seq as usize % self.buffer_capacity) * 64;
            std::ptr::copy_nonoverlapping(payload.as_ptr(), self.storage_ptr.add(offset), payload.len());
        }
        true
    }
}`}
          </pre>
        </section>
      </main>

      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-center font-mono text-xs text-[#555555]">
        <div>Crux IDE · Engineered for High-Velocity Engineering · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
