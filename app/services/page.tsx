import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Code Crux Services — Enterprise Air-Gapped, Dedicated Relays & Custom LSP",
  description:
    "Enterprise systems and deployment services from Code Crux Systems: 100% on-premise air-gapped IDE installations, dedicated private WebRTC mesh relays, custom LSP tree-sitter grammars, and mission-critical 24/7 kernel engineering support.",
  keywords: [
    "Code Crux Services",
    "CodeCrux Services",
    "Code Crux Enterprise",
    "Air-gapped IDE deployment",
    "Private WebRTC relay server",
    "Custom Language Server Protocol",
    "Crux IDE services",
    "codecrux.us services",
  ],
  alternates: {
    canonical: "https://codecrux.us/services",
  },
  openGraph: {
    type: "website",
    url: "https://codecrux.us/services",
    title: "Code Crux Enterprise & Architecture Services",
    description:
      "Enterprise air-gapped IDE deployments, private WebRTC signaling mesh clusters, and custom compiler integrations.",
    siteName: "Code Crux (Crux IDE)",
  },
};

export default function ServicesPage() {
  const services = [
    {
      code: "SRV-01",
      title: "Enterprise Air-Gapped & Sovereign Deployments",
      badge: "MISSION-CRITICAL DEFENSE & FINANCE",
      description:
        "Complete on-premises packaging of the Code Crux IDE ecosystem. Zero outbound internet requests, custom compiled root certificates, local POSIX socket AI inference routing, and isolated network enforcement for compliance-heavy engineering organizations.",
      specs: [
        "100% self-hosted standalone signaling binary (Rust)",
        "Zero external cloud telemetry or tracking packets",
        "Compatible with Red Hat Enterprise Linux, Debian, macOS, and Windows Server",
        "FIPS 140-2 encryption readiness for all local storage ring buffers",
      ],
    },
    {
      code: "SRV-02",
      title: "Private WebRTC Signaling & TURN Mesh Relays",
      badge: "ULTRA-LOW LATENCY GLOBAL TEAMS",
      description:
        "Dedicated global WebRTC signaling infrastructure tailored for distributed enterprise engineering teams. Guaranteed sub-10ms peer-to-peer data channel synchronization with intelligent geo-routed fallback relays.",
      specs: [
        "Global Anycast signaling nodes across 24 AWS & Equinix regions",
        "End-to-end encrypted AST-CRDT peer replication channels",
        "Deterministic NAT traversal with custom enterprise STUN/TURN clusters",
        "Real-time bandwidth throttling and packet loss recovery",
      ],
    },
    {
      code: "SRV-03",
      title: "Custom LSP Bridges & Proprietary Grammar Kernels",
      badge: "SYSTEMS & EMBEDDED LANGUAGES",
      description:
        "Bespoke Tree-sitter grammar parsers and Language Server Protocol (LSP) integrations for proprietary enterprise domain-specific languages (DSLs), aerospace hardware definition languages (VHDL, Verilog), and custom compiler toolchains.",
      specs: [
        "Direct WebGPU token buffer syntax highlighting for custom grammars",
        "Sub-millisecond incremental re-parsing on Apple Silicon & AVX-512",
        "Bidirectional AST symbol graph indexers for multi-million line codebases",
        "Seamless integration with proprietary in-house build daemons",
      ],
    },
    {
      code: "SRV-04",
      title: "Autonomous Agent Fleet Orchestration & PTY daemons",
      badge: "MULTI-AGENT SWARM ENGINEERING",
      description:
        "Architecting multi-agent coding swarms (Amoeba Coding) inside your enterprise infrastructure. Connect Anthropic Claude Code, Google Gemini, OpenAI Codex, or internal open-weights models (Llama 3, DeepSeek) through memory-mapped Unix domain sockets directly to developer editor canvases.",
      specs: [
        "Lock-free AST mutation ring buffers sustaining 50+ concurrent agents",
        "Strict automated syntax validation preventing malformed pull requests",
        "Audit logging and non-repudiation replay records for all AI modifications",
        "Zero API proxy latency via direct host kernel sockets",
      ],
    },
    {
      code: "SRV-05",
      title: "24/7 Kernel Support & Guaranteed Response SLAs",
      badge: "ENTERPRISE ASSURANCE",
      description:
        "Direct access to Code Crux core systems engineers. 15-minute response times for production blocking incidents, dedicated Slack/Discord shared channels, and custom quarterly feature roadmap alignment.",
      specs: [
        "Direct hot-patch releases within 4 hours for critical regressions",
        "Quarterly codebase architecture and performance audits",
        "Dedicated Named Principal Engineer assigned to your account",
        "Custom master service agreements (MSA) and flexible invoicing",
      ],
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Service",
    "@id": "https://codecrux.us/services#service",
    "name": "Code Crux Enterprise & Architecture Services",
    "provider": {
      "@type": "Organization",
      "@id": "https://codecrux.us/#organization",
      "name": "Code Crux Systems",
      "url": "https://codecrux.us",
      "logo": "https://codecrux.us/crux-icon.png",
    },
    "serviceType": "Software Development Tools & Systems Engineering",
    "description":
      "Enterprise deployment, private WebRTC relay infrastructure, custom LSP tree-sitter grammars, and dedicated kernel support from Code Crux Systems.",
    "hasOfferCatalog": {
      "@type": "OfferCatalog",
      "name": "Enterprise Services Catalog",
      "itemListElement": services.map((s, idx) => ({
        "@type": "Offer",
        "position": idx + 1,
        "name": s.title,
        "description": s.description,
      })),
    },
    "breadcrumb": {
      "@type": "BreadcrumbList",
      "itemListElement": [
        {
          "@type": "ListItem",
          "position": 1,
          "name": "Home",
          "item": "https://codecrux.us",
        },
        {
          "@type": "ListItem",
          "position": 2,
          "name": "Services",
          "item": "https://codecrux.us/services",
        },
      ],
    },
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
            <span className="text-[#0055FF] font-bold">ENTERPRISE // ARCHITECTURE SERVICES</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/about" className="text-[#888888] hover:text-white no-underline uppercase">
              About
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/blog" className="text-[#888888] hover:text-white no-underline uppercase">
              Blog
            </Link>
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              LAUNCH IDE ↵
            </Link>
          </nav>
        </div>
      </header>

      {/* Main Body */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [ENTERPRISE INFRASTRUCTURE &amp; SOVEREIGN SOLUTIONS]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Code Crux Enterprise Services.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Designed for engineering organizations that operate under stringent security requirements, demanding
            sub-millisecond collaboration, air-gapped sovereignty, and bespoke compiler toolchains.
          </p>
        </div>

        {/* Services Grid */}
        <section className="py-12 space-y-8">
          {services.map((item, idx) => (
            <div key={idx} className="border border-[#222222] bg-[#0c0c0e] p-8 rounded-none">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] gap-2 mb-6">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs text-[#0055FF] font-bold">{item.code}</span>
                  <h2 className="text-xl sm:text-2xl font-normal text-white">{item.title}</h2>
                </div>
                <div className="font-mono text-[10px] text-[#71717a] border border-[#222222] px-2 py-1 bg-[#000000]">
                  {item.badge}
                </div>
              </div>

              <p className="text-sm text-[#aaaaaa] leading-relaxed mb-6">
                {item.description}
              </p>

              <div>
                <div className="text-xs font-mono text-white uppercase font-bold mb-3">
                  SPECIFICATION DELIVERABLES:
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono text-[#888888]">
                  {item.specs.map((spec, sIdx) => (
                    <div key={sIdx} className="flex items-start gap-2">
                      <span className="text-[#0055FF]">›</span>
                      <span>{spec}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </section>

        {/* Contact Enterprise CTA */}
        <section className="p-8 border border-[#222222] bg-[#0a0a0c] flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <div className="text-xs font-mono text-[#0055FF] font-bold mb-1">[ENGAGE SYSTEMS ARCHITECTS]</div>
            <h3 className="text-2xl font-medium text-white mb-2">Request an Enterprise Deployment Consultation</h3>
            <p className="text-xs text-[#888888] max-w-2xl leading-relaxed">
              Our engineering team responds within 24 hours to schedule an architecture deep dive, air-gapped pilot, or custom SLA evaluation.
            </p>
          </div>
          <div>
            <a
              href="mailto:core@codecrux.us?subject=Enterprise%20Services%20Inquiry%20-%20Code%20Crux"
              className="px-6 py-3 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold text-xs uppercase no-underline inline-block rounded-none"
            >
              CONTACT CORE@CODECRUX.US ↵
            </a>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-xs font-mono text-[#555555]">
        <div className="max-w-[1280px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>© Code Crux Systems 2026. Built for high-velocity software engineering.</div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-white">Home</Link>
            <Link href="/about" className="hover:text-white">About</Link>
            <Link href="/pricing" className="hover:text-white">Pricing</Link>
            <Link href="/blog" className="hover:text-white">Blog</Link>
            <Link href="/services" className="hover:text-white text-white">Services</Link>
            <Link href="/ast-crdt" className="hover:text-white">AST-CRDT</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
