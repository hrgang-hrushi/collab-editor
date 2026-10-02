import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: { absolute: "Crux vs Cursor, VS Code & Zed | Collaborative IDEs" },
  description:
    "Compare coding workflows across Crux, Cursor, VS Code Live Share, and Zed. See where a spatial code canvas, live editing, and an integrated terminal fit your team.",
  alternates: { canonical: "https://codecrux.us/compare" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Crux vs Cursor, VS Code & Zed | Collaborative IDEs",
    description: "Compare collaborative coding workflows across Crux, Cursor, VS Code Live Share, and Zed.",
    url: "https://codecrux.us/compare",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux vs Cursor, VS Code & Zed | Collaborative IDEs",
    description: "Compare collaborative coding workflows across Crux, Cursor, VS Code Live Share, and Zed.",
    images: ["/og-image.png"],
  },
};

const tools = [
  {
    name: "Crux",
    focus: "Shared code editing with a spatial view of files and context",
    usefulWhen: "Your team wants to explore the codebase together while editing and using a terminal.",
    source: "/ide",
    sourceLabel: "Try the Crux IDE",
  },
  {
    name: "Cursor",
    focus: "An AI-focused code editor",
    usefulWhen: "You want AI assistance inside an editor-centered workflow.",
    source: "https://cursor.com/docs",
    sourceLabel: "Cursor documentation",
  },
  {
    name: "VS Code Live Share",
    focus: "Collaborative sessions inside Visual Studio Code",
    usefulWhen: "Your team already works in VS Code and wants to share an editing or debugging session.",
    source: "https://visualstudio.microsoft.com/services/live-share/",
    sourceLabel: "Microsoft Live Share",
  },
  {
    name: "Zed",
    focus: "A code editor with collaboration features",
    usefulWhen: "You want an editor built around fast navigation and real-time teamwork.",
    source: "https://zed.dev/docs/collaboration",
    sourceLabel: "Zed collaboration docs",
  },
];

export default function ComparePage() {
  return (
    <main className="min-h-screen bg-[#000000] text-white font-sans">
      <div className="max-w-6xl mx-auto px-6 py-12 sm:py-20">
        <nav aria-label="Breadcrumb" className="text-xs font-mono text-[#888888] mb-12">
          <Link href="/" className="hover:text-white">Crux</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <span className="text-[#0055FF]">Compare coding tools</span>
        </nav>

        <p className="font-mono text-xs tracking-widest text-[#0055FF] uppercase mb-5">Choose your workflow</p>
        <h1 className="max-w-4xl text-4xl sm:text-6xl font-normal tracking-tight leading-tight">
          Compare collaborative code editors.
        </h1>
        <p className="max-w-3xl mt-6 text-base sm:text-lg leading-relaxed text-[#aaaaaa]">
          Looking at code editor competitors or a Cursor alternative? Start with the way your team works: shared editing, codebase context, and the tools you already use. Crux brings those tasks into one IDE with a spatial code canvas.
        </p>
        <p className="max-w-3xl mt-4 text-sm sm:text-base leading-relaxed text-[#888888]">
          Searches for “code competitors” can mean a coding agent, a pair programming extension, or a full IDE. This guide separates those jobs so you can compare tools that solve the same problem.
        </p>

        <div className="mt-12 border border-[#222222] overflow-x-auto">
          <table className="min-w-[720px] w-full border-collapse text-left">
            <caption className="sr-only">Workflow comparison of Crux, Cursor, VS Code Live Share, and Zed</caption>
            <thead className="bg-[#111111] text-[#888888] text-xs font-mono uppercase tracking-wider">
              <tr>
                <th scope="col" className="p-4 border-b border-r border-[#222222]">Tool</th>
                <th scope="col" className="p-4 border-b border-r border-[#222222]">Main focus</th>
                <th scope="col" className="p-4 border-b border-r border-[#222222]">Consider it when</th>
                <th scope="col" className="p-4 border-b border-[#222222]">Product source</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.name} className="border-b border-[#222222] align-top">
                  <th scope="row" className="p-4 border-r border-[#222222] font-semibold text-white">{tool.name}</th>
                  <td className="p-4 border-r border-[#222222] text-[#cccccc]">{tool.focus}</td>
                  <td className="p-4 border-r border-[#222222] text-[#cccccc]">{tool.usefulWhen}</td>
                  <td className="p-4">
                    <a href={tool.source} className="text-[#74a8ff] underline underline-offset-4" target={tool.source.startsWith("http") ? "_blank" : undefined} rel={tool.source.startsWith("http") ? "noopener noreferrer" : undefined}>
                      {tool.sourceLabel}
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Compare one workflow at a time.</h2>
          <p className="mt-4 max-w-3xl text-[#aaaaaa] leading-relaxed">These guides look at where Crux fits alongside three popular code editor competitors, with links to each product's official documentation.</p>
          <div className="mt-7 grid md:grid-cols-3 gap-4">
            <Link href="/vs-cursor" className="border border-[#222222] bg-[#111111] p-6 hover:border-[#0055FF]">
              <span className="block text-xs font-mono text-[#0055FF] mb-4">AI EDITOR</span>
              <span className="block text-xl text-white">Crux vs Cursor →</span>
              <span className="block mt-3 text-sm text-[#aaaaaa]">Spatial shared context and AI-led editing.</span>
            </Link>
            <Link href="/vs-vscode" className="border border-[#222222] bg-[#111111] p-6 hover:border-[#0055FF]">
              <span className="block text-xs font-mono text-[#0055FF] mb-4">PAIR PROGRAMMING</span>
              <span className="block text-xl text-white">Crux vs VS Code Live Share →</span>
              <span className="block mt-3 text-sm text-[#aaaaaa]">A new workspace or collaboration in your existing editor.</span>
            </Link>
            <Link href="/vs-zed" className="border border-[#222222] bg-[#111111] p-6 hover:border-[#0055FF]">
              <span className="block text-xs font-mono text-[#0055FF] mb-4">MULTIPLAYER EDITOR</span>
              <span className="block text-xl text-white">Crux vs Zed →</span>
              <span className="block mt-3 text-sm text-[#aaaaaa]">Visual codebase context and collaboration rooms.</span>
            </Link>
          </div>
        </section>

        <section className="mt-16 grid md:grid-cols-2 gap-8 items-center border-t border-[#222222] pt-12">
          <div>
            <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">See the whole codebase together.</h2>
            <p className="mt-5 text-[#aaaaaa] leading-relaxed">
              Crux combines a code editor, a spatial view of connected files, live collaboration, and a terminal. Try the browser IDE to decide whether that workflow fits your project.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link href="/ide" className="inline-block px-5 py-3 bg-[#0055FF] border border-[#0055FF] text-white text-sm font-semibold">Try Crux in browser →</Link>
              <Link href="/#waitlist" className="inline-block px-5 py-3 border border-[#444444] text-white text-sm font-semibold">Join the desktop waitlist</Link>
            </div>
          </div>
          <img loading="lazy" decoding="async" src="/email/canvas-preview.png" alt="Crux IDE spatial canvas showing connected files" width="3840" height="2400" className="w-full h-auto border border-[#222222]" />
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12 max-w-3xl">
          <h2 className="text-3xl font-normal">Where does Claude Code fit?</h2>
          <p className="mt-5 text-[#aaaaaa] leading-relaxed">
            If you are searching for Claude Code competitors, note the difference in role: Claude Code is a coding agent, while Crux is an IDE for viewing and editing a shared workspace. A terminal-based agent can be part of an IDE workflow rather than a replacement for it.
          </p>
          <p className="mt-4 text-sm text-[#888888]">
            Read <a href="https://code.claude.com/docs/en/overview" target="_blank" rel="noopener noreferrer" className="text-[#74a8ff] underline">Anthropic’s Claude Code overview</a> for the agent’s current capabilities.
          </p>
        </section>
      </div>
    </main>
  );
}
