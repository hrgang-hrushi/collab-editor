import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: { absolute: "Crux IDE Docs: Canvas, Collaboration & Shortcuts" },
  description:
    "Get started with the Crux browser IDE. Learn how to use the spatial code canvas, open files, share a workspace, and navigate with keyboard shortcuts.",
  alternates: { canonical: "https://codecrux.us/docs" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Crux IDE Docs: Canvas, Collaboration & Shortcuts",
    description: "A practical guide to the Crux browser workspace and its visible controls.",
    url: "https://codecrux.us/docs",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux IDE Docs: Canvas, Collaboration & Shortcuts",
    description: "A practical guide to the Crux browser workspace and its visible controls.",
    images: ["/og-image.png"],
  },
};

const shortcuts = [
  { action: "Search files and commands", keys: "⌘ / Ctrl + P" },
  { action: "Toggle the file explorer", keys: "⌘ / Ctrl + B" },
  { action: "Toggle the terminal panel", keys: "⌘ / Ctrl + J" },
  { action: "Open the AI assistant", keys: "⌘ / Ctrl + I" },
  { action: "Open settings", keys: "⌘ / Ctrl + ," },
];

export default function DocsPage() {
  return (
    <main className="min-h-screen bg-[#000000] text-white font-sans">
      <div className="max-w-6xl mx-auto px-6 py-12 sm:py-20">
        <nav aria-label="Breadcrumb" className="text-xs font-mono text-[#888888] mb-12">
          <Link href="/" className="hover:text-white">Crux</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <span className="text-[#0055FF]">Documentation</span>
        </nav>

        <p className="font-mono text-xs tracking-widest text-[#0055FF] uppercase mb-5">Browser IDE · Getting started</p>
        <h1 className="max-w-5xl text-4xl sm:text-6xl font-normal tracking-tight leading-tight">Crux IDE documentation</h1>
        <p className="max-w-4xl mt-7 text-base sm:text-lg leading-relaxed text-[#aaaaaa]">
          This guide covers the controls in the current Crux browser IDE: opening the workspace, switching between editor and canvas, bringing files into view, and sharing a session. The desktop experience is available through the waitlist.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link href="/ide" className="inline-block px-5 py-3 bg-[#0055FF] border border-[#0055FF] text-white text-sm font-semibold">Open Crux IDE →</Link>
          <Link href="/code-editor" className="inline-block px-5 py-3 border border-[#444444] text-white text-sm font-semibold">Explore the editor</Link>
        </div>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Start in the browser</h2>
          <ol className="mt-7 grid md:grid-cols-3 border border-[#222222] md:divide-x divide-[#222222]">
            <li className="p-6 sm:p-7 border-b md:border-b-0 border-[#222222]">
              <p className="font-mono text-xs text-[#0055FF] mb-6">01 / OPEN</p>
              <h3 className="text-xl font-medium mb-4">Launch the IDE</h3>
              <p className="text-sm leading-relaxed text-[#aaaaaa]">Visit <Link href="/ide" className="text-[#74a8ff] underline underline-offset-4">codecrux.us/ide</Link>. The start screen offers Quick Boot Workspace for a sample project and Import Project Folder for your own files.</p>
            </li>
            <li className="p-6 sm:p-7 border-b md:border-b-0 border-[#222222]">
              <p className="font-mono text-xs text-[#0055FF] mb-6">02 / NAVIGATE</p>
              <h3 className="text-xl font-medium mb-4">Choose a view</h3>
              <p className="text-sm leading-relaxed text-[#aaaaaa]">Use the Editor and Canvas buttons at the top of the workspace. The file explorer lists project files, while Canvas lets you see several open files together.</p>
            </li>
            <li className="p-6 sm:p-7">
              <p className="font-mono text-xs text-[#0055FF] mb-6">03 / WORK</p>
              <h3 className="text-xl font-medium mb-4">Keep tools nearby</h3>
              <p className="text-sm leading-relaxed text-[#aaaaaa]">Use the Files and Terminal buttons to show or hide those panels. The command palette also lets you search files and workspace actions.</p>
            </li>
          </ol>
        </section>

        <section className="mt-16 grid md:grid-cols-2 gap-10 items-center border-t border-[#222222] pt-12">
          <div>
            <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Understand the spatial canvas</h2>
            <p className="mt-5 text-[#aaaaaa] leading-relaxed">
              Canvas mode gives you a wider view of the files in a task. Zoom out to see multiple open files, and use the connection controls to draw arrows that explain relationships in the codebase. Return to Editor mode when you want to focus on text.
            </p>
            <p className="mt-4 text-sm text-[#888888] leading-relaxed">
              If you are comparing this approach with another editor, read the <Link href="/compare" className="text-[#74a8ff] underline underline-offset-4">collaborative IDE comparison</Link>.
            </p>
          </div>
          <img loading="lazy" decoding="async" src="/email/canvas-preview.png" alt="Crux spatial code canvas with several connected code files" width="3840" height="2400" className="w-full h-auto border border-[#222222]" />
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Share a workspace</h2>
          <div className="mt-7 grid md:grid-cols-2 gap-6">
            <div className="border border-[#222222] bg-[#111111] p-6 sm:p-8">
              <h3 className="text-xl font-medium">Copy a collaboration link</h3>
              <p className="mt-4 text-sm leading-relaxed text-[#aaaaaa]">Select Share in the workspace header. The dialog offers a full-edit link and a view-only link. Choose the access level you intend, copy the link, and send it to a collaborator you trust.</p>
            </div>
            <div className="border border-[#222222] bg-[#111111] p-6 sm:p-8">
              <h3 className="text-xl font-medium">Follow live edits</h3>
              <p className="mt-4 text-sm leading-relaxed text-[#aaaaaa]">Shared text and teammate cursor presence help participants see which part of the project is being edited. Keep the canvas visible when you need to discuss related files.</p>
            </div>
          </div>
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Keyboard shortcuts</h2>
          <p className="mt-4 text-[#aaaaaa] leading-relaxed">Use Command on macOS or Control where supported. Custom keybindings in settings can override the defaults.</p>
          <div className="mt-7 border border-[#222222] divide-y divide-[#222222]">
            {shortcuts.map(({ action, keys }) => (
              <div key={action} className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 p-4 sm:px-6 text-sm">
                <span className="text-[#cccccc]">{action}</span>
                <kbd className="font-mono text-[#74a8ff]">{keys}</kbd>
              </div>
            ))}
          </div>
        </section>

        <div className="mt-16 border-t border-[#222222] pt-10 flex flex-wrap gap-x-6 gap-y-3 text-sm">
          <Link href="/" className="text-[#74a8ff] underline underline-offset-4">Crux homepage</Link>
          <Link href="/code-editor" className="text-[#74a8ff] underline underline-offset-4">Collaborative code editor</Link>
          <Link href="/pair-programming" className="text-[#74a8ff] underline underline-offset-4">Online pair programming</Link>
          <Link href="/compare" className="text-[#74a8ff] underline underline-offset-4">Compare coding tools</Link>
        </div>
      </div>
    </main>
  );
}
