import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: { absolute: "Collaborative Code Editor with a Spatial Canvas | Crux" },
  description:
    "Try Crux, a real-time collaborative code editor with a spatial file canvas, teammate cursor presence, and an integrated terminal in the browser.",
  alternates: { canonical: "https://codecrux.us/code-editor" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Collaborative Code Editor with a Spatial Canvas | Crux",
    description: "Explore related code files and edit together in the Crux browser IDE.",
    url: "https://codecrux.us/code-editor",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Collaborative Code Editor with a Spatial Canvas | Crux",
    description: "Explore related code files and edit together in the Crux browser IDE.",
    images: ["/og-image.png"],
  },
};

const useCases = [
  {
    title: "Pair programming",
    detail: "Work in shared files and use teammate cursors to follow where the other person is editing.",
  },
  {
    title: "Codebase walkthroughs",
    detail: "Place relevant files on the canvas so a teammate can see how one part of the project relates to another.",
  },
  {
    title: "Debugging together",
    detail: "Keep the file you are inspecting and the terminal output close to the rest of the task context.",
  },
];

export default function CodeEditorPage() {
  return (
    <main className="min-h-screen bg-[#000000] text-white font-sans">
      <div className="max-w-6xl mx-auto px-6 py-12 sm:py-20">
        <nav aria-label="Breadcrumb" className="text-xs font-mono text-[#888888] mb-12">
          <Link href="/" className="hover:text-white">Crux</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <span className="text-[#0055FF]">Collaborative code editor</span>
        </nav>

        <p className="font-mono text-xs tracking-widest text-[#0055FF] uppercase mb-5">Real-time coding · Spatial context</p>
        <h1 className="max-w-5xl text-4xl sm:text-6xl font-normal tracking-tight leading-tight">
          A collaborative code editor that shows the whole task.
        </h1>
        <p className="max-w-4xl mt-7 text-base sm:text-lg leading-relaxed text-[#aaaaaa]">
          Crux lets people edit code together while keeping related files on a spatial canvas. Instead of losing the thread as you move between tabs, arrange the parts of your project you need to understand and keep the integrated terminal nearby.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link href="/ide" className="inline-block px-5 py-3 bg-[#0055FF] border border-[#0055FF] text-white text-sm font-semibold">Open the browser IDE →</Link>
          <Link href="/#waitlist" className="inline-block px-5 py-3 border border-[#444444] text-white text-sm font-semibold">Join the desktop waitlist</Link>
        </div>

        <figure className="mt-12 border border-[#222222] bg-[#111111] p-2 sm:p-4">
          <img src="/email/canvas-preview.png" alt="Crux IDE spatial canvas with multiple related code files open" width="3840" height="2400" className="w-full h-auto" />
          <figcaption className="px-2 pt-4 pb-2 text-xs font-mono text-[#888888]">CRUX IDE · SPATIAL CODE CANVAS</figcaption>
        </figure>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">How the workspace fits together</h2>
          <div className="mt-7 grid md:grid-cols-3 border border-[#222222] md:divide-x divide-[#222222]">
            <div className="p-6 sm:p-7 border-b md:border-b-0 border-[#222222]">
              <p className="font-mono text-xs text-[#0055FF] mb-6">01 / SEE THE FILES</p>
              <h3 className="text-xl font-medium mb-4">Spatial canvas</h3>
              <p className="text-sm leading-relaxed text-[#aaaaaa]">Open several files and zoom out to see them together. The canvas helps you keep related code visible while you work through a change.</p>
            </div>
            <div className="p-6 sm:p-7 border-b md:border-b-0 border-[#222222]">
              <p className="font-mono text-xs text-[#0055FF] mb-6">02 / EDIT TOGETHER</p>
              <h3 className="text-xl font-medium mb-4">Shared editing</h3>
              <p className="text-sm leading-relaxed text-[#aaaaaa]">Changes to shared text appear in the workspace, with teammate cursor presence to make a live session easier to follow.</p>
            </div>
            <div className="p-6 sm:p-7">
              <p className="font-mono text-xs text-[#0055FF] mb-6">03 / KEEP WORKING</p>
              <h3 className="text-xl font-medium mb-4">Integrated terminal</h3>
              <p className="text-sm leading-relaxed text-[#aaaaaa]">Run commands and inspect output alongside the editor so the code and your tools stay in the same flow.</p>
            </div>
          </div>
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Where a shared editor helps</h2>
          <div className="mt-7 grid md:grid-cols-3 gap-4">
            {useCases.map((item) => (
              <article key={item.title} className="border border-[#222222] bg-[#111111] p-6">
                <h3 className="text-xl font-medium">{item.title}</h3>
                <p className="mt-4 text-sm leading-relaxed text-[#aaaaaa]">{item.detail}</p>
              </article>
            ))}
          </div>
          <p className="mt-6 text-sm text-[#aaaaaa] leading-relaxed">
            Planning to code with a teammate? Follow the <Link href="/pair-programming" className="text-[#74a8ff] underline underline-offset-4">online pair programming guide</Link> to start a shared session and choose the right access link.
          </p>
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12 max-w-4xl">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Try the workflow before choosing an editor</h2>
          <p className="mt-6 text-[#aaaaaa] leading-relaxed">
            Open the browser IDE and put several related files on the canvas. See whether that shared view helps your next pairing session or code review. If you are weighing alternatives, our <Link href="/compare" className="text-[#74a8ff] underline underline-offset-4">code editor comparison</Link> covers Cursor, VS Code Live Share, and Zed with links to their official product information.
          </p>
          <div className="mt-7 flex flex-wrap gap-x-6 gap-y-3 text-sm">
            <Link href="/vs-cursor" className="text-[#74a8ff] underline underline-offset-4">Crux vs Cursor</Link>
            <Link href="/vs-vscode" className="text-[#74a8ff] underline underline-offset-4">Crux vs VS Code Live Share</Link>
            <Link href="/vs-zed" className="text-[#74a8ff] underline underline-offset-4">Crux vs Zed</Link>
          </div>
        </section>
      </div>
    </main>
  );
}
