import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: { absolute: "About Crux IDE | Code Crux" },
  description:
    "Learn what Crux IDE is building: a collaborative code editor with a spatial canvas, live shared editing, and a browser workspace you can try today.",
  alternates: { canonical: "https://codecrux.us/about" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "About Crux IDE | Code Crux",
    description: "A shared workspace for code, context, and the people working on it.",
    url: "https://codecrux.us/about",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "About Crux IDE | Code Crux",
    description: "A shared workspace for code, context, and the people working on it.",
    images: ["/og-image.png"],
  },
};

const principles = [
  {
    number: "01 / CONTEXT",
    title: "Keep related files visible",
    detail:
      "Move between Editor and Canvas views. The canvas gives a task more room than a row of tabs, so you can arrange the files you need to understand together.",
  },
  {
    number: "02 / COLLABORATION",
    title: "Work in the same workspace",
    detail:
      "Share a full-edit link with a collaborator or a view-only link for a walkthrough. Shared text and teammate cursor presence help people follow the work.",
  },
  {
    number: "03 / TOOLS",
    title: "Keep the tools nearby",
    detail:
      "Use the file explorer, command palette, and integrated terminal alongside your code. The browser IDE is available to explore without a desktop install.",
  },
];

export default function AboutPage() {
  return (
    <main className="min-h-screen bg-[#000000] text-white font-sans">
      <div className="max-w-6xl mx-auto px-6 py-12 sm:py-20">
        <nav aria-label="Breadcrumb" className="text-xs font-mono text-[#888888] mb-12">
          <Link href="/" className="hover:text-white">Crux</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <span className="text-[#0055FF]">About</span>
        </nav>

        <p className="font-mono text-xs tracking-widest text-[#0055FF] uppercase mb-5">Code Crux · Collaborative IDE</p>
        <h1 className="max-w-5xl text-4xl sm:text-6xl font-normal tracking-tight leading-tight">About Crux</h1>
        <p className="max-w-4xl mt-7 text-base sm:text-lg leading-relaxed text-[#aaaaaa]">
          Crux is a collaborative code editor built around a simple idea: the code, the surrounding files, and the people changing them should be visible in one workspace. The current browser IDE combines live shared editing with a spatial code canvas and an integrated terminal.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link href="/ide" className="inline-block px-5 py-3 bg-[#0055FF] border border-[#0055FF] text-white text-sm font-semibold">Try the browser IDE →</Link>
          <Link href="/#waitlist" className="inline-block px-5 py-3 border border-[#444444] text-white text-sm font-semibold">Join the desktop waitlist</Link>
        </div>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Why we are building it</h2>
          <p className="mt-5 max-w-4xl text-[#aaaaaa] leading-relaxed">
            Coding with another person often means explaining a change across several files while navigating an editor, a terminal, and a call. Crux brings those parts of a task into a shared view. The goal is to make it easier to keep the project context in sight while people work through the change together.
          </p>
          <div className="mt-8 grid md:grid-cols-3 border border-[#222222] md:divide-x divide-[#222222]">
            {principles.map((principle, index) => (
              <div key={principle.number} className={`p-6 sm:p-8 ${index < 2 ? "border-b md:border-b-0" : ""} border-[#222222]`}>
                <p className="font-mono text-xs text-[#0055FF] mb-6">{principle.number}</p>
                <h3 className="text-xl font-medium mb-4">{principle.title}</h3>
                <p className="text-sm leading-relaxed text-[#aaaaaa]">{principle.detail}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-16 grid md:grid-cols-2 gap-10 items-center border-t border-[#222222] pt-12">
          <div>
            <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">See the current workspace</h2>
            <p className="mt-5 text-[#aaaaaa] leading-relaxed">
              In Canvas mode, you can place related code files together and draw connections between them. Switch back to Editor mode to focus on a file. The browser IDE also has a Share dialog with separate full-edit and view-only links.
            </p>
            <p className="mt-4 text-sm text-[#888888] leading-relaxed">
              Read the <Link href="/docs" className="text-[#74a8ff] underline underline-offset-4">IDE guide</Link> for the current controls, or use the <Link href="/pair-programming" className="text-[#74a8ff] underline underline-offset-4">pair programming guide</Link> to start a shared session.
            </p>
          </div>
          <img loading="lazy" decoding="async" src="/email/canvas-preview.png" alt="Crux IDE spatial canvas showing several related code files" width="3840" height="2400" className="w-full h-auto border border-[#222222]" />
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Available now</h2>
          <div className="mt-7 grid md:grid-cols-2 gap-6">
            <div className="border border-[#0055FF] bg-[#071329] p-6 sm:p-8">
              <h3 className="text-xl font-medium">Browser IDE</h3>
              <p className="mt-4 text-sm leading-relaxed text-[#cccccc]">Open Crux in your browser to explore the editor, canvas, file explorer, terminal, and sharing controls.</p>
              <Link href="/ide" className="inline-block mt-6 text-sm text-[#74a8ff] underline underline-offset-4">Open Crux IDE →</Link>
            </div>
            <div className="border border-[#222222] bg-[#111111] p-6 sm:p-8">
              <h3 className="text-xl font-medium">Desktop access</h3>
              <p className="mt-4 text-sm leading-relaxed text-[#cccccc]">Join the waitlist to hear about desktop access and product updates as the experience develops.</p>
              <Link href="/#waitlist" className="inline-block mt-6 text-sm text-[#74a8ff] underline underline-offset-4">Join the waitlist →</Link>
            </div>
          </div>
        </section>

        <div className="mt-16 border-t border-[#222222] pt-10 flex flex-wrap gap-x-6 gap-y-3 text-sm">
          <Link href="/" className="text-[#74a8ff] underline underline-offset-4">Crux homepage</Link>
          <Link href="/code-editor" className="text-[#74a8ff] underline underline-offset-4">Collaborative editor</Link>
          <Link href="/compare" className="text-[#74a8ff] underline underline-offset-4">Compare coding tools</Link>
        </div>
      </div>
    </main>
  );
}
