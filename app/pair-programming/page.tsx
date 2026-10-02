import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: { absolute: "Online Pair Programming IDE | Share a Crux Workspace" },
  description:
    "Pair program in the Crux browser IDE. Open a project, share a full-edit link, follow live edits, and keep related files visible on a spatial canvas.",
  alternates: { canonical: "https://codecrux.us/pair-programming" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Online Pair Programming IDE | Share a Crux Workspace",
    description: "A practical guide to starting a shared coding session in the Crux browser IDE.",
    url: "https://codecrux.us/pair-programming",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Online Pair Programming IDE | Share a Crux Workspace",
    description: "A practical guide to starting a shared coding session in the Crux browser IDE.",
    images: ["/og-image.png"],
  },
};

const steps = [
  {
    number: "01 / OPEN",
    title: "Open a workspace",
    body: "Launch the browser IDE. Use Quick Boot Workspace to explore the sample project, or Import Project Folder to bring in files you want to work on together.",
  },
  {
    number: "02 / INVITE",
    title: "Share the right link",
    body: "Select Share in the workspace header and copy the full-edit link for a collaborator who will change code. The dialog also offers a view-only link for someone following the session.",
  },
  {
    number: "03 / ORIENT",
    title: "Put the task in view",
    body: "Open the files involved in one change. Switch to Canvas to see several related files at once, then return to Editor when you need a focused text view.",
  },
  {
    number: "04 / WORK",
    title: "Edit and discuss",
    body: "Use shared text and teammate cursor presence to follow the work. Keep the Files and Terminal panels nearby, and switch who leads the change as the task moves forward.",
  },
];

export default function PairProgrammingPage() {
  return (
    <main className="min-h-screen bg-[#000000] text-white font-sans">
      <div className="max-w-6xl mx-auto px-6 py-12 sm:py-20">
        <nav aria-label="Breadcrumb" className="text-xs font-mono text-[#888888] mb-12">
          <Link href="/" className="hover:text-white">Crux</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <span className="text-[#0055FF]">Pair programming</span>
        </nav>

        <p className="font-mono text-xs tracking-widest text-[#0055FF] uppercase mb-5">Browser IDE · Shared coding</p>
        <h1 className="max-w-5xl text-4xl sm:text-6xl font-normal tracking-tight leading-tight">
          Pair program online with the codebase in view.
        </h1>
        <p className="max-w-4xl mt-7 text-base sm:text-lg leading-relaxed text-[#aaaaaa]">
          Crux is a collaborative code editor for developers working in the same project. Share a browser workspace, follow live edits, and arrange related files on a spatial canvas so both people can see the context of a change.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link href="/ide" className="inline-block px-5 py-3 bg-[#0055FF] border border-[#0055FF] text-white text-sm font-semibold">Open the browser IDE →</Link>
          <Link href="/docs" className="inline-block px-5 py-3 border border-[#444444] text-white text-sm font-semibold">Read the IDE guide</Link>
        </div>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Start a shared coding session</h2>
          <p className="mt-4 max-w-3xl text-[#aaaaaa] leading-relaxed">
            For remote pair programming, pick one small task before inviting a teammate. A focused change makes it easier to decide which files belong on the canvas and when to trade the lead.
          </p>
          <ol className="mt-7 grid md:grid-cols-2 border border-[#222222]">
            {steps.map((step, index) => (
              <li key={step.number} className={`p-6 sm:p-8 ${index % 2 === 0 ? "md:border-r" : ""} ${index < 2 ? "border-b" : index === 2 ? "border-b md:border-b-0" : ""} border-[#222222]`}>
                <p className="font-mono text-xs text-[#0055FF] mb-6">{step.number}</p>
                <h3 className="text-xl font-medium mb-4">{step.title}</h3>
                <p className="text-sm leading-relaxed text-[#aaaaaa]">{step.body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="mt-16 grid md:grid-cols-2 gap-10 items-center border-t border-[#222222] pt-12">
          <div>
            <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Keep more than one file in the conversation</h2>
            <p className="mt-5 text-[#aaaaaa] leading-relaxed">
              Pairing often means tracing a change from one file to another. On the canvas, open the relevant code together: for example, a request handler, the type it uses, and the test you are updating. Arrows can show the relationship you are discussing while the text stays available for editing.
            </p>
            <p className="mt-4 text-sm text-[#888888] leading-relaxed">
              The example above is a suggested workflow, not a built-in project. See the <Link href="/code-editor" className="text-[#74a8ff] underline underline-offset-4">collaborative editor overview</Link> for the workspace itself.
            </p>
          </div>
          <img loading="lazy" decoding="async" src="/email/canvas-preview.png" alt="Crux IDE canvas showing several related code files together" width="3840" height="2400" className="w-full h-auto border border-[#222222]" />
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Choose edit access deliberately</h2>
          <div className="mt-7 grid md:grid-cols-2 gap-6">
            <div className="border border-[#0055FF] bg-[#071329] p-6 sm:p-8">
              <h3 className="text-xl font-medium">Full-edit link</h3>
              <p className="mt-4 text-sm leading-relaxed text-[#cccccc]">Use this for a teammate who will edit files with you. The Share dialog labels it as a full-edit link; send it only to the people you intend to work with.</p>
            </div>
            <div className="border border-[#222222] bg-[#111111] p-6 sm:p-8">
              <h3 className="text-xl font-medium">View-only link</h3>
              <p className="mt-4 text-sm leading-relaxed text-[#cccccc]">Use this for a walkthrough or review when someone should follow the workspace without changing files. Copy it separately from the full-edit link.</p>
            </div>
          </div>
          <p className="mt-6 max-w-4xl text-sm text-[#888888] leading-relaxed">
            The browser IDE is available to try now. Desktop access is offered through the <Link href="/#waitlist" className="text-[#74a8ff] underline underline-offset-4">Crux waitlist</Link>.
          </p>
        </section>

        <div className="mt-16 border-t border-[#222222] pt-10 flex flex-wrap gap-x-6 gap-y-3 text-sm">
          <Link href="/ide" className="text-[#74a8ff] underline underline-offset-4">Try Crux in the browser</Link>
          <Link href="/docs" className="text-[#74a8ff] underline underline-offset-4">IDE controls and shortcuts</Link>
          <Link href="/vs-vscode" className="text-[#74a8ff] underline underline-offset-4">Compare VS Code Live Share</Link>
          <Link href="/compare" className="text-[#74a8ff] underline underline-offset-4">Compare coding tools</Link>
        </div>
      </div>
    </main>
  );
}
