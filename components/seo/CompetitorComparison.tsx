import Link from "next/link";

type Comparison = {
  competitor: string;
  category: string;
  heading: string;
  introduction: string;
  cruxSummary: string;
  competitorSummary: string;
  sharedCapabilities: string[];
  differences: { title: string; description: string }[];
  chooseCrux: string[];
  chooseCompetitor: string[];
  closing: string;
  sourceUrl: string;
  sourceLabel: string;
  related: { href: string; label: string }[];
};

export default function CompetitorComparison({ comparison }: { comparison: Comparison }) {
  return (
    <main className="min-h-screen bg-[#000000] text-white font-sans">
      <div className="max-w-6xl mx-auto px-6 py-12 sm:py-20">
        <nav aria-label="Breadcrumb" className="text-xs font-mono text-[#888888] mb-12">
          <Link href="/" className="hover:text-white">Crux</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <Link href="/compare" className="hover:text-white">Compare editors</Link>
          <span className="mx-3 text-[#444444]">/</span>
          <span className="text-[#0055FF]">{comparison.competitor}</span>
        </nav>

        <p className="font-mono text-xs tracking-widest text-[#0055FF] uppercase mb-5">{comparison.category}</p>
        <h1 className="max-w-5xl text-4xl sm:text-6xl font-normal tracking-tight leading-tight">{comparison.heading}</h1>
        <p className="max-w-4xl mt-7 text-base sm:text-lg leading-relaxed text-[#aaaaaa]">{comparison.introduction}</p>

        <section aria-label="At a glance" className="mt-12 grid md:grid-cols-2 border border-[#222222]">
          <div className="p-6 sm:p-8 border-b md:border-b-0 md:border-r border-[#222222]">
            <p className="text-xs font-mono tracking-widest text-[#0055FF] uppercase mb-4">Crux</p>
            <p className="text-lg leading-relaxed text-white">{comparison.cruxSummary}</p>
          </div>
          <div className="p-6 sm:p-8">
            <p className="text-xs font-mono tracking-widest text-[#888888] uppercase mb-4">{comparison.competitor}</p>
            <p className="text-lg leading-relaxed text-white">{comparison.competitorSummary}</p>
          </div>
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Where the tools overlap</h2>
          <ul className="mt-6 grid sm:grid-cols-2 gap-3">
            {comparison.sharedCapabilities.map((capability) => (
              <li key={capability} className="border border-[#222222] bg-[#111111] p-5 text-[#cccccc] leading-relaxed">
                <span className="text-[#0055FF] mr-3" aria-hidden="true">■</span>{capability}
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">The workflow differences</h2>
          <div className="mt-7 grid md:grid-cols-3 border border-[#222222] md:divide-x divide-[#222222]">
            {comparison.differences.map((difference, index) => (
              <div key={difference.title} className="p-6 sm:p-7 border-b last:border-b-0 md:border-b-0 border-[#222222]">
                <p className="font-mono text-xs text-[#0055FF] mb-6">0{index + 1} / 03</p>
                <h3 className="text-xl font-medium mb-4">{difference.title}</h3>
                <p className="text-sm leading-relaxed text-[#aaaaaa]">{difference.description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12">
          <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">Which should you choose?</h2>
          <div className="mt-7 grid md:grid-cols-2 gap-6">
            <div className="border border-[#0055FF] bg-[#071329] p-6 sm:p-8">
              <h3 className="text-xl font-medium mb-5">Try Crux if you want…</h3>
              <ul className="space-y-4 text-[#cccccc] leading-relaxed">
                {comparison.chooseCrux.map((item) => <li key={item}>→ {item}</li>)}
              </ul>
            </div>
            <div className="border border-[#222222] p-6 sm:p-8">
              <h3 className="text-xl font-medium mb-5">Choose {comparison.competitor} if you want…</h3>
              <ul className="space-y-4 text-[#cccccc] leading-relaxed">
                {comparison.chooseCompetitor.map((item) => <li key={item}>→ {item}</li>)}
              </ul>
            </div>
          </div>
          <p className="mt-7 max-w-4xl text-[#aaaaaa] leading-relaxed">{comparison.closing}</p>
        </section>

        <section className="mt-16 grid md:grid-cols-2 gap-8 items-center border-t border-[#222222] pt-12">
          <div>
            <h2 className="text-3xl sm:text-4xl font-normal tracking-tight">See Crux for yourself.</h2>
            <p className="mt-5 text-[#aaaaaa] leading-relaxed">
              This is the spatial code canvas in the Crux IDE. Open the browser workspace to explore the editor, or join the waitlist for desktop access.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link href="/ide" className="inline-block px-5 py-3 bg-[#0055FF] border border-[#0055FF] text-white text-sm font-semibold">Try the browser IDE →</Link>
              <Link href="/#waitlist" className="inline-block px-5 py-3 border border-[#444444] text-white text-sm font-semibold">Join the waitlist</Link>
            </div>
          </div>
          <img loading="lazy" decoding="async" src="/email/canvas-preview.png" alt="Crux IDE showing related files on a spatial code canvas" width="3840" height="2400" className="w-full h-auto border border-[#222222]" />
        </section>

        <section className="mt-16 border-t border-[#222222] pt-12 text-sm text-[#888888]">
          <h2 className="text-xl text-white font-medium">Sources and other comparisons</h2>
          <p className="mt-4 leading-relaxed">
            Competitor capabilities are summarized from <a href={comparison.sourceUrl} target="_blank" rel="noopener noreferrer" className="text-[#74a8ff] underline underline-offset-4">{comparison.sourceLabel}</a>. Product features can change; consult the vendor for current details. Crux descriptions reflect the browser IDE and current product preview.
          </p>
          <div className="mt-6 flex flex-wrap gap-x-6 gap-y-3">
            <Link href="/compare" className="text-[#74a8ff] underline underline-offset-4">All editor comparisons</Link>
            {comparison.related.map((item) => <Link key={item.href} href={item.href} className="text-[#74a8ff] underline underline-offset-4">{item.label}</Link>)}
          </div>
        </section>
      </div>
    </main>
  );
}
