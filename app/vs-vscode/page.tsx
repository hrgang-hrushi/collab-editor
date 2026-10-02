import type { Metadata } from "next";
import CompetitorComparison from "@/components/seo/CompetitorComparison";

export const metadata: Metadata = {
  title: { absolute: "Crux vs VS Code Live Share: Pair Programming IDE Comparison" },
  description:
    "Compare Crux with Visual Studio Code Live Share for pair programming: shared editing, terminal workflows, and a spatial code canvas.",
  alternates: { canonical: "https://codecrux.us/vs-vscode" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Crux vs VS Code Live Share: Pair Programming IDE Comparison",
    description: "Compare collaboration inside VS Code with Crux's shared spatial code workspace.",
    url: "https://codecrux.us/vs-vscode",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux vs VS Code Live Share: Pair Programming IDE Comparison",
    description: "Compare collaboration inside VS Code with Crux's shared spatial code workspace.",
    images: ["/og-image.png"],
  },
};

const comparison = {
  competitor: "VS Code Live Share",
  category: "Live Share alternative · Pair programming",
  heading: "Crux vs VS Code Live Share for coding together",
  introduction:
    "VS Code Live Share and Crux both support collaborative coding, so the choice is about the shape of the workspace. Microsoft documents co-editing, co-debugging, shared terminals and servers, and following a teammate's cursor within Visual Studio or VS Code. Crux combines shared editing with a spatial canvas that keeps related files visible together. This page compares those workflows without unverified speed or memory claims.",
  cruxSummary:
    "Crux gives collaborators a spatial view of connected files alongside live shared editing and an integrated terminal, with a browser IDE available to try.",
  competitorSummary:
    "Live Share adds collaborative sessions to Visual Studio and VS Code. Microsoft documents co-editing, co-debugging, focus and follow, shared terminals, and shared servers.",
  sharedCapabilities: [
    "People can edit code together in real time.",
    "Teammate presence helps you follow work across a session.",
    "Terminal work can be part of the collaboration flow.",
    "Both can support remote pair programming and code review.",
  ],
  differences: [
    {
      title: "Editor you keep",
      description:
        "Live Share lets you collaborate from an existing VS Code or Visual Studio setup. Crux is its own IDE, so a team adopts the Crux workspace to use its canvas.",
    },
    {
      title: "Visual context",
      description:
        "Crux's spatial code canvas is designed to keep related files arranged in view. Live Share focuses on a shared session inside the familiar VS Code or Visual Studio editor layout.",
    },
    {
      title: "Session tools",
      description:
        "Microsoft documents co-debugging, shared servers, and shared terminals in Live Share. If those exact session tools are essential, test them against your team's needs before switching editors.",
    },
  ],
  chooseCrux: [
    "A spatial view that keeps several related files visible during a session.",
    "One IDE for shared code editing, project context, and terminal work.",
    "A browser workspace to explore before committing to a desktop workflow.",
  ],
  chooseCompetitor: [
    "To keep your team's current VS Code or Visual Studio environment.",
    "Microsoft's documented shared debugging and server features.",
    "A collaboration extension that fits an established editor workflow.",
  ],
  closing:
    "If your team already depends on VS Code extensions and Live Share's shared debugging, staying there may be simpler. Try Crux when the missing piece is a shared visual map of the files you are discussing and editing.",
  sourceUrl: "https://visualstudio.microsoft.com/services/live-share/",
  sourceLabel: "Microsoft's Live Share feature page",
  related: [
    { href: "/vs-cursor", label: "Crux vs Cursor" },
    { href: "/vs-zed", label: "Crux vs Zed" },
  ],
};

export default function VSCodeComparisonPage() {
  return <CompetitorComparison comparison={comparison} />;
}
