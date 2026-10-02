import type { Metadata } from "next";
import CompetitorComparison from "@/components/seo/CompetitorComparison";

export const metadata: Metadata = {
  title: { absolute: "Crux vs Zed: Collaborative Code Editor Comparison" },
  description:
    "Compare Crux and Zed for real-time collaborative coding, project context, and a spatial code canvas. Includes links to Zed's current collaboration docs.",
  alternates: { canonical: "https://codecrux.us/vs-zed" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Crux vs Zed: Collaborative Code Editor Comparison",
    description: "A practical look at multiplayer editing and how each tool organizes shared project context.",
    url: "https://codecrux.us/vs-zed",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux vs Zed: Collaborative Code Editor Comparison",
    description: "A practical look at multiplayer editing and how each tool organizes shared project context.",
    images: ["/og-image.png"],
  },
};

const comparison = {
  competitor: "Zed",
  category: "Zed alternative · Collaborative code editor",
  heading: "Crux vs Zed: two ways to code together",
  introduction:
    "Zed and Crux both put real-time collaboration near the center of the editor. Zed's documentation describes multiplayer editing, visible teammate cursors, persistent channels, private calls, and voice chat. Crux emphasizes a spatial canvas where a team can arrange related files while editing together. The key question is whether you want Zed's collaboration rooms or Crux's visual codebase context to shape the session.",
  cruxSummary:
    "Crux combines live shared editing and cursor presence with a spatial code canvas, integrated terminal, and a browser IDE you can try.",
  competitorSummary:
    "Zed supports real-time multiplayer editing with visible cursors and edits. Its documentation describes channels, private calls, and voice chat.",
  sharedCapabilities: [
    "People can edit the same project in real time.",
    "Teammate cursors help everyone follow the work.",
    "Both are designed around coding, navigation, and collaboration.",
    "Both can keep team discussion close to the files being changed.",
  ],
  differences: [
    {
      title: "How files are seen",
      description:
        "Crux's spatial canvas lets you arrange related files as a visual map of a task. Zed uses its editor and project views, including collaboration features described in its docs.",
    },
    {
      title: "How teams gather",
      description:
        "Zed documents persistent channels and private calls, including voice chat. Crux's current public preview focuses on the shared editing workspace and teammate presence.",
    },
    {
      title: "How to try it",
      description:
        "Crux provides a browser IDE to explore immediately and a waitlist for desktop access. Review Zed's current downloads and platform support on its official site before choosing a setup.",
    },
  ],
  chooseCrux: [
    "A spatial canvas for viewing connected code files together.",
    "Shared editing with visible teammate cursors in one workspace.",
    "A browser IDE to assess the workflow before desktop access.",
  ],
  chooseCompetitor: [
    "Zed's documented persistent collaboration channels.",
    "Private calls and voice chat as part of your editor workflow.",
    "The project and navigation model in Zed's current editor.",
  ],
  closing:
    "Both tools deserve a real trial for pair programming. Pick Crux when arranging the codebase itself is central to your discussion; pick Zed when its channels, calls, and current editor experience fit your team better.",
  sourceUrl: "https://zed.dev/docs/collaboration/overview",
  sourceLabel: "Zed's official collaboration overview",
  related: [
    { href: "/vs-cursor", label: "Crux vs Cursor" },
    { href: "/vs-vscode", label: "Crux vs VS Code Live Share" },
  ],
};

export default function ZedComparisonPage() {
  return <CompetitorComparison comparison={comparison} />;
}
