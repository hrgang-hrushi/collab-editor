import type { Metadata } from "next";
import CompetitorComparison from "@/components/seo/CompetitorComparison";

export const metadata: Metadata = {
  title: { absolute: "Crux vs Cursor: Collaborative IDE and AI Editor Comparison" },
  description:
    "Compare Crux and Cursor by workflow: spatial code canvas and real-time shared editing versus Cursor's AI-focused coding agent and editor tools.",
  alternates: { canonical: "https://codecrux.us/vs-cursor" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Crux vs Cursor: Collaborative IDE and AI Editor Comparison",
    description: "A practical comparison of shared codebase context, live editing, and AI-assisted coding workflows.",
    url: "https://codecrux.us/vs-cursor",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux vs Cursor: Collaborative IDE and AI Editor Comparison",
    description: "A practical comparison of shared codebase context, live editing, and AI-assisted coding workflows.",
    images: ["/og-image.png"],
  },
};

const comparison = {
  competitor: "Cursor",
  category: "Cursor alternative · Collaborative IDE",
  heading: "Crux vs Cursor: how do you want to work with code?",
  introduction:
    "If you are looking for a Cursor alternative, start with the job you want the editor to do. Cursor's documentation centers on an AI coding agent that can understand a repo, plan work, edit files, and review changes. Crux centers on a spatial view of related files and a live workspace for people editing together. Both can be useful; the deciding factor is how you want to see and change your project.",
  cruxSummary:
    "Crux is a collaborative IDE with a spatial code canvas, shared text editing, teammate cursor presence, and an integrated terminal. You can try its browser IDE now.",
  competitorSummary:
    "Cursor is an AI-focused editor and coding agent. Its documented workflows cover codebase understanding, feature planning, bug fixes, reviews, and tool integrations.",
  sharedCapabilities: [
    "Both provide a code editing workspace with project context.",
    "Both can sit alongside terminal and developer tools in a coding workflow.",
    "Both aim to reduce the time spent moving between code and supporting context.",
    "Both offer ways to work with AI-assisted development, though their emphasis differs.",
  ],
  differences: [
    {
      title: "Project context",
      description:
        "Crux puts related files on a spatial canvas so you can keep several pieces of a task visible. Cursor's docs emphasize helping an agent understand and act on a codebase through the editor.",
    },
    {
      title: "Collaboration",
      description:
        "Crux's core workflow is live shared editing with visible teammate cursors. Evaluate Cursor's current collaboration tools directly if your decision depends on simultaneous editing; its product changes quickly.",
    },
    {
      title: "AI emphasis",
      description:
        "Cursor is built around an AI coding agent. Crux focuses on the shared workspace and lets you keep coding tools near the files you are editing.",
    },
  ],
  chooseCrux: [
    "A spatial canvas for exploring connected files with your team.",
    "Live shared editing and teammate cursor presence as the main workflow.",
    "A browser IDE you can open without waiting for a desktop install.",
  ],
  chooseCompetitor: [
    "An editor where AI agents lead planning, implementation, and review.",
    "Cursor's documented model, plugin, and coding-agent workflows.",
    "A tool you can evaluate directly for your preferred AI-assisted tasks.",
  ],
  closing:
    "Crux is worth trying as a Cursor alternative when shared codebase context matters most. Cursor may fit better when an AI agent is the center of your day. Try both on the same project and compare the work you can complete comfortably.",
  sourceUrl: "https://cursor.com/docs",
  sourceLabel: "Cursor's official documentation",
  related: [
    { href: "/vs-vscode", label: "Crux vs VS Code Live Share" },
    { href: "/vs-zed", label: "Crux vs Zed" },
  ],
};

export default function CursorComparisonPage() {
  return <CompetitorComparison comparison={comparison} />;
}
