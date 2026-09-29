"""Build the short, source-grounded Crux architecture brief."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "crux-project-summary.pdf"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

INK = colors.HexColor("#111111")
MUTED = colors.HexColor("#555555")
GRID = colors.HexColor("#D7D7D7")
PALE = colors.HexColor("#F3F3F3")

styles = {
    "kicker": ParagraphStyle("kicker", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=MUTED, spaceAfter=7),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22, leading=25, textColor=INK, spaceAfter=7),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10, leading=14, textColor=MUTED, spaceAfter=13),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=INK, spaceBefore=12, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=9.5, leading=13, textColor=INK, spaceBefore=8, spaceAfter=3),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.1, leading=13.2, textColor=INK, spaceAfter=6),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=11.4, textColor=MUTED, spaceAfter=4),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=9, leading=12.7, textColor=INK, leftIndent=12, firstLineIndent=-9, spaceAfter=4),
    "table": ParagraphStyle("table", fontName="Helvetica", fontSize=8.2, leading=11, textColor=INK),
    "tablehead": ParagraphStyle("tablehead", fontName="Helvetica-Bold", fontSize=8.2, leading=11, textColor=colors.white),
    "source": ParagraphStyle("source", fontName="Helvetica", fontSize=7.3, leading=10.2, textColor=MUTED, spaceAfter=3),
}


def p(text, style="body"):
    return Paragraph(text, styles[style])


def bullet(text):
    return p("&#8226; " + text, "bullet")


def table(rows, widths):
    rendered = [[p(value, "tablehead" if index == 0 else "table") for value in row] for index, row in enumerate(rows)]
    result = Table(rendered, colWidths=widths, hAlign="LEFT", repeatRows=1)
    result.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return result


def page_footer(canvas, doc):
    canvas.saveState()
    width, _ = doc.pagesize
    canvas.setStrokeColor(GRID)
    canvas.line(42, 43, width - 42, 43)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(42, 30, "CRUX | INTERNAL VALIDATION BRIEF | 29 SEP 2026")
    canvas.drawRightString(width - 42, 30, f"{doc.page} / 3")
    canvas.restoreState()


story = []

# Page 1: what exists and how collaboration works.
story += [
    p("PROJECT BRIEF / SOURCE-VERIFIED", "kicker"),
    p("Crux: collaborative IDE", "title"),
    p("A concise technical picture for investor and engineering conversations. This brief describes the codebase as inspected on 29 September 2026; it separates implemented paths from positioning claims.", "subtitle"),
    HRFlowable(width="100%", thickness=1, color=GRID),
    p("What the product does today", "h1"),
    p("Crux provides a browser-based coding workspace with a desktop Tauri package. The normal editor is CodeMirror 6; workspace state is held in Zustand. The Rust host supplies native terminal, code execution, filesystem and migration commands. The AI panel routes prompts to configured providers, while some visible agent steps are timed UI stages rather than measured backend work. [1][2][3]"),
    p("How two people edit together", "h1"),
    table([
        ["1. Local edit", "2. Shared document", "3. Peer transport", "4. Presence"],
        ["CodeMirror captures changes and binds to a Y.Text buffer.", "Yjs merges concurrent character edits into the same document state.", "y-webrtc sends document updates over peer data channels; signaling helps peers connect.", "Awareness carries user identity, active file and cursor state separately from file text."],
    ], [125, 125, 125, 125]),
    Spacer(1, 9),
    p("Flow: CodeMirror 6  >  y-codemirror / Y.Text  >  Yjs document  >  WebRTC peers. Awareness is an ephemeral side channel. The app also mirrors content into the workspace store for local UI and persistence. [1][4]", "small"),
    p("Architecture at a glance", "h1"),
    bullet("<b>Interface:</b> Next.js 14 + React 18 + TypeScript; CodeMirror for default text editing; optional hardware canvas view. [1][5]"),
    bullet("<b>Collaboration:</b> one Yjs document / Y.Text session per file, WebRTC peer transport and awareness. Public fallback signaling endpoints appear in code, so an air-gapped claim is not established. [4]"),
    bullet("<b>Desktop:</b> Tauri 2 wraps the web frontend and exposes Rust commands for PTY, execution, file operations, CLI discovery and migration. [3]"),
    bullet("<b>AI:</b> provider routing exists; the product should distinguish real provider activity from illustrative progress stages. [6]"),
    p("Founder takeaway: the collaboration mechanism is concrete. The ultra-low-memory WebGPU positioning needs independent measurement and tighter alignment with the active rendering path.", "small"),
    PageBreak(),
]

# Page 2: performance explanation and evidence limits.
story += [
    p("PERFORMANCE / WHAT THE EVIDENCE SUPPORTS", "kicker"),
    p("The 680 MB to 85 MB question", "title"),
    p("If measured under the same conditions, 680 MB to 85 MB would be an 8x reduction, or 87.5% less memory. The current repository does not demonstrate that measurement.", "subtitle"),
    HRFlowable(width="100%", thickness=1, color=GRID),
    p("Claim audit", "h1"),
    table([
        ["Statement", "Observed evidence", "Investor-safe wording"],
        ["680 MB comparator", "README and benchmark page state 680 MB for VS Code; no raw process capture or script found. [7]", "A published comparison claim, pending independent reproduction."],
        ["85 MB Crux", "User-supplied target; no matching figure or profile found in source. Public pages instead state 38 MB. [7]", "A target or preliminary observation, not a verified result."],
        ["WebGPU memory cause", "Hardware mode requests a GPU device, then renders text via Canvas 2D fillText; default mode uses CodeMirror. No GPU text compute pipeline was found in this path. [1][5]", "WebGPU acceleration is an experimental path; it does not yet explain a measured 85 MB footprint."],
    ], [100, 205, 195]),
    p("What could reduce memory - and what cannot be claimed yet", "h1"),
    bullet("<b>Plausible:</b> CodeMirror's modular editor and viewport work may use less application memory than a larger editor stack. Tauri packages a system webview rather than bundling Electron's Chromium. These are architecture reasons to test, not proof of a specific figure."),
    bullet("<b>Not automatic:</b> WebGPU does not itself shrink process RAM. Device initialization and textures can increase GPU or shared memory. The current 2D text renderer does cull to visible lines, but it still runs inside a webview. [5]"),
    bullet("<b>Current conflict:</b> marketing states 38 MB, your working number is 85 MB, and the comparator is 680 MB. These must use one defined metric - e.g. full app process-tree resident memory at idle, same OS and workspace."),
    p("How to validate the number", "h1"),
    p("On the same machine: define a cold-start and 5-minute idle scenario; open the same 250k-line corpus; measure the whole Crux process tree plus GPU/shared allocations and the whole VS Code process tree; run at least 10 clean repeats; report median and range, OS/hardware, app versions, extensions, open tabs, and raw captures. Repeat with normal editor and hardware mode separately. Do not present 85 MB or 38 MB as measured until those artifacts exist."),
    PageBreak(),
]

# Page 3: roadmap and founder validation checklist.
story += [
    p("ROADMAP / DECISIONS TO VALIDATE", "kicker"),
    p("What to build and prove next", "title"),
    p("These are recommended milestones based on implementation gaps in the inspected repository, not commitments already completed.", "subtitle"),
    HRFlowable(width="100%", thickness=1, color=GRID),
    p("Near-term roadmap", "h1"),
    table([
        ["Priority", "Milestone", "Proof of completion"],
        ["1", "Reproduce memory, latency and collaboration benchmarks with a checked-in harness.", "Raw traces, scripts, environment metadata and published confidence ranges."],
        ["2", "Choose the rendering story: mature CodeMirror path or a real GPU text pipeline.", "Active code path and benchmark agree with public claims; GPU fallback is explicit."],
        ["3", "Harden collaboration rooms, identity, permissions and signaling.", "Two-device tests for convergence, reconnect and authorization; owned signaling service."],
        ["4", "Tie AI status to real backend events; test failure and cancellation.", "UI labels map to emitted events, not timer-driven placeholder stages."],
        ["5", "Polish desktop distribution and migration.", "Signed build, fresh-install test, terminal/FS smoke test and supported platform matrix."],
    ], [55, 225, 220]),
    p("Questions you can answer in the room", "h1"),
    bullet("<b>Why collaboration works:</b> Yjs reconciles concurrent text updates; WebRTC carries them between peers; awareness carries transient presence. [1][4]"),
    bullet("<b>What runs locally:</b> the desktop Rust layer handles native operations; the editor itself remains a web frontend hosted in Tauri. [1][3]"),
    bullet("<b>What is proven about memory:</b> the architecture suggests opportunities, but this repo does not substantiate 680 MB to 85 MB or 38 MB. Show the measurement plan rather than an unverified win. [5][7]"),
    p("Source map for self-validation", "h1"),
    p("[1] components/crux/zenith/ZenithEditorPane.tsx; components/editor/CodeMirrorEditor.tsx; lib/store.ts", "source"),
    p("[2] package.json; [3] src-tauri/src/lib.rs; src-tauri/src/terminal.rs; src-tauri/tauri.conf.json", "source"),
    p("[4] lib/crdt/yjsProvider.ts; [5] lib/webgpu/crexEngineBridge.ts; components/crux/webgpu/CrexWebGpuCanvas.tsx", "source"),
    p("[6] lib/ai/aiRouter.ts; lib/agentEngine.ts; components/crux/agent/CruxDualStateHud.tsx", "source"),
    p("[7] README.md; app/benchmarks/page.tsx. Public performance figures are claims in these files, not raw telemetry.", "source"),
]

doc = SimpleDocTemplate(
    str(OUTPUT),
    pagesize=(612, 792),
    leftMargin=42,
    rightMargin=42,
    topMargin=42,
    bottomMargin=57,
    title="Crux Project Summary",
    author="Crux technical review",
)
doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
print(OUTPUT)
