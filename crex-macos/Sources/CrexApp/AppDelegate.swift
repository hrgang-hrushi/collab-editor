import AppKit

public final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var metalView: CrexMetalView?

    public func applicationDidFinishLaunching(_ notification: Notification) {
        let windowRect = NSRect(x: 100, y: 100, width: 1100, height: 750)

        let window = NSWindow(
            contentRect: windowRect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )

        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isOpaque = true
        window.backgroundColor = .black
        window.hasShadow = false // Hardware brutalism: no drop shadow
        window.isMovableByWindowBackground = true

        let rootContainer = NSView(frame: windowRect)
        rootContainer.wantsLayer = true
        rootContainer.layer?.backgroundColor = NSColor.black.cgColor
        rootContainer.layer?.cornerRadius = 0.0

        // 1. Custom Hardware Titlebar Header (Height 36px)
        let headerView = NSView(frame: NSRect(x: 0, y: windowRect.height - 36, width: windowRect.width, height: 36))
        headerView.wantsLayer = true
        headerView.layer?.backgroundColor = NSColor(white: 0.04, alpha: 1.0).cgColor
        headerView.autoresizingMask = [.width, .minYMargin]

        // 1px #222222 bottom border on header
        let headerBorder = NSView(frame: NSRect(x: 0, y: 0, width: windowRect.width, height: 1))
        headerBorder.wantsLayer = true
        headerBorder.layer?.backgroundColor = NSColor(white: 0.133, alpha: 1.0).cgColor
        headerBorder.autoresizingMask = [.width]
        headerView.addSubview(headerBorder)

        // Title Label
        let titleLabel = NSTextField(labelWithString: "Crex // Native macOS Kernel [ARM64_METAL]")
        titleLabel.frame = NSRect(x: 75, y: 8, width: 350, height: 18)
        titleLabel.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .bold)
        titleLabel.textColor = .white
        headerView.addSubview(titleLabel)

        rootContainer.addSubview(headerView)

        // 2. Native Metal Editor Canvas
        let defaultCode = """
// Crex Native macOS Engine (Piece Table + Metal 120FPS)
fn main() {
    let mut buffer = CrexBuffer::new();
    buffer.insert(0, "[KERNEL_INIT]: Native AppKit window mounted.");
    println!("{}", buffer.get_text());
}
"""
        let editorFrame = NSRect(x: 0, y: 24, width: windowRect.width, height: windowRect.height - 60)
        let metalCanvas = CrexMetalView(initialText: defaultCode)
        metalCanvas.frame = editorFrame
        metalCanvas.autoresizingMask = [.width, .height]
        self.metalView = metalCanvas
        rootContainer.addSubview(metalCanvas)

        // 3. Bottom Hardware Telemetry Bar (Height 24px)
        let footerView = NSView(frame: NSRect(x: 0, y: 0, width: windowRect.width, height: 24))
        footerView.wantsLayer = true
        footerView.layer?.backgroundColor = NSColor.black.cgColor
        footerView.autoresizingMask = [.width, .maxYMargin]

        // 1px #222222 top border on footer
        let footerBorder = NSView(frame: NSRect(x: 0, y: 23, width: windowRect.width, height: 1))
        footerBorder.wantsLayer = true
        footerBorder.layer?.backgroundColor = NSColor(white: 0.133, alpha: 1.0).cgColor
        footerBorder.autoresizingMask = [.width]
        footerView.addSubview(footerBorder)

        let statusLabel = NSTextField(labelWithString: "TARGET: MACOS_ARM64 · RENDER: CAMETALLAYER · BUFFER: PIECE_TABLE · 0PX_RADIUS")
        statusLabel.frame = NSRect(x: 12, y: 4, width: 700, height: 16)
        statusLabel.font = NSFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        statusLabel.textColor = NSColor(white: 0.4, alpha: 1.0)
        footerView.addSubview(statusLabel)

        rootContainer.addSubview(footerView)

        window.contentView = rootContainer
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(metalCanvas)

        self.window = window
    }

    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}
