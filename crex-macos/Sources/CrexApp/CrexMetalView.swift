import AppKit
import Metal
import QuartzCore

public final class CrexMetalView: NSView {
    private var metalDevice: MTLDevice?
    private var commandQueue: MTLCommandQueue?
    private var metalLayer: CAMetalLayer?

    public let buffer: CrexBuffer
    public var cursorLine: Int = 0
    public var cursorCol: Int = 0
    private var cursorVisible: Bool = true
    private var blinkTimer: Timer?

    private let gutterWidth: CGFloat = 48.0
    private let lineHeight: CGFloat = 20.0
    private let charWidth: CGFloat = 8.5

    public init(initialText: String = "") {
        self.buffer = CrexBuffer(initialText: initialText)
        super.init(frame: .zero)

        self.wantsLayer = true
        self.layerContentsRedrawPolicy = .onSetNeedsDisplay

        if let device = MTLCreateSystemDefaultDevice() {
            self.metalDevice = device
            self.commandQueue = device.makeCommandQueue()

            let layer = CAMetalLayer()
            layer.device = device
            layer.pixelFormat = .bgra8Unorm
            layer.framebufferOnly = true
            layer.backgroundColor = NSColor.black.cgColor
            layer.cornerRadius = 0.0 // Strict 0px border radius
            self.layer = layer
            self.metalLayer = layer
        }

        self.blinkTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.cursorVisible.toggle()
            self.needsDisplay = true
        }
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        blinkTimer?.invalidate()
    }

    public override var acceptsFirstResponder: Bool {
        return true
    }

    public override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        guard let ctx = NSGraphicsContext.current?.cgContext else { return }

        // Background: Void #000000
        ctx.setFillColor(NSColor.black.cgColor)
        ctx.fill(bounds)

        // Gutter boundary: 1px #222222
        ctx.setFillColor(NSColor(white: 0.133, alpha: 1.0).cgColor)
        ctx.fill(CGRect(x: gutterWidth, y: 0, width: 1.0, height: bounds.height))

        let text = buffer.text
        let lines = text.components(separatedBy: "\n")

        let font = NSFont.monospacedSystemFont(ofSize: 12.0, weight: .regular)
        let gutterFont = NSFont.monospacedSystemFont(ofSize: 10.0, weight: .regular)

        let activeAttributes: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: NSColor.white
        ]
        let gutterAttributes: [NSAttributedString.Key: Any] = [
            .font: gutterFont,
            .foregroundColor: NSColor(white: 0.35, alpha: 1.0)
        ]
        let activeGutterAttributes: [NSAttributedString.Key: Any] = [
            .font: gutterFont,
            .foregroundColor: NSColor.white
        ]

        for (idx, line) in lines.enumerated() {
            let y = bounds.height - CGFloat(idx + 1) * lineHeight

            // Gutter Line Number
            let lineNumStr = "\(idx + 1)"
            let attr = (idx == cursorLine) ? activeGutterAttributes : gutterAttributes
            let numString = NSAttributedString(string: lineNumStr, attributes: attr)
            let numSize = numString.size()
            numString.draw(at: NSPoint(x: gutterWidth - numSize.width - 8.0, y: y + 2.0))

            // Code Line
            let lineString = NSAttributedString(string: line, attributes: activeAttributes)
            lineString.draw(at: NSPoint(x: gutterWidth + 8.0, y: y + 2.0))
        }

        // Active 1px solid white cursor
        if cursorVisible {
            let cursorX = gutterWidth + 8.0 + CGFloat(cursorCol) * charWidth
            let cursorY = bounds.height - CGFloat(cursorLine + 1) * lineHeight
            ctx.setFillColor(NSColor.white.cgColor)
            ctx.fill(CGRect(x: cursorX, y: cursorY + 2.0, width: 1.5, height: lineHeight - 3.0))
        }
    }

    public override func keyDown(with event: NSEvent) {
        guard let chars = event.characters else { return }

        let isEnter = (event.keyCode == 36)
        let isBackspace = (event.keyCode == 51)
        let isLeft = (event.keyCode == 123)
        let isRight = (event.keyCode == 124)
        let isDown = (event.keyCode == 125)
        let isUp = (event.keyCode == 126)

        if isUp {
            cursorLine = max(0, cursorLine - 1)
        } else if isDown {
            let lines = buffer.text.components(separatedBy: "\n")
            cursorLine = min(lines.count - 1, cursorLine + 1)
        } else if isLeft {
            cursorCol = max(0, cursorCol - 1)
        } else if isRight {
            cursorCol += 1
        } else if isEnter {
            let currentLen = buffer.length
            buffer.insert(offset: currentLen, text: "\n")
            cursorLine += 1
            cursorCol = 0
        } else if isBackspace {
            let currentLen = buffer.length
            if currentLen > 0 {
                buffer.delete(offset: currentLen - 1, length: 1)
                cursorCol = max(0, cursorCol - 1)
            }
        } else if !chars.isEmpty {
            let currentLen = buffer.length
            buffer.insert(offset: currentLen, text: chars)
            cursorCol += chars.count
        }

        cursorVisible = true
        needsDisplay = true
    }
}
