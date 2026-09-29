import AppKit

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let sourceURL = root.appendingPathComponent("src-tauri/icons/Crex.png")
let outputURL = root.appendingPathComponent("src-tauri/icons/crux-source.png")
guard let source = NSImage(contentsOf: sourceURL) else {
  fatalError("Could not load the supplied Crux logo")
}

let canvas = NSSize(width: 1024, height: 1024)
let image = NSImage(size: canvas)
image.lockFocus()
NSColor.black.setFill()
NSRect(origin: .zero, size: canvas).fill()
let crop = min(source.size.width, source.size.height)
source.draw(
  in: NSRect(origin: .zero, size: canvas),
  from: NSRect(
    x: (source.size.width - crop) / 2,
    y: (source.size.height - crop) / 2,
    width: crop,
    height: crop
  ),
  operation: .copy,
  fraction: 1
)
image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
  fatalError("Could not render the Crux icon")
}
try png.write(to: outputURL)
