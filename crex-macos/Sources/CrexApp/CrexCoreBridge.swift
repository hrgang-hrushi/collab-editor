import Foundation
import CrexCoreC

public final class CrexBuffer {
    private var handle: OpaquePointer?

    public init(initialText: String = "") {
        initialText.withCString { cStr in
            self.handle = crex_buffer_create(cStr)
        }
    }

    deinit {
        if let handle = self.handle {
            crex_buffer_free(handle)
        }
    }

    public func insert(offset: Int, text: String) {
        guard let handle = self.handle else { return }
        text.withCString { cStr in
            crex_buffer_insert(handle, offset, cStr)
        }
    }

    public func delete(offset: Int, length: Int) {
        guard let handle = self.handle else { return }
        crex_buffer_delete(handle, offset, length)
    }

    public var text: String {
        guard let handle = self.handle else { return "" }
        guard let rawPtr = crex_buffer_get_text(handle) else { return "" }
        let str = String(cString: rawPtr)
        crex_string_free(rawPtr)
        return str
    }

    public var lineCount: Int {
        guard let handle = self.handle else { return 0 }
        return crex_buffer_line_count(handle)
    }

    public var length: Int {
        guard let handle = self.handle else { return 0 }
        return crex_buffer_length(handle)
    }

    public func parseAST(language: String = "rust") -> String {
        guard let handle = self.handle else { return "{}" }
        return language.withCString { cLang in
            guard let rawPtr = crex_buffer_parse_ast(handle, cLang) else { return "{}" }
            let str = String(cString: rawPtr)
            crex_string_free(rawPtr)
            return str
        }
    }
}
