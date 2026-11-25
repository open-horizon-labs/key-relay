import Foundation

/// Interface B framing: 4-byte big-endian length, then UTF-8 JSON (docs/relay-contract.md).
public enum Wire {
    public static let protocolVersion = 1
    public static let maxFrame = 64 * 1024

    public enum FrameError: Error, Equatable {
        case tooLarge(Int)
        case notAnObject
        case wrongVersion(Any?)

        public static func == (a: FrameError, b: FrameError) -> Bool {
            switch (a, b) {
            case (.tooLarge(let x), .tooLarge(let y)): return x == y
            case (.notAnObject, .notAnObject), (.wrongVersion, .wrongVersion): return true
            default: return false
            }
        }
    }

    public static func frame(_ message: [String: Any]) throws -> Data {
        var body = message
        body["v"] = protocolVersion
        let json = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        guard json.count <= maxFrame else { throw FrameError.tooLarge(json.count) }
        var length = UInt32(json.count).bigEndian
        return Data(bytes: &length, count: 4) + json
    }

    /// Accumulates received bytes and yields complete messages.
    public struct Buffer {
        private var data = Data()
        public init() {}

        public mutating func append(_ bytes: Data) { data.append(bytes) }

        /// The next complete message, nil if more bytes are needed.
        public mutating func next() throws -> [String: Any]? {
            guard data.count >= 4 else { return nil }
            let length = data.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            guard length <= Wire.maxFrame else { throw FrameError.tooLarge(length) }
            guard data.count >= 4 + length else { return nil }
            let body = data.subdata(in: data.startIndex + 4 ..< data.startIndex + 4 + length)
            data = Data(data.dropFirst(4 + length))
            guard let message = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                throw FrameError.notAnObject
            }
            guard message["v"] as? Int == Wire.protocolVersion else { throw FrameError.wrongVersion(message["v"]) }
            return message
        }
    }

    public static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    public static func fromBase64url(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return Data(base64Encoded: s)
    }
}
