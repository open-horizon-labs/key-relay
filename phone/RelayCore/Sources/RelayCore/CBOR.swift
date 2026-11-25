import Foundation

/// The CBOR subset CTAP2 uses, with strict canonical decoding.
///
/// Decoding rejects anything a canonical CTAP2 encoder would not produce: indefinite
/// lengths, non-minimal integer encodings, tags, floats, undefined, duplicate or
/// unsorted map keys, invalid UTF-8 and trailing bytes. A value that decodes therefore
/// re-encodes to the same bytes, so what the phone shows is what the key will read.
public indirect enum CBORValue: Equatable, Sendable {
    case unsigned(UInt64)
    /// Major type 1: represents -1 - n.
    case negative(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    /// Entries in canonical order.
    case map([MapEntry])
    case bool(Bool)
    case null

    public struct MapEntry: Equatable, Sendable {
        public var key: CBORValue
        public var value: CBORValue
        public init(_ key: CBORValue, _ value: CBORValue) {
            self.key = key
            self.value = value
        }
    }

    public static func int(_ value: Int) -> CBORValue {
        value >= 0 ? .unsigned(UInt64(value)) : .negative(UInt64(-1 - value))
    }

    /// Builds a map, sorting entries canonically. Duplicate keys are a programming error.
    public static func makeMap(_ entries: [(CBORValue, CBORValue)]) -> CBORValue {
        let sorted = entries.map { MapEntry($0.0, $0.1) }.sorted { canonicalLess($0.key.encoded(), $1.key.encoded()) }
        precondition(zip(sorted, sorted.dropFirst()).allSatisfy { $0.key != $1.key }, "duplicate CBOR map key")
        return .map(sorted)
    }

    public subscript(key: CBORValue) -> CBORValue? {
        guard case .map(let entries) = self else { return nil }
        return entries.first { $0.key == key }?.value
    }

    public subscript(intKey: Int) -> CBORValue? { self[.int(intKey)] }
    public subscript(textKey: String) -> CBORValue? { self[.text(textKey)] }

    public var mapEntries: [MapEntry]? {
        if case .map(let entries) = self { return entries }
        return nil
    }
}

/// CTAP2 canonical order: shorter encoded key first, then bytewise.
func canonicalLess(_ a: Data, _ b: Data) -> Bool {
    if a.count != b.count { return a.count < b.count }
    return a.lexicographicallyPrecedes(b)
}

public enum CBORError: Error, Equatable {
    case truncated
    case trailingBytes
    case unsupported(String)
    case nonCanonical(String)
    case tooDeep
}

// MARK: Encoding

extension CBORValue {
    public func encoded() -> Data {
        var out = Data()
        encode(into: &out)
        return out
    }

    private func encode(into out: inout Data) {
        switch self {
        case .unsigned(let n): Self.head(0, n, into: &out)
        case .negative(let n): Self.head(1, n, into: &out)
        case .bytes(let d):
            Self.head(2, UInt64(d.count), into: &out)
            out.append(d)
        case .text(let s):
            let d = Data(s.utf8)
            Self.head(3, UInt64(d.count), into: &out)
            out.append(d)
        case .array(let items):
            Self.head(4, UInt64(items.count), into: &out)
            items.forEach { $0.encode(into: &out) }
        case .map(let entries):
            let sorted = entries.sorted { canonicalLess($0.key.encoded(), $1.key.encoded()) }
            Self.head(5, UInt64(sorted.count), into: &out)
            for entry in sorted {
                entry.key.encode(into: &out)
                entry.value.encode(into: &out)
            }
        case .bool(let b): out.append(b ? 0xF5 : 0xF4)
        case .null: out.append(0xF6)
        }
    }

    private static func head(_ major: UInt8, _ value: UInt64, into out: inout Data) {
        let m = major << 5
        switch value {
        case 0..<24: out.append(m | UInt8(value))
        case 24...0xFF: out.append(contentsOf: [m | 24, UInt8(value)])
        case 0x100...0xFFFF: out.append(m | 25); out.append(contentsOf: withUnsafeBytes(of: UInt16(value).bigEndian, Array.init))
        case 0x1_0000...0xFFFF_FFFF: out.append(m | 26); out.append(contentsOf: withUnsafeBytes(of: UInt32(value).bigEndian, Array.init))
        default: out.append(m | 27); out.append(contentsOf: withUnsafeBytes(of: value.bigEndian, Array.init))
        }
    }
}

// MARK: Strict decoding

extension CBORValue {
    public static func decodeStrict(_ data: Data, maxDepth: Int = 16) throws(CBORError) -> CBORValue {
        var reader = Reader(bytes: [UInt8](data))
        let value = try reader.value(depth: maxDepth)
        guard reader.offset == reader.bytes.count else { throw .trailingBytes }
        return value
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        mutating func byte() throws(CBORError) -> UInt8 {
            guard offset < bytes.count else { throw .truncated }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func take(_ n: UInt64) throws(CBORError) -> [UInt8] {
            guard n <= UInt64(bytes.count - offset) else { throw .truncated }
            let end = offset + Int(n)
            defer { offset = end }
            return Array(bytes[offset..<end])
        }

        mutating func argument(_ info: UInt8) throws(CBORError) -> UInt64 {
            switch info {
            case 0..<24: return UInt64(info)
            case 24...27:
                let width = 1 << Int(info - 24)
                let raw = try take(UInt64(width))
                let value = raw.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
                let minimum: UInt64 = [24, 0x100, 0x1_0000, 0x1_0000_0000][Int(info - 24)]
                guard value >= minimum else { throw .nonCanonical("non-minimal integer encoding") }
                return value
            case 31: throw .unsupported("indefinite length")
            default: throw .unsupported("reserved additional information \(info)")
            }
        }

        mutating func value(depth: Int) throws(CBORError) -> CBORValue {
            guard depth > 0 else { throw .tooDeep }
            let initial = try byte()
            let major = initial >> 5
            let info = initial & 0x1F
            switch major {
            case 0: return .unsigned(try argument(info))
            case 1: return .negative(try argument(info))
            case 2: return .bytes(Data(try take(try argument(info))))
            case 3:
                guard let s = String(bytes: try take(try argument(info)), encoding: .utf8) else {
                    throw .unsupported("invalid UTF-8 text")
                }
                return .text(s)
            case 4:
                let count = try argument(info)
                guard count <= UInt64(bytes.count - offset) else { throw .truncated }
                var items: [CBORValue] = []
                for _ in 0..<count { items.append(try value(depth: depth - 1)) }
                return .array(items)
            case 5:
                let count = try argument(info)
                guard count <= UInt64(bytes.count - offset) else { throw .truncated }
                var entries: [MapEntry] = []
                var previousKey: Data?
                for _ in 0..<count {
                    let keyStart = offset
                    let key = try value(depth: depth - 1)
                    let keyBytes = Data(bytes[keyStart..<offset])
                    if let previousKey {
                        guard keyBytes != previousKey else { throw .nonCanonical("duplicate map key") }
                        guard canonicalLess(previousKey, keyBytes) else { throw .nonCanonical("map keys out of canonical order") }
                    }
                    previousKey = keyBytes
                    entries.append(MapEntry(key, try value(depth: depth - 1)))
                }
                return .map(entries)
            case 6: throw .unsupported("tags")
            default:
                switch info {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22: return .null
                default: throw .unsupported("simple value or float \(info)")
                }
            }
        }
    }
}
