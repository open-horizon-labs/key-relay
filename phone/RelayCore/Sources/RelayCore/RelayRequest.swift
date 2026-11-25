import CryptoKit
import Foundation

/// CTAP status codes the phone produces itself (docs/relay-contract.md).
public enum CTAPStatus {
    public static let ok: UInt8 = 0x00
    public static let invalidCommand: UInt8 = 0x01
    public static let invalidCBOR: UInt8 = 0x12
    public static let missingParameter: UInt8 = 0x14
    public static let unsupportedOption: UInt8 = 0x2B
    public static let operationDenied: UInt8 = 0x27
    public static let keepaliveCancel: UInt8 = 0x2D
    public static let noCredentials: UInt8 = 0x2E
    public static let userActionTimeout: UInt8 = 0x2F
    public static let other: UInt8 = 0x7F

    /// Key errors passed to the browser unchanged; everything else becomes `other`
    /// (PIN errors are handled on the phone before this applies).
    public static func forBrowser(_ keyStatus: UInt8) -> UInt8 {
        [0x00, 0x2E, 0x19, 0x26, 0x28].contains(keyStatus) ? keyStatus : other
    }
}

/// A rejected request and the CTAP status to answer it with.
public struct RequestRejection: Error, Equatable {
    public let status: UInt8
    public let reason: String
}

/// A browser request received from the receiver, checked per phone obligations 1–2.
public struct RelayRequest: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case makeCredential
        case getAssertion

        public var ctapCommand: UInt8 { self == .makeCredential ? 0x01 : 0x02 }
        var allowedKeys: Set<Int> { self == .makeCredential ? [1, 2, 3, 4, 5, 7] : [1, 2, 3, 5] }
        var optionsKey: Int { self == .makeCredential ? 7 : 5 }
        var pinUvAuthParamKey: Int { self == .makeCredential ? 8 : 6 }
        var pinUvAuthProtocolKey: Int { self == .makeCredential ? 9 : 7 }
    }

    public let kind: Kind
    public let params: CBORValue
    public let rpId: String
    public let userName: String?
    public let clientDataHash: Data
    /// False only for a silent probe (`options.up == false`).
    public let userPresence: Bool
    public let uvRequested: Bool

    public init(ctapCommand: Int, params data: Data) throws(RequestRejection) {
        switch ctapCommand {
        case 1: kind = .makeCredential
        case 2: kind = .getAssertion
        default: throw RequestRejection(status: CTAPStatus.invalidCommand, reason: "command \(ctapCommand) is not relayed")
        }

        let value: CBORValue
        do { value = try CBORValue.decodeStrict(data) } catch {
            throw RequestRejection(status: CTAPStatus.invalidCBOR, reason: "not canonical CTAP CBOR: \(error)")
        }
        guard let entries = value.mapEntries else {
            throw RequestRejection(status: CTAPStatus.invalidCBOR, reason: "parameters are not a map")
        }
        for entry in entries {
            guard case .unsigned(let k) = entry.key, kind.allowedKeys.contains(Int(k)) else {
                throw RequestRejection(status: CTAPStatus.unsupportedOption, reason: "parameter \(entry.key) is not accepted")
            }
        }
        params = value

        let hashKey = kind == .makeCredential ? 1 : 2
        guard case .bytes(let hash)? = value[hashKey], hash.count == 32 else {
            throw RequestRejection(status: CTAPStatus.missingParameter, reason: "clientDataHash missing or not 32 bytes")
        }
        clientDataHash = hash

        switch kind {
        case .makeCredential:
            guard case .text(let id)? = value[2]?["id"], !id.isEmpty else {
                throw RequestRejection(status: CTAPStatus.missingParameter, reason: "rp.id missing")
            }
            guard case .bytes? = value[3]?["id"] else {
                throw RequestRejection(status: CTAPStatus.missingParameter, reason: "user.id missing")
            }
            guard case .array? = value[4] else {
                throw RequestRejection(status: CTAPStatus.missingParameter, reason: "pubKeyCredParams missing")
            }
            rpId = id
            if case .text(let name)? = value[3]?["name"] { userName = name } else { userName = nil }
        case .getAssertion:
            guard case .text(let id)? = value[1], !id.isEmpty else {
                throw RequestRejection(status: CTAPStatus.missingParameter, reason: "rpId missing")
            }
            rpId = id
            userName = nil
        }

        let options = value[kind.optionsKey]
        if let options {
            guard let optionEntries = options.mapEntries else {
                throw RequestRejection(status: CTAPStatus.invalidCBOR, reason: "options is not a map")
            }
            for entry in optionEntries {
                guard case .text(let name) = entry.key, ["rk", "up", "uv"].contains(name), case .bool = entry.value else {
                    throw RequestRejection(status: CTAPStatus.unsupportedOption, reason: "option \(entry.key) is not accepted")
                }
            }
        }
        userPresence = options?["up"] != .bool(false)
        uvRequested = options?["uv"] == .bool(true)
        if kind == .makeCredential, !userPresence {
            throw RequestRejection(status: CTAPStatus.invalidCBOR, reason: "makeCredential cannot skip user presence")
        }
    }

    /// Phone obligation 5: drop `uv`, add the PIN/UV auth fields, re-encode canonically.
    public func rewritten(pinUvAuthParam: Data, pinUvAuthProtocol: Int) -> Data {
        var entries: [(CBORValue, CBORValue)] = []
        for entry in params.mapEntries ?? [] {
            if entry.key == .int(kind.optionsKey) {
                let remaining = (entry.value.mapEntries ?? []).filter { $0.key != .text("uv") }
                if !remaining.isEmpty { entries.append((entry.key, .map(remaining))) }
            } else {
                entries.append((entry.key, entry.value))
            }
        }
        entries.append((.int(kind.pinUvAuthParamKey), .bytes(pinUvAuthParam)))
        entries.append((.int(kind.pinUvAuthProtocolKey), .int(pinUvAuthProtocol)))
        return CBORValue.makeMap(entries).encoded()
    }

    /// pinUvAuthParam over the clientDataHash, per CTAP PIN/UV auth protocols 1 and 2.
    public static func pinUvAuthParam(token: Data, protocolVersion: Int, clientDataHash: Data) -> Data {
        let key = SymmetricKey(data: protocolVersion == 1 ? token : token.prefix(32))
        let mac = Data(HMAC<SHA256>.authenticationCode(for: clientDataHash, using: key))
        return protocolVersion == 1 ? mac.prefix(16) : mac
    }
}
