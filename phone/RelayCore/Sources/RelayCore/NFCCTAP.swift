import Foundation

/// CTAP over ISO 7816 APDUs (the NFC transport), mirroring YubiKit Swift v1.5.0's
/// SmartCardInterface: command chaining above 255 bytes, 0x61xx continuation, and
/// 0x9100 keepalive polling with NFCCTAP_GETRESPONSE. Raw bytes go in and come out,
/// so the phone returns the key's response unchanged.
public struct NFCCTAP {
    public typealias Transmit = (Data) async throws -> Data

    public enum ExchangeError: Error, Equatable {
        case shortResponse
        case status(UInt16)
        case emptyCTAPResponse
    }

    let transmit: Transmit
    let pollDelay: Duration

    public init(pollDelay: Duration = .milliseconds(100), transmit: @escaping Transmit) {
        self.transmit = transmit
        self.pollDelay = pollDelay
    }

    /// Sends `command || cbor` and returns (CTAP status byte, CBOR body).
    public func send(command: UInt8, cbor: Data = Data()) async throws -> (status: UInt8, body: Data) {
        var payload = Data([command])
        payload.append(cbor)
        var (data, sw) = try await apdu(cla: 0x80, ins: 0x10, p1: 0x80, data: payload)
        while sw == 0x9100 {
            try await Task.sleep(for: pollDelay)
            (data, sw) = try await apdu(cla: 0x80, ins: 0x11, p1: 0x00, data: Data())
        }
        guard sw == 0x9000 else { throw ExchangeError.status(sw) }
        guard let status = data.first else { throw ExchangeError.emptyCTAPResponse }
        return (status, Data(data.dropFirst()))
    }

    func apdu(cla: UInt8, ins: UInt8, p1: UInt8, data: Data) async throws -> (Data, UInt16) {
        var offset = data.startIndex
        if data.count > 255 {
            while data.endIndex - offset > 255 {
                let chunk = data.subdata(in: offset ..< offset + 255)
                let (_, sw) = try await exchange(Self.encode(cla: cla | 0x10, ins: ins, p1: p1, data: chunk))
                guard sw == 0x9000 else { return (Data(), sw) }
                offset += 255
            }
        }
        var (body, sw) = try await exchange(Self.encode(cla: cla, ins: ins, p1: p1, data: data.subdata(in: offset ..< data.endIndex)))
        while sw >> 8 == 0x61 {
            let (more, nextSW) = try await exchange(Data([0x00, 0xC0, 0x00, 0x00, 0x00]))
            body.append(more)
            sw = nextSW
        }
        return (body, sw)
    }

    private func exchange(_ apdu: Data) async throws -> (Data, UInt16) {
        let raw = try await transmit(apdu)
        guard raw.count >= 2 else { throw ExchangeError.shortResponse }
        let sw = UInt16(raw[raw.endIndex - 2]) << 8 | UInt16(raw[raw.endIndex - 1])
        return (Data(raw.dropLast(2)), sw)
    }

    /// Short APDU without Le, as YubiKit sends it.
    static func encode(cla: UInt8, ins: UInt8, p1: UInt8, data: Data) -> Data {
        var out = Data([cla, ins, p1, 0x00])
        if !data.isEmpty {
            out.append(UInt8(data.count))
            out.append(data)
        }
        return out
    }
}
