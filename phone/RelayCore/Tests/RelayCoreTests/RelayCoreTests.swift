import Foundation
import Testing

@testable import RelayCore

func hex(_ s: String) -> Data {
    var data = Data()
    var index = s.startIndex
    while index < s.endIndex {
        let next = s.index(index, offsetBy: 2)
        data.append(UInt8(s[index..<next], radix: 16)!)
        index = next
    }
    return data
}

/// Produced by bench/driver.py (python-fido2's canonical encoder) for the same inputs.
let pythonMakeCredential = hex("a5015820000000000000000000000000000000000000000000000000000000000000000002a2626964696c6f63616c686f7374646e616d65704b657952656c6179207465737420525003a362696450000102030405060708090a0b0c0d0e0f646e616d6569746573742d757365726b646973706c61794e616d6569746573742d757365720482a263616c672664747970656a7075626c69632d6b6579a263616c672764747970656a7075626c69632d6b657907a1627576f5")
let pythonGetAssertion = hex("a401696c6f63616c686f737402582000000000000000000000000000000000000000000000000000000000000000000381a26269645820070707070707070707070707070707070707070707070707070707070707070764747970656a7075626c69632d6b657905a1627576f5")

@Suite struct CBORTests {
    @Test func decodesAndReencodesPythonBytesIdentically() throws {
        for bytes in [pythonMakeCredential, pythonGetAssertion] {
            #expect(try CBORValue.decodeStrict(bytes).encoded() == bytes)
        }
    }

    @Test func encodesCanonicalOrder() {
        let map = CBORValue.makeMap([(.text("uv"), .bool(true)), (.text("rk"), .bool(false)), (.text("up"), .bool(true))])
        #expect(map.encoded() == hex("a362726bf4627570f5627576f5"))
        #expect(CBORValue.int(-7).encoded() == hex("26"))
        #expect(CBORValue.int(500).encoded() == hex("1901f4"))
    }

    @Test(arguments: [
        ("a0" + "00", "trailing byte"),
        ("9fff", "indefinite array"),
        ("1805", "non-minimal integer"),
        ("a201000100", "duplicate key"),
        ("a202000100", "unsorted int keys"),
        ("a2627576f5627266f4", "unsorted text keys"),
        ("c000", "tag"),
        ("f93c00", "half float"),
        ("62ff", "truncated text"),
        ("62c328", "invalid UTF-8"),
    ])
    func rejectsNonCanonicalInput(input: String, label: String) {
        #expect(throws: CBORError.self, "\(label)") { try CBORValue.decodeStrict(hex(input)) }
    }
}

@Suite struct RelayRequestTests {
    @Test func parsesMakeCredential() throws {
        let request = try RelayRequest(ctapCommand: 1, params: pythonMakeCredential)
        #expect(request.kind == .makeCredential)
        #expect(request.rpId == "localhost")
        #expect(request.userName == "test-user")
        #expect(request.uvRequested && request.userPresence)
        #expect(request.clientDataHash == Data(count: 32))
    }

    @Test func parsesGetAssertion() throws {
        let request = try RelayRequest(ctapCommand: 2, params: pythonGetAssertion)
        #expect(request.kind == .getAssertion && request.rpId == "localhost" && request.userName == nil)
    }

    @Test func rejectsOtherCommands() {
        #expect(throws: RequestRejection(status: 0x01, reason: "command 4 is not relayed")) {
            try RelayRequest(ctapCommand: 4, params: hex("a0"))
        }
    }

    @Test(arguments: [6, 8, 9, 10])
    func rejectsFieldsBrowsersDoNotSendHere(key: Int) throws {
        var entries = try #require(CBORValue.decodeStrict(pythonMakeCredential).mapEntries).map { ($0.key, $0.value) }
        entries.append((.int(key), .bytes(Data([1]))))
        let error = #expect(throws: RequestRejection.self) {
            try RelayRequest(ctapCommand: 1, params: CBORValue.makeMap(entries).encoded())
        }
        #expect(error?.status == 0x2B)
    }

    @Test func rejectsUnknownOption() throws {
        let params = CBORValue.makeMap([(.int(1), .text("localhost")), (.int(2), .bytes(Data(count: 32))),
                                        (.int(5), .makeMap([(.text("ep"), .bool(true))]))])
        let error = #expect(throws: RequestRejection.self) { try RelayRequest(ctapCommand: 2, params: params.encoded()) }
        #expect(error?.status == 0x2B)
    }

    @Test func rejectsNonCanonicalBytes() {
        let error = #expect(throws: RequestRejection.self) {
            try RelayRequest(ctapCommand: 2, params: pythonGetAssertion + Data([0x00]))
        }
        #expect(error?.status == 0x12)
    }

    @Test func rejectsWrongHashLength() {
        let params = CBORValue.makeMap([(.int(1), .text("localhost")), (.int(2), .bytes(Data(count: 31)))])
        let error = #expect(throws: RequestRejection.self) { try RelayRequest(ctapCommand: 2, params: params.encoded()) }
        #expect(error?.status == 0x14)
    }

    @Test func rewriteDropsUVAndAddsPinFieldsOnly() throws {
        let request = try RelayRequest(ctapCommand: 1, params: pythonMakeCredential)
        let rewritten = try CBORValue.decodeStrict(request.rewritten(pinUvAuthParam: Data(repeating: 9, count: 32), pinUvAuthProtocol: 2))
        let original = try CBORValue.decodeStrict(pythonMakeCredential)
        for key in 1...4 { #expect(rewritten[key] == original[key]) }
        #expect(rewritten[7] == nil)  // options held only uv, so the map is dropped
        #expect(rewritten[8] == .bytes(Data(repeating: 9, count: 32)))
        #expect(rewritten[9] == .int(2))
    }

    @Test func rewriteKeepsUpFalseForProbes() throws {
        let params = CBORValue.makeMap([(.int(1), .text("localhost")), (.int(2), .bytes(Data(count: 32))),
                                        (.int(5), .makeMap([(.text("up"), .bool(false))]))])
        let request = try RelayRequest(ctapCommand: 2, params: params.encoded())
        #expect(!request.userPresence)
        let rewritten = try CBORValue.decodeStrict(request.rewritten(pinUvAuthParam: Data(count: 16), pinUvAuthProtocol: 1))
        #expect(rewritten[5] == .makeMap([(.text("up"), .bool(false))]))
        #expect(rewritten[6] == .bytes(Data(count: 16)) && rewritten[7] == .int(1))
    }

    @Test func pinUvAuthParamMatchesRFC4231() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let mac = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        let message = Data("what do ya want for nothing?".utf8)
        #expect(RelayRequest.pinUvAuthParam(token: Data("Jefe".utf8), protocolVersion: 2, clientDataHash: message) == mac)
        #expect(RelayRequest.pinUvAuthParam(token: Data("Jefe".utf8), protocolVersion: 1, clientDataHash: message) == mac.prefix(16))
    }

    @Test func browserStatusMapping() {
        #expect(CTAPStatus.forBrowser(0x2E) == 0x2E)
        #expect(CTAPStatus.forBrowser(0x31) == 0x7F)
    }
}

@Suite struct WireTests {
    @Test func framesSurviveArbitrarySplits() throws {
        let frame = try Wire.frame(["type": "arm", "ttl_ms": 300_000]) + Wire.frame(["type": "ping"])
        var buffer = Wire.Buffer()
        var messages: [[String: Any]] = []
        for byte in frame {
            buffer.append(Data([byte]))
            while let message = try buffer.next() { messages.append(message) }
        }
        #expect(messages.map { $0["type"] as? String } == ["arm", "ping"])
        #expect(messages[0]["v"] as? Int == 1)
    }

    @Test func rejectsWrongVersion() throws {
        let json = Data(#"{"type":"hello","v":2}"#.utf8)
        var buffer = Wire.Buffer()
        buffer.append(Data([0, 0, 0, UInt8(json.count)]) + json)
        #expect(throws: Wire.FrameError.self) { try buffer.next() }
    }

    @Test func rejectsOversizedFrame() {
        var buffer = Wire.Buffer()
        buffer.append(Data([0x00, 0x01, 0x00, 0x01]))
        #expect(throws: Wire.FrameError.tooLarge(65537)) { try buffer.next() }
    }

    @Test func base64urlRoundTrip() {
        let data = Data((0...255).map { UInt8($0) })
        let text = Wire.base64url(data)
        #expect(!text.contains("=") && !text.contains("+") && !text.contains("/"))
        #expect(Wire.fromBase64url(text) == data)
    }
}

/// A fake card that records APDUs and replies from a script.
actor FakeCard {
    var sent: [Data] = []
    var replies: [Data]
    init(_ replies: [String]) { self.replies = replies.map(hex) }
    func transmit(_ apdu: Data) -> Data {
        sent.append(apdu)
        return replies.removeFirst()
    }
}

@Suite struct NFCCTAPTests {
    func client(_ card: FakeCard) -> NFCCTAP {
        NFCCTAP(pollDelay: .zero) { try await card.transmit($0) }
    }

    @Test func shortCommand() async throws {
        let card = FakeCard(["00a09000"])
        let (status, body) = try await client(card).send(command: 0x04)
        #expect(status == 0 && body == hex("a0"))
        #expect(await card.sent == [hex("8010800001" + "04")])
    }

    @Test func keepalivePolling() async throws {
        let card = FakeCard(["029100", "029100", "00a09000"])
        let (status, _) = try await client(card).send(command: 0x02, cbor: hex("a0"))
        #expect(status == 0)
        let sent = await card.sent
        #expect(sent.count == 3 && sent[1] == hex("80110000") && sent[2] == hex("80110000"))
    }

    @Test func commandChainingAbove255Bytes() async throws {
        let card = FakeCard(["9000", "9000", "00a09000"])
        let cbor = Data(repeating: 0xAB, count: 599)  // 600 bytes with the command byte
        _ = try await client(card).send(command: 0x01, cbor: cbor)
        let sent = await card.sent
        #expect(sent.count == 3)
        #expect(sent[0].prefix(5) == hex("90108000ff") && sent[0].count == 5 + 255)
        #expect(sent[1].prefix(5) == hex("90108000ff"))
        #expect(sent[2].prefix(5) == hex("801080005a") && sent[2].count == 5 + 90)
    }

    @Test func responseContinuation() async throws {
        let card = FakeCard(["00a1" + "6102", "0102" + "9000"])
        let (status, body) = try await client(card).send(command: 0x02, cbor: hex("a0"))
        #expect(status == 0 && body == hex("a10102"))
        #expect(await card.sent[1] == hex("00c0000000"))
    }

    @Test func failingStatusWordThrows() async {
        let card = FakeCard(["6a82"])
        await #expect(throws: NFCCTAP.ExchangeError.status(0x6A82)) {
            _ = try await client(card).send(command: 0x04)
        }
    }

    @Test func ctapErrorStatusIsReturnedNotThrown() async throws {
        let card = FakeCard(["2e9000"])
        let (status, body) = try await client(card).send(command: 0x02, cbor: hex("a0"))
        #expect(status == 0x2E && body.isEmpty)
    }
}
