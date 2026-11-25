import Foundation
import RelayCore
import YubiKit

/// One NFC session with the YubiKey: PIN verified once, then one or more relayed
/// requests for the same site while the key stays on the phone
/// (phone obligations 4–6 in docs/relay-contract.md).
final class KeySession: @unchecked Sendable {
    enum Failure: Error, Equatable {
        case nfcUnavailable(String)
        case cancelled
        case wrongPin
        case pinBlocked
        case pinAuthBlocked
        case keyMoved
        case other(String)

        var message: String {
            switch self {
            case .nfcUnavailable: return "NFC isn't available right now."
            case .cancelled: return "Cancelled."
            case .wrongPin: return "Wrong PIN. Try again."
            case .pinBlocked: return "This key's PIN is blocked."
            case .pinAuthBlocked: return "Too many wrong PINs. Lift the key away, then try again."
            case .keyMoved: return "The key moved away too soon. Try again and keep it still."
            case .other: return "Something went wrong talking to the key."
            }
        }
    }

    /// Outcome of one relayed request: the CTAP status for the browser and the
    /// key's raw response maps.
    struct Answer {
        let status: UInt8
        let results: [Data]
    }

    let rpId: String
    private let connection: NFCSmartCardConnection
    private let ctap: NFCCTAP
    private let token: CTAP2.Token

    private init(rpId: String, connection: NFCSmartCardConnection, token: CTAP2.Token) {
        self.rpId = rpId
        self.connection = connection
        self.token = token
        self.ctap = NFCCTAP { apdu in try await connection.send(data: apdu) }
    }

    /// Shows the NFC sheet, waits for the key and verifies the PIN. The token covers
    /// both sign-in and registration for this site, so a silent check and the request
    /// that follows it can run in this one session.
    static func open(rpId: String, pin: String) async -> Result<KeySession, Failure> {
        let connection: NFCSmartCardConnection
        do {
            connection = try await NFCSmartCardConnection(alertMessage: "Hold your key to the top of the phone")
        } catch {
            return .failure(classify(error))
        }
        do {
            let session = try await CTAP2.Session.makeSession(connection: connection)
            let token = try await session.getPinUVToken(
                using: .pin(pin), permissions: [.makeCredential, .getAssertion], rpId: rpId
            )
            return .success(KeySession(rpId: rpId, connection: connection, token: token))
        } catch let error as CTAP2.SessionError {
            await connection.close(error: nil)
            return .failure(classify(error))
        } catch {
            await connection.close(error: nil)
            return .failure(.other("\(error)"))
        }
    }

    func run(_ request: RelayRequest) async -> Result<Answer, Failure> {
        let param = RelayRequest.pinUvAuthParam(
            token: token.data, protocolVersion: token.protocolVersion.rawValue, clientDataHash: request.clientDataHash
        )
        do {
            let (status, body) = try await ctap.send(
                command: request.kind.ctapCommand,
                cbor: request.rewritten(pinUvAuthParam: param, pinUvAuthProtocol: token.protocolVersion.rawValue)
            )
            guard status == CTAPStatus.ok else {
                return .success(Answer(status: CTAPStatus.forBrowser(status), results: []))
            }
            var results = [body]
            if request.kind == .getAssertion,
               case .unsigned(let count)? = (try? CBORValue.decodeStrict(body))?[5], count > 1 {
                for _ in 1..<count {
                    let (nextStatus, nextBody) = try await ctap.send(command: 0x08)
                    guard nextStatus == CTAPStatus.ok else { break }
                    results.append(nextBody)
                }
            }
            return .success(Answer(status: CTAPStatus.ok, results: results))
        } catch let error as SmartCardConnectionError {
            return .failure(Self.classify(error))
        } catch {
            return .failure(.other("\(error)"))
        }
    }

    func close(message: String?) async {
        if let message { await connection.close(message: message) } else { await connection.close(error: nil) }
    }

    private static func classify(_ error: CTAP2.SessionError) -> Failure {
        switch error {
        case .ctapError(.pinInvalid, _): return .wrongPin
        case .ctapError(.pinBlocked, _): return .pinBlocked
        case .ctapError(.pinAuthBlocked, _): return .pinAuthBlocked  // cleared by removing power
        case .connectionError(let e, _): return classify(e)
        default: return .other("\(error)")
        }
    }

    private static func classify(_ error: SmartCardConnectionError) -> Failure {
        switch error {
        case .cancelled, .cancelledByUser: return .cancelled
        case .connectionLost, .transmitFailed: return .keyMoved  // the key left the NFC field
        case .unsupported, .busy: return .nfcUnavailable("\(error)")
        default: return .other("\(error)")
        }
    }
}
