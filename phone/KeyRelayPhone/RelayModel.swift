import Foundation
import Network
import Observation
import RelayCore
import UIKit

/// Phone side of interface B (docs/relay-contract.md), as one state machine the UI
/// shows directly: the app is ready while it is open, and each sign-in is
/// "PIN, hold the key once, done".
///
/// Bench build: plain TCP to the receiver, no pinned-key channel (decision D2 pending).
/// Use only on a private network with test credentials.
@MainActor
@Observable
final class RelayModel {
    enum Phase: Equatable {
        case setup
        case connecting
        case ready
        case request
        case holding(String)
        case done(String)
        case failed(String)
    }

    struct Pending: Equatable {
        let id: Int
        let request: RelayRequest

        var site: String { request.rpId }
        var isRegistration: Bool { request.kind == .makeCredential }
    }

    // MARK: State shown by the UI

    private(set) var phase: Phase = .setup
    private(set) var pending: Pending?
    private(set) var armedUntil: Date?
    private(set) var activity: [String] = []
    var address: String = UserDefaults.standard.string(forKey: "receiverAddress") ?? "" {
        didSet { UserDefaults.standard.set(address, forKey: "receiverAddress") }
    }

    var hostLabel: String { address.split(separator: ":").first.map(String.init) ?? address }

    // MARK: Internals

    private static let armDuration = 15 * 60  // seconds; contract maximum
    private static let followUpWindow: TimeInterval = 10

    private var connection: NWConnection?
    private var buffer = Wire.Buffer()
    private var lastReceived = Date()
    private var lastSent = Date()
    private var timer: Timer?
    private var reconnectFailures = 0
    private var nextConnectAt = Date()
    private var foreground = true
    private var phaseReset: Task<Void, Never>?

    /// The request currently running against the key. `abandoned` is set when the
    /// browser cancels or the connection drops meanwhile: the result is then discarded.
    private var executing: (id: Int, abandoned: Bool)?
    private var working: Bool { executing != nil }

    /// Open NFC session kept after answering a silent check, for the request that follows.
    private var liveSession: KeySession?
    private var followUpDeadline: Date?

    init() {
        if !address.isEmpty { phase = .connecting }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
    }

    // MARK: Lifecycle

    func appBecameActive() {
        foreground = true
        if !address.isEmpty, connection == nil { connect() }
    }

    func appWentToBackground() {
        foreground = false
        send(["type": "disarm"])
        disconnect(note: "App in background: not ready")
    }

    func saveAddress(_ newAddress: String) {
        address = newAddress.trimmingCharacters(in: .whitespaces)
        disconnect(note: nil)
        reconnectFailures = 0
        if address.isEmpty { phase = .setup } else { connect() }
    }

    // MARK: Connection

    private func connect() {
        let parts = address.split(separator: ":")
        guard parts.count == 2, let port = NWEndpoint.Port(String(parts[1])) else {
            phase = .setup
            note("Receiver address must look like host:port")
            return
        }
        if pending == nil, !working { phase = .connecting }
        let conn = NWConnection(host: NWEndpoint.Host(String(parts[0])), port: port, using: .tcp)
        connection = conn
        buffer = Wire.Buffer()
        lastReceived = Date()  // give a fresh connection the full liveness window
        conn.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in self?.handle(state: state, of: conn) }
        }
        conn.start(queue: .main)
        receive(on: conn)
    }

    private func disconnect(note text: String?) {
        if let text { note(text) }
        connection?.cancel()
        connection = nil
        armedUntil = nil
        // A key session kept for a follow-up never survives the connection.
        finishSession(message: nil, phase: nil)
        if executing != nil {
            executing?.abandoned = true  // the running key step cleans up when it returns
        } else if let pending {
            note("Request \(pending.id) dropped: connection closed")
            self.pending = nil
        }
        reconnectFailures += 1
        let backoff = [1.0, 2, 4, 8, 10][min(reconnectFailures - 1, 4)]
        nextConnectAt = Date().addingTimeInterval(backoff)
        if pending == nil, !working, phase != .setup { phase = address.isEmpty ? .setup : .connecting }
    }

    private func handle(state: NWConnection.State, of conn: NWConnection) {
        guard conn === connection else { return }
        switch state {
        case .ready:
            reconnectFailures = 0
            lastReceived = Date()
            send(["type": "hello", "role": "phone", "app_version": "KeyRelayPhone 0.2"])
        case .failed(let error):
            disconnect(note: "Connection failed: \(error.localizedDescription)")
        case .waiting(let error):
            note("Waiting for network: \(error.localizedDescription)")
        default:
            break
        }
    }

    private func receive(on conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            Task { @MainActor in
                guard let self, conn === self.connection else { return }
                if let data, !data.isEmpty {
                    self.lastReceived = Date()
                    self.buffer.append(data)
                    do {
                        while let message = try self.buffer.next() { self.handle(message: message) }
                    } catch let error as Wire.FrameError {
                        if case .wrongVersion = error {
                            self.send(["type": "error", "code": "version", "message": "expected v=1"])
                        } else {
                            self.send(["type": "error", "code": "malformed", "message": "bad frame"])
                        }
                        self.disconnect(note: "Receiver sent an unusable frame")
                        return
                    } catch {
                        self.send(["type": "error", "code": "malformed", "message": "bad frame"])
                        self.disconnect(note: "Receiver sent a malformed frame")
                        return
                    }
                }
                if isComplete || error != nil {
                    self.disconnect(note: "Receiver closed the connection")
                } else {
                    self.receive(on: conn)
                }
            }
        }
    }

    private func send(_ message: [String: Any]) {
        guard let connection, let frame = try? Wire.frame(message) else { return }
        lastSent = Date()
        connection.send(content: frame, completion: .contentProcessed { _ in })
    }

    private func tick() {
        let now = Date()
        if connection != nil {
            if now.timeIntervalSince(lastSent) >= 5 { send(["type": "ping"]) }
            if now.timeIntervalSince(lastReceived) > 15 { disconnect(note: "Receiver stopped answering") }
        } else if foreground, !address.isEmpty, !working, now >= nextConnectAt {
            connect()  // backoff after failures: 1, 2, 4, 8, then every 10 s
        }
        // Stay ready while the app is open: re-arm before the receiver's limit.
        if let armedUntil, connection != nil, foreground, armedUntil.timeIntervalSince(now) < 60 { arm() }
        // A silent check was answered and nothing followed: finish quietly.
        if let deadline = followUpDeadline, now > deadline { finishSession(message: "Done", phase: .done("Done")) }
    }

    // MARK: Messages from the receiver

    private func handle(message: [String: Any]) {
        switch message["type"] as? String {
        case "hello":
            note("Connected to \(hostLabel)")
            arm()
        case "state":
            let armed = message["armed"] as? Bool ?? false
            let ms = message["expires_in_ms"] as? Int ?? 0
            armedUntil = armed ? Date().addingTimeInterval(Double(ms) / 1000) : nil
            if pending == nil, !working, phase == .connecting || phase == .ready {
                phase = armed ? .ready : .connecting
            }
        case "ping":
            break
        case "request":
            handle(request: message)
        case "cancel":
            guard let id = message["request_id"] as? Int else { break }
            if executing?.id == id {
                executing?.abandoned = true
                note("Request \(id) cancelled by the browser while the key was in use")
            } else if id == pending?.id {
                note("Request \(id) cancelled by the browser")
                pending = nil
                show(.failed("The sign-in was cancelled on the computer."), resetAfter: 3)
            }
        case "error":
            disconnect(note: "Receiver error: \(message["message"] as? String ?? "?")")
        default:
            send(["type": "error", "code": "unexpected", "message": "unknown message type"])
        }
    }

    private func arm() {
        send(["type": "arm", "ttl_ms": Self.armDuration * 1000])
    }

    private func handle(request message: [String: Any]) {
        guard let id = message["request_id"] as? Int,
              let command = message["ctap_command"] as? Int,
              let encoded = message["ctap_params"] as? String,
              let params = Wire.fromBase64url(encoded) else {
            send(["type": "error", "code": "malformed", "message": "bad request message"])
            return
        }
        let request: RelayRequest
        do {
            request = try RelayRequest(ctapCommand: command, params: params)
        } catch {
            let rejection = error as? RequestRejection
            respond(id: id, status: rejection?.status ?? CTAPStatus.invalidCBOR, results: [])
            note("Refused request \(id): \(rejection?.reason ?? "invalid")")
            return
        }

        // The sign-in that follows an approved silent check runs in the same NFC
        // session, without asking again (phone obligation 6).
        if let session = liveSession, followUpDeadline != nil, !working {
            if request.kind == .getAssertion, request.userPresence, request.rpId == session.rpId {
                followUpDeadline = nil
                runFollowUp(id: id, request: request, in: session)
                return
            }
            finishSession(message: nil, phase: nil)
        }

        guard pending == nil, !working else {
            respond(id: id, status: CTAPStatus.operationDenied, results: [])
            note("Refused request \(id): another request is in progress")
            return
        }
        present(Pending(id: id, request: request), as: .request)
    }

    private func present(_ request: Pending, as newPhase: Phase) {
        phaseReset?.cancel()
        pending = request
        phase = newPhase
        note("Request \(request.id): \(request.isRegistration ? "register" : "sign in") at \(request.site)")
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
    }

    private func respond(id: Int, status: UInt8, results: [Data]) {
        send(["type": "response", "request_id": id, "status": Int(status), "results": results.map(Wire.base64url)])
    }

    // MARK: Operator actions

    func deny() {
        guard let pending, !working else { return }
        respond(id: pending.id, status: CTAPStatus.operationDenied, results: [])
        note("Denied request \(pending.id)")
        self.pending = nil
        show(.failed("Denied."), resetAfter: 2)
    }

    func approve(pin: String) {
        guard let pending, !working else { return }
        executing = (pending.id, false)
        phase = .holding("Hold your key to the top of the phone")
        Task {
            let opened = await KeySession.open(rpId: pending.request.rpId, pin: pin)
            switch opened {
            case .failure(let failure):
                if abandon(pending.id, session: nil) { return }
                executing = nil
                fail(failure, keepRequest: failure != .pinBlocked)
            case .success(let session):
                if await abandonAndClose(pending.id, session: session) { return }
                let outcome = await session.run(pending.request)
                if await abandonAndClose(pending.id, session: session) { return }
                switch outcome {
                case .failure(let failure):
                    await session.close(message: nil)
                    executing = nil
                    fail(failure, keepRequest: true)
                case .success(let answer):
                    respond(id: pending.id, status: answer.status, results: answer.results)
                    note(String(format: "Request %d answered with status 0x%02X", pending.id, answer.status))
                    if answer.status == CTAPStatus.ok, !pending.request.userPresence {
                        // Silent check answered: keep the key session for the sign-in that follows.
                        liveSession = session
                        followUpDeadline = Date().addingTimeInterval(Self.followUpWindow)
                        self.pending = nil
                        executing = nil
                        phase = .holding("Keep holding…")
                        return
                    }
                    let ok = answer.status == CTAPStatus.ok
                    await session.close(message: ok ? (pending.isRegistration ? "Passkey saved" : "Signed in") : nil)
                    self.pending = nil
                    executing = nil
                    if ok {
                        succeed(pending.isRegistration ? "Passkey saved for \(pending.site)" : "Signed in to \(pending.site)")
                    } else if answer.status == CTAPStatus.noCredentials {
                        show(.failed("This key has no passkey for \(pending.site)."), resetAfter: 4)
                    } else {
                        show(.failed("The key refused the request."), resetAfter: 4)
                    }
                }
            }
        }
    }

    private func runFollowUp(id: Int, request: RelayRequest, in session: KeySession) {
        executing = (id, false)
        liveSession = nil
        note("Request \(id): sign in at \(request.rpId), same key session")
        Task {
            let outcome = await session.run(request)
            if await abandonAndClose(id, session: session) { return }
            switch outcome {
            case .success(let answer):
                respond(id: id, status: answer.status, results: answer.results)
                note(String(format: "Request %d answered with status 0x%02X", id, answer.status))
                let ok = answer.status == CTAPStatus.ok
                await session.close(message: ok ? "Signed in" : nil)
                executing = nil
                if ok { succeed("Signed in to \(request.rpId)") } else { show(.failed("The key refused the sign-in."), resetAfter: 4) }
            case .failure(let failure):
                await session.close(message: nil)
                executing = nil
                note("Request \(id) follow-up failed: \(failure)")
                // The key left the field: ask again like a normal request instead of failing the sign-in.
                present(Pending(id: id, request: request), as: .failed(failure.message))
            }
        }
    }

    /// If the running request was cancelled or its connection dropped, discard it.
    private func abandon(_ id: Int, session: KeySession?) -> Bool {
        guard let executing, executing.id == id, executing.abandoned else { return false }
        self.executing = nil
        if pending?.id == id { pending = nil }
        note("Request \(id) discarded: cancelled or disconnected")
        show(.failed("The sign-in was cancelled on the computer."), resetAfter: 3)
        return true
    }

    private func abandonAndClose(_ id: Int, session: KeySession) async -> Bool {
        guard executing?.id == id, executing?.abandoned == true else { return false }
        await session.close(message: nil)
        return abandon(id, session: session)
    }

    private func finishSession(message: String?, phase newPhase: Phase?) {
        followUpDeadline = nil
        guard let session = liveSession else { return }
        liveSession = nil
        Task { await session.close(message: message) }
        if let newPhase { show(newPhase, resetAfter: 2) }
    }

    private func succeed(_ text: String) {
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        show(.done(text), resetAfter: 2)
    }

    /// Key or NFC failure. Retryable failures keep the request so the operator can try again.
    private func fail(_ failure: KeySession.Failure, keepRequest: Bool) {
        note("Key step failed: \(failure)")
        UINotificationFeedbackGenerator().notificationOccurred(.error)
        guard let pending else { return }
        if keepRequest {
            phase = .failed(failure.message)
        } else {
            respond(id: pending.id, status: CTAPStatus.operationDenied, results: [])
            self.pending = nil
            show(.failed(failure.message), resetAfter: 4)
        }
    }

    /// Shows a transient result. Never covers a request that is waiting for the operator.
    private func show(_ newPhase: Phase, resetAfter seconds: Double) {
        guard pending == nil else { return }
        phase = newPhase
        phaseReset?.cancel()
        phaseReset = Task {
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, pending == nil, !working, liveSession == nil else { return }
            phase = connection == nil ? (address.isEmpty ? .setup : .connecting) : (armedUntil != nil ? .ready : .connecting)
        }
    }

    private func note(_ text: String) {
        let time = Date().formatted(date: .omitted, time: .standard)
        activity.insert("\(time)  \(text)", at: 0)
        if activity.count > 100 { activity.removeLast() }
        print("[KeyRelay] \(time)  \(text)")  // console output for debugging
    }
}
