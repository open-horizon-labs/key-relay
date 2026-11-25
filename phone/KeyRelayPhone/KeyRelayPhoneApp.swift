import RelayCore
import SwiftUI

@main
struct KeyRelayPhoneApp: App {
    @State private var model = RelayModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .onChange(of: scenePhase) { _, phase in
                    switch phase {
                    case .active: model.appBecameActive()
                    case .background: model.appWentToBackground()
                    default: break
                    }
                }
        }
    }
}

/// One screen, one state, one next step.
struct ContentView: View {
    @Bindable var model: RelayModel
    @State private var pin = ""
    @State private var showingSettings = false
    @FocusState private var pinFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()
                status
                Spacer()
                actions
            }
            .padding(24)
            .frame(maxWidth: .infinity)
            .animation(.snappy, value: model.phase)
            .toolbar {
                Button { showingSettings = true } label: { Image(systemName: "gearshape") }
                    .accessibilityLabel("Settings")
            }
            .sheet(isPresented: $showingSettings) { SettingsView(model: model) }
            .onChange(of: model.phase) { _, phase in
                if phase == .request { pinFocused = true }
            }
        }
    }

    // MARK: Status

    @ViewBuilder private var status: some View {
        switch model.phase {
        case .setup:
            StatusBlock(symbol: "key.horizontal", tint: .secondary, title: "Set up KeyRelay",
                        detail: "Add your receiver's address in Settings to get started.")
        case .connecting:
            VStack(spacing: 16) {
                ProgressView().controlSize(.large)
                Text("Connecting…").font(.title2.weight(.semibold))
                Text(model.hostLabel).foregroundStyle(.secondary)
            }
        case .ready:
            StatusBlock(symbol: "checkmark.shield.fill", tint: .green, title: "Ready",
                        detail: "Sign-ins from \(model.hostLabel) will appear here.\nKeep this app open.")
        case .request:
            if let pending = model.pending {
                VStack(spacing: 12) {
                    Image(systemName: pending.isRegistration ? "person.badge.key.fill" : "person.badge.shield.checkmark.fill")
                        .font(.system(size: 56)).foregroundStyle(.tint)
                    Text(pending.isRegistration ? "Save a new passkey for" : "Sign in to")
                        .font(.title3).foregroundStyle(.secondary)
                    Text(pending.site).font(.largeTitle.weight(.bold)).multilineTextAlignment(.center)
                    if pending.isRegistration, let user = pending.request.userName {
                        Text("as \(user)").foregroundStyle(.secondary)
                        Text("This replaces any passkey this site already has for that account.")
                            .font(.footnote).foregroundStyle(.orange).multilineTextAlignment(.center)
                    }
                    Text("from \(model.hostLabel)").font(.footnote).foregroundStyle(.secondary)
                }
            }
        case .holding(let text):
            VStack(spacing: 16) {
                Image(systemName: "wave.3.right.circle.fill")
                    .font(.system(size: 72)).foregroundStyle(.tint)
                    .symbolEffect(.variableColor.iterative, options: .repeating)
                Text(text).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
                Text("Keep it still until the sheet closes.").foregroundStyle(.secondary)
            }
        case .done(let text):
            StatusBlock(symbol: "checkmark.circle.fill", tint: .green, title: text, detail: nil)
        case .failed(let text):
            StatusBlock(symbol: "exclamationmark.triangle.fill", tint: .orange, title: text, detail: nil)
        }
    }

    // MARK: Actions

    @ViewBuilder private var actions: some View {
        switch model.phase {
        case .setup:
            Button("Open Settings") { showingSettings = true }
                .buttonStyle(.borderedProminent).controlSize(.large)
        case .request, .failed where model.pending != nil:
            VStack(spacing: 12) {
                SecureField("YubiKey PIN", text: $pin)
                    .textContentType(.password)
                    .keyboardType(.asciiCapable)
                    .submitLabel(.go)
                    .focused($pinFocused)
                    .onSubmit(approve)
                    .padding(14)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
                Button(action: approve) {
                    Text(model.phase == .request ? "Continue" : "Try again").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(pin.count < 4)
                Button("Deny", role: .destructive) { model.deny(); pin = "" }
            }
        default:
            EmptyView()
        }
    }

    private func approve() {
        guard pin.count >= 4 else { return }
        pinFocused = false
        model.approve(pin: pin)
        pin = ""
    }
}

private struct StatusBlock: View {
    let symbol: String
    let tint: Color
    let title: String
    let detail: String?

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: symbol).font(.system(size: 72)).foregroundStyle(tint)
            Text(title).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
            if let detail { Text(detail).foregroundStyle(.secondary).multilineTextAlignment(.center) }
        }
    }
}

private struct SettingsView: View {
    @Bindable var model: RelayModel
    @State private var draft = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("host:port", text: $draft)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("Receiver")
                } footer: {
                    Text("The receiver's Tailscale address and port, e.g. 100.x.y.z:47100.")
                }
                Section("Activity") {
                    if model.activity.isEmpty { Text("Nothing yet").foregroundStyle(.secondary) }
                    ForEach(Array(model.activity.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption.monospaced())
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        if draft != model.address { model.saveAddress(draft) }
                        dismiss()
                    }
                }
            }
            .onAppear { draft = model.address }
        }
    }
}
