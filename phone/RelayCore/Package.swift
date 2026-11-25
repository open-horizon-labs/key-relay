// swift-tools-version: 6.1
import PackageDescription

// Platform-independent KeyRelay phone logic: strict CTAP CBOR, request checks and
// rewriting, interface B framing, and CTAP-over-APDU exchange. Tested on macOS.
let package = Package(
    name: "RelayCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "RelayCore", targets: ["RelayCore"])],
    targets: [
        .target(name: "RelayCore"),
        .testTarget(name: "RelayCoreTests", dependencies: ["RelayCore"]),
    ]
)
